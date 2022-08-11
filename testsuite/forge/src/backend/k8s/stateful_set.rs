// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::{Result, KUBECTL_BIN};
use std::{process::Command, time::Duration};

use k8s_openapi::api::{apps::v1::StatefulSet, core::v1::Pod};
use once_cell::sync::Lazy;

use again::RetryPolicy;
use aptos_logger::info;
use kube::{
    api::{Api, Meta, Patch, PatchParams},
    client::Client as K8sClient,
};
use thiserror::Error;

use crate::create_k8s_client;

// retry every 10 seconds for 60 times, for up to 10 minutes
// we want a fixed retry policy here to be as fast as possible
static RETRY_POLICY: Lazy<RetryPolicy> =
    Lazy::new(|| RetryPolicy::fixed(Duration::from_millis(10 * 1000)).with_max_retries(60));

#[derive(Error, Debug)]
#[error("{0}")]
enum WorkloadScalingError {
    RetryableError(String),
    FinalError(String),
}

pub struct KubeImage {
    pub name: String,
    pub tag: String,
}

pub fn get_stateful_set_image(stateful_set: &StatefulSet) -> Result<KubeImage> {
    let s = stateful_set
        .spec
        .as_ref()
        .expect("Failed to get StatefulSet spec")
        .template
        .spec
        .as_ref()
        .expect("Failed to get StatefulSet spec")
        .containers[0]
        .image
        .as_ref()
        .expect("Failed to get StatefulSet image")
        .split(':')
        .collect::<Vec<&str>>();

    Ok(KubeImage {
        name: s[0].to_string(),
        tag: s[1].to_string(),
    })
}

/// Waits for a single K8s StatefulSet to be ready
pub async fn wait_stateful_set(
    kube_client: &K8sClient,
    kube_namespace: &str,
    sts_name: &str,
    desired_replicas: u64,
) -> Result<()> {
    RETRY_POLICY
        .retry_if(
            move || {
                check_stateful_set_status(kube_client, kube_namespace, sts_name, desired_replicas)
            },
            |e: &WorkloadScalingError| matches!(e, WorkloadScalingError::RetryableError(_)),
        )
        .await?;

    Ok(())
}

/// Checks the status of a single K8s StatefulSet
async fn check_stateful_set_status(
    kube_client: &K8sClient,
    kube_namespace: &str,
    sts_name: &str,
    desired_replicas: u64,
) -> Result<(), WorkloadScalingError> {
    let sts_api: Api<StatefulSet> = Api::namespaced(kube_client.clone(), kube_namespace);
    let pod_api: Api<Pod> = Api::namespaced(kube_client.clone(), kube_namespace);
    match sts_api.get_status(sts_name).await {
        Ok(s) => {
            let sts_name = &s.name();
            // get the StatefulSet status
            if let Some(sts_status) = s.status {
                let ready_replicas = sts_status.ready_replicas.unwrap_or(0) as u64;
                let replicas = sts_status.replicas as u64;
                if ready_replicas == replicas && replicas == desired_replicas {
                    info!(
                        "StatefulSet {} has scaled to {}",
                        sts_name, desired_replicas
                    );
                }
                info!(
                    "StatefulSet {} has {}/{} replicas",
                    sts_name, ready_replicas, desired_replicas
                );
            }
            let pod_name = format!("{}-0", sts_name);
            // Get the StatefulSet's Pod status
            if let Some(status) = pod_api
                .get_status(&pod_name)
                .await
                .map_err(|e| WorkloadScalingError::RetryableError(e.to_string()))?
                .status
            {
                if let Some(container_statuses) = status.container_statuses {
                    if let Some(container_status) = container_statuses.last() {
                        if let Some(state) = &container_status.state {
                            if let Some(waiting) = &state.waiting {
                                if let Some(waiting_reason) = &waiting.reason {
                                    match waiting_reason.as_str() {
                                        "ImagePullBackOff" => {
                                            info!("Pod {} has ImagePullBackOff", &pod_name);
                                            return Err(WorkloadScalingError::FinalError(
                                                "ImagePullBackOff".to_string(),
                                            ));
                                        }
                                        "CrashLoopBackOff" => {
                                            info!("Pod {} has CrashLoopBackOff", &pod_name);
                                            return Err(WorkloadScalingError::FinalError(
                                                "CrashLoopBackOff".to_string(),
                                            ));
                                        }
                                        "ErrImagePull" => {
                                            info!("Pod {} has ErrImagePull", &pod_name);
                                            return Err(WorkloadScalingError::FinalError(
                                                "ErrImagePull".to_string(),
                                            ));
                                        }
                                        _ => {
                                            info!("Pod {} has unknown waiting reason", &pod_name);
                                            return Err(WorkloadScalingError::RetryableError(
                                                "Unknown waiting reason".to_string(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(phase) = status.phase.as_ref() {
                    info!("Pod {} at phase {}", &pod_name, phase)
                }
            } else {
                return Err(WorkloadScalingError::FinalError(
                    "Pod not found".to_string(),
                ));
            }
        }
        Err(e) => {
            info!("Failed to get sts: {}", e);
            return Err(WorkloadScalingError::RetryableError(format!(
                "Failed to get sts: {}",
                e
            )));
        }
    }
    Ok(())
}

/// Given the name of a node's StatefulSet, sets the node's image tag. Assumes that the StatefulSet has only one container
pub async fn set_stateful_set_image_tag(
    stateful_set_name: String,
    container_name: String,
    image_tag: String,
    kube_namespace: String,
) -> Result<()> {
    let kube_client: K8sClient = create_k8s_client().await;
    let sts_api: Api<StatefulSet> = Api::namespaced(kube_client.clone(), &kube_namespace);
    let sts = sts_api.get(&stateful_set_name).await?;
    let image_repo = get_stateful_set_image(&sts)?.name;

    // replace the image tag
    let new_image = format!("{}:{}", &image_repo, &image_tag);

    // patch it
    Command::new(KUBECTL_BIN)
        .args([
            "set",
            "image",
            &format!("statefulset/{}", &stateful_set_name),
            &format!("{}={}", &container_name, &new_image),
        ])
        .status()
        .expect("Failed to set image for StatefulSet");
    // kubectl patch statefulset <statefulset_name> --type='json' -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/image", "value":"<new_image_name>"}]'
    // let pp = PatchParams::apply("forge").force();
    // let patch = serde_json::json!({
    //     "apiVersion": "apps/v1",
    //     "kind": "StatefulSet",
    //     "metadata": {
    //         "name": stateful_set_name,
    //     },
    //     "spec": {
    //         "template": {
    //             "spec": {
    //                 "containers": [
    //                     {
    //                         "name": &container_name,
    //                         "image": new_image
    //                     },
    //                 ],
    //             },
    //         },
    //     }
    // });
    // info!("Patching with: {}", patch);
    // let patch = Patch::Apply(&patch);
    // sts_api.patch(&stateful_set_name, &pp, &patch).await?;
    wait_stateful_set(&kube_client, &kube_namespace, &stateful_set_name, 1).await?;

    Ok(())
}

/// Scales the given StatefulSet to the given number of replicas
pub async fn scale_stateful_set_replicas(
    sts_name: &str,
    kube_namespace: &str,
    replica_num: u64,
) -> Result<()> {
    let kube_client = create_k8s_client().await;
    let stateful_set_api: Api<StatefulSet> = Api::namespaced(kube_client.clone(), kube_namespace);
    let pp = PatchParams::apply("forge").force();
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": sts_name,
        },
        "spec": {
            "replicas": replica_num,
        }
    });
    let patch = Patch::Apply(&patch);
    stateful_set_api.patch(sts_name, &pp, &patch).await?;
    wait_stateful_set(&kube_client, kube_namespace, sts_name, replica_num).await?;

    Ok(())
}
