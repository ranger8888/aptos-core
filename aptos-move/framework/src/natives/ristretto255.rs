// Copyright (c) Aptos
// SPDX-License-Identifier: Apache-2.0

use crate::natives::util::make_native_from_func;
use move_deps::{
    move_binary_format::errors::PartialVMResult,
    move_vm_runtime::native_functions::{NativeContext, NativeFunction},
    move_vm_types::{
        loaded_data::runtime_types::Type, natives::function::NativeResult, pop_arg, values::Value,
    },
};
use sha2::Sha512;
use smallvec::smallvec;
use std::ops::{Add, Mul, Neg, Sub};
use std::{collections::VecDeque, convert::TryFrom};

#[derive(Debug, Clone)]
pub struct ScalarIsCanonicalGasParameters {
    pub base_cost: u64,
    pub per_point_deserialize_cost: u64,
}

fn native_scalar_is_canonical(
    gas_params: &ScalarIsCanonicalGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    let bytes_slice = match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            return Ok(NativeResult::ok(cost, smallvec![Value::bool(false)]));
        }
    };

    cost += gas_params.per_point_deserialize_cost;

    // TODO: Speed up this implementation using bit testing?
    // This will build a Scalar in-memory and call curve25519-dalek's is_canonical
    match curve25519_dalek::scalar::Scalar::from_canonical_bytes(bytes_slice) {
        Some(_) => Ok(NativeResult::ok(cost, smallvec![Value::bool(true)])),
        None => Ok(NativeResult::ok(cost, smallvec![Value::bool(false)])),
    }
}

#[derive(Debug, Clone)]
pub struct ScalarInvertGasParameters {
    pub base_cost: u64,
    pub per_scalar_invert_cost: u64,
}

fn native_scalar_invert(
    gas_params: &ScalarInvertGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(bytes.len() == 32);
    let bytes_slice = match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    let s = curve25519_dalek::scalar::Scalar::from_bits(bytes_slice);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(s.is_canonical());

    // Invert and return
    cost += gas_params.per_scalar_invert_cost;
    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.invert().to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromSha512GasParameters {
    pub base_cost: u64,
    pub per_hash_sha512_cost: u64,
    pub per_byte_sha512_cost: u64,
}

fn native_scalar_from_sha512(
    gas_params: &ScalarFromSha512GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    cost += gas_params.per_hash_sha512_cost + gas_params.per_byte_sha512_cost * bytes.len() as u64;
    let s = curve25519_dalek::scalar::Scalar::hash_from_bytes::<Sha512>(bytes.as_slice());

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarMulGasParameters {
    pub base_cost: u64,
    pub per_mul_cost: u64,
}

fn native_scalar_mul(
    gas_params: &ScalarMulGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(a_bytes.len() == 32);
    let a_bytes_slice = match <[u8; 32]>::try_from(a_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    debug_assert!(b_bytes.len() == 32);
    let b_bytes_slice = match <[u8; 32]>::try_from(b_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    let a = curve25519_dalek::scalar::Scalar::from_bits(a_bytes_slice);
    let b = curve25519_dalek::scalar::Scalar::from_bits(b_bytes_slice);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.per_mul_cost;
    let s = a.mul(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}
#[derive(Debug, Clone)]
pub struct ScalarAddGasParameters {
    pub base_cost: u64,
    pub per_add_cost: u64,
}

fn native_scalar_add(
    gas_params: &ScalarAddGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(a_bytes.len() == 32);
    let a_bytes_slice = match <[u8; 32]>::try_from(a_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    debug_assert!(b_bytes.len() == 32);
    let b_bytes_slice = match <[u8; 32]>::try_from(b_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    let a = curve25519_dalek::scalar::Scalar::from_bits(a_bytes_slice);
    let b = curve25519_dalek::scalar::Scalar::from_bits(b_bytes_slice);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.per_add_cost;
    let s = a.add(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarSubGasParameters {
    pub base_cost: u64,
    pub per_sub_cost: u64,
}

fn native_scalar_sub(
    gas_params: &ScalarSubGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 2);

    let mut cost = gas_params.base_cost;

    let b_bytes = pop_arg!(arguments, Vec<u8>);
    let a_bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(a_bytes.len() == 32);
    let a_bytes_slice = match <[u8; 32]>::try_from(a_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    debug_assert!(b_bytes.len() == 32);
    let b_bytes_slice = match <[u8; 32]>::try_from(b_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    let a = curve25519_dalek::scalar::Scalar::from_bits(a_bytes_slice);
    let b = curve25519_dalek::scalar::Scalar::from_bits(b_bytes_slice);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());
    debug_assert!(b.is_canonical());

    cost += gas_params.per_sub_cost;
    let s = a.sub(b);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarNegGasParameters {
    pub base_cost: u64,
    pub per_neg_cost: u64,
}

fn native_scalar_neg(
    gas_params: &ScalarNegGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let a_bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(a_bytes.len() == 32);
    let a_bytes_slice = match <[u8; 32]>::try_from(a_bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    let a = curve25519_dalek::scalar::Scalar::from_bits(a_bytes_slice);

    // We'd like to ensure all Move Scalar types are canonical scalars reduced modulo \ell
    debug_assert!(a.is_canonical());

    cost += gas_params.per_neg_cost;
    let s = a.neg();

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromU64GasParameters {
    pub base_cost: u64,
    pub from_u64_cost: u64,
}

fn native_scalar_from_u64(
    gas_params: &ScalarFromU64GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let num = pop_arg!(arguments, u64);

    cost += gas_params.from_u64_cost;
    let s = curve25519_dalek::scalar::Scalar::from(num);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFromU128GasParameters {
    pub base_cost: u64,
    pub from_u128_cost: u64,
}

fn native_scalar_from_u128(
    gas_params: &ScalarFromU128GasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let num = pop_arg!(arguments, u128);

    cost += gas_params.from_u128_cost;
    let s = curve25519_dalek::scalar::Scalar::from(num);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFrom256BitsGasParameters {
    pub base_cost: u64,
    pub from_256_bits_cost: u64,
}

fn native_scalar_from_256_bits(
    gas_params: &ScalarFrom256BitsGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 32 bytes
    debug_assert!(bytes.len() == 32);
    let bytes_slice = match <[u8; 32]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 32
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    cost += gas_params.from_256_bits_cost;
    let s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(bytes_slice);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct ScalarFrom512BitsGasParameters {
    pub base_cost: u64,
    pub from_512_bits_cost: u64,
}

fn native_scalar_from_512_bits(
    gas_params: &ScalarFrom512BitsGasParameters,
    _context: &mut NativeContext,
    _ty_args: Vec<Type>,
    mut arguments: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    debug_assert!(_ty_args.is_empty());
    debug_assert!(arguments.len() == 1);

    let mut cost = gas_params.base_cost;

    let bytes = pop_arg!(arguments, Vec<u8>);

    // Length should be exactly 64 bytes
    debug_assert!(bytes.len() == 64);
    let bytes_slice = match <[u8; 64]>::try_from(bytes) {
        Ok(slice) => slice,
        Err(_) => {
            // NOTE: We return an empty vector in this case. Since the caller always passes in 64
            // bytes to this function, this path should never be reached.
            return Ok(NativeResult::ok(cost, smallvec![Value::vector_u8(vec![])]));
        }
    };

    cost += gas_params.from_512_bits_cost;
    let s = curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&bytes_slice);

    Ok(NativeResult::ok(
        cost,
        smallvec![Value::vector_u8(s.to_bytes().to_vec())],
    ))
}

#[derive(Debug, Clone)]
pub struct GasParameters {
    pub is_canonical: ScalarIsCanonicalGasParameters,
    pub scalar_invert: ScalarInvertGasParameters,
    pub scalar_from_sha512: ScalarFromSha512GasParameters,
    pub scalar_mul: ScalarMulGasParameters,
    pub scalar_add: ScalarAddGasParameters,
    pub scalar_sub: ScalarSubGasParameters,
    pub scalar_neg: ScalarNegGasParameters,
    pub scalar_from_u64: ScalarFromU64GasParameters,
    pub scalar_from_u128: ScalarFromU128GasParameters,
    pub scalar_from_256_bits: ScalarFrom256BitsGasParameters,
    pub scalar_from_512_bits: ScalarFrom512BitsGasParameters,
}

pub fn make_all(gas_params: GasParameters) -> impl Iterator<Item = (String, NativeFunction)> {
    let natives = [
        (
            "is_canonical_internal",
            make_native_from_func(gas_params.is_canonical, native_scalar_is_canonical),
        ),
        (
            "scalar_invert_internal",
            make_native_from_func(gas_params.scalar_invert, native_scalar_invert),
        ),
        (
            "scalar_from_sha512_internal",
            make_native_from_func(gas_params.scalar_from_sha512, native_scalar_from_sha512),
        ),
        (
            "scalar_mul_internal",
            make_native_from_func(gas_params.scalar_mul, native_scalar_mul),
        ),
        (
            "scalar_add_internal",
            make_native_from_func(gas_params.scalar_add, native_scalar_add),
        ),
        (
            "scalar_sub_internal",
            make_native_from_func(gas_params.scalar_sub, native_scalar_sub),
        ),
        (
            "scalar_neg_internal",
            make_native_from_func(gas_params.scalar_neg, native_scalar_neg),
        ),
        (
            "scalar_from_u64_internal",
            make_native_from_func(gas_params.scalar_from_u64, native_scalar_from_u64),
        ),
        (
            "scalar_from_u128_internal",
            make_native_from_func(gas_params.scalar_from_u128, native_scalar_from_u128),
        ),
        (
            "scalar_from_256_bits_internal",
            make_native_from_func(gas_params.scalar_from_256_bits, native_scalar_from_256_bits),
        ),
        (
            "scalar_from_512_bits_internal",
            make_native_from_func(gas_params.scalar_from_512_bits, native_scalar_from_512_bits),
        ),
    ];

    crate::natives::helpers::make_module_natives(natives)
}
