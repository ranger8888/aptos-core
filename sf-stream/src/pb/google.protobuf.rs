
# [allow (dead_code)] const IMPL_MESSAGE_SERDE_FOR_TIMESTAMP : () = { use :: prost_wkt :: typetag ; # [typetag :: serde (name = "type.googleapis.com/google.protobuf.Timestamp")] impl :: prost_wkt :: MessageSerde for Timestamp { fn package_name (& self) -> & 'static str { "google.protobuf" } fn message_name (& self) -> & 'static str { "Timestamp" } fn type_url (& self) -> & 'static str { "type.googleapis.com/google.protobuf.Timestamp" } fn new_instance (& self , data : Vec < u8 >) -> Result < Box < dyn :: prost_wkt :: MessageSerde > , :: prost :: DecodeError > { let mut target = Self :: default () ; :: prost :: Message :: merge (& mut target , data . as_slice ()) ? ; let erased : Box < dyn :: prost_wkt :: MessageSerde > = Box :: new (target) ; Ok (erased) } fn encoded (& self) -> Vec < u8 > { let mut buf = Vec :: new () ; buf . reserve (:: prost :: Message :: encoded_len (self)) ; :: prost :: Message :: encode (self , & mut buf) . expect ("Failed to encode message") ; buf } fn try_encoded (& self) -> Result < Vec < u8 > , :: prost :: EncodeError > { let mut buf = Vec :: new () ; buf . reserve (:: prost :: Message :: encoded_len (self)) ; :: prost :: Message :: encode (self , & mut buf) ? ; Ok (buf) } } } ;
