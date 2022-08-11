/// Contains functions for Ristretto255 curve arithmetic.
///
/// The order of this elliptic curve group is $\ell = 2^252 + 27742317777372353535851937790883648493$, same as the order
/// of the prime-order subgroup of Curve25519.
module cryptography::ristretto255 {
    use std::option::Option;
    use std::bit_vector::BitVector;

    // TODO: compressedpoint struct (to store on chain)
    // TODO: point struct (to do fast arithmetic with)
    //  - hash_from_bytes<D: Digest>
    //  - from_uniform_bytes
    //  - equals
    //  - add(_assign), sub(_assign), neg(_assign), double(_assign), mul(_assign),
    //  - hash, msm

    /// The maximum size in bytes of a canonically-encoded Scalar is 32 bytes.
    const MAX_SCALAR_NUM_BYTES : u64 = 32u64;

    /// The maximum size in bits of a canonically-encoded Scalar is 256 bits.
    const MAX_SCALAR_NUM_BITS : u64 = 256u64;

    /// The order of the Ristretto255 group and its scalar field, in little-endian.
    const ORDER_ELL : vector<u8> = vector[
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    // TODO: Consider supporting:
    //  - Batch inversion (batch_invert())

    /// This struct represents a scalar as a little-endian byte encoding of an integer in $\mathbb{Z}_\ell$, which is
    /// stored in `data`. Here, \ell denotes the order of the scalar field (and the underlying elliptic curve group).
    struct Scalar has key, store, drop {
        data: vector<u8>
    }

    /// Returns a Scalar from a sequence of 32 canonically-encoded bytes: i.e., the unsigned big integer encoded in
    /// these bytes is less than the Ristretto group order $\ell$.
    public fun new_scalar_from_canonical_bytes(bytes: vector<u8>): Option<Scalar> {
        if (is_canonical_internal(bytes)) {
            std::option::some(Scalar {
                data: bytes
            })
        } else {
            std::option::none<Scalar>()
        }
    }

    /// Hashes the input to a Scalar via SHA512
    public fun new_scalar_from_sha512(sha512_input: vector<u8>): Scalar {
        Scalar {
            data: scalar_from_sha512_internal(sha512_input)
        }
    }

    /// Creates a Scalar from an u8.
    public fun new_scalar_from_u8(byte: u8): Scalar {
        let s = scalar_zero();
        let byte_zero = std::vector::borrow_mut(&mut s.data, 0);
        *byte_zero = byte;

        s
    }

    /// Creates a Scalar from an u64.
    public fun new_scalar_from_u64(eight_bytes: u64): Scalar {
        Scalar {
            data: scalar_from_u64_internal(eight_bytes)
        }
    }

    /// Creates a Scalar from an u128.
    public fun new_scalar_from_u128(sixteen_bytes: u128): Scalar {
        Scalar {
            data: scalar_from_u128_internal(sixteen_bytes)
        }
    }

    /// Creates a Scalar from 32 bytes by reducing the little-endian-encoded number in those bytes modulo $\ell$.
    public fun new_scalar_from_reduced_256_bits(bytes: vector<u8>): Option<Scalar> {
        if (std::vector::length(&bytes) == 32) {
            std::option::some(Scalar {
                data: scalar_from_256_bits_internal(bytes)
            })
        } else {
            std::option::none()
        }
    }

    /// Creates a Scalar from 64 bytes by reducing the little-endian-encoded number in those bytes modulo $\ell$.
    public fun new_scalar_from_reduced_512_bits(bytes: vector<u8>): Option<Scalar> {
        if (std::vector::length(&bytes) == 64) {
            std::option::some(Scalar {
                data: scalar_from_512_bits_internal(bytes)
            })
        } else {
            std::option::none()
        }
    }

    /// Returns 0 as a Scalar.
    public fun scalar_zero(): Scalar {
        Scalar {
            data: x"0000000000000000000000000000000000000000000000000000000000000000"
        }
    }

    /// Returns true if the given Scalar equals 0.
    public fun scalar_is_zero(s: &Scalar): bool {
        //assert!(is_canonical_internal(s.data), 1);

        s.data == x"0000000000000000000000000000000000000000000000000000000000000000"
    }

    /// Returns 1 as a Scalar.
    public fun scalar_one(): Scalar {
        Scalar {
            data: x"0100000000000000000000000000000000000000000000000000000000000000"
        }
    }

    /// Returns true if the given Scalar equals 1.
    public fun scalar_is_one(s: &Scalar): bool {
        //assert!(is_canonical_internal(s.data), 1);

        s.data == x"0100000000000000000000000000000000000000000000000000000000000000"
    }

    /// Returns true if the two scalars are equal.
    public fun scalar_equals(lhs: &Scalar, rhs: &Scalar): bool {
        //assert!(is_canonical_internal(lhs.data), 1);
        //assert!(is_canonical_internal(rhs.data), 1);

        lhs.data == rhs.data
    }

    /// Returns the 256-bit binary representation of a Scalar, where bits within a byte are sorted in litle-endian order.
    ///
    /// e.g., 0x1C would typically be expressed in binary as:
    ///     bit: 0 0 0 1 1 1 0 0
    ///     idx: 0 1 2 3 4 5 6 7
    ///
    /// However, this function will represent it by reversing the bits as:
    ///     bit: 0 0 1 1 1 0 0 0
    ///     idx: 0 1 2 3 4 5 6 7
    public fun scalar_little_endian_bits(s: &Scalar): BitVector {
        //assert!(std::vector::length(&s.data) == MAX_SCALAR_NUM_BYTES, 1);

        std::bit_vector::new_little_endian_from_byte_vector(s.data)
    }

    /// Returns the 256-bit binary representation of a Scalar, where bits within a byte are sorted in big-endian order.
    ///
    /// e.g., for 0x1C this function would represent it as:
    ///     bit: 0 0 0 1 1 1 0 0
    ///     idx: 0 1 2 3 4 5 6 7
    public fun scalar_big_endian_bits(s: &Scalar): BitVector {
        //assert!(std::vector::length(&s.data) == MAX_SCALAR_NUM_BYTES, 1);

        std::bit_vector::new_big_endian_from_byte_vector(s.data)
    }

    /// Returns the inverse s^{-1} mod \ell of a scalar s.
    /// Returns None if s is zero.
    public fun scalar_invert(s: &Scalar): Option<Scalar> {
        //assert!(is_canonical_internal(s.data), 1);

        if (scalar_is_zero(s)) {
            std::option::none<Scalar>()
        } else {
            std::option::some(Scalar {
                data: scalar_invert_internal(s.data)
            })
        }
    }

    /// Returns the product of the two scalars.
    public fun scalar_mul(a: &Scalar, b: &Scalar): Scalar {
        Scalar {
            data: scalar_mul_internal(a.data, b.data)
        }
    }

    /// Computes the product of 'a' and 'b' and assigns the result to 'a'
    public fun scalar_mul_assign(a: &mut Scalar, b: &Scalar) {
        a.data = scalar_mul(a, b).data
    }

    /// Returns the sum of the two scalars.
    public fun scalar_add(a: &Scalar, b: &Scalar): Scalar {
        Scalar {
            data: scalar_add_internal(a.data, b.data)
        }
    }

    /// Computes the sum of 'a' and 'b' and assigns the result to 'a'
    public fun scalar_add_assign(a: &mut Scalar, b: &Scalar) {
        a.data = scalar_add(a, b).data
    }

    /// Returns the difference of the two scalars.
    public fun scalar_sub(a: &Scalar, b: &Scalar): Scalar {
        Scalar {
            data: scalar_sub_internal(a.data, b.data)
        }
    }

    /// Subtracts 'b' from 'a' and assigns the result to 'a'
    public fun scalar_sub_assign(a: &mut Scalar, b: &Scalar) {
        a.data = scalar_sub(a, b).data
    }

    /// Returns the negation of 'a': i.e., $(0 - a) \mod \ell$.
    public fun scalar_neg(a: &Scalar): Scalar {
        Scalar {
            data: scalar_neg_internal(a.data)
        }
    }

    /// Replaces 'a' by its negation.
    public fun scalar_neg_assign(a: &mut Scalar) {
        a.data = scalar_neg(a).data
    }

    /// Returns the byte-representation of the scalar.
    public fun to_bytes(s: &Scalar): vector<u8> {
        s.data
    }

    //
    // Only used internally.
    //
    native fun is_canonical_internal(s: vector<u8>): bool;

    native fun scalar_from_u64_internal(num: u64): vector<u8>;

    native fun scalar_from_u128_internal(num: u128): vector<u8>;

    native fun scalar_from_256_bits_internal(bytes: vector<u8>): vector<u8>;

    native fun scalar_from_512_bits_internal(bytes: vector<u8>): vector<u8>;

    native fun scalar_invert_internal(bytes: vector<u8>): vector<u8>;

    native fun scalar_from_sha512_internal(sha512_input: vector<u8>): vector<u8>;

    native fun scalar_mul_internal(a_bytes: vector<u8>, b_bytes: vector<u8>): vector<u8>;

    native fun scalar_add_internal(a_bytes: vector<u8>, b_bytes: vector<u8>): vector<u8>;

    native fun scalar_sub_internal(a_bytes: vector<u8>, b_bytes: vector<u8>): vector<u8>;

    native fun scalar_neg_internal(a_bytes: vector<u8>): vector<u8>;

    //
    // Testing
    //

    // The scalar 2
    const TWO: vector<u8> = vector[
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // The order minus 1: i.e., the "largest", reduced scalar in the field
    const L_MINUS_ONE: vector<u8> = vector[
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    // Non-canonical scalar: the order \ell of the group + 1
    const L_PLUS_ONE: vector<u8> = vector[
        0xee, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    // Non-canonical scalar: the order \ell of the group + 2
    const L_PLUS_TWO: vector<u8> = vector[
        0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ];

    // Some random scalar denoted by X
    const X: vector<u8> = vector[
        0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84,
        0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d, 0x52,
        0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44,
        0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9, 0xf2, 0x04,
    ];

    // X^{-1} = 1/X = 6859937278830797291664592131120606308688036382723378951768035303146619657244
    // 0x1CDC17FCE0E9A5BBD9247E56BB016347BBBA31EDD5A9BB96D50BCD7A3F962A0F
    const X_INV: vector<u8> = vector[
        0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb,
        0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63, 0x47,
        0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96,
        0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96, 0x2a, 0x0f,
    ];

    // X_INV from above, but in big-endian binary:
    // 0001110011011100000101111111110011100000111010011010010110111011110110010010010001111110010101101011101100000001011000110100011110111011101110100011000111101101110101011010100110111011100101101101010100001011110011010111101000111111100101100010101000001111
    const X_INV_BE_BITS: vector<bool> = vector[
        false, false, false, true,  true,  true,  false, false, true,  true,  false, true,  true,  true,  false, false,
        false, false, false, true,  false, true,  true,  true,  true,  true,  true,  true,  true,  true,  false, false,
        true,  true,  true,  false, false, false, false, false, true,  true,  true,  false, true,  false, false, true,
        true,  false, true,  false, false, true,  false, true,  true,  false, true,  true,  true,  false, true,  true,
        true,  true,  false, true,  true,  false, false, true,  false, false, true,  false, false, true,  false, false,
        false, true,  true,  true,  true,  true,  true,  false, false, true,  false, true,  false, true,  true,  false,
        true,  false, true,  true,  true,  false, true,  true,  false, false, false, false, false, false, false, true,
        false, true,  true,  false, false, false, true,  true,  false, true,  false, false, false, true,  true,  true,
        true,  false, true,  true,  true,  false, true,  true,  true,  false, true,  true,  true,  false, true,  false,
        false, false, true,  true,  false, false, false, true,  true,  true,  true,  false, true,  true,  false, true,
        true,  true,  false, true,  false, true,  false, true,  true,  false, true,  false, true,  false, false, true,
        true,  false, true,  true,  true,  false, true,  true,  true,  false, false, true,  false, true,  true,  false,
        true,  true,  false, true,  false, true,  false, true,  false, false, false, false, true,  false, true,  true,
        true,  true,  false, false, true,  true,  false, true,  false, true,  true,  true,  true,  false, true,  false,
        false, false, true,  true,  true,  true,  true,  true,  true,  false, false, true,  false, true,  true,  false,
        false, false, true,  false, true,  false, true,  false, false, false, false, false, true,  true,  true,  true,
    ];

    // X_INV from above, but in little-endian binary (least significant bit is at the smallest index)
    // These bits were obtained by writing a custom test in curve25519-dalek's src/scalar.rs file.
    const X_INV_LE_BITS: vector<bool> = vector[
        false, false, true,  true,  true,  false, false, false, false, false, true,  true,  true,  false, true,  true,
        true,  true,  true,  false, true,  false, false, false, false, false, true,  true,  true,  true,  true,  true,
        false, false, false, false, false, true,  true,  true,  true,  false, false, true,  false, true,  true,  true,
        true,  false, true,  false, false, true,  false, true,  true,  true,  false, true,  true,  true,  false, true,
        true,  false, false, true,  true,  false, true,  true,  false, false, true,  false, false, true,  false, false,
        false, true,  true,  true,  true,  true,  true,  false, false, true,  true,  false, true,  false, true,  false,
        true,  true,  false, true,  true,  true,  false, true,  true,  false, false, false, false, false, false, false,
        true,  true,  false, false, false, true,  true,  false, true,  true,  true,  false, false, false, true,  false,
        true,  true,  false, true,  true,  true,  false, true,  false, true,  false, true,  true,  true,  false, true,
        true,  false, false, false, true,  true,  false, false, true,  false, true,  true,  false, true,  true,  true,
        true,  false, true,  false, true,  false, true,  true,  true,  false, false, true,  false, true,  false, true,
        true,  true,  false, true,  true,  true,  false, true,  false, true,  true,  false, true,  false, false, true,
        true,  false, true,  false, true,  false, true,  true,  true,  true,  false, true,  false, false, false, false,
        true,  false, true,  true,  false, false, true,  true,  false, true,  false, true,  true,  true,  true,  false,
        true,  true,  true,  true,  true,  true,  false, false, false, true,  true,  false, true,  false, false, true,
        false, true,  false, true,  false, true,  false, false, true,  true,  true,  true,  false, false, false, false
    ];

    // Some random scalar Y = 2592331292931086675770238855846338635550719849568364935475441891787804997264
    const Y: vector<u8> = vector[
        0x90, 0x76, 0x33, 0xfe, 0x1c, 0x4b, 0x66, 0xa4,
        0xa2, 0x8d, 0x2d, 0xd7, 0x67, 0x83, 0x86, 0xc3,
        0x53, 0xd0, 0xde, 0x54, 0x55, 0xd4, 0xfc, 0x9d,
        0xe8, 0xef, 0x7a, 0xc3, 0x1f, 0x35, 0xbb, 0x05,
    ];

    // X * Y = 5690045403673944803228348699031245560686958845067437804563560795922180092780
    const X_TIMES_Y: vector<u8> = vector[
        0x6c, 0x33, 0x74, 0xa1, 0x89, 0x4f, 0x62, 0x21,
        0x0a, 0xaa, 0x2f, 0xe1, 0x86, 0xa6, 0xf9, 0x2c,
        0xe0, 0xaa, 0x75, 0xc2, 0x77, 0x95, 0x81, 0xc2,
        0x95, 0xfc, 0x08, 0x17, 0x9a, 0x73, 0x94, 0x0c,
    ];

    // X + 2^256 * X \mod \ell
    const CANONICAL_X_PLUS_2_TO_256_TIMES_X : vector<u8> = vector[
        216, 154, 179, 139, 210, 121,   2,  71,
        69,  99, 158, 216,  23, 173,  63, 100,
        204,   0,  91,  50, 219, 153,  57, 249,
        28,  82,  31, 197, 100, 165, 192,   8,
    ];

    // sage: l = 2^252 + 27742317777372353535851937790883648493
    // sage: big = 2^256 - 1
    // sage: repr((big % l).digits(256))
    const CANONICAL_2_256_MINUS_1: vector<u8> = vector[
        28, 149, 152, 141, 116,  49, 236, 214,
        112, 207, 125, 115, 244,  91, 239, 198,
        254, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255,  15,
    ];

    const NON_CANONICAL_ALL_ONES: vector<u8> = vector[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

//    const A_SCALAR: vector<u8> = vector[
//        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d,
//        0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8, 0x26, 0x4d,
//        0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1,
//        0x58, 0x9e, 0x7b, 0x7f, 0x23, 0x76, 0xef, 0x09,
//    ];
//
//    const NON_CANONICAL_LARGEST_ED25519_S: vector<u8> = vector[
//        0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
//    ];
//
//    const CANONICAL_LARGEST_ED25519_S_PLUS_ONE: vector<u8> = vector[
//        0x7e, 0x34, 0x47, 0x75, 0x47, 0x4a, 0x7f, 0x97,
//        0x23, 0xb6, 0x3a, 0x8b, 0xe9, 0x2a, 0xe7, 0x6d,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
//    ];
//
//    const CANONICAL_LARGEST_ED25519_S_MINUS_ONE: vector<u8> = vector[
//        0x7c, 0x34, 0x47, 0x75, 0x47, 0x4a, 0x7f, 0x97,
//        0x23, 0xb6, 0x3a, 0x8b, 0xe9, 0x2a, 0xe7, 0x6d,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
//    ];

    //
    // TODO: Add "Test cases for test_<name> were generated by running `cargo test -- test_sample_<name> --nocapture --include-ignored` in `crates/aptos-crypto`"
    // TODO: ...to each test case that needs it
    //

    #[test]
    fun test_scalar_basic_viability() {
        // Test conversion from u8
        let two = Scalar { data: TWO };
        assert!(scalar_equals(&new_scalar_from_u8(2u8), &two), 1);

        // Test conversion from u64
        assert!(scalar_equals(&new_scalar_from_u64(2u64), &two), 1);

        // Test conversion from u128
        assert!(scalar_equals(&new_scalar_from_u128(2u128), &two), 1);
    }

    #[test]
    /// Tests deserializing a Scalar from a sequence of canonical bytes
    fun test_scalar_from_canonical_bytes() {
        // Too few bytes
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(x"00")), 1);

        // 32 zero bytes are canonical
        assert!(std::option::is_some(&new_scalar_from_canonical_bytes(x"0000000000000000000000000000000000000000000000000000000000000000")), 1);

        // Non-canonical because high bit is set
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(x"0000000000000000000000000000000000000000000000000000000000000080")), 1);

        // Non-canonical because unreduced
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(x"1010101010101010101010101010101010101010101010101010101010101010")), 1);

        // Canonical because \ell - 1
        assert!(std::option::is_some(&new_scalar_from_canonical_bytes(L_MINUS_ONE)), 1);

        // Non-canonical because \ell
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(ORDER_ELL)), 1);

        // Non-canonical because \ell+1
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(L_PLUS_ONE)), 1);

        // Non-canonical because \ell+2
        assert!(std::option::is_none(&new_scalar_from_canonical_bytes(L_PLUS_TWO)), 1);
    }

    #[test]
    fun test_scalar_zero() {
        // 0 == 0
        assert!(scalar_is_zero(&scalar_zero()), 1);
        assert!(scalar_is_zero(&new_scalar_from_u8(0u8)), 1);

        // 0 != 1
        assert!(scalar_is_zero(&scalar_one()) == false, 1);

        // Pick a random scalar by hashing from some "random" bytes
        let s = new_scalar_from_sha512(x"deadbeef");

        // Technically, there is a negligible probability (i.e., 1/2^\ell) that the hashed s is zero or one
        assert!(scalar_is_zero(&s) == false, 1);
        assert!(scalar_is_one(&s) == false, 1);

        // Multiply 0 with a random scalar and make sure you get zero
        assert!(scalar_is_zero(&scalar_mul(&scalar_zero(), &s)), 1);
        assert!(scalar_is_zero(&scalar_mul(&s, &scalar_zero())), 1);
    }

    #[test]
    fun test_scalar_one() {
        // 1 == 1
        assert!(scalar_is_one(&scalar_one()), 1);
        assert!(scalar_is_one(&new_scalar_from_u8(1u8)), 1);

        // 1 != 0
        assert!(scalar_is_one(&scalar_zero()) == false, 1);

        // Pick a random scalar by hashing from some "random" bytes
        let s = new_scalar_from_sha512(x"deadbeef");
        let inv = scalar_invert(&s);

        // Technically, there is a negligible probability (i.e., 1/2^\ell) that s was zero and the call above returned None
        assert!(std::option::is_some(&inv), 1);

        let inv = std::option::extract(&mut inv);

        // Multiply s with s^{-1} and make sure you get one
        assert!(scalar_is_one(&scalar_mul(&s, &inv)), 1);
        assert!(scalar_is_one(&scalar_mul(&inv, &s)), 1);
    }

    #[test]
    fun test_scalar_from_sha512() {
        // Test a specific message hashes correctly to the field
        let str: vector<u8> = vector[];
        std::vector::append(&mut str, b"To really appreciate architecture, you may even need to commit a murder.");
        std::vector::append(&mut str, b"While the programs used for The Manhattan Transcripts are of the most extreme");
        std::vector::append(&mut str, b"nature, they also parallel the most common formula plot: the archetype of");
        std::vector::append(&mut str, b"murder. Other phantasms were occasionally used to underline the fact that");
        std::vector::append(&mut str, b"perhaps all architecture, rather than being about functional standards, is");
        std::vector::append(&mut str, b"about love and death.");

        let s = new_scalar_from_sha512(str);

        let expected : vector<u8> = vector[
            21,  88, 208, 252,  63, 122, 210, 152,
            154,  38,  15,  23,  16, 167,  80, 150,
            192, 221,  77, 226,  62,  25, 224, 148,
            239,  48, 176,  10, 185,  69, 168,  11
        ];

        assert!(s.data == expected, 1)
    }

    #[test]
    fun test_scalar_invert() {
        // Cannot invert zero
        assert!(std::option::is_none(&scalar_invert(&scalar_zero())), 1);

        // One's inverse is one
        let one = scalar_invert(&scalar_one());
        assert!(std::option::is_some(&one), 1);

        let one = std::option::extract(&mut one);
        assert!(scalar_is_one(&one), 1);

        // Test a random point X's inverse is correct
        let x = Scalar { data: X };
        let xinv = scalar_invert(&x);
        assert!(std::option::is_some(&xinv), 1);

        let xinv = std::option::extract(&mut xinv);
        let xinv_expected = Scalar { data: X_INV };

        assert!(scalar_equals(&xinv, &xinv_expected), 1)
    }

    #[test]
    fun test_scalar_neg() {
        // -(-X) == X
        let x = Scalar { data: X };
        let x_neg = scalar_neg(&x);
        let x_neg_neg = scalar_neg(&x_neg);

        assert!(scalar_equals(&x, &x_neg_neg), 1);
    }

    #[test]
    fun test_scalar_mul() {
        // X * 1 == X
        let x = Scalar { data: X };
        assert!(scalar_equals(&x, &scalar_mul(&x, &scalar_one())), 1);

        // Test multiplication of two random scalars
        let y = Scalar { data: Y };
        let x_times_y = Scalar { data: X_TIMES_Y };
        assert!(scalar_equals(&scalar_mul(&x, &y), &x_times_y), 1);
    }

    #[test]
    fun test_scalar_add() {
        // Addition reduces: \ell-1 + 1 = \ell = 0
        let ell_minus_one = Scalar { data: L_MINUS_ONE };
        assert!(scalar_is_zero(&scalar_add(&ell_minus_one, &scalar_one())), 1);

        // 1 + 1 = 2
        let two = Scalar { data: TWO };
        assert!(scalar_equals(&scalar_add(&scalar_one(), &scalar_one()), &two), 1);
    }

    #[test]
    fun test_scalar_sub() {
        // Subtraction reduces: 0 - 1 = \ell - 1
        let ell_minus_one = Scalar { data: L_MINUS_ONE };
        assert!(scalar_equals(&scalar_sub(&scalar_zero(), &scalar_one()), &ell_minus_one), 1);

        // 2 - 1 = 1
        let two = Scalar { data: TWO };
        assert!(scalar_is_one(&scalar_sub(&two, &scalar_one())), 1);

        // 1 - 2 = -1 = \ell - 1
        let ell_minus_one = Scalar { data: L_MINUS_ONE };
        assert!(scalar_equals(&scalar_sub(&scalar_one(), &two), &ell_minus_one), 1);
    }

    #[test]
    fun test_scalar_from_256_bits() {
        // \ell + 2 = 0 + 2 = 2 (modulo \ell)
        let s = std::option::extract(&mut new_scalar_from_reduced_256_bits(L_PLUS_TWO));
        let two = Scalar { data: TWO };
        assert!(scalar_equals(&s, &two), 1);

        // Reducing the all 1's bit vector yields $(2^256 - 1) \mod \ell$
        let biggest = std::option::extract(&mut new_scalar_from_reduced_256_bits(NON_CANONICAL_ALL_ONES));
        assert!(scalar_equals(&biggest, &Scalar { data: CANONICAL_2_256_MINUS_1 }), 1);
    }

    #[test]
    fun test_scalar_from_512_bits() {
        // Test X + 2^256 * X reduces correctly
        let x_plus_2_to_256_times_x: vector<u8> = vector[];

        std::vector::append(&mut x_plus_2_to_256_times_x, X);
        std::vector::append(&mut x_plus_2_to_256_times_x, X);

        let reduced = std::option::extract(&mut new_scalar_from_reduced_512_bits(x_plus_2_to_256_times_x));
        let expected = Scalar { data: CANONICAL_X_PLUS_2_TO_256_TIMES_X };
        assert!(scalar_equals(&reduced, &expected), 1)
    }

    #[test]
    fun test_scalar_little_endian_bits() {
        let xinv = Scalar { data: X_INV };

        // Get the little-endian bit representation of X_INV
        let bits = scalar_little_endian_bits(&xinv);
        let len = std::bit_vector::length(&bits);
        assert!(len == 256, 1);

        assert_same_bits(len, bits, X_INV_LE_BITS);

        // Get the big-endian bit representation of X_INV
        let bits = scalar_big_endian_bits(&xinv);
        let len = std::bit_vector::length(&bits);
        assert!(len == 256, 1);

        assert_same_bits(len, bits, X_INV_BE_BITS);
    }

    fun assert_same_bits(len: u64, bits: BitVector, rhs_bits: vector<bool>) {
        let i = 0u64;
        while (i < len) {
            assert!(std::bit_vector::is_index_set(&bits, i) == *std::vector::borrow(&rhs_bits, i), 1);
            i = i + 1;
        }
    }
}
