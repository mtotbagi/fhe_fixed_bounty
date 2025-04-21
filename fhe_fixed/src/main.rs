#![allow(unused_imports)]

use std::io;
use std::time::Instant;

use fixed::traits::FixedUnsigned;
use fixed::types::{U0F16, U10F6, U11F5, U12F4, U16F0, U8F8};
use fixed::FixedU128;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U11, U15, U16, U2, U3, U32, U4, U5, U6, U8};
use tfhe::shortint::ClassicPBSParameters;
use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};
use tfhe::integer::{ServerKey, ClientKey};

pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

mod fhefixed;
mod arb_fixed_u;
mod types;
mod fhe_testing_macros;

use crate::fhefixed::*;


fn main() {
    test_func_manual!(U16, U5, ck, server_key,          // Type of the operation, and key names
        a.smart_sqrt_guess_block(&server_key),               // The operation to test
        U11F5::from_num(clear_a).wrapping_sqrt(),               // A ground truth to compare to, optional
        | clear_a, a |                      // The clear and encrypted name(s) of relevant variables
        // iters                                        // The name(s) of variables that are only used as clear
    );
}


#[cfg(test)]
mod tests {
    use crate::types::{FheU0F8, FheU1F7, FheU4F4, FheU5F3, FheU8F0};

    use super::*;
    use rand::random;
    use typenum::{U0, U1, U10, U12, U14, U16, U2, U4, U6, U64, U7, U8};
    use fixed::{traits::ToFixed, types::{extra::{LeEqU128, LeEqU16}, U32F32, U0F64, U16F0, U0F16, U0F8, U10F6, U12F4, U14F2, U2F6, U1F7, U2F14, U4F12, U4F4, U5F3, U6F10, U8F0, U8F8}, FixedU16, FixedU8};
    use crate::arb_fixed_u::ArbFixedU;
    use std::sync::LazyLock;

    static CKEY: LazyLock<FixedClientKey> = LazyLock::new(|| {
        FixedClientKey::new()
    });
    static SKEY: LazyLock<FixedServerKey> = LazyLock::new(|| {
        FixedServerKey::new(&CKEY)
    });

    // This currently only works with size less than 128 bit
    // This type of testing propably can't be implemented for larger than 128 bits
    // as there the max size for clear fixed is 128 bits. 
    // Over that size, we should probably do a few manual test for edge cases 
    // (with the expected result hard coded)

    macro_rules! test_bin_op {
        ($LhsBits:expr, $RhsBits:expr, 
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedU<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;
            
            let (lhs_bits, rhs_bits) = if $Trivial_encrypt {
                (SKEY.key.create_trivial_radix($LhsBits, num_blocks),
                SKEY.key.create_trivial_radix($RhsBits, num_blocks))
            } else {
                (CKEY.key.encrypt_radix($LhsBits, num_blocks),
                 CKEY.key.encrypt_radix($RhsBits, num_blocks))
            };

            let (mut lhs, mut rhs) = 
                (FheFixed::from_bits(lhs_bits, &SKEY),
                 FheFixed::from_bits(rhs_bits, &SKEY));

            let (lhs_fixed, rhs_fixed) = 
                (<$Fixed>::from_bits($LhsBits),
                 <$Fixed>::from_bits($RhsBits));

            let clear_res = <$Fixed>::$ClearMethod(lhs_fixed, rhs_fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(ArbFixedU::<$Size,$Frac>::from(clear_res), decrypted_res);
        };
    }

    macro_rules! test_bin_op_extensive {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Size:ty, $Frac:ty, $Fixed:ty, $ClearType:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for _ in 0..1024 {
                        let i: $ClearType = random();
                        let j: $ClearType = random();
                        test_bin_op!(i, j,$EncryptedMethod,$ClearMethod,$Size,$Frac,$Fixed,true);
                    }
                }
            )*
        };
    }

    //This is now much easier to generate by script
    test_bin_op_extensive!(smart_add, wrapping_add,
        (test_add_extensive_u32f32, U64, U32, U32F32, u64),
        (test_add_extensive_u0f64, U64, U64, U0F64, u64)
    );

    macro_rules! test_bin_op_exhaustive_u8 {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Frac:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for i in 0..=255u8 {
                        for j in 0..=255u8 {
                            test_bin_op!(i, j,$EncryptedMethod,$ClearMethod,U8,$Frac,FixedU8<$Frac>,true);
                        }
                    }
                }
            )*
        };
    }

    test_bin_op_exhaustive_u8!(smart_add, wrapping_add,
        (test_add_exhaustive_u0f8, U8),
        (test_add_exhaustive_u1f7, U7),
        (test_add_exhaustive_u2f6, U6),
        (test_add_exhaustive_u3f5, U5),
        (test_add_exhaustive_u4f4, U4),
        (test_add_exhaustive_u5f3, U3),
        (test_add_exhaustive_u6f2, U2),
        (test_add_exhaustive_u7f1, U1),
        (test_add_exhaustive_u8f0, U0)
    );

    test_bin_op_exhaustive_u8!(smart_sub, wrapping_sub,
        (test_sub_exhaustive_u0f8, U8),
        (test_sub_exhaustive_u1f7, U7),
        (test_sub_exhaustive_u2f6, U6),
        (test_sub_exhaustive_u3f5, U5),
        (test_sub_exhaustive_u4f4, U4),
        (test_sub_exhaustive_u5f3, U3),
        (test_sub_exhaustive_u6f2, U2),
        (test_sub_exhaustive_u7f1, U1),
        (test_sub_exhaustive_u8f0, U0)
    );

    test_bin_op_exhaustive_u8!(smart_mul, wrapping_mul,
        (test_mul_exhaustive_u0f8, U8),
        (test_mul_exhaustive_u1f7, U7),
        (test_mul_exhaustive_u2f6, U6),
        (test_mul_exhaustive_u3f5, U5),
        (test_mul_exhaustive_u4f4, U4),
        (test_mul_exhaustive_u5f3, U3),
        (test_mul_exhaustive_u6f2, U2),
        (test_mul_exhaustive_u7f1, U1),
        (test_mul_exhaustive_u8f0, U0)
    );

    macro_rules! test_bin_op_random_encrypted {
        ($EncryptedMethod:ident, $ClearMethod:ident,
            $(($TestFnName:ident, $Size:ty, $Frac:ty, $Fixed:ty, $ClearType:ty)),*) => {
                $(
                    #[test]
                    fn $TestFnName() {
                        for _ in 0..8 {
                            let i: $ClearType = random();
                            let j: $ClearType = random();
                            test_bin_op!(i,j,$EncryptedMethod,$ClearMethod,$Size,$Frac,$Fixed,false);
                        }
                    }
                )*
            };
    }

    test_bin_op_random_encrypted!(smart_add, wrapping_add,
        (test_add_random_u32f32, U64, U32, U32F32, u64),
        (test_add_random_u0f64, U64, U64, U0F64, u64),
        
        (test_mul_u16f0, U16, U0, U16F0, u16),
        (test_mul_u14f2, U16, U2, U14F2, u16),
        (test_mul_u12f4, U16, U4, U12F4, u16),
        (test_mul_u10f6, U16, U6, U10F6, u16),
        (test_mul_u8f8, U16, U8, U8F8, u16),
        (test_mul_u6f10, U16, U10, U6F10, u16),
        (test_mul_u4f12, U16, U12, U4F12, u16),
        (test_mul_u2f14, U16, U14, U2F14, u16),
        (test_mul_u0f16, U16, U16, U0F16, u16)
    );

    macro_rules! test_unary_op {
        ($ClearBits:expr, 
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedU<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;
            
            let encrypted_bits = if $Trivial_encrypt {
                SKEY.key.create_trivial_radix($ClearBits, num_blocks)
            } else {
                CKEY.key.encrypt_radix($ClearBits, num_blocks)
            };

            let mut lhs = FheFixed::from_bits(encrypted_bits, &SKEY);

            let fixed = <$Fixed>::from_bits($ClearBits);

            let clear_res = <$Fixed>::$ClearMethod(fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(ArbFixedU::<$Size,$Frac>::from(clear_res), decrypted_res);
        };
    }

    macro_rules! test_unary_op_exhaustive_u8 {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Frac:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for i in 0..=255u8 {
                        test_unary_op!(i,$EncryptedMethod,$ClearMethod,U8,$Frac,FixedU8<$Frac>,true);
                    }
                }
            )*
        };
    }

    test_unary_op_exhaustive_u8!(smart_sqrt, wrapping_sqrt,
        (test_sqrt_exhaustive_u0f8, U8),
        (test_sqrt_exhaustive_u1f7, U7),
        (test_sqrt_exhaustive_u2f6, U6),
        (test_sqrt_exhaustive_u3f5, U5),
        (test_sqrt_exhaustive_u4f4, U4),
        (test_sqrt_exhaustive_u5f3, U3),
        (test_sqrt_exhaustive_u6f2, U2),
        (test_sqrt_exhaustive_u7f1, U1),
        (test_sqrt_exhaustive_u8f0, U0)
    );

    test_unary_op_exhaustive_u8!(smart_floor, wrapping_floor,
        (test_floor_exhaustive_u0f8, U8),
        (test_floor_exhaustive_u1f7, U7),
        (test_floor_exhaustive_u2f6, U6),
        (test_floor_exhaustive_u3f5, U5),
        (test_floor_exhaustive_u4f4, U4),
        (test_floor_exhaustive_u5f3, U3),
        (test_floor_exhaustive_u6f2, U2),
        (test_floor_exhaustive_u7f1, U1),
        (test_floor_exhaustive_u8f0, U0)
    );

    test_unary_op_exhaustive_u8!(smart_ceil, wrapping_ceil,
        (test_ceil_exhaustive_u0f8, U8),
        (test_ceil_exhaustive_u1f7, U7),
        (test_ceil_exhaustive_u2f6, U6),
        (test_ceil_exhaustive_u3f5, U5),
        (test_ceil_exhaustive_u4f4, U4),
        (test_ceil_exhaustive_u5f3, U3),
        (test_ceil_exhaustive_u6f2, U2),
        (test_ceil_exhaustive_u7f1, U1),
        (test_ceil_exhaustive_u8f0, U0)
    );

    test_unary_op_exhaustive_u8!(smart_round, wrapping_round,
        (test_round_exhaustive_u0f8, U8),
        (test_round_exhaustive_u1f7, U7),
        (test_round_exhaustive_u2f6, U6),
        (test_round_exhaustive_u3f5, U5),
        (test_round_exhaustive_u4f4, U4),
        (test_round_exhaustive_u5f3, U3),
        (test_round_exhaustive_u6f2, U2),
        (test_round_exhaustive_u7f1, U1),
        (test_round_exhaustive_u8f0, U0)
    );

    test_unary_op_exhaustive_u8!(smart_neg, wrapping_neg,
        (test_neg_exhaustive_u0f8, U8),
        (test_neg_exhaustive_u1f7, U7),
        (test_neg_exhaustive_u2f6, U6),
        (test_neg_exhaustive_u3f5, U5),
        (test_neg_exhaustive_u4f4, U4),
        (test_neg_exhaustive_u5f3, U3),
        (test_neg_exhaustive_u6f2, U2),
        (test_neg_exhaustive_u7f1, U1),
        (test_neg_exhaustive_u8f0, U0)
    );

    macro_rules! test_unary_op_random_encrypted {
        ($EncryptedMethod:ident, $ClearMethod:ident,
            $(($TestFnName:ident, $Size:ty, $Frac:ty, $Fixed:ty, $ClearType:ty)),*) => {
                $(
                    #[test]
                    fn $TestFnName() {
                        for _ in 0..8 {
                            let i: $ClearType = random();
                            test_unary_op!(i,$EncryptedMethod,$ClearMethod,$Size,$Frac,$Fixed,false);
                        }
                    }
                )*
            };
    }

    test_unary_op_random_encrypted!(smart_neg, wrapping_neg,
        (test_neg_u16f0, U16, U0, U16F0, u16),
        (test_neg_u14f2, U16, U2, U14F2, u16),
        (test_neg_u12f4, U16, U4, U12F4, u16),
        (test_neg_u10f6, U16, U6, U10F6, u16),
        (test_neg_u8f8, U16, U8, U8F8, u16),
        (test_neg_u6f10, U16, U10, U6F10, u16),
        (test_neg_u4f12, U16, U12, U4F12, u16),
        (test_neg_u2f14, U16, U14, U2F14, u16),
        (test_neg_u0f16, U16, U16, U0F16, u16)
    );
    macro_rules! test_sqr {
        ($ClearBits:expr, 
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedU<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;
            
            let encrypted_bits = if $Trivial_encrypt {
                SKEY.key.create_trivial_radix($ClearBits, num_blocks)
            } else {
                CKEY.key.encrypt_radix($ClearBits, num_blocks)
            };

            let mut lhs = FheFixed::from_bits(encrypted_bits, &SKEY);

            let fixed = <$Fixed>::from_bits($ClearBits);

            let clear_res = <$Fixed>::$ClearMethod(fixed, fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(ArbFixedU::<$Size,$Frac>::from(clear_res), decrypted_res);
        };
    }
    macro_rules! test_sqr_exhaustive_u8 {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Frac:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for i in 0..=255u8 {
                        test_sqr!(i,$EncryptedMethod,$ClearMethod,U8,$Frac,FixedU8<$Frac>,true);
                    }
                }
            )*
        };
    }

    test_sqr_exhaustive_u8!(smart_sqr, wrapping_mul,
        (test_sqr_exhaustive_u0f8, U8),
        (test_sqr_exhaustive_u1f7, U7),
        (test_sqr_exhaustive_u2f6, U6),
        (test_sqr_exhaustive_u3f5, U5),
        (test_sqr_exhaustive_u4f4, U4),
        (test_sqr_exhaustive_u5f3, U3),
        (test_sqr_exhaustive_u6f2, U2),
        (test_sqr_exhaustive_u7f1, U1),
        (test_sqr_exhaustive_u8f0, U0)
    );
}
