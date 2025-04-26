#![allow(unused_imports)]

use std::io;
use std::time::Instant;

extern crate fixed as fixed_crate;

use fixed_crate::types::{U0F16, U10F6, U11F5, U12F4, U16F0, U8F8};
use fixed_crate::{FixedU16, FixedU8, FixedU128};
use tfhe::integer::IntegerCiphertext;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U11, U15, U16, U2, U3, U32, U4, U5, U6, U8};
use tfhe::shortint::ClassicPBSParameters;

pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

mod fixed;
mod fhe_testing_macros;
use crate::fixed::*;

fn main() {
    type FracType = U0;
    type ClearFixed = FixedU16<FracType>;
    test_func_manual!(U16, FracType, ck, server_key,          // Type of the operation, and key names
        {
            // a.smart_div(&mut b, &server_key)
            let mut res = a.clone();
            server_key.key.smart_div_assign_parallelized(res.inner.bits_mut(), b.inner.bits_mut());
            res
        },               // The operation to test
        ClearFixed::from_num(clear_a).wrapping_div(ClearFixed::from_num(clear_b)),               // A ground truth to compare to, optional
        | clear_a, a; clear_b, b |                      // The clear and encrypted name(s) of relevant variables
        // iters                                        // The name(s) of variables that are only used as clear
    );
}


#[cfg(test)]
mod tests {
    use crate::aliases::{FheU0F8, FheU1F7, FheU4F4, FheU5F3, FheU8F0};

    use super::*;
    use rand::random;
    use typenum::{U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13,
        U14, U15, U16, U17, U18, U19, U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, U32,
        U33, U34, U35, U36, U37, U38, U39, U40, U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51,
        U52, U53, U54, U55, U56, U57, U58, U59, U60, U61, U62, U63, U64, U65, U66, U67, U68, U69, U70,
        U71, U72, U73, U74, U75, U76, U77, U78, U79, U80, U81, U82, U83, U84, U85, U86, U87, U88, U89,
        U90, U91, U92, U93, U94, U95, U96, U97, U98, U99, U100, U101, U102, U103, U104, U105, U106,
        U107, U108, U109, U110, U111, U112, U113, U114, U115, U116, U117, U118, U119, U120, U121, U122,
        U123, U124, U125, U126, U127, U128};
    use fixed_crate::{traits::ToFixed, types::{extra::{LeEqU128, LeEqU16}, U0F128, U0F16, U0F32, U0F64, U0F8, U10F6, U12F4, U14F18, U14F2, U16F0, U16F48, U1F7, U25F7, U2F14, U2F6, U32F0, U32F32, U3F5, U48F16, U4F12, U4F4, U5F3, U64F0, U6F10, U6F2, U7F1, U8F0, U8F8}, FixedU16, FixedU8};
    use crate::fixed::ArbFixedU;
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
            assert_eq!(ArbFixedU::<$Size,$Frac>::from(clear_res), decrypted_res,
            "expected: {}, got: {}, from: {}, {}",
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $LhsBits,
                $RhsBits
            );
        };
    }
/*
    macro_rules! test_bin_op_signed {
        ($LhsBits:expr, $RhsBits:expr,
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedI<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;

            let (lhs_bits, rhs_bits) = if $Trivial_encrypt {
                (
                    SKEY.key.create_trivial_radix($LhsBits, num_blocks),
                    SKEY.key.create_trivial_radix($RhsBits, num_blocks),
                )
            } else {
                (
                    CKEY.key.encrypt_radix($LhsBits, num_blocks),
                    CKEY.key.encrypt_radix($RhsBits, num_blocks),
                )
            };

            let (mut lhs, mut rhs) = (
                FheFixed::from_bits(lhs_bits, &SKEY),
                FheFixed::from_bits(rhs_bits, &SKEY),
            );

            let (lhs_fixed, rhs_fixed) =
                (<$Fixed>::from_bits($LhsBits as _), <$Fixed>::from_bits($RhsBits as));

            let clear_res = <$Fixed>::$ClearMethod(lhs_fixed, rhs_fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}, {}",
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $LhsBits,
                $RhsBits
            );
        };
    }
*/
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

    macro_rules! test_div_extensive {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Size:ty, $Frac:ty, $Fixed:ty, $ClearType:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for _ in 0..1024 {
                        let i: $ClearType = random();
                        let mut j: $ClearType = random();
                        if j == 0 {j += 1};
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

    macro_rules! test_div_exhaustive_u8 {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Frac:ty)),*) => {
            $(
                #[test]
                #[ignore]
                fn $TestFnName() {
                    for i in 0..=255u8 {
                        for j in 1..=255u8 {
                            test_bin_op!(i, j,$EncryptedMethod,$ClearMethod,U8,$Frac,FixedU8<$Frac>,true);
                        }
                    }
                }
            )*
        };
    }

    test_div_exhaustive_u8!(smart_div, wrapping_div,
        (test_div_exhaustive_u0f8, U8),
        (test_div_exhaustive_u1f7, U7),
        (test_div_exhaustive_u2f6, U6),
        (test_div_exhaustive_u3f5, U5),
        (test_div_exhaustive_u4f4, U4),
        (test_div_exhaustive_u5f3, U3),
        (test_div_exhaustive_u6f2, U2),
        (test_div_exhaustive_u7f1, U1),
        (test_div_exhaustive_u8f0, U0)
    );

    test_div_extensive!(smart_div, wrapping_div,
        (test_div_extensive_u8_u8f0, U8, U0, U8F0, u8),
        (test_div_extensive_u8_u7f1, U8, U1, U7F1, u8),
        (test_div_extensive_u8_u6f2, U8, U2, U6F2, u8),
        (test_div_extensive_u8_u5f3, U8, U3, U5F3, u8),
        (test_div_extensive_u8_u4f4, U8, U4, U4F4, u8),
        (test_div_extensive_u8_u3f5, U8, U5, U3F5, u8),
        (test_div_extensive_u8_u2f6, U8, U6, U2F6, u8),
        (test_div_extensive_u8_u1f7, U8, U7, U1F7, u8),
        (test_div_extensive_u8_u0f8, U8, U8, U0F8, u8),
        (test_div_extensive_u64f0, U64, U0, U64F0, u64),
        (test_div_extensive_u48f16, U64, U16, U48F16, u64),
        (test_div_extensive_u32f32, U64, U32, U32F32, u64),
        (test_div_extensive_u16f48, U64, U48, U16F48, u64),
        (test_div_extensive_u0f64, U64, U64, U0F64, u64)
    );

    // (test_add_extensive_u32f32, U64, U32, U32F32, u64),

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
        (test_add_random_u0f64, U64, U64, U0F64, u64)
    );
        
    test_bin_op_random_encrypted!(smart_mul, wrapping_mul,
        (test_mul_u16f0, U16, U0, U16F0, u16),
        (test_mul_u14f2, U16, U2, U14F2, u16),
        (test_mul_u8f8, U16, U8, U8F8, u16),
        (test_mul_u6f10, U16, U10, U6F10, u16),
        (test_mul_u0f16, U16, U16, U0F16, u16),
        (test_mul_u0f32, U32, U32, U0F32, u32),
        (test_mul_u25f7, U32, U7, U25F7, u32),
        (test_mul_u14f18, U32, U18, U14F18, u32),
        (test_mul_u32f0, U32, U0, U32F0, u32),
        (test_mul_u0f64, U64, U64, U0F64, u64),
        (test_mul_u0f128, U128, U128, U0F128, u128)
    );

    macro_rules! test_binary_op_random_encrypted {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, $($Frac:literal),*)),*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<ttest_ $MethodName _ u $Size f $Frac>]() {
    
                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }

                        /*#[test]
                        fn [<ttest_ $MethodName _ i $Size f $Frac>]() {
    
                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_bin_op_signed!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }*/
                    )*
                )*
            }
            };
    }

    test_binary_op_random_encrypted!(method_name: "add", 
        (size: 32, iter: 8,
            0,1,2,4,7,8,16,29,31,32),
        (size: 16, iter: 8,
            0,2,3,5,6,8,12,15,16)
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

    macro_rules! test_unary_op_extensive {
        ($EncryptedMethod:ident, $ClearMethod:ident,
        $(($TestFnName:ident, $Size:ty, $Frac:ty, $Fixed:ty, $ClearType:ty)),*) => {
            $(
                #[test]
                fn $TestFnName() {
                    for _ in 0..1024 {
                        let i: $ClearType = random();
                        test_unary_op!(i,$EncryptedMethod,$ClearMethod,$Size,$Frac,$Fixed,true);
                    }
                }
            )*
        };
    }

    test_unary_op_extensive!(smart_sqrt, wrapping_sqrt,
        (test_sqrt_extensive_u32f32, U64, U32, U32F32, u64),
        (test_sqrt_extensive_u0f64, U64, U64, U0F64, u64)
    );

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
