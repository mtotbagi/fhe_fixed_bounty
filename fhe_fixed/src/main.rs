#![allow(unused_imports)]

use std::io;
use std::time::Instant;

extern crate fixed as fixed_crate;

use fixed_crate::types::{U0F16, U8F8, U10F6, U11F5, U12F4, U16F0};
use fixed_crate::{FixedU8, FixedU16, FixedU128};
use tfhe::integer::IntegerCiphertext;
use tfhe::shortint::ClassicPBSParameters;
use typenum::{
    B0, B1, Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, U0, U2, U3, U4,
    U5, U6, U8, U10, U11, U15, U16, U32, U1000, UInt, Unsigned,
};

pub const PARAM: ClassicPBSParameters =
    tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

mod fhe_testing_macros;
mod fixed;
use crate::fixed::*;
use paste::paste;

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
    use crate::fixed::{ArbFixedI, ArbFixedU};
    use crate::{FheFixedI, FheFixedU};
    use fixed_crate::{
        FixedU8, FixedU16,
        traits::ToFixed,
        types::{
            U0F8, U0F16, U0F32, U0F64, U0F128, U1F7, U2F6, U2F14, U3F5, U4F4, U4F12, U5F3, U6F2,
            U6F10, U7F1, U8F0, U8F8, U10F6, U12F4, U14F2, U14F18, U16F0, U16F48, U25F7, U32F0,
            U32F32, U48F16, U64F0,
            extra::{LeEqU16, LeEqU128},
        },
    };
    use rand::random;
    use std::sync::LazyLock;
    use typenum::{
        U0, U1, U2, U3, U4, U5, U6, U7, U8, U9, U10, U11, U12, U13, U14, U15, U16, U17, U18, U19,
        U20, U21, U22, U23, U24, U25, U26, U27, U28, U29, U30, U31, U32, U33, U34, U35, U36, U37,
        U38, U39, U40, U41, U42, U43, U44, U45, U46, U47, U48, U49, U50, U51, U52, U53, U54, U55,
        U56, U57, U58, U59, U60, U61, U62, U63, U64, U65, U66, U67, U68, U69, U70, U71, U72, U73,
        U74, U75, U76, U77, U78, U79, U80, U81, U82, U83, U84, U85, U86, U87, U88, U89, U90, U91,
        U92, U93, U94, U95, U96, U97, U98, U99, U100, U101, U102, U103, U104, U105, U106, U107,
        U108, U109, U110, U111, U112, U113, U114, U115, U116, U117, U118, U119, U120, U121, U122,
        U123, U124, U125, U126, U127, U128,
    };

    static CKEY: LazyLock<FixedClientKey> = LazyLock::new(|| FixedClientKey::new());
    static SKEY: LazyLock<FixedServerKey> = LazyLock::new(|| FixedServerKey::new(&CKEY));

    // This currently only works with size less than 128 bit
    // This type of testing propably can't be implemented for larger than 128 bits
    // as the max size for clear fixed is 128 bits.
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
                (<$Fixed>::from_bits($LhsBits), <$Fixed>::from_bits($RhsBits));

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

            let (lhs_fixed, rhs_fixed) = (
                <$Fixed>::from_bits($LhsBits as _),
                <$Fixed>::from_bits($RhsBits as _),
            );

            let clear_res = <$Fixed>::$ClearMethod(lhs_fixed, rhs_fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}, {}",
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $LhsBits,
                $RhsBits
            );
        };
    }

    macro_rules! test_bin_op_extensive {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }

                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                if $MethodName == "div" && j == 0 { continue; }
                                test_bin_op_signed!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    )*
                )*
            }
        };
    }

    //This is now much easier to generate by script
    test_bin_op_extensive!(method_name: "add",
        (size: 64, iter: 1024, (0, 32, 64))
    );

    macro_rules! test_bin_op_exhaustive_u8_inner {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                for j in 0..=255u8 {
                                    test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                        ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                        ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                                }
                            }
                        }

                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                for j in 0..=255u8 {
                                    test_bin_op_signed!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                        ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                        ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                                }
                            }
                        }
                    )*
                )*
            }
        };
    }

    macro_rules! test_bin_op_exhaustive_u8 {
        (method_name: $MethodName:literal) => {
            test_bin_op_exhaustive_u8_inner!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
        };
    }
    test_bin_op_exhaustive_u8!(method_name: "add");
    test_bin_op_exhaustive_u8!(method_name: "sub");
    test_bin_op_exhaustive_u8!(method_name: "mul");

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

    test_div_exhaustive_u8!(
        smart_div,
        wrapping_div,
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

    test_div_extensive!(
        smart_div,
        wrapping_div,
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
    // div is not yet done for signed, this can't be used
    /*test_bin_op_extensive!(method_name: "div",
        (size: 8, iter:1024, (0,1,2,3,4,5,6,7,8)),
        (size: 32, iter: 128, (0,32,48,64))
    );*/

    macro_rules! test_binary_op_random_encrypted {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }

                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                if $MethodName == "div" && j == 0 { continue; }
                                test_bin_op_signed!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }
                    )*
                )*
            }
        };
    }

    test_binary_op_random_encrypted!(method_name: "add",
        (size: 32, iter: 8,
            (0,1,2,4,7,8,16,29,31,32)),
        (size: 16, iter: 8,
            (0,2,3,5,6,8,12,15,16)),
        (size: 64, iter: 8,
            (0, 32, 48, 57, 64))
    );

    test_binary_op_random_encrypted!(method_name: "mul",
        (size: 16, iter:8,
            (0,1,4,6,8,11,12,16)),
        (size: 32, iter:8,
            (0, 7, 18, 32)),
        (size: 64, iter:2,
            (0, 32, 64)),
        /*(size: 128, iter:2,
            (0, 128))*/
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
            assert_eq!(
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}",
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $ClearBits,
            );
        };
    }

    macro_rules! test_unary_op_signed {
        ($ClearBits:expr,
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedI<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;

            let encrypted_bits = if $Trivial_encrypt {
                SKEY.key.create_trivial_radix($ClearBits, num_blocks)
            } else {
                CKEY.key.encrypt_radix($ClearBits, num_blocks)
            };

            let mut lhs = FheFixed::from_bits(encrypted_bits, &SKEY);

            let fixed = <$Fixed>::from_bits($ClearBits as _);

            let clear_res = <$Fixed>::$ClearMethod(fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}",
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $ClearBits,
            );
        };
    }

    macro_rules! test_unary_op_extensive {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }

                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                if i >= 1<<($Size-1) { continue; }
                                test_unary_op_signed!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    )*
                )*
            }
        };
    }

    test_unary_op_extensive!(method_name: "sqrt",
        (size: 64, iter:1024, (32, 64))
    );
    test_unary_op_extensive!(method_name: "neg",
        (size: 64, iter:1024, (32, 64))
    );

    macro_rules! test_unary_op_exhaustive_u8_inner {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }

                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                if i >= 128 && $MethodName == "sqrt" { continue; }
                                test_unary_op_signed!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    )*
                )*
            }
        };
    }

    macro_rules! test_unary_op_exhaustive_u8 {
        (method_name: $MethodName:literal) => {
            test_unary_op_exhaustive_u8_inner!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
        };
    }

    test_unary_op_exhaustive_u8!(method_name: "sqrt");
    test_unary_op_exhaustive_u8!(method_name: "floor");
    test_unary_op_exhaustive_u8!(method_name: "ceil");
    test_unary_op_exhaustive_u8!(method_name: "round");
    test_unary_op_exhaustive_u8!(method_name: "neg");

    macro_rules! test_unary_op_random_encrypted {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }

                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                if i >= 1<<($Size-1) { continue; }
                                test_unary_op_signed!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }
                    )*
                )*
            }
        };
    }

    test_unary_op_random_encrypted!(method_name: "neg",
        (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
    );
    test_unary_op_random_encrypted!(method_name: "sqrt",
        (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
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
            assert_eq!(
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}",
                ArbFixedU::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $ClearBits,
            );
        };
    }

    macro_rules! test_sqr_signed {
        ($ClearBits:expr,
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedI<$Size, $Frac>;

            // TODO this generally
            let num_blocks = <$Size>::USIZE >> 1;

            let encrypted_bits = if $Trivial_encrypt {
                SKEY.key.create_trivial_radix($ClearBits, num_blocks)
            } else {
                CKEY.key.encrypt_radix($ClearBits, num_blocks)
            };

            let mut lhs = FheFixed::from_bits(encrypted_bits, &SKEY);

            let fixed = <$Fixed>::from_bits($ClearBits as _);

            let clear_res = <$Fixed>::$ClearMethod(fixed, fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &SKEY);
            let decrypted_res = FheFixed::decrypt(&encrypted_res, &CKEY);
            assert_eq!(
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                "expected: {}, got: {}, from: {}",
                ArbFixedI::<$Size, $Frac>::from(clear_res),
                decrypted_res,
                $ClearBits,
            );
        };
    }

    macro_rules! test_sqr_exhaustive_u8_inner {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }

                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                test_sqr_signed!(i,[<smart_ $MethodName>],wrapping_mul,
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    )*
                )*
            }
        };
    }

    macro_rules! test_sqr_exhaustive_u8 {
        (method_name: $MethodName:literal) => {
            test_sqr_exhaustive_u8_inner!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
        };
    }

    test_sqr_exhaustive_u8!(method_name: "sqr");

    macro_rules! test_comp {
        ($LhsBits:expr, $RhsBits:expr,
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedU<$Size, $Frac>;

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
                (<$Fixed>::from_bits($LhsBits as _), <$Fixed>::from_bits($RhsBits as _));

            let clear_res = <$Fixed>::$ClearMethod(&lhs_fixed, &rhs_fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
            let decrypted_res = CKEY.key.decrypt_bool(&encrypted_res);
            assert_eq!(
                clear_res,
                decrypted_res,
                "expected: {}, got: {}, from: {}, {}",
                clear_res,
                decrypted_res,
                $LhsBits,
                $RhsBits
            );
        };
    }

    macro_rules! test_comp_signed {
        ($LhsBits:expr, $RhsBits:expr,
         $EncryptedMethod:ident, $ClearMethod:ident,
         $Size:ty, $Frac:ty, $Fixed:ty,
         $Trivial_encrypt:expr) => {
            type FheFixed = FheFixedU<$Size, $Frac>;

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
                (<$Fixed>::from_bits($LhsBits as _), <$Fixed>::from_bits($RhsBits as _));

            let clear_res = <$Fixed>::$ClearMethod(&lhs_fixed, &rhs_fixed);
            let encrypted_res = FheFixed::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
            let decrypted_res = CKEY.key.decrypt_bool(&encrypted_res);
            assert_eq!(
                clear_res,
                decrypted_res,
                "expected: {}, got: {}, from: {}, {}",
                clear_res,
                decrypted_res,
                $LhsBits,
                $RhsBits
            );
        };
    }

    macro_rules! test_comp_random_encrypted {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }

                        #[test]
                        fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                            }
                        }
                    )*
                )*
            }
        };
    }

    macro_rules! test_comp_extensive {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }

                        #[test]
                        fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                            for _ in 0..$Iter {
                                let i: [<u $Size>] = random();
                                let j: [<u $Size>] = random();
                                if $MethodName == "div" && j == 0 { continue; }
                                test_comp_signed!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    )*
                )*
            }
        };
    }


    macro_rules! test_comp_exhaustive_u8_inner {
        (method_name: $MethodName:literal,
            $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
            ::paste::paste! {
                $(
                    $(
                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                for j in 0..=255u8 {
                                    test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                        ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                        ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                                }
                            }
                        }

                        #[test]
                        fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                            for i in 0..=255u8 {
                                for j in 0..=255u8 {
                                    test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                        ::typenum::[<U $Size>],::typenum::[<U $Frac>],
                                        ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                                }
                            }
                        }
                    )*
                )*
            }
        };
    }

    macro_rules! test_comp_exhaustive_u8 {
        (method_name: $MethodName:literal) => {
            test_comp_exhaustive_u8_inner!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
        };
    }

    test_comp_exhaustive_u8!(method_name: "eq");
    test_comp_exhaustive_u8!(method_name: "ne");
    test_comp_exhaustive_u8!(method_name: "le");
    test_comp_exhaustive_u8!(method_name: "lt");
    test_comp_exhaustive_u8!(method_name: "ge");
    test_comp_exhaustive_u8!(method_name: "gt");
    test_comp_extensive!(method_name: "eq",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );
    test_comp_extensive!(method_name: "ne",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );
    test_comp_extensive!(method_name: "lt",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );
    test_comp_extensive!(method_name: "le",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );
    test_comp_extensive!(method_name: "gt",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );
    test_comp_extensive!(method_name: "ge",
        (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
        (size: 64, iter: 128, (0, 64)) 
    );

    test_comp_random_encrypted!(method_name: "eq",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));
    test_comp_random_encrypted!(method_name: "ne",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));
    test_comp_random_encrypted!(method_name: "le",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));
    test_comp_random_encrypted!(method_name: "lt",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));
    test_comp_random_encrypted!(method_name: "ge",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));
    test_comp_random_encrypted!(method_name: "gt",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64)));

}
