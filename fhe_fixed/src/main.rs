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
    use typenum::{U0, U1, U10, U12, U14, U16, U2, U4, U6, U7, U8};
    use fixed::{traits::ToFixed, types::{extra::{LeEqU128, LeEqU16}, U0F16, U0F8, U10F6, U12F4, U14F2, U16F0, U1F7, U2F14, U4F12, U4F4, U5F3, U6F10, U8F0, U8F8}, FixedU16, FixedU8};
    use crate::arb_fixed_u::ArbFixedU;
    use std::sync::LazyLock;

    static CKEY: LazyLock<FixedClientKey> = LazyLock::new(|| {
        FixedClientKey::new()
    });
    static SKEY: LazyLock<FixedServerKey> = LazyLock::new(|| {
        FixedServerKey::new(&CKEY)
    });

    macro_rules! test_mul_u16 {
        ($FnName:ident, $Fixed:ty, $Frac:ty) => {
            #[test]
            fn $FnName() {
                let a = <$Fixed>::from_bits(random());
                let b = <$Fixed>::from_bits(random());
                test_mul_u16_gen::<$Fixed, $Frac>(a, b, &CKEY, &SKEY);
            }
        };
    }

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

    // TODO write script which can generate these for every bin op and type combination
    #[test]
    fn test_add_exhaustive_u1f7() {
        for i in 0..=255u8 {
            for j in 0..=255u8 {
                test_bin_op!(i,j,smart_add,wrapping_add,U8,U7,U1F7,true);
            }
        }
    }

    #[test]
    fn test_sub_exhaustive_u1f7() {
        for i in 0..=255u8 {
            for j in 0..=255u8 {
                test_bin_op!(i,j,smart_sub,wrapping_sub,U8,U7,U1F7,true);
            }
        }
    }

    #[test]
    fn test_mul_exhaustive_u1f7() {
        for i in 0..=255u8 {
            for j in 0..=255u8 {
                test_bin_op!(i,j,smart_mul,wrapping_mul,U8,U7,U1F7,true);
            }
        }
    }

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

    /*#[test]
    fn test_sqrt_exhaustive_u1f7() {
        for i in 0..=255u8 {
            test_unary_op!(i,smart_sqrt,wrapping_sqrt,U8,U7,U1F7,true);
        }
    }*/

    #[test]
    fn test_floor_exhaustive_u1f7() {
        for i in 0..=255u8 {
            test_unary_op!(i,smart_floor,wrapping_floor,U8,U7,U1F7,true);
        }
    }

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
    
    #[test]
    fn test_sqr_exhaustive_u1f7() {
        for i in 0..=255u8 {
            test_sqr!(i,smart_sqr,wrapping_mul,U8,U7,U1F7,true);
        }
    }

    test_mul_u16!(test_mul_u16f0, U16F0, U0);
    test_mul_u16!(test_mul_u14f2, U14F2, U2);
    test_mul_u16!(test_mul_u12f4, U12F4, U4);
    test_mul_u16!(test_mul_u10f6, U10F6, U6);
    test_mul_u16!(test_mul_u8f8, U8F8, U8);
    test_mul_u16!(test_mul_u6f10, U6F10, U10);
    test_mul_u16!(test_mul_u4f12, U4F12, U12);
    test_mul_u16!(test_mul_u2f14, U2F14, U14);
    test_mul_u16!(test_mul_u0f16, U0F16, U16);

    fn test_mul_u16_gen<T: ToFixed, Frac: Unsigned>(lhs: T, rhs: T, ckey: &FixedClientKey, skey: &FixedServerKey)
    where
    U16: Unsigned + LeEqU128 +
          Cmp<Frac> +
          typenum::private::IsGreaterOrEqualPrivate<Frac, <U16 as typenum::Cmp<Frac>>::Output> +
          PowerOfTwo + Even,
    Frac: Unsigned + Even + LeEqU16 + LeEqU128 + Send + Sync,
    <U16 as IsGreaterOrEqual<Frac>>::Output: Same<True>{
        let fixed_lhs = FixedU16::<Frac>::wrapping_from_num(lhs);
        let fixed_rhs = FixedU16::<Frac>::wrapping_from_num(rhs);
        let clear_res = fixed_lhs.wrapping_mul(fixed_rhs);
    
        let mut a = FheFixedU::<U16, Frac>::encrypt(fixed_lhs, &ckey);
        let mut b = FheFixedU::<U16, Frac>::encrypt(fixed_rhs, &ckey);
    
        let res = a.smart_mul(&mut b, skey);
    
        assert_eq!(clear_res.to_bits(),
        FixedU16::<Frac>::from_num(Into::<FixedU128<Frac>>::into(res.decrypt(ckey))).to_bits(),
        "{}, {}", fixed_lhs.to_bits(), fixed_rhs.to_bits());
    }

    
}
