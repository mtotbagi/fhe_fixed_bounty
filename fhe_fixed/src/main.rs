#![allow(unused_imports)]

use std::io;
use std::time::Instant;

use fixed::traits::FixedUnsigned;
use fixed::types::{U0F16, U10F6, U12F4};
use fixed::FixedU128;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U11, U16, U2, U3, U32, U4, U6, U8};
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
    test_func_manual!(U16, U4, ck, server_key,          // Type of the operation, and key names
        a.smart_add(&mut b, &server_key),               // The operation to test
        // U12F4::from_num(clear_a+clear_b),               // A ground truth to compare to, optional
        | clear_a, a; clear_b, b |                      // The clear and encrypted name(s) of relevant variables
        // iters                                        // The name(s) of variables that are only used as clear
    );
}

pub fn sqrt_goldschmidt<F>(x: F, iters: u32) -> F
where
    F: FixedUnsigned + Copy,
{
    let (x_scaled, n) = if x <= 2 {
        (x, 0)
    } else {
        let log4 = x.int_log(4)+1;
        (x.wrapping_div(pow(F::from_num(4), log4)), log4)
    };
    //println!("x_scaled: {}", x_scaled);
    let mut x_k = x_scaled;
    let mut r_k = x_scaled;
    
    let three = F::from_num(3);
    for _ in 0..iters {
        let m_k = three.wrapping_sub(x_k).shr(1);
        
        
        let m_k_sqr = m_k.wrapping_mul(m_k);
        x_k = x_k.wrapping_mul(m_k_sqr);
        
        r_k = r_k.wrapping_mul(m_k);
    }
    
    r_k * pow(F::from_num(2), n)
}

pub fn pow<F>(x: F, pow: i32) -> F
where
    F: FixedUnsigned + Copy,
{
    if pow < 0 {
        return F::from_num(1) / pow_positive(x, (-pow) as u32);
    }
    
    pow_positive(x, pow as u32)
}

fn pow_positive<F>(x: F, pow: u32) -> F
where
    F: FixedUnsigned + Copy,
{
    if pow == 0 {
        return F::from_num(1);
    }
    if pow == 1 {
        return x;
    }
    
    let mut result = F::from_num(1);
    let mut base = x;
    let mut exponent = pow;
    
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        
        base = base * base;
        exponent >>= 1;
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;
    use typenum::{U0, U2, U12, U14, U16, U4, U8, U10, U6};
    use fixed::{traits::ToFixed, types::{extra::{LeEqU128, LeEqU16}, U0F16, U10F6, U12F4, U14F2, U16F0, U2F14, U4F12, U6F10, U8F8}, FixedU16};

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
