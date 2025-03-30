#![allow(unused_imports)]

use std::io;

use fixed::traits::FixedUnsigned;
use fixed::types::U10F6;
use fixed::FixedU128;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U16, U2, U3, U4, U6, U8};
use tfhe::shortint::ClassicPBSParameters;
use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};
use tfhe::integer::{ServerKey, ClientKey};

pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

mod fhefixed;
mod arb_fixed_u;

use crate::fhefixed::*;

pub type FheFixedU12F4 = FheFixedU<U16, U4>;
pub type FheFixedU13F3 = FheFixedU<U16, U3>;
pub type FheFixedU16F0 = FheFixedU<U16, U0>;

fn main() {

    let client_key = FixedClientKey::new();
    let server_key = FixedServerKey::new(&client_key);

    let mut input = String::new();

    println!("Please input a:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let clear_a: f32 = input.trim().parse().expect("Please type a number!");
    input.clear();
    println!("Please input the iteration count:");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");

    let iters: u32 = input.trim().parse().expect("Please type a number!");
    println!("{:017.4b}", sqrt_goldschmidt(FixedU128::<U16>::from_num(clear_a), iters));
    println!("a: {:14}", sqrt_goldschmidt(FixedU128::<U16>::from_num(clear_a), iters));
    println!("Builtin result:");
    println!("{:017.4b}", FixedU128::<U16>::from_num(clear_a).wrapping_sqrt());
    println!("a: {:14}", FixedU128::<U16>::from_num(clear_a).wrapping_sqrt());
    // input.clear();
    // println!("Please input b:");
    // io::stdin()
    //     .read_line(&mut input)
    //     .expect("Failed to read line");

    // let clear_b: f32 = input.trim().parse().expect("Please type a number!");
    
    /*println!("Please wait!");
    let now = Instant::now();

    let mut a:FheFixedU12F4 = FheFixedU12F4::encrypt(clear_a, &client_key);
    let a2:FheFixedU12F4 = FheFixedU12F4::from_bits
    (client_key.key.encrypt_radix
        (U12F4::from_num(clear_a).to_bits(), 8), &server_key);
    //let mut a = client_key.key.encrypt_radix(clear_a, 8);
    // let mut b:FheFixedU16F0 = FheFixedU16F0::encrypt(clear_b, &client_key);
    let elapsed = now.elapsed();
    println!("Time for encrypting the inputs: {:.2?}", elapsed);
    println!("{:017.4b}", a.decrypt(&client_key));
    println!("a: {:14}", a.decrypt(&client_key));
    println!("{:017.4b}", a2.decrypt(&client_key));
    println!("a2: {:13}", a2.decrypt(&client_key));

    let now2 = Instant::now();
    
    let a_sqr = a.smart_sqr(&server_key);
    //let a_round:FheFixedU12F4 = a.smart_round(&server_key);

    // let b_ceil:FheFixedU16F0 = b.smart_ceil(&server_key);
    // let b_round:FheFixedU16F0 = b.smart_round(&server_key);
    
    let elapsed2 = now2.elapsed();
    println!("Time for computing own square: {:.2?}", elapsed2);
    let now3 = Instant::now();
    let mut a_clone = a.clone();
    let a_mul = a.smart_mul( &mut a_clone, &server_key);
    //let a_round:FheFixedU12F4 = a.smart_round(&server_key);

    // let b_ceil:FheFixedU16F0 = b.smart_ceil(&server_key);
    // let b_round:FheFixedU16F0 = b.smart_round(&server_key);
    
    let elapsed2 = now3.elapsed();
    println!("Time for computing builtin : {:.2?}", elapsed2);

    println!("Please inspect the results:");
    
    
    println!("{:017.4b}", a.decrypt(&client_key));
    println!("a: {:14}", a.decrypt(&client_key));
    println!("{:017.4b}", a_sqr.decrypt(&client_key));
    println!("sqr: {:12}", a_sqr.decrypt(&client_key));
    println!("correct result:");
    println!("{:017.4b}", a_mul.decrypt(&client_key));
    println!("sqr: {:12}", a_mul.decrypt(&client_key));*/
    /*println!("{:017.4b}", a_round.decrypt(&client_key));
    println!("round: {:10}", a_round.decrypt(&client_key));*/
    // println!();

    // println!("{:016b}", b.decrypt(&client_key));
    // println!("b: {:13}", b.decrypt(&client_key));
    // println!("{:016b}", b_ceil.decrypt(&client_key));
    // println!("ceil: {:10}", b_ceil.decrypt(&client_key));
    // println!("{:016b}", b_round.decrypt(&client_key));
    // println!("round: {:9}", b_round.decrypt(&client_key));
    
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
    println!("x_scaled: {}", x_scaled);
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
    // Handle negative exponents
    if pow < 0 {
        return F::from_num(1) / pow_positive(x, (-pow) as u32);
    }
    
    pow_positive(x, pow as u32)
}

// Helper function to handle positive exponents
fn pow_positive<F>(x: F, pow: u32) -> F
where
    F: FixedUnsigned + Copy,
{
    // Base cases
    if pow == 0 {
        return F::from_num(1);
    }
    if pow == 1 {
        return x;
    }
    
    // Use binary exponentiation (square-and-multiply) for efficiency
    let mut result = F::from_num(1);
    let mut base = x;
    let mut exponent = pow;
    
    while exponent > 0 {
        // If current exponent is odd, multiply result by the current base
        if exponent & 1 == 1 {
            result = result * base;
        }
        
        // Square the base and halve the exponent
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
    Frac: Unsigned + Even + LeEqU16 + LeEqU128,
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
