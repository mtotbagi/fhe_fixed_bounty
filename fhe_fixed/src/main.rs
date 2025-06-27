extern crate fixed as fixed_crate;

use fixed_crate::types::extra::LeEqU128;
use fixed_crate::types::U4F12;

mod fixed;
use fixed::*;
use fixed::aliases::*;

fn main() {
    
    // Generate the client key and the server key:
    let ckey = FixedClientKey::new();
    let skey = FixedServerKey::new(&ckey);
    
    let clear_one: U4F12 = U4F12::from_num(1);
    let clear_five: U4F12 = U4F12::from_num(5);
    
    // Encrypt:
    let mut one: FheU4F12 = ckey.encrypt(clear_one);
    let mut five: FheU4F12 = ckey.encrypt(clear_five);
    
    // Calculate the golden ratio:
    let mut sqrt_five = five.smart_sqrt(&skey);
    let mut one_plus_sqrt_five = one.smart_add(&mut sqrt_five, &skey);
    let mut half = reciprocal(&mut skey.encrypt_trivial(2), &skey);
    let mut golden_ratio = one_plus_sqrt_five
        .smart_mul(&mut half, &skey);

    
    // Decrypt:
    let dec_golden_ratio_precise: U4F12 = ckey.decrypt(&golden_ratio);
    println!("Golden ratio to twelve bits of precision: {:.4}", dec_golden_ratio_precise);

    // We truncate to keep the 4 most significant fractional bits
    let golden_ratio_trunc = golden_ratio.smart_trunc(4, &skey);
    
    // Decrypt:
    let dec_golden_ratio_trunc: U4F12 = ckey.decrypt(&golden_ratio_trunc);
    println!("Golden ratio to four bits of precision: {:.4}", dec_golden_ratio_trunc);

    let golden_ratio_round = golden_ratio.smart_round(&skey);
    let clear_two: U4F12 = ckey.decrypt(&golden_ratio_round);
    println!("Golden ratio rounded is two: {}", clear_two);
}


// We can write functions that work on "any" FheFixedU type
fn reciprocal<Size, Frac>(c: &mut FheFixedU<Size, Frac>, key: &FixedServerKey) -> FheFixedU<Size, Frac>
where Size: FixedSize<Frac> + LeEqU128,
      Frac: FixedFrac + LeEqU128
{
    let trivial_one: FheFixedU::<Size, Frac> = key.encrypt_trivial(1u32);

    // If the carries are not empty, we propagate
    if c.bits().block_carries_are_empty() {
        c.full_propagate_parallelized(key);
    }

    FheFixedU::<Size, Frac>::unchecked_div(&trivial_one, c, key)
}