use fixed::types::U4F12;
use tfhe::{FixedClientKey, FixedServerKey};
use tfhe::FheU4F12;

fn main() {
    
    // Generate the client key and the server key:
    let ckey = FixedClientKey::new();
    let skey = FixedServerKey::new(&ckey);
    
    let clear_one: U4F12 = U4F12::from_num(1);
    let clear_five: U4F12 = U4F12::from_num(5);
    
    // Encrypt:
    let mut one = FheU4F12::encrypt(clear_one, &ckey);
    let mut five = FheU4F12::encrypt(clear_five, &ckey);
    
    // Calculate the golden ratio:
    let mut sqrt_five = five.smart_sqrt(&skey);
    let mut one_plus_sqrt_five = one.smart_add(&mut sqrt_five, &skey);
    let mut golden_ratio = one_plus_sqrt_five
        .smart_div(&mut FheU4F12::encrypt_trivial(2, &skey), &skey);

    
    // Decrypt:
    let dec_golden_ratio_precise: U4F12 = golden_ratio.decrypt(&ckey);
    println!("Golden ratio to twelve bits of precision: {:.4}", dec_golden_ratio_precise);

    // We truncate to keep the 4 most significant fractional bits
    let golden_ratio_trunc = golden_ratio.smart_trunc(4, &skey);
    
    // Decrypt:
    let dec_golden_ratio_trunc: U4F12 = golden_ratio_trunc.decrypt(&ckey);
    println!("Golden ratio to four bits of precision: {:.4}", dec_golden_ratio_trunc);

    let golden_ratio_round = golden_ratio.smart_round(&skey);
    let clear_two: U4F12 = golden_ratio_round.decrypt(&ckey);
    println!("Golden ratio rounded is two: {}", clear_two);
}