#![allow(dead_code)]
use rayon::prelude::*;
use tfhe::integer::prelude::ServerKeyDefaultCMux;
use tfhe::shortint::parameters::Degree;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::integer::{BooleanBlock, IntegerRadixCiphertext};
use tfhe::integer::{ServerKey, ClientKey};

pub mod aliases;
pub mod size_frac;
mod arb_fixed_u;
mod types;

mod add;
mod sub;
mod mul;
mod comp;
mod rounding;
mod ilog2;
mod neg;
mod abs;
mod encrypt_decrypt;

use types::FixedCiphertextInner;
pub use types::{FheFixedU, FixedCiphertext};
pub use arb_fixed_u::ArbFixedU;


pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;


pub struct FixedServerKey {
    pub key: ServerKey
}

impl FixedServerKey {
    pub fn new(cks: &FixedClientKey) -> FixedServerKey{
        FixedServerKey{
            key: ServerKey::new_radix_server_key(&cks.key)
        }
    }
}

pub(crate) fn print_if_trivial<T: FixedCiphertext>(c: &T) {
    if c.inner().is_trivial() {
        let a: u32 = c.inner().decrypt_trivial().unwrap();
        let size = c.size() as usize;
        println!("Size: {}, Frac: {}, Bits:", c.size(), c.frac());
        println!("{:0size$b}", a);
        println!("{}", a);
    }
}

pub struct FixedClientKey {
    pub key: ClientKey
}

impl FixedClientKey {
    pub fn new() -> FixedClientKey{
        FixedClientKey{
            key: ClientKey::new(PARAM)
        }
    }
}

/*Requirements (for now):
Size and Frac are Unsigned
Size >= Frac
Size is even and at least 2*/

/*
impl<Size, Frac> FheFixed<ArbFixedU<Size, Frac>, FixedClientKey, FixedServerKey> for FheFixedU<Size, Frac> 
where
Size: FixedSize<Frac>,
Frac: FixedFrac
{
    fn smart_div(&mut self, rhs: &mut Self, key: &FixedServerKey) -> Self {
        // Pseudo code of the algorithm used:
        // sqrt(V)
        // V = V.clone()                    -- we use this as a remainder, but don't change the input
        // R = 0                            -- initialise the result/root as 0
        // B = max_possible_bit(V.len())    -- we find the maximum possible bit in the root
        //                                      all bits larger than this, have a square larger
        //                                      than the max value V could take
        // BS = square_of(B)                -- we find the square of B via a shift
        //
        // while B > 0
        //      if V >= 2*B*R + BS          -- since (R+B)^2 = R^2 + 2*B*R + BS
        //          R += B                  -- (R+B)^2 was less then original(V)
        //                                      here we essentially set one of the result bits
        //          V -= 2*B*R + BS         -- update V to be original(V) - (R+B)^2
        //
        //      B >>= 1
        //      BS >>= 2
        //needed since this is a smart function, also since bivariate lookup would drop carries
        if !self.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut self.inner);
        }
        
        // self.inner = key.key.create_trivial_radix(128, self.inner.blocks().len());
        // rhs.inner = key.key.create_trivial_radix(2, self.inner.blocks().len());

        // some helper numbers for ease of use later
        let log_modulus_usize = key.key.message_modulus().0.ilog2() as usize;               // number of bits in msg
        let blocks_with_frac = (Frac::USIZE + log_modulus_usize - 1) / log_modulus_usize;   // number of blocks containing a fractional bit
        let wide_block_size = self.inner.blocks().len() + blocks_with_frac*2;                 // the size of the wide versions in blocks (widness when we have fractional bits)
        let least_used_bit_idx = blocks_with_frac * log_modulus_usize;                      // the index of the first non-wide bit (so the least bit that is relevant to the result)
        let largest_used_bit_idx = least_used_bit_idx + Size::USIZE + Frac::USIZE - 1;                    // the index of the most significant bit that could be set

        // the wide remainder, we will decrease this each iteration if it was still larger than the current square
        let mut wide_remainder = key.key.extend_radix_with_trivial_zero_blocks_lsb(&self.inner, blocks_with_frac);
        key.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut wide_remainder, blocks_with_frac);
        let mut wide_result: Cipher = key.key.create_trivial_zero_radix(wide_block_size); // only needed as wide for ease of indexing later

        // the single guess bit, starting at its largest value
        let mut guess_radix: Cipher = key.key.create_trivial_radix(1, wide_block_size);
        key.key.unchecked_scalar_left_shift_assign_parallelized(&mut guess_radix, largest_used_bit_idx);
        
        // two lookup tables used to zero out half the calculations depending on `if V > 2*B*R + BS` (represented by an overflow)
        let zero_out_if_overflow_lut = 
            key.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow == 0 { block } else { 0 }
            );
        let zero_out_if_no_overflow_lut = 
            key.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow != 0 { block } else { 0 }
            );
        
        let (shifted_wide_rhs_vec, leading_zeros) = rayon::join(
            || {
                let message_mod = key.key.message_modulus().0 as isize;
                //since rhs never changes, you can precompute all the shifts
                let wide_rhs = key.key.extend_radix_with_trivial_zero_blocks_lsb(&rhs.inner, blocks_with_frac);
                let wide_rhs = key.key.extend_radix_with_trivial_zero_blocks_msb(&wide_rhs, blocks_with_frac + 1);
                let wide_shifted_rhs_vec = 
                    (0..=message_mod).into_par_iter().map(
                        |idx| {
                            unchecked_signed_scalar_left_shift_parallelized(&key.key, &wide_rhs, idx)
                        }
                    ).collect::<Vec<_>>();

                (least_used_bit_idx..=largest_used_bit_idx).into_par_iter().map(
                    |idx| {
                        let shift_amount_signed = idx as isize - least_used_bit_idx as isize - Frac::USIZE as isize; //same as shift amount calc later
                        let mod_of_shift = (shift_amount_signed % message_mod + message_mod) % message_mod;
                        let shift_amount_signed = shift_amount_signed - mod_of_shift;
                        let wider_shifted = unchecked_signed_scalar_left_shift_parallelized(&key.key, &wide_shifted_rhs_vec[mod_of_shift as usize], shift_amount_signed);
                        Cipher::from_blocks(wider_shifted.blocks()[..wider_shifted.blocks().len() - 1].to_vec())
                    }
                ).collect::<Vec<_>>()
            }, || {
                // leading zeros:
                // we can't have a bit set, if that would result in an overflow -> if rhs has 5 leading zeros, then we have i_bits - 5 - 1
                //leading zeros should be max(i_bits - 1 - lz_rhs, 0)
                // we actually need size-1-lz_rhs
                key.key.unchecked_leading_zeros_parallelized(&rhs.inner)
            }
        );

        // main loop, iterates through the index of every result bit that could be set
        for guess_bit_idx in (least_used_bit_idx..=largest_used_bit_idx).rev() {
            // we assign some more helper vars
            let guess_block_idx = guess_bit_idx / log_modulus_usize;
            let shift_amount_signed = guess_bit_idx as isize - least_used_bit_idx as isize - Frac::USIZE as isize;
            let ls_used_bit_idx = (least_used_bit_idx as isize + shift_amount_signed) as usize;
            let ls_used_block_idx = ls_used_bit_idx / log_modulus_usize;

            // in each loop we only operate on the sub-parts of the ciphers that could be non-zero, so we drop unneeded parts
            let mut narrow_remainder_old = Cipher::from(wide_remainder.blocks()[ls_used_block_idx..].to_vec());
            let mut guess_block = guess_radix.blocks()[guess_block_idx].clone();    // they are created as entire ciphers, since there is no convenient block-rotate
            
            // this does 2*R*B, since 2*B is still a (clear) power of two, we can just shift R by a scalar
            // for some reason we need to ensure that it has the correct degrees, else the subtraction will not work
            let narrow_rhs_shifted = Cipher::from(shifted_wide_rhs_vec[guess_bit_idx-least_used_bit_idx].blocks()[ls_used_block_idx..].to_vec());
            // calculate V - (2*R*B + BS) and V >= (2*R*B + BS)      (the new value of V, and the guard of the if-stmt)
            let ((mut narrow_remainder_new, sub_overflowed), is_leading_zero) = 
                rayon::join(
                    || {
                        key.key.unchecked_unsigned_overflowing_sub_parallelized(&narrow_remainder_old, &narrow_rhs_shifted)
                    }, || {
                        let cmp_val = Size::USIZE - (largest_used_bit_idx - guess_bit_idx) - 1;
                        if cmp_val < 1 {
                            key.key.key.create_trivial(0)
                        } else {
                            key.key.unchecked_scalar_lt_parallelized(&leading_zeros, cmp_val as u64).into_raw_parts()
                        }
                });
            let overflow_happened = key.key.key.unchecked_add(&sub_overflowed.into_raw_parts(), &is_leading_zero);

            // here we evaluate which branch of the if was taken, by zeroing out the unused branch (the second branch is just the identity)
            rayon::join(
                || {
                    // compute wether the next bit should be set to 0 or 1, set the degree needed for the subtraction, and set the bit in the result
                    key.key.key.unchecked_apply_lookup_table_bivariate_assign(&mut guess_block, &overflow_happened, &zero_out_if_overflow_lut);
                    guess_block.degree = Degree::new(1 << (guess_bit_idx % log_modulus_usize));
                    key.key.key.unchecked_add_assign(&mut wide_result.blocks_mut()[guess_block_idx], &guess_block);
                }, || {
                    // calculate the new value of V
                    rayon::join(
                        || {
                            //keep the old if overflowed (V < 2*R*B + BS) -> zero if not overflow
                            narrow_remainder_old.blocks_mut().par_iter_mut().for_each( 
                                |block|
                                key.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_no_overflow_lut)
                            );
                        }, || {
                            //keep the new if it didn't overflow (V >= 2*R*B + BS) -> zero if overflow
                            narrow_remainder_new.blocks_mut().par_iter_mut().for_each(
                                |block| {
                                    key.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_overflow_lut);
                                    block.degree = Degree::new(0); // the degree of the remainder doesn't matter, so just keep it in check for good measure
                                }
                            );
                        }
                    );
                    // one of the two is 0, so the sum is the new value of V, also set this new value
                    let narrow_remainder_final = key.key.unchecked_add_parallelized(&narrow_remainder_new, &narrow_remainder_old);
                    wide_remainder.blocks_mut()[ls_used_block_idx..]
                        .par_iter_mut()
                        .zip(narrow_remainder_final.blocks().par_iter())
                        .for_each(|(remainder_block, new_value)| {
                            remainder_block.clone_from(new_value);
                    });
                }
            );

            // compute B >>= 1 and BS >>= 2, keeping track of the indicies
            key.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_radix, 1);
        }
        // discard unused part of the result, and return the rest
        Self::new(Cipher::from_blocks(wide_result.into_blocks()[blocks_with_frac..].to_vec()))
    }

    fn smart_sqrt(&mut self, key: &FixedServerKey) -> Self {
        self.smart_sqrt_guess_bit(key)
    }

    fn smart_sqrt_guess_bit(&mut self, key: &FixedServerKey) -> Self {
        // Pseudo code of the algorithm used:
        // sqrt(V)
        // V = V.clone()                    -- we use this as a remainder, but don't change the input
        // R = 0                            -- initialise the result/root as 0
        // B = max_possible_bit(V.len())    -- we find the maximum possible bit in the root
        //                                      all bits larger than this, have a square larger
        //                                      than the max value V could take
        // BS = square_of(B)                -- we find the square of B via a shift
        //
        // while B > 0
        //      if V >= 2*B*R + BS          -- since (R+B)^2 = R^2 + 2*B*R + BS
        //          R += B                  -- (R+B)^2 was less then original(V)
        //                                      here we essentially set one of the result bits
        //          V -= 2*B*R + BS         -- update V to be original(V) - (R+B)^2
        //
        //      B >>= 1
        //      BS >>= 2

        //needed since this is a smart function, also since bivariate lookup would drop carries
        if !self.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut self.inner);
        }

        // some helper numbers for ease of use later
        let log_modulus_usize = key.key.message_modulus().0.ilog2() as usize;               // number of bits in msg
        let blocks_with_frac = (Frac::USIZE + log_modulus_usize - 1) / log_modulus_usize;   // number of blocks containing a fractional bit
        let wide_block_size = self.inner.blocks().len() + blocks_with_frac;                 // the size of the wide versions in blocks (widness when we have fractional bits)
        let i_bits = Size::USIZE - Frac::USIZE;                                             // the number of integer (non-frac) bits
        let used_i_bits = (i_bits+1) / 2;                                                   // the number of integer bits that could be 1
        let least_used_bit_idx = blocks_with_frac * log_modulus_usize;                      // the index of the first non-wide bit (so the least bit that is relevant to the result)
        let largest_used_bit_idx = least_used_bit_idx + Frac::USIZE + used_i_bits - 1;      // the index of the most significant bit that could be set
        
        // the wide remainder, we will decrease this each iteration if it was still larger than the current square
        let mut wide_remainder = key.key.extend_radix_with_trivial_zero_blocks_lsb(&self.inner, blocks_with_frac);
        let mut wide_result: Cipher = key.key.create_trivial_zero_radix(wide_block_size); // only needed as wide for ease of indexing later

        // the single guess bit, starting at its largest value
        let mut guess_radix: Cipher = key.key.create_trivial_radix(1, wide_block_size);
        key.key.unchecked_scalar_left_shift_assign_parallelized(&mut guess_radix, largest_used_bit_idx);
        
        // the square of the guess bit is usually shifted left, unless there are no integer bits at all, in which case guess is 1/2, so square is 1/4
        let mut guess_square = 
            if used_i_bits > 0 {
                key.key.unchecked_scalar_left_shift_parallelized(&guess_radix, used_i_bits-1)
            } else { // used_i_bits is 0
                key.key.unchecked_scalar_right_shift_parallelized(&guess_radix, 1)
            };
        let mut sqr_bit_idx = largest_used_bit_idx + used_i_bits - 1; // we also store the index of the square bit for ease of use later

        // two lookup tables used to zero out half the calculations depending on `if V > 2*B*R + BS` (represented by an overflow)
        let zero_out_if_overflow_lut = 
            key.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow == 0 { block } else { 0 }
            );
        let zero_out_if_no_overflow_lut = 
            key.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow != 0 { block } else { 0 }
            );
        
        // main loop, iterates through the index of every result bit that could be set
        for guess_bit_idx in (least_used_bit_idx..=largest_used_bit_idx).rev() {
            // we assign some more helper vars
            let guess_block_idx = guess_bit_idx / log_modulus_usize;
            let sqr_block_idx_wide = sqr_bit_idx / log_modulus_usize;
            let shift_amount_signed = guess_bit_idx as isize - least_used_bit_idx as isize - Frac::USIZE as isize + 1;
            let ls_used_bit_idx = std::cmp::min(guess_bit_idx as isize + shift_amount_signed,std::cmp::min(sqr_bit_idx, guess_bit_idx) as isize) as usize;
            let ls_used_block_idx = ls_used_bit_idx / log_modulus_usize;            
            let sqr_block_idx_narrow = sqr_block_idx_wide - ls_used_block_idx;

            // in each loop we only operate on the sub-parts of the ciphers that could be non-zero, so we drop unneeded parts
            let mut narrow_remainder_old = Cipher::from(wide_remainder.blocks()[ls_used_block_idx..].to_vec());
            let mut narrow_result_shifted = Cipher::from(wide_result.blocks()[ls_used_block_idx..].to_vec());
            let mut sqr_block = guess_square.blocks()[sqr_block_idx_wide].clone();  // it is sufficient to store the guess and its square in a single block
            let mut guess_block = guess_radix.blocks()[guess_block_idx].clone();    // they are created as entire ciphers, since there is no convenient block-rotate
            
            // this does 2*R*B, since 2*B is still a (clear) power of two, we can just shift R by a scalar
            // for some reason we need to ensure that it has the correct degrees, else the subtraction will not work
            narrow_result_shifted = unchecked_signed_scalar_left_shift_parallelized(&key.key, &narrow_result_shifted, shift_amount_signed);

            //calculate 2*R*B + BS, again maintaining a correct degree
            // note that this can never result in carries, since least_bit_of(R) > B therefore least_bit_of(2*R*B) > BS
            // furthermore there can also never be an overflow, since either R=0 so 2*R*B + BS = BS, or 
            // 2*B <= R, so 2*B*R <= R^2 <= original(V) <= MAX_VALUE and since there is no carry from the addition, this gives no overflow either
            sqr_block.degree = Degree::new(1 << (sqr_bit_idx % log_modulus_usize));
            key.key.key.unchecked_add_assign(&mut narrow_result_shifted.blocks_mut()[sqr_block_idx_narrow], &sqr_block);

            // calculate V - (2*R*B + BS) and V >= (2*R*B + BS)      (the new value of V, and the guard of the if-stmt)
            let (mut narrow_remainder_new, overflow_happened) = key.key.unchecked_unsigned_overflowing_sub_parallelized(&narrow_remainder_old, &narrow_result_shifted);
            let overflow_happened = overflow_happened.into_raw_parts();

            // here we evaluate which branch of the if was taken, by zeroing out the unused branch (the second branch is just the identity)
            rayon::join(
                || {
                    // compute wether the next bit should be set to 0 or 1, set the degree needed for the subtraction, and set the bit in the result
                    key.key.key.unchecked_apply_lookup_table_bivariate_assign(&mut guess_block, &overflow_happened, &zero_out_if_overflow_lut);
                    guess_block.degree = Degree::new(1 << (guess_bit_idx % log_modulus_usize));
                    key.key.key.unchecked_add_assign(&mut wide_result.blocks_mut()[guess_block_idx], &guess_block);
                }, || {
                    // calculate the new value of V
                    rayon::join(
                        || {
                            //keep the old if overflowed (V < 2*R*B + BS) -> zero if not overflow
                            narrow_remainder_old.blocks_mut().par_iter_mut().for_each( 
                                |block|
                                key.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_no_overflow_lut)
                            );
                        }, || {
                            //keep the new if it didn't overflow (V >= 2*R*B + BS) -> zero if overflow
                            narrow_remainder_new.blocks_mut().par_iter_mut().for_each(
                                |block| {
                                    key.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_overflow_lut);
                                    block.degree = Degree::new(0); // the degree of the remainder doesn't matter, so just keep it in check for good measure
                                }
                            );
                        }
                    );
                    // one of the two is 0, so the sum is the new value of V, also set this new value
                    let narrow_remainder_final = key.key.unchecked_add_parallelized(&narrow_remainder_new, &narrow_remainder_old);
                    wide_remainder.blocks_mut()[ls_used_block_idx..]
                        .par_iter_mut()
                        .zip(narrow_remainder_final.blocks().par_iter())
                        .for_each(|(remainder_block, new_value)| {
                            remainder_block.clone_from(new_value);
                    });
                }
            );

            // compute B >>= 1 and BS >>= 2, keeping track of the indicies
            key.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_radix, 1);
            key.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_square, 2);
            sqr_bit_idx -= 2;
        }
        // discard unused part of the result, and return the rest
        Self::new(Cipher::from_blocks(wide_result.into_blocks()[blocks_with_frac..].to_vec()))
    }

    fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedU::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }
    fn encrypt<T>(clear: T, key: &FixedClientKey) -> Self
    where ArbFixedU<Size, Frac>: From<T>{
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::from(clear);
        /*this encrypts 1 block
        key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));*/

        let extract_bits = |x:&u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix.parts.iter().flat_map(extract_bits).
        take(Size::USIZE >> 1).map(|x| {
            key.key.encrypt_one_block(x as u64)
        }).collect::<Vec<Ciphertext>>();
        
        FheFixedU {
            inner: Cipher::from_blocks(blocks),
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }

    fn encrypt_trivial<T>(clear: T, key: &FixedServerKey) -> Self
    where ArbFixedU<Size, Frac>: From<T>{
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::from(clear);
        /*this encrypts 1 block
        key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));*/

        let extract_bits = |x:&u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix.parts.iter().flat_map(extract_bits).
        take(Size::USIZE >> 1).map(|x| {
            key.key.key.create_trivial(x as u64)
        }).collect::<Vec<Ciphertext>>();
        
        FheFixedU {
            inner: Cipher::from_blocks(blocks),
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }

    fn decrypt(&self, key: &FixedClientKey) -> ArbFixedU<Size, Frac>
    {
        let blocks = &self.inner.blocks();
        let clear_blocks: Vec<u8> = blocks.iter().map(|x| {
            key.key.key.decrypt_message_and_carry(x) as u8
        }).collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        ArbFixedU::from_bits(values)
    }
}
*/
/// Given an array ciphertexts, propagates them in parallel, if their block carries are not empty
pub(crate) fn propagate_if_needed_parallelized<T: IntegerRadixCiphertext>(
    ciphertexts: &mut [&mut T],
    key: &ServerKey,
) {
    ciphertexts
        .par_iter_mut()
        .filter(|cipher| !cipher.block_carries_are_empty())
        .for_each(|cipher| key.full_propagate_parallelized(*cipher));
}



/// Performs a left shift by scalar amount on the input ciphertext.
/// 
/// If the scalar is negative it will perfom a right shift instead.
/// 
/// Will give the degrees the correct value. \
/// 
/// ## Warning
/// This only works on unsigned numbers right now, may change in the future
fn unchecked_signed_scalar_left_shift_parallelized<T>(key: &ServerKey, ct: &T, scalar:isize) -> T
where
    T: IntegerRadixCiphertext,
{
    // bunch of helper values for ease of use
    let mut result = ct.clone();
    let shift = scalar.abs() as usize;
    let modulus = key.message_modulus().0 as u64;
    let log_modulus = key.message_modulus().0.ilog2() as usize;
    let blocks_shifted = shift / log_modulus;
    let bits_shifted = shift % log_modulus;

    // save the old degrees, we do our own calculation on them
    let mut degrees = ct.blocks().iter().map(|block| block.degree.get()).collect::<Vec<u64>>();
    
    // if scalar is positive, it is a left shift, otherwise a right shift
    if scalar >= 0 {
        // use built-in shift for the cipher
        key.unchecked_scalar_left_shift_assign_parallelized(&mut result, shift);
        
        // numbering of blocks is backwards in this library, so we do a right rotate, by the amount of full blocks shifted
        degrees.rotate_right(blocks_shifted);
        //since there is no vec_shift, we manually set the start to 0 after a rotate
        for i in 0..blocks_shifted {
            degrees[i] = 0;
        }

        // we do a left shift on each block, propagating the bits that get moved between blocks
        let mut carry = 0u64;
        for i in 0..degrees.len() {
            (carry, degrees[i]) = ((degrees[i] << bits_shifted) >> log_modulus, (degrees[i] << bits_shifted) % modulus + carry);
        }
    } else { // same as left shift, but in the other direction
        key.unchecked_scalar_right_shift_assign_parallelized(&mut result, shift);
        
        degrees.rotate_left(blocks_shifted);
        for i in degrees.len()-blocks_shifted..degrees.len() {
            degrees[i] = 0;
        }
        let mut carry = 0u64;
        for i in (0..degrees.len()).rev() {
            (carry, degrees[i]) = (((degrees[i] << log_modulus) >> bits_shifted) % modulus, (degrees[i] >> bits_shifted) + carry);
        }
    }

    // we overwrite the (potentially faulty) degrees of the built-in by our own (correct) degrees 
    result.blocks_mut().iter_mut().zip(degrees.into_iter()).for_each(|(block, deg)| block.degree = Degree::new(deg));
    result
}

