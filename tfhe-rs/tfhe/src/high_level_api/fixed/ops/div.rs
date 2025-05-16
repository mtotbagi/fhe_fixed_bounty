use crate::high_level_api::fixed::{unchecked_signed_scalar_left_shift_parallelized, propagate_if_needed_parallelized};
use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use crate::{integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext}, shortint::parameters::Degree};

impl FixedServerKey {
    pub(crate) fn smart_div<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_div_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_div<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_div_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_div_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &mut T) {
        propagate_if_needed_parallelized(&mut[lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_div_assign(lhs, rhs);
    }

    pub(crate) fn unchecked_div_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) {
        if T::IS_SIGNED {
            //cast both to unsigned with absolute value
            let mut rhs_abs = rhs.clone();
            let mut lhs_abs = lhs.clone();
            rayon::join(
                || {
                    rhs_abs = self.unchecked_abs(&rhs_abs);
                }, || {
                    lhs_abs = self.unchecked_abs(&lhs_abs);
                }
            );

            // do the division, and calculate the sign bit
            let (_, sign_bits_are_different) = rayon::join(
                || {
                    self.unchecked_unsigned_div_assign_rem(&mut lhs_abs, &rhs_abs);
                }, || {
                    let sign_bit_pos = self.key.key.message_modulus.0.ilog2() - 1;
                    let compare_sign_bits = |x, y| {
                        let x_sign_bit = (x >> sign_bit_pos) & 1;
                        let y_sign_bit = (y >> sign_bit_pos) & 1;
                        u64::from(x_sign_bit != y_sign_bit)
                    };
                    let lut = self.key.key.generate_lookup_table_bivariate(compare_sign_bits);
                    BooleanBlock::new_unchecked(self.key.key.unchecked_apply_lookup_table_bivariate(
                        lhs.bits().blocks().last().unwrap(),
                        rhs.bits().blocks().last().unwrap(),
                        &lut,
                    ))
                });

            // fix sign of result
            let negated_lhs = self.key.neg_parallelized(lhs_abs.bits());

            *lhs.bits_mut() = self.key.unchecked_if_then_else_parallelized(
                &sign_bits_are_different,
                &negated_lhs,
                &lhs_abs.bits()
            );
        } else {
            self.unchecked_unsigned_div_assign_rem(lhs, rhs);
        }
    }
    
    /// Does wrapping division, assigns the quotient and returns the remainder.
    fn unchecked_unsigned_div_assign_rem<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) -> T {
        // Pseudo code of the algorithm used:
        // div(N, D)
        // R = N.clone()                    -- we use this as a remainder, but don't change the input
        // Q = 0                            -- initialise the result as 0
        // B = max_possible_bit(N.len())    -- we find the maximum possible bit in the result
        //                                      all bits larger than this would yield a product larger
        //                                      than the msb, even when multiplied by the lsb
        //
        // while B > 0
        //      if R >= B*D                 -- since (Q+B)*D = Q*D + B*D
        //          Q += B                  -- (Q+B)*D was less then N
        //                                      here we essentially set one of the result bits
        //          R -= B*D                -- update R to be N - (Q+B)*D
        //
        //      B >>= 1
        
        // some helper numbers for ease of use later
        let log_modulus_usize = self.key.message_modulus().0.ilog2() as usize;                      // number of bits in msg
        let blocks_with_frac = (lhs.frac() as usize + log_modulus_usize - 1) / log_modulus_usize;   // number of blocks containing a fractional bit
        let narrow_block_size = lhs.bits().blocks().len();                                          // the size of the wide versions in blocks (widness when we have fractional bits)
        let wide_block_size = narrow_block_size + blocks_with_frac;                                 // the size of the wide versions in blocks (widness when we have fractional bits)
        let largest_used_bit_idx = lhs.size() as usize + lhs.frac() as usize - 1;                   // the index of the most significant bit that could be set
        
        // the wide remainder, we will decrease this each iteration if it was still larger than the current Quotient
        // it needs to be extended to handle the differning behaviour of fractional bits
        let mut wide_remainder = lhs.bits().clone();
        self.key.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut wide_remainder, blocks_with_frac);
        if lhs.frac() % 2 == 1 {self.key.unchecked_scalar_right_shift_assign(&mut wide_remainder, 1);}
        
        // the result is only needed as wide for ease of indexing later, but this results in practically no performance overhead
        let mut wide_result: Cipher = self.key.create_trivial_zero_radix(wide_block_size);

        // the single guess bit, starting at its largest value
        let mut guess_radix: Cipher = self.key.create_trivial_radix(1, wide_block_size);
        self.key.unchecked_scalar_left_shift_assign_parallelized(&mut guess_radix, largest_used_bit_idx);
        
        // two lookup tables used to zero out half the calculations depending on `if R > B*D` (represented by an overflow)
        let zero_out_if_overflow_lut = 
            self.key.key.generate_lookup_table(
                |block| if block & 1 == 0 { block >> 1 } else { 0 }
            );
        let zero_out_if_no_overflow_lut = 
            self.key.key.generate_lookup_table(
                |block| if block & 1 != 0 { block >> 1 } else { 0 }
            );
        
        let (shifted_wide_rhs_vec, leading_zeros) = rayon::join(
            || {
                // since the Dividend (rhs) never changes, we can precompute all the possible values of B*D now, resulting in an overall performance gain
                // since B is always a single bit, we can just shift D by the correct amount to get B*D
                // first we compute all the within-block shifts, these are the only expensive steps, so we want to do as few as possible
                let message_mod = self.key.message_modulus().0 as isize;
                let wide_rhs = self.key.extend_radix_with_trivial_zero_blocks_msb(&rhs.bits(), blocks_with_frac + 1);
                let wide_shifted_rhs_vec = 
                    (0..=message_mod).into_par_iter().map(
                        |idx| {
                            // for some reason we need to ensure that it has the correct degrees, else the subtraction will not work
                            unchecked_signed_scalar_left_shift_parallelized(&self.key, &wide_rhs, idx)
                        }
                    ).collect::<Vec<_>>();
                
                // once we have all the in-block shifts we compute all the full shifts too
                (0..=largest_used_bit_idx as isize).into_par_iter().map(
                    |idx| {
                        let mod_of_shift = (idx % message_mod + message_mod) % message_mod;
                        let shift_amount_signed = idx - mod_of_shift;
                        let wider_shifted = unchecked_signed_scalar_left_shift_parallelized(&self.key, &wide_shifted_rhs_vec[mod_of_shift as usize], shift_amount_signed);
                        Cipher::from_blocks(wider_shifted.blocks()[..wider_shifted.blocks().len() - 1].to_vec())
                    }
                ).collect::<Vec<_>>()
            }, || {
                // leading zeros:
                // we can't have a bit set, if that would result in an overflow -> if rhs has 5 leading zeros, then we have i_bits - 5 - 1
                // therefore the result has `size - 1 - lz_rhs` leading zeros, this means that bit `i` is always a 0 if
                // size - 1 - lz_rhs > i
                // size - 1 - i > lz_rhs -> this is fewer operations

                // here we just calculate the leading zeros, we can do the comparisons later 
                self.key.unchecked_leading_zeros_parallelized(rhs.bits())
            }
        );

        // main loop, iterates through the index of every result bit that could be set
        for guess_bit_idx in (0..=largest_used_bit_idx).rev() {
            // we assign some more helper vars
            let ls_used_block_idx = guess_bit_idx / log_modulus_usize;

            // in each loop we only operate on the sub-parts of the ciphers that could be non-zero, so we drop unneeded parts
            let mut narrow_remainder_old = Cipher::from(wide_remainder.blocks()[ls_used_block_idx..].to_vec());
            let mut guess_block = guess_radix.blocks()[ls_used_block_idx].clone();    // they are created as entire ciphers, since there is no convenient block-rotate
            
            // this is B*D, since we already computed these, we can just get the correct one, and trim it to the correct length
            let narrow_rhs_shifted = Cipher::from(shifted_wide_rhs_vec[guess_bit_idx].blocks()[ls_used_block_idx..].to_vec());

            // calculate R - B*D and R >= B*D also check if the current bit is guaranteed to be a leading zero      (the new value of R, and the guard of the if-stmt)
            let ((mut narrow_remainder_new, sub_overflowed), is_leading_zero) = 
                rayon::join(
                    || {
                        self.key.unchecked_unsigned_overflowing_sub_parallelized(&narrow_remainder_old, &narrow_rhs_shifted)
                    }, || {
                        let total_size = lhs.size() as isize + lhs.frac() as isize - (blocks_with_frac * log_modulus_usize) as isize;
                        let inverse_idx = (largest_used_bit_idx - guess_bit_idx) as isize;
                        let cmp_val = total_size - 1 - inverse_idx;
                        if cmp_val < 1 {
                            self.key.key.create_trivial(0)
                        } else {
                            self.key.unchecked_scalar_lt_parallelized(&leading_zeros, cmp_val as u64).into_raw_parts()
                        }
                });
            // IMPORTANT --------- if we can get the two booleans below to be in the carry-space without any extra noise, than this could be an add
            // which would result in a major speed gain. This would also require some changes in the lookup tables and the way they are called.
            let overflow_happened = self.key.key.unchecked_bitor(&sub_overflowed.into_raw_parts(), &is_leading_zero);

            // here we evaluate which branch of the if was taken, by zeroing out the unused branch (the second branch is just the identity)
            rayon::join(
                || {
                    // compute wether the next bit should be set to 0 or 1, set the degree needed for the subtraction, and set the bit in the result
                    guess_block = self.key.key.unchecked_add(&guess_block, &guess_block);
                    self.key.key.unchecked_add_assign(&mut guess_block, &overflow_happened);
                    self.key.key.apply_lookup_table_assign(&mut guess_block, &zero_out_if_overflow_lut);
                    guess_block.degree = Degree::new(1 << (guess_bit_idx % log_modulus_usize));
                    self.key.key.unchecked_add_assign(&mut wide_result.blocks_mut()[ls_used_block_idx], &guess_block);
                }, || {
                    // calculate the new value of R
                    rayon::join(
                        || {
                            //keep the old if overflowed (R < B*D) -> zero if not overflow
                            narrow_remainder_old.blocks_mut().par_iter_mut().for_each( 
                                |block| {
                                    *block = self.key.key.unchecked_add(block, block);
                                    self.key.key.unchecked_add_assign(block, &overflow_happened);
                                    self.key.key.apply_lookup_table_assign(block, &zero_out_if_no_overflow_lut);
                            });
                        }, || {
                            //keep the new if it didn't overflow (R >= B*D) -> zero if overflow
                            narrow_remainder_new.blocks_mut().par_iter_mut().for_each(
                                |block| {
                                    *block = self.key.key.unchecked_add(block, block);
                                    self.key.key.unchecked_add_assign(block, &overflow_happened);
                                    self.key.key.apply_lookup_table_assign(block, &zero_out_if_overflow_lut);
                                    block.degree = Degree::new(0); // the degree of the remainder doesn't matter, so just keep it in check for good measure
                                }
                            );
                        }
                    );
                    // one of the two is 0, so the sum is the new value of R, also set this new value
                    let narrow_remainder_final = self.key.unchecked_add_parallelized(&narrow_remainder_new, &narrow_remainder_old);
                    wide_remainder.blocks_mut()[ls_used_block_idx..]
                        .par_iter_mut()
                        .zip(narrow_remainder_final.blocks().par_iter())
                        .for_each(|(remainder_block, new_value)| {
                            remainder_block.clone_from(new_value);
                    });
                }
            );

            // compute B >>= 1
            self.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_radix, 1);
        }
        // discard unused part of the result, and return the rest
        let mut narrow_result = Cipher::from_blocks(wide_result.into_blocks()[..narrow_block_size].to_vec());
        let mut narrow_remainder = Cipher::from_blocks(wide_remainder.into_blocks()[..narrow_block_size].to_vec());
        rayon::join(
            || {
                narrow_result.blocks_mut().par_iter_mut().for_each(|block| {
                    // while there are no carries, there is some noise that we should clear
                    self.key.key.message_extract_assign(block);
                });
            }, || {
                narrow_remainder.blocks_mut().par_iter_mut().for_each(|block| {
                    // while there are no carries, there is some noise that we should clear
                    self.key.key.message_extract_assign(block);
                });
            }
        );
        *lhs.bits_mut() = narrow_result;
        T::new(narrow_remainder)
    }
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    pub fn smart_div(&mut self, rhs: &mut Self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_div(&mut self.inner, &mut rhs.inner) }
    }
    pub fn unchecked_div(&self, rhs: &Self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_div(&self.inner, &rhs.inner) }
    }
    pub fn smart_div_assign(&mut self, rhs: &mut Self, key: &FixedServerKey){
        key.smart_div_assign(&mut self.inner, &mut rhs.inner)
    }
    pub fn unchecked_div_assign(&mut self, rhs: &Self, key: &FixedServerKey){
        key.unchecked_div_assign(&mut self.inner, &rhs.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    pub fn smart_div(&mut self, rhs: &mut Self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_div(&mut self.inner, &mut rhs.inner) }
    }
    pub fn unchecked_div(&self, rhs: &Self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_div(&self.inner, &rhs.inner) }
    }
    pub fn smart_div_assign(&mut self, rhs: &mut Self, key: &FixedServerKey){
        key.smart_div_assign(&mut self.inner, &mut rhs.inner)
    }
    pub fn unchecked_div_assign(&mut self, rhs: &Self, key: &FixedServerKey){
        key.unchecked_div_assign(&mut self.inner, &rhs.inner)
    }
}