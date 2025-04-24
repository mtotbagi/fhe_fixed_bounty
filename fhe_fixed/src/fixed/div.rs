use crate::{unchecked_signed_scalar_left_shift_parallelized, propagate_if_needed_parallelized, size_frac::{FixedFrac, FixedSize}, Cipher, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use tfhe::{integer::{IntegerCiphertext, IntegerRadixCiphertext}, shortint::parameters::Degree};

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
        propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);
        self.unchecked_div_assign(lhs, rhs);
    }
    
    pub(crate) fn unchecked_div_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) {
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
        let log_modulus_usize = self.key.message_modulus().0.ilog2() as usize;                          // number of bits in msg
        let blocks_with_frac = (lhs.frac() as usize + log_modulus_usize - 1) / log_modulus_usize;       // number of blocks containing a fractional bit
        let wide_block_size = lhs.inner().blocks().len() + blocks_with_frac*2;                          // the size of the wide versions in blocks (widness when we have fractional bits)
        let least_used_bit_idx = blocks_with_frac * log_modulus_usize;                                  // the index of the first non-wide bit (so the least bit that is relevant to the result)
        let largest_used_bit_idx = least_used_bit_idx + lhs.size() as usize + lhs.frac() as usize - 1;  // the index of the most significant bit that could be set

        // the wide remainder, we will decrease this each iteration if it was still larger than the current Quotient
        let mut wide_remainder = self.key.extend_radix_with_trivial_zero_blocks_lsb(&lhs.inner(), blocks_with_frac);
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut wide_remainder, blocks_with_frac);
        
        // the result is only needed as wide for ease of indexing later, but this results in practically no performance overhead
        let mut wide_result: Cipher = self.key.create_trivial_zero_radix(wide_block_size);

        // the single guess bit, starting at its largest value
        let mut guess_radix: Cipher = self.key.create_trivial_radix(1, wide_block_size);
        self.key.unchecked_scalar_left_shift_assign_parallelized(&mut guess_radix, largest_used_bit_idx);
        
        // two lookup tables used to zero out half the calculations depending on `if R > B*D` (represented by an overflow)
        let zero_out_if_overflow_lut = 
            self.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow == 0 { block } else { 0 }
            );
        let zero_out_if_no_overflow_lut = 
            self.key.key.generate_lookup_table_bivariate(
                |block, overflow| if overflow != 0 { block } else { 0 }
            );
        
        let (shifted_wide_rhs_vec, leading_zeros) = rayon::join(
            || {
                // since the Dividend (rhs) never changes, we can precompute all the possible values of B*D now, resulting in an overall performance gain
                // since B is always a single bit, we can just shift D by the correct amount to get B*D
                // first we compute all the within-block shifts, these are the only expensive steps, so we want to do as few as possible
                let message_mod = self.key.message_modulus().0 as isize;
                let wide_rhs = self.key.extend_radix_with_trivial_zero_blocks_lsb(rhs.inner(), blocks_with_frac);
                let wide_rhs = self.key.extend_radix_with_trivial_zero_blocks_msb(&wide_rhs, blocks_with_frac + 1);
                let wide_shifted_rhs_vec = 
                    (0..=message_mod).into_par_iter().map(
                        |idx| {
                            // for some reason we need to ensure that it has the correct degrees, else the subtraction will not work
                            unchecked_signed_scalar_left_shift_parallelized(&self.key, &wide_rhs, idx)
                        }
                    ).collect::<Vec<_>>();
                
                // once we have all the in-block shifts we compute all the full shifts too
                (least_used_bit_idx..=largest_used_bit_idx).into_par_iter().map(
                    |idx| {
                        let shift_amount_signed = idx as isize - least_used_bit_idx as isize - lhs.frac() as usize as isize; //same as shift amount calculation later
                        let mod_of_shift = (shift_amount_signed % message_mod + message_mod) % message_mod;
                        let shift_amount_signed = shift_amount_signed - mod_of_shift;
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
                self.key.unchecked_leading_zeros_parallelized(rhs.inner())
            }
        );

        // main loop, iterates through the index of every result bit that could be set
        for guess_bit_idx in (least_used_bit_idx..=largest_used_bit_idx).rev() {
            // we assign some more helper vars
            let guess_block_idx = guess_bit_idx / log_modulus_usize;
            let shift_amount_signed = guess_bit_idx as isize - least_used_bit_idx as isize - lhs.frac() as usize as isize;
            let ls_used_bit_idx = (least_used_bit_idx as isize + shift_amount_signed) as usize;
            let ls_used_block_idx = ls_used_bit_idx / log_modulus_usize;

            // in each loop we only operate on the sub-parts of the ciphers that could be non-zero, so we drop unneeded parts
            let mut narrow_remainder_old = Cipher::from(wide_remainder.blocks()[ls_used_block_idx..].to_vec());
            let mut guess_block = guess_radix.blocks()[guess_block_idx].clone();    // they are created as entire ciphers, since there is no convenient block-rotate
            
            // this is B*D, since we already computed these, we can just get the correct one, and trim it to the correct length
            let narrow_rhs_shifted = Cipher::from(shifted_wide_rhs_vec[guess_bit_idx-least_used_bit_idx].blocks()[ls_used_block_idx..].to_vec());

            // calculate R - B*D and R >= B*D also check if the current bit is guaranteed to be a leading zero      (the new value of R, and the guard of the if-stmt)
            let ((mut narrow_remainder_new, sub_overflowed), is_leading_zero) = 
                rayon::join(
                    || {
                        self.key.unchecked_unsigned_overflowing_sub_parallelized(&narrow_remainder_old, &narrow_rhs_shifted)
                    }, || {
                        let cmp_val = lhs.size() as isize - (largest_used_bit_idx - guess_bit_idx) as isize - 1;
                        if cmp_val < 1 {
                            self.key.key.create_trivial(0)
                        } else {
                            self.key.unchecked_scalar_lt_parallelized(&leading_zeros, cmp_val as u64).into_raw_parts()
                        }
                });
            let overflow_happened = self.key.key.unchecked_add(&sub_overflowed.into_raw_parts(), &is_leading_zero);

            // here we evaluate which branch of the if was taken, by zeroing out the unused branch (the second branch is just the identity)
            rayon::join(
                || {
                    // compute wether the next bit should be set to 0 or 1, set the degree needed for the subtraction, and set the bit in the result
                    self.key.key.unchecked_apply_lookup_table_bivariate_assign(&mut guess_block, &overflow_happened, &zero_out_if_overflow_lut);
                    guess_block.degree = Degree::new(1 << (guess_bit_idx % log_modulus_usize));
                    self.key.key.unchecked_add_assign(&mut wide_result.blocks_mut()[guess_block_idx], &guess_block);
                }, || {
                    // calculate the new value of R
                    rayon::join(
                        || {
                            //keep the old if overflowed (R < B*D) -> zero if not overflow
                            narrow_remainder_old.blocks_mut().par_iter_mut().for_each( 
                                |block|
                                self.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_no_overflow_lut)
                            );
                        }, || {
                            //keep the new if it didn't overflow (R >= B*D) -> zero if overflow
                            narrow_remainder_new.blocks_mut().par_iter_mut().for_each(
                                |block| {
                                    self.key.key.unchecked_apply_lookup_table_bivariate_assign(block, &overflow_happened, &zero_out_if_overflow_lut);
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
        let mut narrow_result = Cipher::from_blocks(wide_result.into_blocks()[blocks_with_frac..wide_block_size-blocks_with_frac].to_vec());
        narrow_result.blocks_mut().par_iter_mut().for_each(|block| {
            // while there are no carries, there is some noise that we should clear
            self.key.key.message_extract_assign(block);
        });
        *lhs.inner_mut() = narrow_result;
    }
}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
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