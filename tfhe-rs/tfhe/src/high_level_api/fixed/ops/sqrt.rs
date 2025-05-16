use crate::high_level_api::fixed::{unchecked_signed_scalar_left_shift_parallelized, propagate_if_needed_parallelized};
use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator};
use crate::{integer::{IntegerCiphertext, IntegerRadixCiphertext}, shortint::parameters::Degree};

impl FixedServerKey {
    pub(crate) fn smart_sqrt<T: FixedCiphertextInner>(&self, lhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_sqrt_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_sqrt<T: FixedCiphertextInner>(&self, lhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_sqrt_assign(&mut result_value);
        result_value
    }

    
    pub(crate) fn smart_sqrt_assign<T: FixedCiphertextInner> (&self, lhs: &mut T) {
        propagate_if_needed_parallelized(&mut[lhs.bits_mut()], &self.key);
        self.unchecked_sqrt_assign(lhs);
    }
    
    pub(crate) fn unchecked_sqrt_assign<T: FixedCiphertextInner> (&self, c: &mut T) {
        // Pseudo code of the algorithm used:
        // sqrt(V)
        // V = V.clone()                    -- we use this as a remainder, but don't change the input
        // R = 0                            -- initialise the result/root as 0
        // B = max_possible_bit(V.len())    -- we find the maximum possible bit in the root
        //                                      all bits larger than this have a square larger
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

        // some helper numbers for ease of use later
        let log_modulus_usize = self.key.message_modulus().0.ilog2() as usize;                      // number of bits in msg
        let blocks_with_frac = (c.frac() as usize + log_modulus_usize - 1) / log_modulus_usize;     // number of blocks containing a fractional bit
        let wide_block_size = c.bits().blocks().len() + blocks_with_frac;                          // the size of the wide versions in blocks (widness when we have fractional bits)
        let i_bits = c.size() as usize - c.frac() as usize;                                         // the number of integer (non-frac) bits
        let used_i_bits = (i_bits+1) / 2;                                                           // the number of integer bits that could be 1
        let least_used_bit_idx = blocks_with_frac * log_modulus_usize;                              // the index of the first non-wide bit (so the least bit that is relevant to the result)
        let largest_used_bit_idx = least_used_bit_idx + c.frac() as usize + used_i_bits - 1;        // the index of the most significant bit that could be set
        
        // the wide remainder, we will decrease this each iteration if it was still larger than the current square
        let mut wide_remainder = self.key.extend_radix_with_trivial_zero_blocks_lsb(&c.bits(), blocks_with_frac);

        // result is only needed as wide for ease of indexing later
        let mut wide_result: Cipher = self.key.create_trivial_zero_radix(wide_block_size); 

        // the single guess bit, starting at its largest value
        let mut guess_radix: Cipher = self.key.create_trivial_radix(1, wide_block_size);
        self.key.unchecked_scalar_left_shift_assign_parallelized(&mut guess_radix, largest_used_bit_idx);
        
        // the square of the guess bit is usually shifted left, unless there are no integer bits at all, in which case guess is 1/2, so square is 1/4
        let mut guess_square = 
            if used_i_bits > 0 {
                self.key.unchecked_scalar_left_shift_parallelized(&guess_radix, used_i_bits-1)
            } else { // used_i_bits is 0
                self.key.unchecked_scalar_right_shift_parallelized(&guess_radix, 1)
            };
        let mut sqr_bit_idx = largest_used_bit_idx + used_i_bits - 1; // we also store the index of the square bit for ease of use later

        // two lookup tables used to zero out half the calculations depending on `if V > 2*B*R + BS` (represented by an overflow)
        let zero_out_if_overflow_lut = 
            self.key.key.generate_lookup_table(
                |block| if block & 1 == 0 { block >> 1 } else { 0 }
            );
        let zero_out_if_no_overflow_lut = 
            self.key.key.generate_lookup_table(
                |block| if block & 1 != 0 { block >> 1 } else { 0 }
            );

        let guess_overflow_lut = 
            self.key.key.generate_lookup_table(
                |block| (block & (self.key.message_modulus().0 - 2)) + if (block & 1) == 0 { block >> 2 } else { 0 }
            );
        
        // main loop, iterates through the index of every result bit that could be set
        for guess_bit_idx in (least_used_bit_idx..=largest_used_bit_idx).rev() {
            // we assign some more helper vars
            let guess_block_idx = guess_bit_idx / log_modulus_usize;
            let sqr_block_idx_wide = sqr_bit_idx / log_modulus_usize;
            let shift_amount_signed = guess_bit_idx as isize - least_used_bit_idx as isize - c.frac() as isize + 1;
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
            narrow_result_shifted = unchecked_signed_scalar_left_shift_parallelized(&self.key, &narrow_result_shifted, shift_amount_signed);

            //calculate 2*R*B + BS, again maintaining a correct degree
            // note that this can never result in carries, since least_bit_of(R) > B therefore least_bit_of(2*R*B) > BS
            // furthermore there can also never be an overflow, since either R=0 so 2*R*B + BS = BS, or 
            // 2*B <= R, so 2*B*R <= R^2 <= original(V) <= MAX_VALUE and since there is no carry from the addition, this gives no overflow either
            sqr_block.degree = Degree::new(1 << (sqr_bit_idx % log_modulus_usize));
            self.key.key.unchecked_add_assign(&mut narrow_result_shifted.blocks_mut()[sqr_block_idx_narrow], &sqr_block);

            // calculate V - (2*R*B + BS) and V >= (2*R*B + BS)      (the new value of V, and the guard of the if-stmt)
            let (mut narrow_remainder_new, overflow_happened) = self.key.unchecked_unsigned_overflowing_sub_parallelized(&narrow_remainder_old, &narrow_result_shifted);
            let overflow_happened = overflow_happened.into_raw_parts();

            // here we evaluate which branch of the if was taken, by zeroing out the unused branch (the second branch is just the identity)
            rayon::join(
                || {
                    // compute wether the next bit should be set to 0 or 1, set the degree needed for the subtraction, and set the bit in the result
                    // we also need to make sure that the noise level is nominal
                    self.key.key.unchecked_scalar_mul_assign(&mut guess_block, 4);
                    self.key.key.unchecked_add_assign(&mut guess_block, &overflow_happened);
                    self.key.key.unchecked_add_assign(&mut guess_block, &wide_result.blocks()[guess_block_idx]);
                    self.key.key.apply_lookup_table_assign(&mut guess_block, &guess_overflow_lut);
                    guess_block.degree = Degree::new(1 << (guess_bit_idx % log_modulus_usize));
                    wide_result.blocks_mut()[guess_block_idx] = guess_block;
                }, || {
                    // calculate the new value of V
                    rayon::join(
                        || {
                            //keep the old if overflowed (V < 2*R*B + BS) -> zero if not overflow
                            narrow_remainder_old.blocks_mut().par_iter_mut().for_each( 
                                |block| {
                                    *block = self.key.key.unchecked_add(block, block);
                                    self.key.key.unchecked_add_assign(block, &overflow_happened);
                                    self.key.key.apply_lookup_table_assign(block, &zero_out_if_no_overflow_lut);
                            });
                        }, || {
                            //keep the new if it didn't overflow (V >= 2*R*B + BS) -> zero if overflow
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
                    // one of the two is 0, so the sum is the new value of V, also set this new value
                    let narrow_remainder_final = self.key.unchecked_add_parallelized(&narrow_remainder_new, &narrow_remainder_old);
                    wide_remainder.blocks_mut()[ls_used_block_idx..]
                        .par_iter_mut()
                        .zip(narrow_remainder_final.blocks().par_iter())
                        .for_each(|(remainder_block, new_value)| {
                            remainder_block.clone_from(new_value);
                    });
                }
            );

            // compute B >>= 1 and BS >>= 2, keeping track of the indicies
            self.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_radix, 1);
            self.key.unchecked_scalar_right_shift_assign_parallelized(&mut guess_square, 2);
            sqr_bit_idx -= 2;
        }
        // discard unused part of the result, and return the rest
        *c.bits_mut() = Cipher::from_blocks(wide_result.into_blocks()[blocks_with_frac..].to_vec());
    }
}

        impl<Size, Frac> FheFixedU<Size, Frac>
        where
Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_sqrt(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_sqrt(&mut self.inner),
                }
    }
    pub fn unchecked_sqrt(&self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_sqrt(&self.inner),
                }
    }
            pub fn smart_sqrt_assign(&mut self, key: &FixedServerKey) {
        key.smart_sqrt_assign(&mut self.inner)
    }
            pub fn unchecked_sqrt_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_sqrt_assign(&mut self.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
        where
Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_sqrt(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_sqrt(&mut self.inner),
                }
    }
    pub fn unchecked_sqrt(&self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_sqrt(&self.inner),
                }
    }
            pub fn smart_sqrt_assign(&mut self, key: &FixedServerKey) {
        key.smart_sqrt_assign(&mut self.inner)
    }
            pub fn unchecked_sqrt_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_sqrt_assign(&mut self.inner)
    }
}