use crate::{propagate_if_needed_parallelized, size_frac::{FixedFrac, FixedSize}, Cipher, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};
use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext, ServerKey};
use rayon::prelude::*;

impl FixedServerKey {
    pub(crate) fn smart_mul<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        propagate_if_needed_parallelized(&mut[lhs.bits_mut(), rhs.bits_mut()], &self.key);

        self.unchecked_mul(lhs, rhs)
    }

    pub(crate) fn unchecked_mul<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let blocks_with_frac = (lhs.frac() + 1) >> 1;

        let mut lhs_bits = lhs.bits().clone();
        let mut rhs_bits = rhs.bits().clone();

        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
            (&mut lhs_bits, blocks_with_frac as usize);
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
            (&mut rhs_bits, blocks_with_frac as usize);

        self.key.unchecked_mul_assign_parallelized(&mut lhs_bits, &rhs_bits);

        if lhs.frac() % 2 != 0 {
            self.key.scalar_left_shift_assign_parallelized(&mut lhs_bits, 1);
        }

        let mut blocks = lhs_bits.into_blocks();
        blocks.drain(0..blocks_with_frac as usize);

        T::new(Cipher::from_blocks(blocks))
    }

    pub(crate) fn smart_mul_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &mut T) {
        *lhs = self.smart_mul(lhs, rhs);
    }
    
    pub(crate) fn unchecked_mul_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) {
        *lhs = self.unchecked_mul(lhs, rhs)
    }

    pub(crate) fn smart_sqr<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        assert!(c.size() >= c.frac());
        
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }

        self.unchecked_sqr(c)
    }
    
    pub(crate) fn unchecked_sqr<T: FixedCiphertextInner>(&self, c: &T) -> T {
        let blocks_with_frac = (c.frac() + 1) >> 1;

        let mut bits = c.bits().clone();
        
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
        (&mut bits, blocks_with_frac as usize);

        smart_sqr_assign(&mut bits, &self.key);
        if !bits.block_carries_are_empty() {
            self.key.full_propagate_parallelized(&mut bits);
        }
        if c.frac() % 2 != 0 {
            self.key.scalar_left_shift_assign_parallelized(&mut bits, 1);
        }

        let mut blocks = bits.into_blocks();
        blocks.drain(0..blocks_with_frac as usize);

        T::new(Cipher::from_blocks(blocks))
    }

    pub(crate) fn smart_sqr_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        *c = self.smart_sqr(c);
    }

    pub(crate) fn unchecked_sqr_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        *c = self.unchecked_sqr(c);
    }

}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    pub fn smart_mul(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_mul(&mut self.inner, &mut lhs.inner) }
    }
    pub fn unchecked_mul(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_mul(&self.inner, &lhs.inner) }
    }
    pub fn smart_mul_assign(&mut self, lhs: &mut Self, key: &FixedServerKey){
        key.smart_mul_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_mul_assign(&mut self, lhs: &Self, key: &FixedServerKey){
        key.unchecked_mul_assign(&mut self.inner, &lhs.inner)
    }

    pub fn smart_sqr(&mut self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_sqr(&mut self.inner) }
    }
    pub fn unchecked_sqr(&self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_sqr(&self.inner) }
    }
    pub fn smart_sqr_assign(&mut self, key: &FixedServerKey){
        key.smart_sqr_assign(&mut self.inner)
    }
    pub fn unchecked_sqr_assign(&mut self, key: &FixedServerKey){
        key.unchecked_sqr_assign(&mut self.inner)
    }
}

pub fn smart_sqr<T: IntegerRadixCiphertext>(c: &mut T, key: &ServerKey) -> T {
    if !c.block_carries_are_empty() {
        key.full_propagate_parallelized(c);
    }
    let mut result = c.clone();
    smart_sqr_assign(&mut result, key);
    result

}

/// Calculates the square of an encrypted integer. The algorithm used is the following:
/// Let c = sum_{i=0}^{n-1} c_i * b^i, where 0 <= c_i < b, where b is  the message modulus
/// Let a_i = c_i * b^i
/// Then c^2 = (sum a_i)^2 = 2*(sum_{i != j} a_i * a_j) + sum_{i=0}^{n-1} a_i^2
/// The first sum can be calculated with radix_ciphertext * block multiplications
/// The second with a few block*block multiplication
pub fn smart_sqr_assign<T: IntegerRadixCiphertext>(c: &mut T, key: &ServerKey) {
    if !c.block_carries_are_empty() {
        key.full_propagate_parallelized(c);
    }
    
    // This computes the terms a_i*a_j, where i != j, and a_i, a_j are the blocks of c
    let terms = compute_terms_for_sqr_low(c, key);
    
    // we calculate the terms a_i * a_i, and add them together into a single ciphertext
    let mut same_terms = compute_block_sqrs::<T>(c, key);
    
    if let Some(result) = key.unchecked_sum_ciphertexts_vec_parallelized(terms) {
        *c = result
    } else {
        key.create_trivial_zero_assign_radix(c)
    }

    if !same_terms.block_carries_are_empty() {
        key.full_propagate_parallelized(&mut same_terms);
    }
    
    // This may be done with a left shift, but that is more expensive
    // The two unchecked add is valid, because before the addition every carry is clear
    // and at every block the sum is at most 3+3+3 < 15
    *c = key.unchecked_add(c, c);
    key.unchecked_add_assign(c, &same_terms);
}

/// This function computes the blockwise square of the input, that is
/// if we denote with a_i the (i-th block value) * (message_modulus)^i then
/// we calculate the sum of a_i*a_i for every i
fn compute_block_sqrs<T: IntegerRadixCiphertext>(c: &T, key: &ServerKey) -> T {
    let message_modulus = key.key.message_modulus.0;
    let lsb_block_sqr_lut = key
        .key.generate_lookup_table(|x| (x*x) % message_modulus);
    let msb_block_sqr_lut = key
        .key.generate_lookup_table(|x| (x*x) / message_modulus);

    let mut result: T = key.create_trivial_zero_radix::<T>(c.blocks().len());

    result.blocks_mut()
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, block)| {
            let block_to_square = &c.blocks()[i >> 1];
            if block_to_square.degree.get() != 0 {
                if i % 2 == 0 {
                    *block = key.key.apply_lookup_table(
                        block_to_square,
                        &lsb_block_sqr_lut,
                    );
                }
                else if message_modulus > 2 {
                    *block = key.key.apply_lookup_table(
                        block_to_square,
                        &msb_block_sqr_lut,
                    );
                }
            }
        });

    result
}

/// I copied this function from compute_terms_for_mul_low, modified to calculate the terms for efficient squaring
/// Denote with a_i the (i-th block value) * (message_modulus)^i
/// The result of this function will be a Vec of ciphertexts, whose sum
/// equals to the sum of a_i*a_j for every distinct i,j pair
fn compute_terms_for_sqr_low<T>(lhs: &T, key: &ServerKey) -> Vec<T>
where
    T: IntegerRadixCiphertext,
{
    let message_modulus = key.key.message_modulus.0;

    let lsb_block_mul_lut = key
        .key
        .generate_lookup_table_bivariate(|x, y| (x * y) % message_modulus);

    let msb_block_mul_lut = key
        .key
        .generate_lookup_table_bivariate(|x, y| (x * y) / message_modulus);
    let rhs = lhs.clone();
    let message_part_terms_generator = rhs
        .blocks()
        .par_iter()
        .enumerate()
        .filter(|(i, block)| block.degree.get() != 0 
        && 2*i+2 <= lhs.blocks().len())
        .map(|(i, rhs_block)| {
            let mut result = key.blockshift(lhs, i);
            // We only want to compute every a_i*a_j once, hence we start from 2i+1 instead of i
            result.blocks_mut()[2*i+1..]
                .par_iter_mut()
                .filter(|block| block.degree.get() != 0)
                .for_each(|lhs_block| {
                    key.key.unchecked_apply_lookup_table_bivariate_assign(
                        lhs_block,
                        rhs_block,
                        &lsb_block_mul_lut,
                    );
                });
            // But we need to swap those that we left out to 0
            result.blocks_mut()[i..2*i+1]
                .par_iter_mut()
                .filter(|block| block.degree.get() != 0)
                .for_each(|lhs_block| {
                    key.key.create_trivial_assign(lhs_block, 0);
                });
            result
        });

    if key.message_modulus().0 > 2 {
        // Multiplying 2 blocks generates some part this is in the carry
        // we have to compute them.
        message_part_terms_generator
            .chain(
                rhs.blocks()[..rhs.blocks().len() - 1] // last block carry would be thrown away
                    .par_iter()
                    .enumerate()
                    .filter(|(i, block)| block.degree.get() != 0 
                    && 2*i+3 <= lhs.blocks().len())
                    .map(|(i, rhs_block)| {
                        // Here we are doing (a * b) / modulus
                        // that is, getting the carry part of the block multiplication
                        // so the shift is one block longer
                        let mut result = key.blockshift(lhs, i + 1);
                        
                        // We only want to compute every a_i*a_j once, hence we start from 2i+2 instead of i+1
                        result.blocks_mut()[2*i+2..]
                            .par_iter_mut()
                            .filter(|block| block.degree.get() != 0)
                            .for_each(|lhs_block| {
                                key.key.unchecked_apply_lookup_table_bivariate_assign(
                                    lhs_block,
                                    rhs_block,
                                    &msb_block_mul_lut,
                                );
                            });

                            // But we need to swap those that we left out to 0
                            result.blocks_mut()[i+1..2*i+2]
                            .par_iter_mut()
                            .filter(|block| block.degree.get() != 0)
                            .for_each(|lhs_block| {
                                key.key.create_trivial_assign(lhs_block, 0);
                            });
                        result
                    }),
            )
            .collect::<Vec<_>>()
    } else {
        message_part_terms_generator.collect::<Vec<_>>()
    }
}

