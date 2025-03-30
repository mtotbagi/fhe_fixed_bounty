#![allow(unused_imports)]
#![allow(dead_code)]
use std::fmt::{Binary, Display, Formatter, Result};
use std::sync::Arc;
use std::time::Instant;
use std::{marker::PhantomData, ops::Add};

use rayon::{prelude::*, result};
use fixed::traits::FixedUnsigned;
use fixed::types::U10F6;
use tfhe::integer::block_decomposition::{Decomposable, DecomposableInto};
use tfhe::FheBool;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U16, U6, U8, U2};
use fixed::{traits::ToFixed, types::U8F8};
use tfhe::shortint::{ClassicPBSParameters, Ciphertext};
use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};
use tfhe::integer::{ServerKey, ClientKey};

pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

use crate::arb_fixed_u::ArbFixedU;

#[derive(Clone)]
pub struct FheFixedU<Size, Frac> {
    inner: Cipher,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>
}

impl<Size, Frac> FheFixedU<Size, Frac> {
    pub fn new(inner: Cipher) -> FheFixedU<Size, Frac> {
        FheFixedU { inner, phantom1: PhantomData, phantom2: PhantomData }
    }
}

#[derive(Clone)]
pub(crate) struct InnerFheFixedU {
    inner: Cipher,
    size: u32,
    frac: u32
}

pub trait FixedCiphertext: Clone {
    const IS_SIGNED: bool;
    fn inner(&self) -> Cipher;
    fn size(&self) -> u32;
    fn frac(&self) -> u32;
    fn new(inner: Cipher, size: u32, frac: u32) -> Self;
}

pub struct FixedServerKey {
    pub key: ServerKey
}

impl FixedServerKey {
    pub fn new(cks: &FixedClientKey) -> FixedServerKey{
        FixedServerKey{
            key: ServerKey::new_radix_server_key(&cks.key)
        }
    }

    pub fn smart_add<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());
        let mut result_value = lhs.inner().clone();
        self.key.smart_add_assign(&mut result_value, &mut rhs.inner());
        T::new(result_value, lhs.size(), lhs.frac())
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

pub trait FheFixed<AF, CKey, SKey>
{
    // Binary operations
    fn smart_add(&self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_sub(&self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_mul(&mut self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_sqr(&mut self, key: &SKey) -> Self;
    fn smart_mul_assign(&mut self, rhs: &mut Self, key: &SKey);
    fn smart_div(&self, rhs: &mut Self, key: &SKey) -> Self;

    // Unary operations
    fn smart_ilog2(&mut self, key: &SKey) -> SignedRadixCiphertext;
    fn smart_sqrt(&mut self, key: &SKey) -> Self;
    fn smart_sqrt_guess_block(&mut self, key: &SKey) -> Self;
    fn smart_neg(&self, key: &SKey) -> Self;
    fn smart_abs(&self, key: &SKey) -> Self;
    // Roundings
    fn smart_floor(&mut self, key: &SKey) -> Self;
    fn smart_ceil(&mut self, key: &SKey) -> Self;
    fn smart_trunc(&mut self, prec: usize, key: &SKey) -> Self;
    fn smart_round(&mut self, key: &SKey) -> Self;
    //Comparisons
    fn smart_eq(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;
    fn smart_ne(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;
    fn smart_gt(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;
    fn smart_ge(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;
    fn smart_lt(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;
    fn smart_le(&mut self, rhs: &mut Self, key: &SKey) -> BooleanBlock;

    // TODO we may need to swap out Cipher to T: IntegerRadixCiphertext
    // but then that's another type parameter, because for unsigned we need
    // BaseRadixCiphertext<Ciphertext> for signed
    // BaseSignedRadixCiphertext<Ciphertext>

    /// Creates an encrypted fixed-point number 
    /// that has a bitwise representation identical to the given encrypted integer.
    fn from_bits(bits: Cipher, key: &SKey) -> Self;

    fn encrypt<T>(clear: T, key: &CKey) -> Self
        where AF: From<T>;
    fn encrypt_from_bits(bits: Vec<u64>, key: &CKey) -> Self;

    fn decrypt(&self, key: &FixedClientKey) -> AF;
}


/*Requirements (for now):
Size and Frac are Unsigned
Size >= Frac
Size is even and at least 2*/
impl<Size, Frac> FheFixed<ArbFixedU<Size, Frac>, FixedClientKey, FixedServerKey> for FheFixedU<Size, Frac> 
where
Size: Unsigned +
      Cmp<Frac> +
      typenum::private::IsGreaterOrEqualPrivate<Frac, <Size as typenum::Cmp<Frac>>::Output> +
      Even + Cmp<U2> +
      typenum::private::IsGreaterOrEqualPrivate<U2, <Size as typenum::Cmp<U2>>::Output>,
Frac: Unsigned,
<Size as IsGreaterOrEqual<Frac>>::Output: Same<True>,
<Size as IsGreaterOrEqual<U2>>::Output: Same<True>
{
    fn smart_add(&self, rhs: &mut Self, key: &FixedServerKey) -> Self {
        let mut result_value = self.inner.clone();
        key.key.smart_add_assign(&mut result_value, &mut rhs.inner);
        FheFixedU::new(result_value)
    }

    fn smart_sub(&self, rhs: &mut Self, key: &FixedServerKey) -> Self {
        let mut result_value = self.inner.clone();
        key.key.smart_sub_assign(&mut result_value, &mut rhs.inner);

        FheFixedU {
            inner: result_value,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }

    fn smart_mul(&mut self, rhs: &mut Self, key: &FixedServerKey) -> Self {
        // We can do the propagation here before extending the ciphertexts
        // The trivial encryption don't need propagation
        // Also the other version (propagate after extend) is incorrect
        // If we extend 11c10 00c11 and get 00c00 11c10 00c11 
        // The propagation will result in   00c11 00c10 00c11 but we don't want that!
        rayon::join(
            || if !self.inner.block_carries_are_empty()
            {key.key.full_propagate_parallelized(&mut self.inner);},
            || if !rhs.inner.block_carries_are_empty()
            {key.key.full_propagate_parallelized(&mut rhs.inner);},
        );
        
        let mut lhs = self.clone();

        let blocks_with_frac = (Frac::USIZE + 1) >> 1;

        key.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut lhs.inner, blocks_with_frac);
        key.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut rhs.inner, blocks_with_frac);

        key.key.unchecked_mul_assign_parallelized(&mut lhs.inner, &rhs.inner);
        // at the end of this there is a propagate
        
        if Frac::U8 % 2 != 0 {
            // bcs of above, this is fine as a default
            key.key.scalar_left_shift_assign_parallelized(&mut lhs.inner, 1);
        }
        let mut blocks = lhs.inner.into_blocks();
        blocks.drain(0..blocks_with_frac);

        Self::new(Cipher::from_blocks(blocks))
    }

    fn smart_mul_assign(&mut self, rhs: &mut Self, key: &FixedServerKey) {
        *self = self.smart_mul(rhs, key);
    }
    
    fn smart_sqr(&mut self, key: &FixedServerKey) -> Self {
        if !self.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut self.inner)
        }
        let mut result = self.clone();

        let blocks_with_frac = (Frac::USIZE + 1) >> 1;

        key.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut result.inner, blocks_with_frac);

        smart_sqr_assign(&mut result.inner, &key.key);
        // at the end of this there is a propagate
        
        if Frac::U8 % 2 != 0 {
            // bcs of above, this is fine as a default
            key.key.scalar_left_shift_assign_parallelized(&mut result.inner, 1);
        }
        let mut blocks = result.inner.into_blocks();
        blocks.drain(0..blocks_with_frac);

        Self::new(Cipher::from_blocks(blocks))
    }


    fn smart_div(&self, rhs: &mut Self, key: &FixedServerKey) -> Self {
        let _ = key;
        let _ = rhs;
        todo!()
    }

    fn smart_ilog2(&mut self, key: &FixedServerKey) -> SignedRadixCiphertext {
        let tmp: Cipher = key.key.smart_ilog2_parallelized(&mut self.inner);
        let len = tmp.blocks().len();
        let mut inner = key.key.cast_to_signed(tmp, len);
        key.key.smart_scalar_sub_assign_parallelized(&mut inner, Frac::U64);
        inner
    }
    fn smart_sqrt(&mut self, key: &FixedServerKey) -> Self {
        let _ = key;
        todo!()
    }

    fn smart_sqrt_guess_block(&mut self, key: &FixedServerKey) -> Self {
        let _ = key;
        todo!()
    }

    fn smart_neg(&self, key: &FixedServerKey) -> Self {
        let _ = key;
        panic!("Cannot negate an unsigned number!")
    }
    fn smart_abs(&self, key: &FixedServerKey) -> Self {
        let _ = key;
        self.clone()
    }
    // Roundings
    fn smart_floor(&mut self, key: &FixedServerKey) -> Self {
        self.smart_trunc(0, key)
    }
    fn smart_ceil(&mut self, key: &FixedServerKey) -> Self {
        let tmp = key.key.smart_scalar_sub_parallelized(&mut self.inner, 1u64);
        let mut res = FheFixedU::new(tmp).smart_floor(&key);
        key.key.smart_scalar_add_assign_parallelized(&mut res.inner, 1<<Frac::USIZE);
        res
    }
    fn smart_trunc(&mut self, prec: usize, key: &FixedServerKey) -> Self {
        if prec > Frac::USIZE {
            panic!("Prec cannot be greater then the Frac of self!");
        }
        let bits_to_lose = Frac::USIZE - prec;
        if !self.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut self.inner);
        }
        let mut blocks = self.inner.clone().into_blocks();
        blocks.drain(0..bits_to_lose>>1);
        if bits_to_lose % 2 == 1 {
            let block = blocks.drain(0..1).collect::<Vec<Ciphertext>>();
            let acc = key.key.key.generate_lookup_table(|x| x & 0b10);

            let ct_res = key.key.key.apply_lookup_table(&block[0], &acc);
            blocks.insert(0, ct_res);
        }
        let mut cipher = Cipher::from_blocks(blocks);
        key.key.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut cipher, bits_to_lose>>1);
        FheFixedU::new(cipher)
    }
    fn smart_round(&mut self, key: &FixedServerKey) -> Self {
        if Frac::USIZE == 0{
            return self.clone();
        } // Now we know frac > 0
        let tmp = key.key.smart_scalar_sub_parallelized(&mut self.inner, 1<<(Frac::USIZE-1));
        let mut res = Self::new(tmp.clone()).smart_floor(&key);
        key.key.smart_scalar_add_assign_parallelized(&mut res.inner, 1<<Frac::USIZE);
        res
    }

    fn smart_eq(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_eq_parallelized(&mut self.inner, &mut rhs.inner)
    }
    fn smart_ne(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_ne_parallelized(&mut self.inner, &mut rhs.inner)
    }
    fn smart_gt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_gt_parallelized(&mut self.inner, &mut rhs.inner)
    }
    fn smart_ge(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_ge_parallelized(&mut self.inner, &mut rhs.inner)
    }
    fn smart_lt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_lt_parallelized(&mut self.inner, &mut rhs.inner)
    }
    fn smart_le(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.smart_le_parallelized(&mut self.inner, &mut rhs.inner)
    }

    fn from_bits(bits: Cipher, key: &FixedServerKey) -> Self {
        
        let len: usize = Size::USIZE / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let cur_len = blocks.len();
        let mut inner = Cipher::from_blocks(blocks);
        key.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut inner, len-cur_len);
        Self::new(inner)
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

pub type FheFixedU6F10 = FheFixedU<U16, U10>;
pub type FheFixedUF6 = FheFixedU<U6, U16>;

/// ### NOTE
/// Currently the carry and the overflow from the msb block may or may not be lost. This may or may not change!
fn blocks_with_carry_to_u64(blocks: Vec<u8>) -> Vec<u64> {
    // The result vector
    let mut result = Vec::new();
    // The current element of the vector, stored as u128 to handle overflow
    let mut current_u64:u128 = 0;
    // The index of the current 2 bits that we are adding to 
    let mut position = 0;
    
    for i in 0..blocks.len() {
        //extract value and carry from input block
        let value = blocks[i] & 0b11;
        let carry = (blocks[i] >> 2) & 0b11;

        // add value at current position
        current_u64 += (value as u128) << (position * 2);
        
        position += 1;
        
        // If position is 32, then we have filled in the current u64, so push it to the result
        if position == 32 {
            // This is the part of the result so far that fits in a u64
            let result_u64 = current_u64 & (u64::MAX as u128);
            // Push the result
            result.push(result_u64 as u64);
            // The next u64 will start as the overflow from the current
            current_u64 >>= 64;
            // Reset the position
            position = 0;
        }

        // Finally add the carry bits to the next position
        current_u64 += (carry as u128) << (position * 2);
    }
    
    // Add the last partially filled u64 if necessary
    if position > 0 {
        let result_u64 = current_u64 & (u64::MAX as u128);
        result.push(result_u64 as u64);
    }
    
    result
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
    let same_terms = compute_block_sqrs::<T>(c, key);
    
    if let Some(result) = key.unchecked_sum_ciphertexts_vec_parallelized(terms) {
        *c = result
    } else {
        key.create_trivial_zero_assign_radix(c)
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

pub trait Even {}
impl<U: Unsigned> Even for UInt<U, B0> {}
impl Even for U0 {}