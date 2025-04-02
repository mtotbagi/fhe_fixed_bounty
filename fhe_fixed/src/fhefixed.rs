#![allow(unused_imports)]
#![allow(dead_code)]
use core::num;
use std::fmt::{Binary, Display, Formatter, Result};
use std::sync::Arc;
use std::time::Instant;
use std::{marker::PhantomData, ops::Add};

use rayon::{prelude::*, result};
use fixed::traits::{Fixed, FixedUnsigned};
use fixed::types::U10F6;
use tfhe::integer::block_decomposition::{Decomposable, DecomposableInto};
use tfhe::integer::prelude::ServerKeyDefaultCMux;
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

pub trait FixedCiphertext: Clone + Sync{
    const IS_SIGNED: bool;
    fn inner(&self) -> &Cipher;
    fn inner_mut(&mut self) -> &mut Cipher;
    fn into_inner(self) -> Cipher;
    fn size(&self) -> u32;
    fn frac(&self) -> u32;
    fn new(inner: Cipher, size: u32, frac: u32) -> Self;
    fn block_size(&self) -> u32;
}

impl FixedCiphertext for InnerFheFixedU {
    const IS_SIGNED: bool = false;

    fn inner(&self) -> &Cipher {
        &self.inner
    }

    fn into_inner(self) -> Cipher {
        self.inner
    }
    
    fn inner_mut(&mut self) -> &mut Cipher {
        &mut self.inner
    }

    fn size(&self) -> u32 {
        self.size
    }

    fn frac(&self) -> u32 {
        self.frac
    }

    fn new(inner: Cipher, size: u32, frac: u32) -> Self {
        assert!(size > 0);
        assert!(size >= frac);
        Self { inner, size, frac }
    }

    fn block_size(&self) -> u32 {
        assert!(self.size > 0);
        let modulus = self.inner.blocks()[0].message_modulus.0;
        let log2 = modulus.ilog2();
        if 2u64.pow(log2) == modulus {
            log2
        } else {
            log2 + 1
        }
    }
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

    pub(crate) fn smart_add<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());

        if self.key.is_add_possible(lhs.inner(), rhs.inner()).is_err() {
            propagate_if_needed_parallelized(lhs.inner_mut(), rhs.inner_mut(), &self.key);
        }

        let mut result_value = lhs.inner().clone();
        self.key.smart_add_assign(&mut result_value, rhs.inner_mut());
        T::new(result_value, lhs.size(), lhs.frac())
    }

    pub(crate) fn smart_sub<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());

        if self.key.is_sub_possible(lhs.inner(), rhs.inner()).is_err() {
            propagate_if_needed_parallelized(lhs.inner_mut(), rhs.inner_mut(), &self.key);
        }

        let mut result_value = lhs.inner().clone();
        self.key.smart_sub_assign(&mut result_value, rhs.inner_mut());
        T::new(result_value, lhs.size(), lhs.frac())
    }

    pub(crate) fn smart_mul<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());

        propagate_if_needed_parallelized(lhs.inner_mut(), rhs.inner_mut(), &self.key);

        let blocks_with_frac = (lhs.frac() + 1) >> 1;

        let mut lhs_inner = lhs.inner().clone();
        let mut rhs_inner = rhs.inner().clone();

        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
        (&mut lhs_inner, blocks_with_frac as usize);
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
        (&mut rhs_inner, blocks_with_frac as usize);

        self.key.unchecked_mul_assign_parallelized(&mut lhs_inner, &rhs_inner);

        if lhs.frac() % 2 != 0 {
            self.key.scalar_left_shift_assign_parallelized(&mut lhs_inner, 1);
        }

        let mut blocks = lhs_inner.into_blocks();
        blocks.drain(0..blocks_with_frac as usize);

        T::new(Cipher::from_blocks(blocks), lhs.size(), lhs.frac())
    }

    pub(crate) fn smart_sqr<T: FixedCiphertext>(&self, c: &mut T) -> T {
        
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        
        let blocks_with_frac = (c.frac() + 1) >> 1;

        let mut inner = c.inner().clone();
        
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
        (&mut inner, blocks_with_frac as usize);

        smart_sqr_assign(&mut inner, &self.key);

        if c.frac() % 2 != 0 {
            self.key.scalar_left_shift_assign_parallelized(&mut inner, 1);
        }

        let mut blocks = inner.into_blocks();
        blocks.drain(0..blocks_with_frac as usize);

        T::new(Cipher::from_blocks(blocks), c.size(), c.frac())
    }
    
    // TODO rewrite to work with any block length (currently works for 2)
    pub(crate) fn smart_sqrt_goldschmidt<T: FixedCiphertext>(&self, c: &mut T, iters: u32) -> T {
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        let num_blocks: usize = (c.size()/2) as usize;
        let frac_bits = c.frac();
        let int_bits = c.size() - frac_bits;
        // Because we need to scale with 4^n, not 2^n it get's messy when frac is odd
        let blocks_to_add: usize = (int_bits % 2 + 1) as usize;
        let new_size=  c.size() + 2 * (blocks_to_add as u32);
        let new_frac = c.size() + (c.frac() % 2);
        
        // We divide everything by 4^scale_factor,
        // in the end the result is multiplied with 2^scale_factor
        // TODO when the input is relatively small, this converges slowly,
        // we should base the scaling factor on ilog
        let scale_factor = (new_frac - c.frac()) / 2;
        /*println!("size: {}", c.size());
        println!("frac: {}", c.frac());
        println!("int_bits: {}", int_bits);
        println!("blocks_to_add: {}", blocks_to_add);
        println!("new_size: {}", new_size);
        println!("new_frac: {}", new_frac);
        println!("scale_factor: {}", scale_factor);*/
        let mut inner = c.inner().clone();

        if T::IS_SIGNED {
            let mut _signed_inner = self.key
            .cast_to_signed(inner, num_blocks + 1);
            todo!()
        }
        else {
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut inner, blocks_to_add);
            
            let mut x_k = T::new(inner.clone(), new_size, new_frac);
            let mut r_k = T::new(inner.clone(), new_size, new_frac);

            let mut three_inner: Cipher = self.key
                .create_trivial_radix(3*blocks_to_add as u32, blocks_to_add);
            self.key.extend_radix_with_trivial_zero_blocks_lsb_assign
                (&mut three_inner, num_blocks);
            let mut three: T = T::new(three_inner, new_size, new_frac);
            
            for _ in 0..iters {
                // We know that three always has empty carries, it doesn't need to be propagated
                if self.key.is_sub_possible(three.inner(), x_k.inner()).is_err() {
                    self.key.full_propagate_parallelized(x_k.inner_mut());
                }
                let mut m_k = self.smart_sub(&mut three, &mut x_k);
                
                self.key.scalar_right_shift_assign_parallelized(m_k.inner_mut(), 1);
                
                let mut m_k_sqr = self.smart_mul(&mut m_k.clone(), &mut m_k.clone());
                
                x_k = self.smart_mul(&mut x_k, &mut m_k_sqr);
                r_k = self.smart_mul(&mut r_k, &mut m_k);
            }
            // Now 2^n * r_k = sqrt(c), where n = ceil((Size-Frac) / 2)

            let mut result_inner = r_k.clone().into_inner();
            
            self.key.scalar_right_shift_assign_parallelized(&mut result_inner, scale_factor);
            let mut result_blocks = result_inner.into_blocks();
            let len = result_blocks.len();
            result_blocks.drain(len-blocks_to_add..len);
            T::new(Cipher::from_blocks(result_blocks), c.size(), c.frac())
        }

        /*let mut x_k = x_scaled;
        let mut r_k = x_scaled;
        
        let three = F::from_num(3);
        for _ in 0..iters {
            let m_k = three.wrapping_sub(x_k).shr(1);
            
            
            let m_k_sqr = m_k.wrapping_mul(m_k);
            x_k = x_k.wrapping_mul(m_k_sqr);
            
            r_k = r_k.wrapping_mul(m_k);
        } */
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
    fn smart_mul_assign(&mut self, rhs: &mut Self, key: &SKey);
    fn smart_sqr(&mut self, key: &SKey) -> Self;
    fn smart_sqr_assign(&mut self, key: &FixedServerKey);
    fn smart_div(&self, rhs: &mut Self, key: &SKey) -> Self;
    
    // Unary operations
    fn smart_ilog2(&mut self, key: &SKey) -> SignedRadixCiphertext;
    fn smart_sqrt(&mut self, key: &SKey) -> Self;
    fn smart_sqrt_goldschmidt(&mut self, iters: u32, key: &SKey) -> Self;
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
    fn unchecked_ge(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock;
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
      typenum::private::IsGreaterOrEqualPrivate<U2, <Size as typenum::Cmp<U2>>::Output> +
      Send + Sync,
Frac: Unsigned + Send + Sync,
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

        //resolve carries both for shift and for drain
        if !result.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut result.inner);
        }

        if Frac::U8 % 2 != 0 {
            // bcs of above, this is fine as a default
            key.key.scalar_left_shift_assign_parallelized(&mut result.inner, 1);
        }
        let mut blocks = result.inner.into_blocks();
        blocks.drain(0..blocks_with_frac);

        Self::new(Cipher::from_blocks(blocks))
    }

    fn smart_sqr_assign(&mut self, key: &FixedServerKey) {
        *self = self.smart_sqr(key);
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
        // Pseudo code, unrefined, for msg_mod = 4:
        // We know that all bits greater than FRAC + (SIZE - FRAC) / 2 are 0, since their square is greater than maxvalue
        // so current guess is 0000xxxx.yyyyyyyy (in case of U8F8)
        // loop
        //      guess the 3 options (b1=11, b2=10, b3=01) for most sig. unknown block (also b4=00)
        //      compute in parallel
        //          sq1, sq2, sq3 = (current_guess+b1)^2, (current_guess+b2)^2, (current_guess+b3)^2
        //      evaluate in parallel
        //          r1, r2 = sq1<=num?b1:b2, sq3<=num?b3:b4
        //      evaluate
        //          res = sq2<=num?r1:r2
        //      current_guess += res

        //needed for the unchecked ge later on
        if !self.inner.block_carries_are_empty() {
            key.key.full_propagate_parallelized(&mut self.inner);
        }
        // initialise the result as a trivial 0
        let mut res = Self::new(key.key.create_trivial_zero_radix(self.inner.blocks().len()));

        // The first few blocks are always 0, since their square would be too large. The number of such bits is the half
        // of the integer bits rounded down, and the number of blocks is the half of the bits rounded down.
        // TODO this only supports blocksize 2 -> chaanged the rightshift from 2 to msg modulus, now it is good, but needs new explanation
        let i_blocks = (Size::USIZE - Frac::USIZE) >> (key.key.message_modulus().0.ilog2() - 1);
        let frac_blocks = (Frac::USIZE + key.key.message_modulus().0.ilog2() as usize - 1) >> (key.key.message_modulus().0.ilog2() - 1);
        let max_nonzero_block_idx = i_blocks / 2 + frac_blocks;

        // all the possible blocks we could have
        let guess_blocks = (0..key.key.message_modulus().0).into_par_iter().map(
            |clear_guess| {
                //encrypt the guess for the block 
                key.key.create_trivial_radix::<u32, Cipher>(clear_guess as u32, 1usize).clone()             
            }
        ).collect::<Vec<Cipher>>();
        
        for idx in (0..max_nonzero_block_idx).rev() {
            let mut guess_blocks = guess_blocks.clone();
            let mut squares = (1..key.key.message_modulus().0 as usize).into_par_iter().map(
                |clear_guess| {
                    // clone res
                    let mut res_plus_guess = res.clone();
                    // assign guess block, so now we have res+guess, with the guessed block in the correct position
                    res_plus_guess.inner.blocks_mut()[idx] = guess_blocks[clear_guess].blocks()[0].clone();
                    // square the sum and return it
                    res_plus_guess.smart_sqr_assign(key);
                    if !res_plus_guess.inner.block_carries_are_empty() {
                        key.key.full_propagate_parallelized(&mut res_plus_guess.inner);
                    }
                    res_plus_guess
                }
            ).collect::<Vec<Self>>();
            
            //we can eleminate half of the remaining guesses at a time, for now all are possible
            let mut iter_size = guess_blocks.len();
            
            // evaluate which guess is the correct one this needs to be some kind of pyramid scheme TODO
            while iter_size > 1 {
                iter_size >>= 1;
                guess_blocks = (0..iter_size).into_par_iter().map(
                    |i| {
                        // did we really need an unchecked ge just for this, or maybe I should use key.key.stuff here?
                        let keep_smaller = self.unchecked_ge(&squares[i*2], key);
                        key.key.if_then_else_parallelized(&keep_smaller, &guess_blocks[i * 2 + 1], &guess_blocks[i * 2])
                    }
                ).collect::<Vec<Cipher>>();

                //remove all even indicies as we just did the operation on them, they aren't needed anymore
                for i in (0..iter_size).rev() {
                    squares.remove(i*2);
                }
            }

            // only one guess left, it is the right one
            res.inner.blocks_mut()[idx] = guess_blocks[0].blocks()[0].clone();
        }
        res
    }

    
    fn smart_sqrt_goldschmidt(&mut self, iters: u32, key: &FixedServerKey) -> Self {
        let result_inner = key
            .smart_sqrt_goldschmidt(
                &mut <InnerFheFixedU as FixedCiphertext>::new(
                    self.inner.clone(), Size::U32, Frac::U32),
                    iters)
            .into_inner();
        Self::from_bits(result_inner, key)
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
    fn unchecked_ge(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.key.unchecked_ge_parallelized(&self.inner, &rhs.inner)
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

/// Given two ciphertexts, propagates them in parallel, if their block carries are not empty
pub(crate) fn propagate_if_needed_parallelized<T: IntegerRadixCiphertext>(lhs: &mut T, rhs: &mut T, key: &ServerKey) {
    rayon::join(
        || if !lhs.block_carries_are_empty() {
            key.full_propagate_parallelized(lhs);
        
        },
        || if !rhs.block_carries_are_empty() {
            key.full_propagate_parallelized(rhs);
        },
    );
}


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

pub trait Even {}
impl<U: Unsigned> Even for UInt<U, B0> {}
impl Even for U0 {}