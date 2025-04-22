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
use tfhe::{FheBool, MatchValues};
use tfhe::shortint::parameters::Degree;
use typenum::{Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, UInt, Unsigned, B0, B1, U0, U10, U1000, U16, U6, U8, U2};
use fixed::{traits::ToFixed, types::U8F8};
use tfhe::shortint::{ClassicPBSParameters, Ciphertext};
use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};
use tfhe::integer::{ServerKey, ClientKey};

pub const PARAM: ClassicPBSParameters = tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

use crate::arb_fixed_u::ArbFixedU;
use crate::size_frac::{FixedFrac, FixedSize};


#[derive(Clone)]
pub struct FheFixedU<Size, Frac> {
    inner: Cipher,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>
}

impl<Size, Frac> FixedCiphertext for FheFixedU<Size, Frac> where
Size: FixedSize<Frac>,
Frac: FixedFrac {
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
        Size::U32
    }

    fn frac(&self) -> u32 {
        Frac::U32
    }

    fn new(inner: Cipher, size: u32, frac: u32) -> Self {
        // TODO remove these params when we remove unsafe fixed
        _ = size;
        _ = frac;
        Self::new(inner)
    }

    fn bits_in_block(&self) -> u32 {
        let modulus = self.inner.blocks()[0].message_modulus.0;
        let log2 = modulus.ilog2();
        if 2u64.pow(log2) == modulus {
            log2
        } else {
            log2 + 1
        }
    }
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

pub trait FixedCiphertext: Clone + Sync + Send{
    const IS_SIGNED: bool;
    fn inner(&self) -> &Cipher;
    fn inner_mut(&mut self) -> &mut Cipher;
    fn into_inner(self) -> Cipher;
    fn size(&self) -> u32;
    fn frac(&self) -> u32;
    fn new(inner: Cipher, size: u32, frac: u32) -> Self;
    fn bits_in_block(&self) -> u32;
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

    fn bits_in_block(&self) -> u32 {
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
            propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);
        }

        self.unchecked_add(lhs, rhs)
    }

    pub(crate) fn unchecked_add<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value = lhs.inner().clone();
        self.key.unchecked_add_assign_parallelized(&mut result_value, rhs.inner());
        T::new(result_value, lhs.size(), lhs.frac())
    }

    pub(crate) fn smart_sub<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());

        if self.key.is_sub_possible(lhs.inner(), rhs.inner()).is_err() {
            propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);
        }

        self.unchecked_sub(lhs, rhs)
    }

    pub(crate) fn unchecked_sub<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value = lhs.inner().clone();
        // This should be unchecked_sub_assign_parallelized, but there is no such function!
        // Only a non-parallelized version of it exists
        self.key.smart_sub_assign_parallelized(&mut result_value, &mut rhs.inner().clone());
        T::new(result_value, lhs.size(), lhs.frac())
    }

    pub(crate) fn smart_mul<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());

        propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);

        self.unchecked_mul(lhs, rhs)
    }

    pub(crate) fn unchecked_mul<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> T {
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
        assert!(c.size() >= c.frac());
        
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }

        self.unchecked_sqr(c)
    }
    
    pub(crate) fn unchecked_sqr<T: FixedCiphertext>(&self, c: &T) -> T {
        let blocks_with_frac = (c.frac() + 1) >> 1;

        let mut inner = c.inner().clone();
        
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
        (&mut inner, blocks_with_frac as usize);

        smart_sqr_assign(&mut inner, &self.key);
        if !inner.block_carries_are_empty() {
            self.key.full_propagate_parallelized(&mut inner);
        }
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
        let bits_in_block = self.key.message_modulus().0.ilog2();
        assert_eq!(0, c.size() % bits_in_block);
        let num_blocks: usize = (c.size()/bits_in_block) as usize;
        // We divide everything by 4^scale_factor,
        // in the end the result is multiplied with 2^scale_factor
        
        let mut inner = c.inner().clone();
        println!("input:");
        print_if_trivial(c);
        if T::IS_SIGNED {
            let mut _signed_inner = self.key
            .cast_to_signed(inner, num_blocks + 1);
            todo!()
        }
        else {
            if c.frac() % bits_in_block != 0 {
                let n = c.frac() % bits_in_block;
                let mut wide_c = self.widen(c,
                     c.size() + bits_in_block, c.frac() + bits_in_block - n);
                
                let wide_res = self.smart_sqrt_goldschmidt(&mut wide_c, iters);
                
                self.shrink(&wide_res, c.size(), c.frac())
            }
            // This is needed because else we don't have enough precision
            else if c.frac() == c.size() {
                let mut wide_c = self.widen(c,
                    c.size() + bits_in_block, c.frac());
                let wide_res = self.smart_sqrt_goldschmidt(&mut wide_c, iters);
                self.shrink(&wide_res, c.size(), c.frac())
            }
            else {
                
                let new_size=  c.size() + bits_in_block;
                let new_frac = c.size();
                // We will scale c into the range [0.25, 1) by shifting it with ilog4+1 blocks
                // The ilog4 here means as a fixed point number, not as the inner integer representing it
                // This is a bit messy because frac can be odd

                // We would like to do the following: extend c.inner with size/2 blocks lsb
                // (This too probably could be more efficient, but it is messy enough as it is)
                // Blockshift with ilog4(c.inner)+1 blocks right (this is an encrypted shift)
                // Cut of the unnecessary 0 blocks from the front
                // Create a new InnerFheFixed with c.size() as it's frac
                // But if c.frac() is odd, then this is shifting by 2^odd, which means we can't scale back
                
                let ilog2 = self.key.smart_ilog2_parallelized(&mut inner);
                let mut ilog4: Cipher = self.key.scalar_right_shift_parallelized(&ilog2, 1);
                self.key.smart_scalar_add_assign_parallelized(&mut ilog4, 1);

                self.key.extend_radix_with_trivial_zero_blocks_lsb_assign
                    (&mut inner, num_blocks);
                self.key.full_propagate_parallelized(&mut ilog4);
                inner = self.key.smart_block_shift_left(&mut inner, &mut ilog4);

                let mut new_blocks = inner.into_blocks();
                new_blocks.drain(num_blocks+1..);

                let new_inner = Cipher::from_blocks(new_blocks);
                let mut x_k = T::new(new_inner.clone(), new_size, new_frac);
                let mut r_k = T::new(new_inner, new_size, new_frac);

                let mut three_inner: Cipher = self.key
                    .create_trivial_radix(3u32, 1);
                self.key.extend_radix_with_trivial_zero_blocks_lsb_assign
                    (&mut three_inner, num_blocks);
                
                let mut three: T = T::new(three_inner, new_size, new_frac);
                println!();
                println!("x_k:");
                print_if_trivial(&x_k);
                println!("r_k:");
                print_if_trivial(&r_k);
                // the first 5 iterations (which are not necessarily quadratically convergent)
                // are replaced with a self.key.smart_match_value_parallelized(ct, matches);
                // That is, we look up the first m_k from a table
                let mut m_0 = self.sqrt_first_bits(&mut x_k);
                println!("m_0:");
                print_if_trivial(&m_0);

                propagate_if_needed_parallelized(&mut [m_0.inner_mut(), x_k.inner_mut(), r_k.inner_mut()], &self.key);
                    rayon::join(
                        || {
                            let mut m_0_sqr = self.unchecked_mul(&m_0, &m_0);
                            propagate_if_needed_parallelized(&mut [m_0_sqr.inner_mut()], &self.key);
                            x_k = self.unchecked_mul(&x_k, &m_0_sqr);
                        },
                        || r_k = self.unchecked_mul(&r_k, &m_0),
                    );

                for _ in 0..iters {
                    /*println!();
                    println!("x_k:");
                    print_if_trivial(&x_k);
                    println!("r_k:");
                    print_if_trivial(&r_k);*/
                    // We know that three always has empty carries, it doesn't need to be propagated
                    if self.key.is_sub_possible(three.inner(), x_k.inner()).is_err() {
                        self.key.full_propagate_parallelized(x_k.inner_mut());
                    }
                    let mut m_k = self.smart_sub(&mut three, &mut x_k);
                    
                    self.key.scalar_right_shift_assign_parallelized(m_k.inner_mut(), 1);
                    
                    /*println!("m_k:");
                    print_if_trivial(&m_k);*/
                    propagate_if_needed_parallelized(&mut [m_k.inner_mut(), x_k.inner_mut(), r_k.inner_mut()], &self.key);
                    rayon::join(
                        || {
                            let mut m_k_sqr = self.unchecked_mul(&m_k, &m_k);
                            propagate_if_needed_parallelized(&mut [m_k_sqr.inner_mut()], &self.key);
                            x_k = self.unchecked_mul(&x_k, &m_k_sqr);
                        },
                        || r_k = self.unchecked_mul(&r_k, &m_k),
                    );
                }
                let blocks_to_add = num_blocks - 1 as usize;
                let mut temp_inner = r_k.into_inner();
                //println!("result_length: {}", result_inner.blocks().len());

                self.key.extend_radix_with_trivial_zero_blocks_msb_assign(&mut temp_inner, blocks_to_add);
                self.key.smart_left_shift_assign_parallelized(&mut temp_inner, &mut ilog4);
                let temp_frac: u32 = c.size() + c.frac()/2;
                let temp_size: u32 = (temp_inner.blocks().len() * 2) as u32;
                let temp = T::new(temp_inner, temp_size, temp_frac);
                
                /*println!("blocks_to_drain: {}", blocks_to_drain);
                println!("blocks_to_add: {}", blocks_to_add);
                println!("result_length: {}", result_blocks.len());*/
                
                let mut result = self.shrink(&temp, c.size(), c.frac());
                println!("result:");
                print_if_trivial(&result);
                
                result = self.sqrt_try_minus_eps(c, &mut result);
                result = self.sqrt_try_plus_eps(c, &mut result);

                result
            }
        }
    }

    fn sqrt_try_minus_eps<T: FixedCiphertext>(&self, c: &mut T, sqrt: &mut T) -> T {
        let num_blocks = (c.size() / 2) as usize;
        // -eps_inner as unsigned, "temporary"
        let mut minus_eps: Cipher = self.key.create_trivial_radix(1u128.wrapping_neg(), num_blocks);
        let sqrteps_inner: Cipher = self.key.smart_add(sqrt.inner_mut(), &mut minus_eps);
            
        let sqrtteps = T::new(sqrteps_inner, c.size(), c.frac());
        let mut sqr = self.wide_sqr(sqrt);
        
        let mut c_extended = self.widen(c, c.size()*2, c.frac()*2);
        
        let bool = &self.smart_gt(&mut sqr, &mut c_extended);
        
        let result = self.select(bool, &sqrtteps, sqrt);
        result
    }

    fn sqrt_try_plus_eps<T: FixedCiphertext>(&self, c: &mut T, sqrt: &mut T) -> T {
        let sqrteps_inner = self.key.smart_add(sqrt.inner_mut(),
            &mut self.key.create_trivial_radix(1, (c.size() / 2) as usize));
            
        let mut sqrtteps = T::new(sqrteps_inner, c.size(), c.frac());
        let mut sqr = self.wide_sqr(&mut sqrtteps);
        let mut c_extended = self.widen(c, c.size()*2, c.frac()*2);

        let bool = &self.smart_gt(&mut sqr, &mut c_extended);

        let result = self.select(bool, sqrt, &sqrtteps);
        result
    }

    fn sqrt_first_bits<T: FixedCiphertext>(&self, c: &mut T) -> T {
        let len = c.inner().blocks().len();
        let bits_for_guessing: Vec<Ciphertext> = 
            vec![c.inner().blocks()[len-3].clone(), c.inner().blocks()[len-2].clone()];

        let matches: MatchValues<u64> = MatchValues::new(vec![
            (4, 7<<4),
            (5, 25<<2),
            (6, 23<<2),
            (7, 21<<2),
            (8, 5<<4),
            (9, 5<<4),
            (10, 71),
            (11, 71),
            (12, 1<<6),
            (13, 1<<6),
            (14, 1<<6),
            (15, 1<<6),
        ]).unwrap();
        print_if_trivial(&T::new(Cipher::from_blocks(bits_for_guessing.clone()), 4,0));
        let (mut guessed_bits, _) =
            self.key.unchecked_match_value_parallelized(&Cipher::from_blocks(bits_for_guessing), &matches);
        self.key.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut guessed_bits, ((c.size()>>1) - 4) as usize);
        T::new(guessed_bits, c.size(), c.frac())
    }

       
    pub(crate) fn wide_sqr<T: FixedCiphertext>(&self, c: &mut T) -> T {
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        let wide_c = self.widen(c, c.size()*2, c.frac()*2);
        self.unchecked_sqr(&wide_c)
    }

    // Shrinks the input to the given size and frac. Does NOT return with clear carries
    pub(crate) fn shrink<T: FixedCiphertext>(&self, c: &T, new_size: u32, new_frac: u32) -> T {
        assert!(new_size >= new_frac);
        assert!(new_size - new_frac <= c.size() - c.frac());
        assert!(new_frac <= c.frac());
        assert!(new_size % 2 == 0);
        assert!(c.size() % 2 == 0);

        let frac_bits_to_remove: usize = (c.frac() - new_frac) as usize;
        let start_blocks_to_remove = (frac_bits_to_remove+1) / 2 as usize;
        let blocks_to_remove = ((c.size() - new_size) / 2) as usize;
        let end_blocks_to_remove = blocks_to_remove - start_blocks_to_remove;

        /*println!("{start_blocks_to_remove}");
        println!("{end_blocks_to_remove}");
        println!("{}", c.inner().blocks().len());*/

        let mut new_c = c.clone();
        if frac_bits_to_remove % 2 == 1 {
            new_c = self.smart_double(&mut new_c);
        }
        propagate_if_needed_parallelized(&mut [new_c.inner_mut()], &self.key);
        /*println!("shrink dbl");
        print_if_trivial(&new_c);*/
        let mut blocks = new_c.inner().clone().into_blocks();
        let len = blocks.len();
        blocks.drain(len - end_blocks_to_remove..);
        blocks.drain(0..start_blocks_to_remove);
        

        let inner_res = Cipher::from_blocks(blocks);

        let result = T::new(inner_res, new_size, new_frac);
        /*println!("shrink result");
        print_if_trivial(&result);*/
        result
    }

    // Widens the input to the given size and frac. Does NOT return with clear carries 
    pub(crate) fn widen<T: FixedCiphertext>(&self, c: &T, new_size: u32, new_frac: u32) -> T {
        assert!(new_size >= new_frac);
        assert!(new_size - new_frac >= c.size() - c.frac());
        assert!(new_frac >= c.frac());
        assert!(new_size % 2 == 0);
        assert!(c.size() % 2 == 0);

        let extra_frac_bits = new_frac - c.frac();
        let extra_int_bits = new_size - new_frac - (c.size() - c.frac());

        let mut inner = c.inner().clone();
        self.key.extend_radix_with_trivial_zero_blocks_lsb_assign
            (&mut inner, (extra_frac_bits/2) as usize);
        self.key.extend_radix_with_trivial_zero_blocks_msb_assign
            (&mut inner, 
                ((extra_int_bits+1)/2) as usize);

        if extra_frac_bits % 2 == 1 {
            if self.key.is_add_possible(&inner, &inner).is_err() {
                self.key.full_propagate_parallelized(&mut inner);
            }
            inner = self.key.unchecked_add_parallelized(&inner, &inner);
        }

        T::new(inner, new_size, new_frac)
    }

    pub(crate) fn smart_double<T: FixedCiphertext>(&self, c: &mut T) -> T {
        if self.key.is_add_possible(c.inner(), c.inner()).is_err() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        let result_inner: Cipher = self.key.unchecked_add_parallelized(c.inner(), c.inner());
        T::new(result_inner, c.size(), c.frac())
    }

    fn smart_gt<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_gt_parallelized(lhs.inner_mut(), rhs.inner_mut())
    }

    fn smart_lt<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_lt_parallelized(lhs.inner_mut(), rhs.inner_mut())
    }
    
    fn smart_ge<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_ge_parallelized(lhs.inner_mut(), rhs.inner_mut())
    }

    fn select<T: FixedCiphertext>(&self, c: &BooleanBlock, lhs: &T, rhs: &T) -> T {
        assert!(lhs.size() >= lhs.frac());
        assert_eq!(lhs.size(), rhs.size());
        assert_eq!(lhs.frac(), rhs.frac());
        T::new(self.key.
            select_parallelized(c, lhs.inner(), rhs.inner()),
            lhs.size(), lhs.frac())
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

pub trait FheFixed<AF, CKey, SKey>
{
    // Binary operations
    fn smart_add(&self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_sub(&self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_mul(&mut self, rhs: &mut Self, key: &SKey) -> Self;
    fn smart_mul_assign(&mut self, rhs: &mut Self, key: &SKey);
    fn smart_sqr(&mut self, key: &SKey) -> Self;
    fn smart_sqr_assign(&mut self, key: &FixedServerKey);
    fn smart_div(&mut self, rhs: &mut Self, key: &SKey) -> Self;
    
    // Unary operations
    fn smart_ilog2(&mut self, key: &SKey) -> SignedRadixCiphertext;
    fn smart_sqrt(&mut self, key: &SKey) -> Self;
    fn smart_sqrt_goldschmidt(&mut self, iters: u32, key: &SKey) -> Self;
    fn smart_sqrt_guess_bit(&mut self, key: &SKey) -> Self;
    fn smart_neg(&mut self, key: &SKey) -> Self;
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

    fn encrypt_from_bits(bits: Vec<u64>, key: &CKey) -> Self;
    fn encrypt<T>(clear: T, key: &CKey) -> Self
        where AF: From<T>;
    fn encrypt_trivial<T>(clear: T, key: &SKey) -> Self
        where AF: From<T>;

    fn decrypt(&self, key: &FixedClientKey) -> AF;
}


/*Requirements (for now):
Size and Frac are Unsigned
Size >= Frac
Size is even and at least 2*/
impl<Size, Frac> FheFixed<ArbFixedU<Size, Frac>, FixedClientKey, FixedServerKey> for FheFixedU<Size, Frac> 
where
Size: FixedSize<Frac>,
Frac: FixedFrac
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

    fn smart_ilog2(&mut self, key: &FixedServerKey) -> SignedRadixCiphertext {
        let tmp: Cipher = key.key.smart_ilog2_parallelized(&mut self.inner);
        let len = tmp.blocks().len();
        let mut inner = key.key.cast_to_signed(tmp, len);
        key.key.smart_scalar_sub_assign_parallelized(&mut inner, Frac::U64);
        inner
    }
    fn smart_sqrt(&mut self, key: &FixedServerKey) -> Self {
        self.smart_sqrt_goldschmidt(4, key)
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
    
    fn smart_sqrt_goldschmidt(&mut self, iters: u32, key: &FixedServerKey) -> Self {
        let result_inner = key
            .smart_sqrt_goldschmidt(
                &mut <InnerFheFixedU as FixedCiphertext>::new(
                    self.inner.clone(), Size::U32, Frac::U32),
                    iters)
            .into_inner();
        Self::from_bits(result_inner, key)
    }

    fn smart_neg(&mut self, key: &FixedServerKey) -> Self {
        // This is needed because the builting smart_neg_parallelized does not work with trivial encryptions
        /*if self.inner.is_trivial() {
            let clear_inner: u64 = self.inner.decrypt_trivial().unwrap();
            Self::from_bits(key.key.create_trivial_radix((1<<Size::U64) - clear_inner,
            Size::USIZE>>1), key)
        } else*/ {
            let res_inner = key.key.smart_neg_parallelized(&mut self.inner);
            Self::from_bits(res_inner, key)
        }

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

