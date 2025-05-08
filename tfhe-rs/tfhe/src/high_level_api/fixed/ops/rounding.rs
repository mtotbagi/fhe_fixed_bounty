use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};
use crate::{
    integer::{IntegerCiphertext, IntegerRadixCiphertext},
    shortint::Ciphertext,
};

impl FixedServerKey {
    fn smart_floor<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        self.smart_trunc(c, 0)
    }
    fn smart_ceil<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let tmp = self.key.smart_scalar_sub_parallelized(c.bits_mut(), 1u64);
        let mut res = self.smart_floor(&mut T::new(tmp));
        self.key
            .smart_scalar_add_assign_parallelized(res.bits_mut(), 1 << c.frac());
        res
    }
    fn smart_round<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let frac = c.frac();
        if frac == 0 {
            return c.clone();
        } // Now we know frac > 0
        let tmp: Cipher = self
            .key
            .smart_scalar_sub_parallelized(c.bits_mut(), 1 << (frac - 1));
        let mut res = self.smart_floor(&mut T::new(tmp.clone()));
        self.key
            .smart_scalar_add_assign_parallelized(res.bits_mut(), 1 << frac);
        res
    }
    fn smart_trunc<T: FixedCiphertextInner>(&self, c: &mut T, prec: usize) -> T {
        let frac: usize = c.frac() as usize;
        if prec > frac {
            panic!("Prec cannot be greater then the Frac of self!");
        }
        let bits_to_lose = frac - prec;
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        let mut blocks = c.bits().clone().into_blocks();
        blocks.drain(0..bits_to_lose >> 1);
        if bits_to_lose % 2 == 1 {
            let block = blocks.drain(0..1).collect::<Vec<Ciphertext>>();
            let acc = self.key.key.generate_lookup_table(|x| x & 0b10);

            let ct_res = self.key.key.apply_lookup_table(&block[0], &acc);
            blocks.insert(0, ct_res);
        }
        let mut cipher = Cipher::from_blocks(blocks);
        self.key
            .extend_radix_with_trivial_zero_blocks_lsb_assign(&mut cipher, bits_to_lose >> 1);
        T::new(cipher)
    }
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_floor(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_floor(&mut self.inner),
                }
            }
            pub fn smart_ceil(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_ceil(&mut self.inner),
                }
            }
            pub fn smart_round(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_round(&mut self.inner),
                }
            }
            pub fn smart_trunc(&mut self, prec: usize, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_trunc(&mut self.inner, prec),
                }
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
