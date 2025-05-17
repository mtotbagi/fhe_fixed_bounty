use crate::fixed::{FheFixedU, FixedCiphertextInner};
use crate::{
    Cipher, FixedServerKey, propagate_if_needed_parallelized,
    traits::{FixedFrac, FixedSize},
};

use crate::FheFixedI;

impl FixedServerKey {
    pub(crate) fn smart_add<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_add<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_add_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_add_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut()),
                || self.key.full_propagate_parallelized(rhs.bits_mut()));
        }
        self.unchecked_add_assign(lhs, rhs);
    }

    pub(crate) fn unchecked_add_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &T) {
        self.key
            .unchecked_add_assign_parallelized(lhs.bits_mut(), rhs.bits());
    }

    pub(crate) fn smart_dbl<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.smart_dbl_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_dbl<T: FixedCiphertextInner>(&self, c: &T) -> T {
        let result_bits: Cipher = self.key.unchecked_add_parallelized(c.bits(), c.bits());
        T::new(result_bits)
    }

    pub(crate) fn smart_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        if self.key.is_add_possible(c.bits(), c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_dbl_assign(c)
    }

    pub(crate) fn unchecked_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        *c.bits_mut() = self.key.unchecked_add_parallelized(c.bits(), c.bits());
    }
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_add(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_add(&mut self.inner, &mut lhs.inner),
                }
            }
            pub fn unchecked_add(&self, lhs: &Self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_add(&self.inner, &lhs.inner),
                }
            }
            pub fn smart_add_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
                key.smart_add_assign(&mut self.inner, &mut lhs.inner)
            }
            pub fn unchecked_add_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
                key.unchecked_add_assign(&mut self.inner, &lhs.inner)
            }

            pub fn smart_dbl(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_dbl(&mut self.inner),
                }
            }
            pub fn unchecked_dbl(&self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_dbl(&self.inner),
                }
            }
            pub fn smart_dbl_assign(&mut self, key: &FixedServerKey) {
                key.smart_dbl_assign(&mut self.inner)
            }
            pub fn unchecked_dbl_assign(&mut self, key: &FixedServerKey) {
                key.unchecked_dbl_assign(&mut self.inner)
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
