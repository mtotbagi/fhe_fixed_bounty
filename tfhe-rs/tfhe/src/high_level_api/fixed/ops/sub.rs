use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::FixedServerKey;

use crate::{FheFixedI, FheFixedU};

impl FixedServerKey {
    pub(crate) fn smart_sub<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_sub<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_sub_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_neg_possible(rhs.bits()).is_err() {
            self.key.full_propagate_parallelized(rhs.bits_mut());
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.key.is_sub_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut()),
                || self.key.full_propagate_parallelized(rhs.bits_mut()));
        }
        self.unchecked_sub_assign(lhs, rhs);
    }

    // TODO WHY IS THERE NO unchecked_sub_assign_parallelized?????????
    pub(crate) fn unchecked_sub_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &T) {
        self.key.unchecked_sub_assign(lhs.bits_mut(), rhs.bits());
    }
}


impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    pub fn smart_sub(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_sub(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_sub(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_sub(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_sub_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_sub_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_sub_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_sub_assign(&mut self.inner, &lhs.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    pub fn smart_sub(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_sub(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_sub(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_sub(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_sub_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_sub_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_sub_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_sub_assign(&mut self.inner, &lhs.inner)
    }
}
