use crate::{propagate_if_needed_parallelized, size_frac::{FixedFrac, FixedSize}, Cipher, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};

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

    pub(crate) fn smart_sub_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_sub_possible(lhs.inner(), rhs.inner()).is_err() {
            propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);
        }
        self.unchecked_sub_assign(lhs, rhs);
    }

    // TODO WHY IS THERE NO unchecked_sub_assign_parallelized?????????
    pub(crate) fn unchecked_sub_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) {
        self.key.unchecked_sub_assign(lhs.inner_mut(), rhs.inner());
    }
}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    pub fn smart_sub(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_sub(&mut self.inner, &mut lhs.inner) }
    }
    pub fn unchecked_sub(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_sub(&self.inner, &lhs.inner) }
    }
    pub fn smart_sub_assign(&mut self, lhs: &mut Self, key: &FixedServerKey){
        key.smart_sub_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_sub_assign(&mut self, lhs: &Self, key: &FixedServerKey){
        key.unchecked_sub_assign(&mut self.inner, &lhs.inner)
    }
}