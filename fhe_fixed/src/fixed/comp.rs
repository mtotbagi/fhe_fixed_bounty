use tfhe::integer::BooleanBlock;

use crate::{traits::{FixedFrac, FixedSize}, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};

impl FixedServerKey {

    fn smart_eq<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_eq_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }
    fn smart_ne<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_ne_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }
    fn smart_lt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_lt_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }
    fn smart_le<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_le_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }
    fn smart_gt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_gt_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }
    fn smart_ge<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.smart_ge_parallelized(lhs.bits_mut(), &mut rhs.bits_mut())
    }

    fn unchecked_eq<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_eq_parallelized(lhs.bits(), &mut rhs.bits())
    }
    fn unchecked_ne<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_ne_parallelized(lhs.bits(), &mut rhs.bits())
    }
    fn unchecked_lt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_lt_parallelized(lhs.bits(), &mut rhs.bits())
    }
    fn unchecked_le<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_le_parallelized(lhs.bits(), &mut rhs.bits())
    }
    fn unchecked_gt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_gt_parallelized(lhs.bits(), &mut rhs.bits())
    }
    fn unchecked_ge<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        self.key.unchecked_ge_parallelized(lhs.bits(), &mut rhs.bits())
    }
}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    fn smart_eq(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_eq(&mut self.inner, &mut rhs.inner)
    }
    fn smart_ne(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ne(&mut self.inner, &mut rhs.inner)
    }
    fn smart_lt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_lt(&mut self.inner, &mut rhs.inner)
    }
    fn smart_le(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_le(&mut self.inner, &mut rhs.inner)
    }
    fn smart_gt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_gt(&mut self.inner, &mut rhs.inner)
    }
    fn smart_ge(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ge(&mut self.inner, &mut rhs.inner)
    }

    fn unchecked_eq(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_eq(&mut self.inner, &mut rhs.inner)
    }
    fn unchecked_ne(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ne(&mut self.inner, &mut rhs.inner)
    }
    fn unchecked_lt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_lt(&mut self.inner, &mut rhs.inner)
    }
    fn unchecked_le(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_le(&mut self.inner, &mut rhs.inner)
    }
    fn unchecked_gt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_gt(&mut self.inner, &mut rhs.inner)
    }
    fn unchecked_ge(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ge(&mut self.inner, &mut rhs.inner)
    }
}