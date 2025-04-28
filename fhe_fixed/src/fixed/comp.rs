use tfhe::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};

use crate::fixed::{FheFixedU, FixedCiphertextInner};
use crate::{
    FixedServerKey,
    traits::{FixedFrac, FixedSize},
};

use super::propagate_if_needed_parallelized;
use super::types::FheFixedI;

impl FixedServerKey {
    fn smart_eq<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_eq(lhs, rhs)
    }
    fn smart_ne<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_ne(lhs, rhs)
    }
    fn smart_lt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_lt(lhs, rhs)
    }
    fn smart_le<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_le(lhs, rhs)
    }
    fn smart_gt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_gt(lhs, rhs)
    }
    fn smart_ge<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_ge(lhs, rhs)
    }

    fn unchecked_eq<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key
        .unchecked_eq_parallelized(lhs.bits(),  rhs.bits())
    }
    fn unchecked_ne<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key
            .unchecked_ne_parallelized(lhs.bits(),  rhs.bits())
    }
    fn unchecked_lt<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_lt_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_lt_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_le<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_le_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_le_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_gt<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_gt_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_gt_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_ge<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_ge_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_ge_parallelized(lhs.bits(),  rhs.bits())
        }
    }
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
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

            fn unchecked_eq(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_eq(&self.inner, &rhs.inner)
            }
            fn unchecked_ne(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_ne(&self.inner, &rhs.inner)
            }
            fn unchecked_lt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_lt(&self.inner, &rhs.inner)
            }
            fn unchecked_le(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_le(&self.inner, &rhs.inner)
            }
            fn unchecked_gt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_gt(&self.inner, &rhs.inner)
            }
            fn unchecked_ge(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
                key.unchecked_ge(&self.inner, &rhs.inner)
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
