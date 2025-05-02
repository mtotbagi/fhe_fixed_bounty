use crate::fixed::{FheFixedU, FixedCiphertextInner};
use crate::{
    FixedServerKey,
    traits::{FixedFrac, FixedSize},
};

use crate::FheFixedI;

impl FixedServerKey {
    pub(crate) fn smart_neg<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.smart_neg_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_neg<T: FixedCiphertextInner>(&self, c: &T) -> T {
        let mut result_value = c.clone();
        self.unchecked_neg_assign(&mut result_value);
        result_value
    }

    pub(crate) fn smart_neg_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        if self.key.is_neg_possible(c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_neg_assign(c)
    }

    pub(crate) fn unchecked_neg_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        self.key.unchecked_neg_assign(c.bits_mut())
    }
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_neg(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_neg(&mut self.inner),
                }
            }
            pub fn unchecked_neg(&self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_neg(&self.inner),
                }
            }
            pub fn smart_neg_assign(&mut self, key: &FixedServerKey) {
                key.smart_neg_assign(&mut self.inner)
            }
            pub fn unchecked_neg_assign(&mut self, key: &FixedServerKey) {
                key.unchecked_neg_assign(&mut self.inner)
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
