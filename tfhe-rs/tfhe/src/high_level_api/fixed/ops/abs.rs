use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::FixedServerKey;

use crate::{FheFixedI, FheFixedU};
use crate::integer::IntegerCiphertext;

impl FixedServerKey {
    pub(crate) fn smart_abs<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_abs(c)
    }

    pub(crate) fn unchecked_abs<T: FixedCiphertextInner>(&self, c: &T) -> T {
        if T::IS_SIGNED {
            let len = c.bits().blocks().len();
            let bits = self.key.cast_to_signed(c.bits().clone(), len);
            let res_bits = self.key.unchecked_abs_parallelized(&bits);
            T::new(self.key.cast_to_unsigned(res_bits, len))
        } else {
            c.clone()
        }
    }
    // There is no abs_assign in TFHE, so I also left it out
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_abs(&mut self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.smart_abs(&mut self.inner),
                }
            }
            pub fn unchecked_abs(&self, key: &FixedServerKey) -> Self {
                Self {
                    inner: key.unchecked_abs(&self.inner),
                }
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
