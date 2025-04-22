use crate::{propagate_if_needed_parallelized, size_frac::{FixedFrac, FixedSize}, Cipher, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};
use tfhe::{integer::{ciphertext::BaseSignedRadixCiphertext, IntegerCiphertext, IntegerRadixCiphertext}, shortint::Ciphertext};

impl FixedServerKey {
    pub(crate) fn smart_abs<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        self.unchecked_abs(c)
    }

    pub(crate) fn unchecked_abs<T: FixedCiphertextInner>(&self, c: &T) -> T {
        if T::IS_SIGNED {
            let len = c.inner().blocks().len();
            let inner = self.key.cast_to_signed(c.inner().clone(), len);
            let res_inner = self.key.unchecked_abs_parallelized(&inner);
            T::new(self.key.cast_to_unsigned(res_inner, len))
        } else {
            c.clone()
        }
    }
    // There is no abs_assign in TFHE, so I also left it out
}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    pub fn smart_abs(&mut self, key: &FixedServerKey) -> Self{
        Self {inner: key.smart_abs(&mut self.inner) }
    }
    pub fn unchecked_abs(&self, key: &FixedServerKey) -> Self {
        Self {inner: key.unchecked_abs(&self.inner) }
    }
}