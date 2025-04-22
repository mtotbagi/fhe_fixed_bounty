use crate::{size_frac::{FixedFrac, FixedSize}, Cipher, FixedServerKey};
use crate::fixed::{FheFixedU, FixedCiphertextInner};
use tfhe::{integer::{ciphertext::BaseSignedRadixCiphertext, IntegerCiphertext}, shortint::Ciphertext};

impl FixedServerKey {
    
    pub(crate) fn smart_ilog2<T: FixedCiphertextInner>(&self, c: &mut T) -> BaseSignedRadixCiphertext<Ciphertext> {
        if !c.inner().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        self.unchecked_ilog2(c)
    }

    pub(crate) fn unchecked_ilog2<T: FixedCiphertextInner>(&self, c: &T) -> BaseSignedRadixCiphertext<Ciphertext> {
        let tmp: Cipher = self.key.unchecked_ilog2_parallelized(c.inner());
        let len = tmp.blocks().len();
        let mut inner = self.key.cast_to_signed(tmp, len);
        self.key.smart_scalar_sub_assign_parallelized(&mut inner, c.frac());
        inner
    }
}

impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    pub fn smart_ilog2(&mut self, key: &FixedServerKey) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.smart_ilog2(&mut self.inner)
    }
    pub fn unchecked_ilog2(&self, key: &FixedServerKey) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.unchecked_ilog2(&self.inner)
    }
}