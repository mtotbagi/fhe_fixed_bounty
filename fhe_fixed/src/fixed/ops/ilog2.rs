use crate::fixed::{FheFixedU, FixedCiphertextInner};
use crate::{
    Cipher, FixedServerKey,
    traits::{FixedFrac, FixedSize},
};
use tfhe::{
    integer::{IntegerCiphertext, ciphertext::BaseSignedRadixCiphertext},
    shortint::Ciphertext,
};

use crate::FheFixedI;

impl FixedServerKey {
    pub(crate) fn smart_ilog2<T: FixedCiphertextInner>(
        &self,
        c: &mut T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_ilog2(c)
    }

    pub(crate) fn unchecked_ilog2<T: FixedCiphertextInner>(
        &self,
        c: &T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        let tmp: Cipher = self.key.unchecked_ilog2_parallelized(c.bits());
        let len = tmp.blocks().len();
        let mut bits = self.key.cast_to_signed(tmp, len);
        self.key
            .smart_scalar_sub_assign_parallelized(&mut bits, c.frac());
        bits
    }
}

macro_rules! fhe_fixed_op {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: FixedSize<Frac>,
            Frac: FixedFrac,
        {
            pub fn smart_ilog2(
                &mut self,
                key: &FixedServerKey,
            ) -> BaseSignedRadixCiphertext<Ciphertext> {
                key.smart_ilog2(&mut self.inner)
            }
            pub fn unchecked_ilog2(
                &self,
                key: &FixedServerKey,
            ) -> BaseSignedRadixCiphertext<Ciphertext> {
                key.unchecked_ilog2(&self.inner)
            }
        }
    };
}

fhe_fixed_op!(FheFixedU);
fhe_fixed_op!(FheFixedI);
