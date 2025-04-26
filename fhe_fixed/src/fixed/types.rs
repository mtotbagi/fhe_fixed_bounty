use std::marker::PhantomData;
use tfhe::integer::IntegerCiphertext;
use super::{traits::{FixedFrac, FixedSize, FixedCiphertext, FixedCiphertextInner}, ArbFixedU};

pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;



#[derive(Clone)]
pub(crate) struct InnerFheFixedU<Size, Frac> {
    bits: Cipher,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>
}

impl<Size, Frac> InnerFheFixedU<Size, Frac> {
    fn new(bits: Cipher) -> InnerFheFixedU<Size, Frac> {
        InnerFheFixedU { bits, phantom1: PhantomData, phantom2: PhantomData }
    }
}

impl<Size, Frac> FixedCiphertext for InnerFheFixedU<Size, Frac> where
Size: FixedSize<Frac>,
Frac: FixedFrac {
    const IS_SIGNED: bool = false;
    const SIZE: u32 = Size::U32;
    const FRAC: u32 = Frac::U32;

    fn bits(&self) -> &Cipher {
        &self.bits
    }

    fn into_bits(self) -> Cipher {
        self.bits
    }
    fn size(&self) -> u32 {
        Size::U32
    }

    fn frac(&self) -> u32 {
        Frac::U32
    }

    fn new(inner: Cipher) -> Self {
        Self::new(inner)
    }

    fn bits_in_block(&self) -> u32 {
        let modulus = self.bits.blocks()[0].message_modulus.0;
        let log2 = modulus.ilog2();
        if 2u64.pow(log2) == modulus {
            log2
        } else {
            log2 + 1
        }
    }
}

impl<Size, Frac> FixedCiphertextInner for InnerFheFixedU<Size, Frac> where
Size: FixedSize<Frac>,
Frac: FixedFrac {
    fn bits_mut(&mut self) -> &mut Cipher {
        &mut self.bits
    }
}

#[derive(Clone)]
pub struct FheFixedU<Size, Frac> {
    pub(crate) inner: InnerFheFixedU<Size, Frac>
}
impl<Size, Frac> FheFixedU<Size, Frac> {
    pub fn new(bits: Cipher) -> FheFixedU<Size, Frac> {
        FheFixedU { inner: InnerFheFixedU::new(bits) }
    }
}
impl<Size, Frac> FixedCiphertext for FheFixedU<Size, Frac> where
Size: FixedSize<Frac>,
Frac: FixedFrac {
    const IS_SIGNED: bool = false;
    const SIZE: u32 = Size::U32;
    const FRAC: u32 = Frac::U32;

    fn bits(&self) -> &Cipher {
        self.inner.bits()
    }

    fn into_bits(self) -> Cipher {
        self.inner.into_bits()
    }

    fn size(&self) -> u32 {
        Self::SIZE
    }

    fn frac(&self) -> u32 {
        Frac::U32
    }

    fn new(inner: Cipher) -> Self {
        Self::new(inner)
    }

    fn bits_in_block(&self) -> u32 {
        self.inner.bits_in_block()
    }
}