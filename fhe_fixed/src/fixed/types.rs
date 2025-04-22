use std::marker::PhantomData;
use tfhe::integer::IntegerCiphertext;
use super::{size_frac::{FixedFrac, FixedSize}, ArbFixedU};

pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

pub trait FixedCiphertext: Clone + Sync + Send{
    const IS_SIGNED: bool;
    const SIZE: u32;
    const FRAC: u32;
    fn inner(&self) -> &Cipher;
    fn into_inner(self) -> Cipher;
    fn size(&self) -> u32;
    fn frac(&self) -> u32;
    fn new(inner: Cipher) -> Self;
    fn bits_in_block(&self) -> u32;
}

pub trait FixedCiphertextInner: FixedCiphertext + Clone + Sync + Send{
    type ClearType;
    fn inner_mut(&mut self) -> &mut Cipher;
}

#[derive(Clone)]
pub(crate) struct InnerFheFixedU<Size, Frac> {
    inner: Cipher,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>
}

impl<Size, Frac> InnerFheFixedU<Size, Frac> {
    pub fn new(inner: Cipher) -> InnerFheFixedU<Size, Frac> {
        InnerFheFixedU { inner, phantom1: PhantomData, phantom2: PhantomData }
    }
}

impl<Size, Frac> FixedCiphertext for InnerFheFixedU<Size, Frac> where
Size: FixedSize<Frac>,
Frac: FixedFrac {
    const IS_SIGNED: bool = false;
    const SIZE: u32 = Size::U32;
    const FRAC: u32 = Frac::U32;

    fn inner(&self) -> &Cipher {
        &self.inner
    }

    fn into_inner(self) -> Cipher {
        self.inner
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
        let modulus = self.inner.blocks()[0].message_modulus.0;
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
    type ClearType = ArbFixedU<Size, Frac>;
    fn inner_mut(&mut self) -> &mut Cipher {
        &mut self.inner
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

    fn inner(&self) -> &Cipher {
        &self.inner.inner()
    }

    fn into_inner(self) -> Cipher {
        self.inner.into_inner()
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
        self.inner.bits_in_block()
    }
}