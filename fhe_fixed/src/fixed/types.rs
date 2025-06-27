use super::traits::{FixedCiphertext, FixedFrac, FixedSize};
use crate::fixed::{traits::private::BitsMutToken, Bits};
use tfhe::integer::IntegerCiphertext;
use std::marker::PhantomData;

#[derive(Clone)]
pub struct FheFixedU<Size, Frac> {
    bits: Bits,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>,
}

#[derive(Clone)]
pub struct FheFixedI<Size, Frac> {
    bits: Bits,
    phantom1: PhantomData<Size>,
    phantom2: PhantomData<Frac>,
}

impl<Size, Frac> FheFixedU<Size, Frac> {
    fn new(bits: Bits) -> Self {
        Self {
            bits,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
}

impl<Size, Frac> FixedCiphertext for FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    const IS_SIGNED: bool = false;
    const SIZE: u32 = Size::U32;
    const FRAC: u32 = Frac::U32;

    fn bits(&self) -> &Bits {
        &self.bits
    }

    fn into_bits(self) -> Bits {
        self.bits
    }
    fn size(&self) -> u32 {
        Size::U32
    }

    fn frac(&self) -> u32 {
        Frac::U32
    }

    fn new(inner: Bits) -> Self {
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

    fn bits_mut(&mut self, _: BitsMutToken) -> &mut Bits {
        &mut self.bits
    }
}

impl<Size, Frac> FheFixedI<Size, Frac> {
    fn new(bits: Bits) -> Self {
        Self {
            bits,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
}

impl<Size, Frac> FixedCiphertext for FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    const IS_SIGNED: bool = true;
    const SIZE: u32 = Size::U32;
    const FRAC: u32 = Frac::U32;

    fn bits(&self) -> &Bits {
        &self.bits
    }

    fn into_bits(self) -> Bits {
        self.bits
    }
    fn size(&self) -> u32 {
        Size::U32
    }

    fn frac(&self) -> u32 {
        Frac::U32
    }

    fn new(inner: Bits) -> Self {
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

    fn bits_mut(&mut self, _: BitsMutToken) -> &mut Bits {
        &mut self.bits
    }
}