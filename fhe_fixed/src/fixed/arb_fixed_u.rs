#![allow(unused_imports)]

use std::fmt::{Binary, Debug, Display, Formatter, Result};
use std::marker::PhantomData;

use crate::traits::{FixedFrac, FixedSize};
use fixed_crate::FixedU128;
use fixed_crate::traits::ToFixed;
use fixed_crate::types::extra::LeEqU128;
use typenum::Unsigned;

#[derive(Clone)]
/// Fixed point unsigned, of arbitrary length.
///
/// The first `Frac` bits in the u64s will be the fractional bits.
pub struct ArbFixedU<Size, Frac> {
    // Maybe this should be called bits instead?
    pub(crate) parts: Vec<u64>,
    pub(crate) phantom1: PhantomData<Frac>,
    pub(crate) phantom2: PhantomData<Size>,
}

impl<Size, Frac> ArbFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    // Does not check whether bits length is appropriate
    // If you want that use from_bits instead
    pub(crate) fn new(bits: Vec<u64>) -> Self {
        Self {
            parts: bits,
            phantom1: PhantomData,
            phantom2: PhantomData,
        }
    }
    pub fn from_bits(mut bits: Vec<u64>) -> Self {
        let mut len: usize = Size::USIZE / 64;
        if Size::USIZE % 64 != 0 {
            len += 1;
        }
        bits.resize(len, 0);
        if Size::USIZE % 64 != 0 {
            bits[len - 1] %= 1 << (Size::USIZE % 64);
        }
        Self::new(bits)
    }
}

impl<Size, Frac> PartialEq for ArbFixedU<Size, Frac> {
    fn eq(&self, rhs: &ArbFixedU<Size, Frac>) -> bool {
        // As parts.len() should always be Size / 64, this should never fail
        assert!(self.parts.len() == rhs.parts.len());

        self.parts == rhs.parts
    }
}

impl<Size, Frac> Eq for ArbFixedU<Size, Frac> {}

/* This converts back an ArbFixedU to a FixedU128, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU128<Frac>
where
    Size: LeEqU128,
{
    fn from(arb: ArbFixedU<Size, Frac>) -> Self {
        let mut res = 0u128;
        for part in arb.parts.iter().rev() {
            res = res << 64;
            res += *part as u128;
        }
        FixedU128::<Frac>::from_bits(res)
    }
}

impl<Size: Unsigned, Frac: Unsigned> From<&ArbFixedU<Size, Frac>> for FixedU128<Frac>
where
    Size: LeEqU128,
{
    fn from(arb: &ArbFixedU<Size, Frac>) -> Self {
        let mut res = 0u128;
        for part in arb.parts.iter().rev() {
            res = res << 64;
            res += *part as u128;
        }
        FixedU128::<Frac>::from_bits(res)
    }
}
/* This now works for any type which implements ToFixed
(Which is basically every builtin numeric type, and every fixed type) */
impl<T, Size: Unsigned, Frac: Unsigned> From<T> for ArbFixedU<Size, Frac>
where
    T: ToFixed,
    Size: FixedSize<Frac> + LeEqU128,
    Frac: FixedFrac + LeEqU128,
{
    fn from(f: T) -> Self {
        // get the bits we need
        let fixed_bits: u128 = FixedU128::<Frac>::from_num(f).to_bits();
        // split it into the two sections
        let lower_bits = fixed_bits as u64;
        let upper_bits = (fixed_bits >> 64) as u64;

        // If fits inside a single u64, keep only that
        let parts = if Size::USIZE <= 64 {
            vec![lower_bits]
        } else {
            vec![lower_bits, upper_bits]
        };
        Self::new(parts)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Debug for ArbFixedU<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "ArbFixedU<Size={}, Frac={}> {:?}",
            Size::U32,
            Frac::U32,
            self.parts
        )
    }
}

impl<Size: Unsigned, Frac: Unsigned> Display for ArbFixedU<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedU128::<Frac>::from(self);
        std::fmt::Display::fmt(&fixed, f)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Binary for ArbFixedU<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedU128::<Frac>::from(self);
        std::fmt::Binary::fmt(&fixed, f)
    }
}
