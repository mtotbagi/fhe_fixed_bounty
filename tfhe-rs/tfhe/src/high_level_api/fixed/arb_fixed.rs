#![allow(unused_imports)]

use std::fmt::{Binary, Debug, Display, Formatter, Result};
use std::marker::PhantomData;

use super::traits::{FixedFrac, FixedSize};
use fixed::traits::{Fixed, FromFixed, ToFixed};
use fixed::types::extra::{LeEqU128, LeEqU16, LeEqU32, LeEqU64, LeEqU8};
use fixed::{
    FixedI128, FixedI16, FixedI32, FixedI64, FixedI8, FixedU128, FixedU16, FixedU32, FixedU64,
    FixedU8,
};
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
    pub(crate) fn from_bits(mut bits: Vec<u64>) -> Self {
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

/* This converts back an ArbFixedU to a FixedU64, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU64<Frac>
where
    Size: LeEqU64,
{
    fn from(arb: ArbFixedU<Size, Frac>) -> Self {
        FixedU64::<Frac>::from_bits(arb.parts[0] as u64)
    }
}

/* This converts back an ArbFixedU to a FixedU32, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU32<Frac>
where
    Size: LeEqU32,
{
    fn from(arb: ArbFixedU<Size, Frac>) -> Self {
        FixedU32::<Frac>::from_bits(arb.parts[0] as u32)
    }
}

/* This converts back an ArbFixedU to a FixedU16, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU16<Frac>
where
    Size: LeEqU16,
{
    fn from(arb: ArbFixedU<Size, Frac>) -> Self {
        FixedU16::<Frac>::from_bits(arb.parts[0] as u16)
    }
}

/* This converts back an ArbFixedU to a FixedU8, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU8<Frac>
where
    Size: LeEqU8,
{
    fn from(arb: ArbFixedU<Size, Frac>) -> Self {
        FixedU8::<Frac>::from_bits(arb.parts[0] as u8)
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
        let fixed_bits: u128 = FixedU128::<Frac>::wrapping_from_num(f).to_bits();
        // split it into the two sections
        let lower_bits = fixed_bits as u64;
        let upper_bits = (fixed_bits >> 64) as u64;

        // If fits inside a single u64, keep only that
        let parts = if Size::USIZE <= 64 {
            vec![lower_bits]
        } else {
            vec![lower_bits, upper_bits]
        };
        Self::from_bits(parts)
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

#[derive(Clone)]
/// Fixed point unsigned, of arbitrary length.
///
/// The first `Frac` bits in the u64s will be the fractional bits.
/// The `Size`th bit is the sign
pub struct ArbFixedI<Size, Frac> {
    // Maybe this should be called bits instead?
    pub(crate) parts: Vec<u64>,
    pub(crate) phantom1: PhantomData<Frac>,
    pub(crate) phantom2: PhantomData<Size>,
}

impl<Size, Frac> ArbFixedI<Size, Frac>
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
    pub(crate) fn from_bits(mut bits: Vec<u64>) -> Self {
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

impl<Size, Frac> PartialEq for ArbFixedI<Size, Frac> {
    fn eq(&self, rhs: &Self) -> bool {
        // As parts.len() should always be Size / 64, this should never fail
        assert!(self.parts.len() == rhs.parts.len());

        self.parts == rhs.parts
    }
}

impl<Size, Frac> Eq for ArbFixedI<Size, Frac> {}

/* This converts back an ArbFixedI to a FixedI128, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedI<Size, Frac>> for FixedI128<Frac>
where
    Size: LeEqU128,
{
    fn from(arb: ArbFixedI<Size, Frac>) -> Self {
        let mut res = 0u128;
        for part in arb.parts.iter().rev() {
            res = res << 64;
            res += *part as u128;
        }
        FixedI128::<Frac>::from_bits(res as i128)
    }
}

/* This converts back an ArbFixedI to a FixedI128, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<&ArbFixedI<Size, Frac>> for FixedI128<Frac>
where
    Size: LeEqU128,
{
    fn from(arb: &ArbFixedI<Size, Frac>) -> Self {
        let mut res = 0u128;
        for part in arb.parts.iter().rev() {
            res = res << 64;
            res += *part as u128;
        }
        FixedI128::<Frac>::from_bits(res as i128)
    }
}

/* This converts back an ArbFixedI to a FixedI64, if Size <= 64 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedI<Size, Frac>> for FixedI64<Frac>
where
    Size: LeEqU64,
{
    fn from(arb: ArbFixedI<Size, Frac>) -> Self {
        FixedI64::<Frac>::from_bits(arb.parts[0] as i64)
    }
}

/* This converts back an ArbFixedI to a FixedI32, if Size <= 32 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedI<Size, Frac>> for FixedI32<Frac>
where
    Size: LeEqU32,
{
    fn from(arb: ArbFixedI<Size, Frac>) -> Self {
        FixedI32::<Frac>::from_bits(arb.parts[0] as i32)
    }
}

/* This converts back an ArbFixedI to a FixedI16, if Size <= 16 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedI<Size, Frac>> for FixedI16<Frac>
where
    Size: LeEqU16,
{
    fn from(arb: ArbFixedI<Size, Frac>) -> Self {
        FixedI16::<Frac>::from_bits(arb.parts[0] as i16)
    }
}

/* This converts back an ArbFixedI to a FixedI8, if Size <= 8 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedI<Size, Frac>> for FixedI8<Frac>
where
    Size: LeEqU8,
{
    fn from(arb: ArbFixedI<Size, Frac>) -> Self {
        FixedI8::<Frac>::from_bits(arb.parts[0] as i8)
    }
}

/* This now works for any type which implements ToFixed
(Which is basically every builtin numeric type, and every fixed type) */
impl<T, Size: Unsigned, Frac: Unsigned> From<T> for ArbFixedI<Size, Frac>
where
    T: ToFixed,
    Size: FixedSize<Frac> + LeEqU128,
    Frac: FixedFrac + LeEqU128,
{
    fn from(f: T) -> Self {
        // get the bits we need
        let fixed_bits: u128 = FixedI128::<Frac>::wrapping_from_num(f).to_bits() as u128;

        // split it into the two sections
        let lower_bits = fixed_bits as u64;
        let upper_bits = (fixed_bits >> 64) as u64;

        // If fits inside a single u64, keep only that
        let parts = if Size::USIZE <= 64 {
            vec![lower_bits]
        } else {
            vec![lower_bits, upper_bits]
        };
        Self::from_bits(parts)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Debug for ArbFixedI<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "ArbFixedI<Size={}, Frac={}> {:?}",
            Size::U32,
            Frac::U32,
            self.parts
        )
    }
}

impl<Size: Unsigned, Frac: Unsigned> Display for ArbFixedI<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedI128::<Frac>::from(self);
        std::fmt::Display::fmt(&fixed, f)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Binary for ArbFixedI<Size, Frac>
where
    Frac: LeEqU128,
    Size: LeEqU128,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedI128::<Frac>::from(self);
        std::fmt::Binary::fmt(&fixed, f)
    }
}
