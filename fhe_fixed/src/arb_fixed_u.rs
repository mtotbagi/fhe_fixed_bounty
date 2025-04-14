#![allow(unused_imports)]

use std::fmt::{Binary, Display, Formatter, Result};
use std::{marker::PhantomData, ops::Add};

use fixed::traits::FixedUnsigned;
use fixed::types::extra::LeEqU128;
use fixed::types::U10F6;
use fixed::FixedU128;
use crate::fhefixed::Even;
use tfhe::integer::block_decomposition::{Decomposable, DecomposableInto};
use typenum::{Bit, Cmp, Diff, IsGreater, PowerOfTwo, Same, True, UInt, Unsigned, U10, U1000, U16, U6, U8, U2,U0, IsGreaterOrEqual};
use fixed::{traits::ToFixed, types::U8F8};

#[derive(Debug, Clone)]
/// Fixed point unsigned, of arbitrary length.
/// 
/// The first `Frac` bits in the u64s will be the fractional bits.
pub struct ArbFixedU<Size, Frac> {
    // Maybe this should be called bits instead?
    pub(crate) parts: Vec<u64>,
    pub(crate) phantom1: PhantomData<Frac>,
    pub(crate) phantom2: PhantomData<Size>
}

impl<Size, Frac> ArbFixedU<Size, Frac> where
Size: Unsigned +
      Cmp<Frac> +
      typenum::private::IsGreaterOrEqualPrivate<Frac, <Size as typenum::Cmp<Frac>>::Output> +
      Even + Cmp<U2> +
      typenum::private::IsGreaterOrEqualPrivate<U2, <Size as typenum::Cmp<U2>>::Output>,
Frac: Unsigned,
<Size as IsGreaterOrEqual<Frac>>::Output: Same<True>,
<Size as IsGreaterOrEqual<U2>>::Output: Same<True>
{
    // Does not check whether bits length is appropriate
    // If you want that use from_bits instead
    pub(crate) fn new(bits: Vec<u64>) -> Self {
        Self { parts: bits, phantom1: PhantomData, phantom2: PhantomData }
    }
    pub fn from_bits(mut bits: Vec<u64>) -> Self {
        let mut len: usize = Size::USIZE / 64;
        if Size::USIZE % 64 != 0 { len += 1; }
        bits.resize(len, 0);
        if Size::USIZE % 64 != 0 { bits[len-1] %= 1 << (Size::USIZE % 64); }
        Self::new(bits)
    }
}

/* This converts back an ArbFixedU to a FixedU128, if Size <= 128 */
impl<Size: Unsigned, Frac: Unsigned> From<ArbFixedU<Size, Frac>> for FixedU128<Frac>
where Size: LeEqU128
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
where Size: LeEqU128
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
impl<T, Size: Unsigned, Frac: Unsigned> From<T> for ArbFixedU<Size, Frac> where
T: ToFixed,
Size: Unsigned +
      Cmp<Frac> +
      typenum::private::IsGreaterOrEqualPrivate<Frac, <Size as typenum::Cmp<Frac>>::Output> +
      Even + Cmp<U2> +
      typenum::private::IsGreaterOrEqualPrivate<U2, <Size as typenum::Cmp<U2>>::Output>,
Frac: Unsigned + LeEqU128,
<Size as IsGreaterOrEqual<Frac>>::Output: Same<True>,
<Size as IsGreaterOrEqual<U2>>::Output: Same<True>,
{
    fn from(f: T) -> Self {
        // get the bits we need
        let fixed_bits: u128 = FixedU128::<Frac>::from_num(f).to_bits();
        // split it into the two sections
        let lower_bits = fixed_bits as u64;
        let upper_bits = (fixed_bits >> 64) as u64;

        // If fits inside a single u64, keep only that
        let parts =    
            if Size::USIZE <= 64 {vec![lower_bits]}
            else {vec![lower_bits, upper_bits]};
        Self::new(parts)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Display for ArbFixedU<Size, Frac>
where 
Frac: LeEqU128,
Size: LeEqU128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedU128::<Frac>::from(self);
        std::fmt::Display::fmt(&fixed, f)
    }
}

impl<Size: Unsigned, Frac: Unsigned> Binary for ArbFixedU<Size, Frac>
where 
Frac: LeEqU128,
Size: LeEqU128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let fixed = FixedU128::<Frac>::from(self);
        std::fmt::Binary::fmt(&fixed, f)
    }
}