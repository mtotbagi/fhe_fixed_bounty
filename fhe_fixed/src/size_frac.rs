use typenum::{Cmp, IsGreater, IsGreaterOrEqual, Same, True, Unsigned, U2, U0, UInt, B0};

mod sealed {
    use super::*;

    pub trait IsGEq<T> {}

    impl<S, T> IsGEq<T> for S 
    where 
        S: IsGreaterOrEqual<T>,
        <S as IsGreaterOrEqual<T>>::Output: Same<True> {}

    pub trait HasValidFrac<T> {}
    impl<S, F> HasValidFrac<F> for S where F: FixedFrac {}

    pub trait Even {}
    impl<U: Unsigned> Even for UInt<U, B0> {}
    impl Even for U0 {}
}

pub trait FixedFrac: Unsigned + Send + Sync {}

impl<F> FixedFrac for F where F: Unsigned + Send + Sync {}

pub trait FixedSize<Frac>: 
    Unsigned + sealed::Even + Send + Sync +

    Cmp<Frac> + IsGreaterOrEqual<Frac> + sealed::IsGEq<Frac> +
    Cmp<U2> + IsGreaterOrEqual<U2> + sealed::IsGEq<U2> +

    sealed::HasValidFrac<Frac>
{}

// Implementation for all matching types
impl<S, F> FixedSize<F> for S
where
    S: Unsigned + sealed::Even + Send + Sync + 
       Cmp<F> + IsGreaterOrEqual<F> + sealed::IsGEq<F> +
       Cmp<U2> + IsGreaterOrEqual<U2> + sealed::IsGEq<U2> +
       sealed::HasValidFrac<F>,
    F: FixedFrac,
{}