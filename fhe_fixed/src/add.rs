use crate::{fhefixed::FheFixedU, propagate_if_needed_parallelized, size_frac::{FixedFrac, FixedSize}, Cipher, FixedCiphertextInner, FixedServerKey};


impl FixedServerKey {
    pub(crate) fn smart_add<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_add<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value = lhs.clone();
        self.unchecked_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_dbl<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.unchecked_dbl_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_dbl<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let result_inner: Cipher = self.key.unchecked_add_parallelized(c.inner(), c.inner());
        T::new(result_inner)
    }

    pub(crate) fn smart_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        if self.key.is_add_possible(c.inner(), c.inner()).is_err() {
            self.key.full_propagate_parallelized(c.inner_mut());
        }
        self.unchecked_dbl_assign(c)
    }

    pub(crate) fn unchecked_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        *c.inner_mut() = self.key.unchecked_add_parallelized(c.inner(), c.inner());
    }

    pub(crate) fn smart_add_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_add_possible(lhs.inner(), rhs.inner()).is_err() {
            propagate_if_needed_parallelized(&mut[lhs.inner_mut(), rhs.inner_mut()], &self.key);
        }
        self.unchecked_add_assign(lhs, rhs);
    }

    pub(crate) fn unchecked_add_assign<T: FixedCiphertextInner> (&self, lhs: &mut T, rhs: &T) {
        self.key.unchecked_add_assign_parallelized(lhs.inner_mut(), rhs.inner());
    }
}

/*impl<Size, Frac> FheFixedU<Size, Frac> where 
Size: FixedSize<Frac>,
Frac: FixedFrac {
    pub fn unchecked_add_assign(&mut self, lhs: &mut Self, key: FixedServerKey) -> Self {

    }
}*/