use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};

impl FixedServerKey {
    pub(crate) fn smart_add<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_add<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_add_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_add_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_add_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut()),
                || self.key.full_propagate_parallelized(rhs.bits_mut()));
        }
        self.unchecked_add_assign(lhs, rhs);
    }

    pub(crate) fn unchecked_add_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &T) {
        self.key
            .unchecked_add_assign_parallelized(lhs.bits_mut(), rhs.bits());
    }

    pub(crate) fn smart_dbl<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.unchecked_dbl_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_dbl<T: FixedCiphertextInner>(&self, c: &T) -> T {
        let result_bits: Cipher = self.key.unchecked_add_parallelized(c.bits(), c.bits());
        T::new(result_bits)
    }

    pub(crate) fn smart_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        if self.key.is_add_possible(c.bits(), c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_dbl_assign(c)
    }

    pub(crate) fn unchecked_dbl_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        *c.bits_mut() = self.key.unchecked_add_parallelized(c.bits(), c.bits());
    }
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically an addition between two ciphertexts encrypting fixed point numbers.
    /// On overflow, the result is wrapped around.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::FheU8F8;
    /// use fixed::types::U8F8;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    /// let clear_b: U8F8 = U8F8::from_num(1.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// let mut b = FheU8F8::encrypt(clear_b, &ckey);
    /// 
    /// // Compute homomorphically an addition:
    /// let ct_res = a.smart_add(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a + clear_b);
    /// ```
    pub fn smart_add(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_add(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_add(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_add(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_add_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_add_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_add_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_add_assign(&mut self.inner, &lhs.inner)
    }

    pub fn smart_dbl(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_dbl(&mut self.inner),
        }
    }
    pub fn unchecked_dbl(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_dbl(&self.inner),
        }
    }
    pub fn smart_dbl_assign(&mut self, key: &FixedServerKey) {
        key.smart_dbl_assign(&mut self.inner)
    }
    pub fn unchecked_dbl_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_dbl_assign(&mut self.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically an addition between two ciphertexts encrypting fixed point numbers.
    /// On overflow, the result is wrapped around.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::FheI8F8;
    /// use fixed::types::I8F8;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: I8F8 = I8F8::from_num(12.8);
    /// let clear_b: I8F8 = I8F8::from_num(1.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// let mut b = FheI8F8::encrypt(clear_b, &ckey);
    /// 
    /// // Compute homomorphically an addition:
    /// let ct_res = a.smart_add(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a + clear_b);
    /// ```
    pub fn smart_add(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_add(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_add(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_add(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_add_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_add_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_add_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_add_assign(&mut self.inner, &lhs.inner)
    }

    pub fn smart_dbl(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_dbl(&mut self.inner),
        }
    }
    pub fn unchecked_dbl(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_dbl(&self.inner),
        }
    }
    pub fn smart_dbl_assign(&mut self, key: &FixedServerKey) {
        key.smart_dbl_assign(&mut self.inner)
    }
    pub fn unchecked_dbl_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_dbl_assign(&mut self.inner)
    }
}