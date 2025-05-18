use crate::high_level_api::fixed::FixedServerKey;
use crate::high_level_api::fixed::{
    traits::{FixedFrac, FixedSize},
    FixedCiphertextInner,
};

use crate::{FheFixedI, FheFixedU};

impl FixedServerKey {
    pub(crate) fn smart_sub<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn unchecked_sub<T: FixedCiphertextInner>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub(crate) fn smart_sub_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_neg_possible(rhs.bits()).is_err() {
            self.key.full_propagate_parallelized(rhs.bits_mut());
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.key.is_sub_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut()),
                || self.key.full_propagate_parallelized(rhs.bits_mut()),
            );
        }
        self.unchecked_sub_assign(lhs, rhs);
    }

    // TODO WHY IS THERE NO unchecked_sub_assign_parallelized?????????
    pub(crate) fn unchecked_sub_assign<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &T) {
        self.key.unchecked_sub_assign(lhs.bits_mut(), rhs.bits());
    }
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically a subtraction between two ciphertexts encrypting fixed point numbers.
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
    /// let ct_res = a.smart_sub(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a - clear_b);
    /// ```
    pub fn smart_sub(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_sub(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_sub(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_sub(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_sub_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_sub_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_sub_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_sub_assign(&mut self.inner, &lhs.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically a subtraction between two ciphertexts encrypting fixed point numbers.
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
    /// let ct_res = a.smart_sub(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a - clear_b);
    /// ```
    pub fn smart_sub(&mut self, lhs: &mut Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_sub(&mut self.inner, &mut lhs.inner),
        }
    }
    pub fn unchecked_sub(&self, lhs: &Self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_sub(&self.inner, &lhs.inner),
        }
    }
    pub fn smart_sub_assign(&mut self, lhs: &mut Self, key: &FixedServerKey) {
        key.smart_sub_assign(&mut self.inner, &mut lhs.inner)
    }
    pub fn unchecked_sub_assign(&mut self, lhs: &Self, key: &FixedServerKey) {
        key.unchecked_sub_assign(&mut self.inner, &lhs.inner)
    }
}
