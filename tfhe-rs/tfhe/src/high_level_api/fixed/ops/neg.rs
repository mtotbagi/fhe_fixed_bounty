use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::FixedServerKey;

use crate::{FheFixedI, FheFixedU};

impl FixedServerKey {
    pub(crate) fn smart_neg<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.smart_neg_assign(&mut result_value);
        result_value
    }

    pub(crate) fn unchecked_neg<T: FixedCiphertextInner>(&self, c: &T) -> T {
        let mut result_value = c.clone();
        self.unchecked_neg_assign(&mut result_value);
        result_value
    }

    pub(crate) fn smart_neg_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        if self.key.is_neg_possible(c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_neg_assign(c)
    }

    pub(crate) fn unchecked_neg_assign<T: FixedCiphertextInner>(&self, c: &mut T) {
        self.key.unchecked_neg_assign(c.bits_mut())
    }
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the negation of a ciphertext encrypting a fixed point number.
    /// On overflow, the result is wrapped around.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
    /// use fixed::types::U8F8;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_neg(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_neg());
    /// ```
    pub fn smart_neg(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_neg(&mut self.inner),
        }
    }
    pub fn unchecked_neg(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_neg(&self.inner),
        }
    }
    pub fn smart_neg_assign(&mut self, key: &FixedServerKey) {
        key.smart_neg_assign(&mut self.inner)
    }
    pub fn unchecked_neg_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_neg_assign(&mut self.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the negation of a ciphertext encrypting a fixed point number.
    /// On overflow, the result is wrapped around.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
    /// use fixed::types::I8F8;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: I8F8 = I8F8::from_num(12.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_neg(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_neg());
    /// ```
    pub fn smart_neg(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_neg(&mut self.inner),
        }
    }
    pub fn unchecked_neg(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_neg(&self.inner),
        }
    }
    pub fn smart_neg_assign(&mut self, key: &FixedServerKey) {
        key.smart_neg_assign(&mut self.inner)
    }
    pub fn unchecked_neg_assign(&mut self, key: &FixedServerKey) {
        key.unchecked_neg_assign(&mut self.inner)
    }
}