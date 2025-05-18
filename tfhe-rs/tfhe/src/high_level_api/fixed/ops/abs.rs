use crate::high_level_api::fixed::{
    traits::{FixedFrac, FixedSize},
    FixedCiphertextInner,
};
use crate::FixedServerKey;

use crate::integer::IntegerCiphertext;
use crate::{FheFixedI, FheFixedU};

impl FixedServerKey {
    pub(crate) fn smart_abs<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_abs(c)
    }

    pub(crate) fn unchecked_abs<T: FixedCiphertextInner>(&self, c: &T) -> T {
        if T::IS_SIGNED {
            let len = c.bits().blocks().len();
            let bits = self.key.cast_to_signed(c.bits().clone(), len);
            let res_bits = self.key.unchecked_abs_parallelized(&bits);
            T::new(self.key.cast_to_unsigned(res_bits, len))
        } else {
            c.clone()
        }
    }
    // There is no abs_assign in TFHE, so I also left it out
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the absolute value of a ciphertext encrypting a fixed point number.
    /// For unsigned numbers absolute value does nothing. It is only here for consistency.
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
    ///
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    ///
    /// let ct_res = a.smart_abs(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn smart_abs(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_abs(&mut self.inner),
        }
    }
    pub fn unchecked_abs(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_abs(&self.inner),
        }
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the absolute value of a ciphertext encrypting a fixed point number.
    /// On overflow, the result is wrapped around.
    /// This can only occur when the input is the smallest representable number.
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
    /// let clear_a: I8F8 = I8F8::from_num(-12.8);
    ///
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    ///
    /// let ct_res = a.smart_abs(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.abs());
    /// ```
    pub fn smart_abs(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_abs(&mut self.inner),
        }
    }
    pub fn unchecked_abs(&self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.unchecked_abs(&self.inner),
        }
    }
}
