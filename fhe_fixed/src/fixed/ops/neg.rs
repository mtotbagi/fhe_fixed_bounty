use crate::fixed::{BitsMutToken, FixedServerKey};
use crate::fixed::FixedCiphertext;

impl FixedServerKey {
    /// Computes homomorphically the negation of a ciphertext encrypting a fixed point number.
    /// On overflow, the result is wrapped around.
    ///
    /// # Warning
    ///
    /// - Multithreaded
    ///
    /// # Example
    /// ```rust
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// //Encrypt:
    /// let mut a: FheU8F8 = ckey.encrypt(clear_a);
    ///
    /// let ct_res = skey.smart_neg(&mut a);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ckey.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a.wrapping_neg());
    /// ```
    pub fn smart_neg<T: FixedCiphertext>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.smart_neg_assign(&mut result_value);
        result_value
    }

    pub fn unchecked_neg<T: FixedCiphertext>(&self, c: &T) -> T {
        let mut result_value = c.clone();
        self.unchecked_neg_assign(&mut result_value);
        result_value
    }

    pub fn smart_neg_assign<T: FixedCiphertext>(&self, c: &mut T) {
        if self.key.is_neg_possible(c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut(BitsMutToken));
        }
        self.unchecked_neg_assign(c)
    }

    pub fn unchecked_neg_assign<T: FixedCiphertext>(&self, c: &mut T) {
        self.key.unchecked_neg_assign(c.bits_mut(BitsMutToken))
    }
}