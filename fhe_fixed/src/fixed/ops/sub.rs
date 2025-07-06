use crate::fixed::{BitsMutToken, FixedServerKey};
use crate::fixed::FixedCiphertext;


impl FixedServerKey {
    /// Computes homomorphically a subtraction between two ciphertexts encrypting fixed point numbers.
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
    /// let clear_b: U8F8 = U8F8::from_num(1.8);
    ///
    /// //Encrypt:
    /// let mut a: FheU8F8 = ckey.encrypt(clear_a);
    /// let mut b: FheU8F8 = ckey.encrypt(clear_b);
    ///
    /// let ct_res = skey.smart_sub(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ckey.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a - clear_b);
    /// ```
    pub fn smart_sub<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub fn unchecked_sub<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_sub_assign(&mut result_value, rhs);
        result_value
    }

    pub fn smart_sub_assign<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_neg_possible(rhs.bits()).is_err() {
            self.key.full_propagate_parallelized(rhs.bits_mut(BitsMutToken));
        }

        // If the ciphertext cannot be added together without exceeding the capacity of a ciphertext
        if self.key.is_sub_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut(BitsMutToken)),
                || self.key.full_propagate_parallelized(rhs.bits_mut(BitsMutToken)),
            );
        }
        self.unchecked_sub_assign(lhs, rhs);
    }

    pub fn unchecked_sub_assign<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &T) {
        self.key.unchecked_sub_assign(lhs.bits_mut(BitsMutToken), rhs.bits());
    }
}