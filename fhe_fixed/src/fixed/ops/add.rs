use crate::fixed::{
    BitsMutToken, FixedCiphertext
};
use crate::fixed::{Bits, FixedServerKey};


impl FixedServerKey {
    /// Computes homomorphically an addition between two ciphertexts encrypting fixed point numbers.
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
    /// // Compute homomorphically an addition:
    /// let ct_res = skey.smart_add(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ckey.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a + clear_b);
    /// ```
    pub fn smart_add<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> T {
        let mut result_value = lhs.clone();
        self.smart_add_assign(&mut result_value, rhs);
        result_value
    }

    pub fn unchecked_add<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> T {
        let mut result_value: T = lhs.clone();
        self.unchecked_add_assign(&mut result_value, rhs);
        result_value
    }

    pub fn smart_add_assign<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) {
        if self.key.is_add_possible(lhs.bits(), rhs.bits()).is_err() {
            rayon::join(
                || self.key.full_propagate_parallelized(lhs.bits_mut(BitsMutToken)),
                || self.key.full_propagate_parallelized(rhs.bits_mut(BitsMutToken)),
            );
        }
        self.unchecked_add_assign(lhs, rhs);
    }

    pub fn unchecked_add_assign<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &T) {
        self.key
            .unchecked_add_assign_parallelized(lhs.bits_mut(BitsMutToken), rhs.bits());
    }

    pub fn smart_dbl<T: FixedCiphertext>(&self, c: &mut T) -> T {
        let mut result_value = c.clone();
        self.smart_dbl_assign(&mut result_value);
        result_value
    }

    pub fn unchecked_dbl<T: FixedCiphertext>(&self, c: &T) -> T {
        let result_bits: Bits = self.key.unchecked_add_parallelized(c.bits(), c.bits());
        T::new(result_bits)
    }

    pub fn smart_dbl_assign<T: FixedCiphertext>(&self, c: &mut T) {
        if self.key.is_add_possible(c.bits(), c.bits()).is_err() {
            self.key.full_propagate_parallelized(c.bits_mut(BitsMutToken));
        }
        self.unchecked_dbl_assign(c)
    }

    pub fn unchecked_dbl_assign<T: FixedCiphertext>(&self, c: &mut T) {
        *c.bits_mut(BitsMutToken) = self.key.unchecked_add_parallelized(c.bits(), c.bits());
    }
}