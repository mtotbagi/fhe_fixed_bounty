use crate::fixed::{
    BitsMutToken, FixedCiphertext
};
use crate::FixedServerKey;

use tfhe::integer::IntegerCiphertext;

impl FixedServerKey {
    /// Computes homomorphically the absolute value of a ciphertext encrypting a fixed point number.
    /// For unsigned numbers absolute value does nothing.
    /// On overflow, the result is wrapped around.
    /// This can only occur when the input is the smallest representable number.
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
    /// let ct_res = skey.smart_abs(&mut a);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ckey.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn smart_abs<T: FixedCiphertext>(&self, c: &mut T) -> T {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut(BitsMutToken));
        }
        self.unchecked_abs(c)
    }

    pub fn unchecked_abs<T: FixedCiphertext>(&self, c: &T) -> T {
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