use crate::fixed::{
    BitsMutToken, FixedCiphertext
};
use crate::fixed::{Bits, FixedServerKey};

use tfhe::{
    integer::{ciphertext::BaseSignedRadixCiphertext, IntegerCiphertext},
    shortint::Ciphertext,
};

impl FixedServerKey {
    /// Computes homomorphically the integer logarithm (base 2) of a ciphertext encrypting a fixed point number.
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
    /// let ct_res = skey.smart_ilog2(&mut a);
    ///
    /// // Decrypt:
    /// let dec_result: i32 = ckey.key.decrypt_signed_radix(&ct_res);
    /// assert_eq!(dec_result, clear_a.int_log2());
    /// ```
    pub fn smart_ilog2<T: FixedCiphertext>(
        &self,
        c: &mut T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut(BitsMutToken));
        }
        self.unchecked_ilog2(c)
    }

    pub fn unchecked_ilog2<T: FixedCiphertext>(
        &self,
        c: &T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        let tmp: Bits = self.key.unchecked_ilog2_parallelized(c.bits());
        let len = tmp.blocks().len();
        let mut bits = self.key.cast_to_signed(tmp, len);
        self.key
            .smart_scalar_sub_assign_parallelized(&mut bits, c.frac());
        bits
    }
}