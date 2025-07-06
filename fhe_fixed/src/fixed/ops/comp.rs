use tfhe::integer::{
    BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext,
};

use crate::fixed::{
    BitsMutToken, FixedCiphertext
};
use crate::FixedServerKey;

use crate::fixed::propagate_if_needed_parallelized;

impl FixedServerKey {
    /// Compares for equality 2 ciphertexts encrypting fixed point numbers
    ///
    /// Returns a ciphertext containing 1 if self == rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_eq(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a == clear_b);
    /// ```
    pub fn smart_eq<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_eq(lhs, rhs)
    }

    /// Compares for inequality 2 ciphertexts encrypting fixed point numbers
    ///
    /// Returns a ciphertext containing 1 if self != rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_ne(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a != clear_b);
    /// ```
    pub fn smart_ne<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_ne(lhs, rhs)
    }

    /// Compares if self is strictly lower than rhs
    ///
    /// Returns a ciphertext containing 1 if self < rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_lt(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a < clear_b);
    /// ```
    pub fn smart_lt<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_lt(lhs, rhs)
    }

    /// Compares if self is lower or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if self <= rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_le(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a <= clear_b);
    /// ```
    pub fn smart_le<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_le(lhs, rhs)
    }

    /// Compares if self is strictly greater than rhs
    ///
    /// Returns a ciphertext containing 1 if self > rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_gt(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a > clear_b);
    /// ```
    pub fn smart_gt<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_gt(lhs, rhs)
    }

    /// Compares if self is greater or equal than rhs
    ///
    /// Returns a ciphertext containing 1 if self >= rhs, otherwise 0
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
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
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
    /// let ct_res = skey.smart_ge(&mut a, &mut b);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a >= clear_b);
    /// ```
    pub fn smart_ge<T: FixedCiphertext>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(BitsMutToken), rhs.bits_mut(BitsMutToken)], &self.key);
        self.unchecked_ge(lhs, rhs)
    }

    pub fn unchecked_eq<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key.unchecked_eq_parallelized(lhs.bits(), rhs.bits())
    }
    pub fn unchecked_ne<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key.unchecked_ne_parallelized(lhs.bits(), rhs.bits())
    }
    pub fn unchecked_lt<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_lt_parallelized(&lhs_signed, &rhs_signed)
        } else {
            self.key.unchecked_lt_parallelized(lhs.bits(), rhs.bits())
        }
    }
    pub fn unchecked_le<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_le_parallelized(&lhs_signed, &rhs_signed)
        } else {
            self.key.unchecked_le_parallelized(lhs.bits(), rhs.bits())
        }
    }
    pub fn unchecked_gt<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_gt_parallelized(&lhs_signed, &rhs_signed)
        } else {
            self.key.unchecked_gt_parallelized(lhs.bits(), rhs.bits())
        }
    }
    pub fn unchecked_ge<T: FixedCiphertext>(&self, lhs: &T, rhs: &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_ge_parallelized(&lhs_signed, &rhs_signed)
        } else {
            self.key.unchecked_ge_parallelized(lhs.bits(), rhs.bits())
        }
    }
}