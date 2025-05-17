use crate::integer::{BooleanBlock, IntegerCiphertext, IntegerRadixCiphertext, SignedRadixCiphertext};

use crate::high_level_api::fixed::{FheFixedU, FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::FixedServerKey;

use crate::high_level_api::fixed::propagate_if_needed_parallelized;
use crate::FheFixedI;

impl FixedServerKey {
    fn smart_eq<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_eq(lhs, rhs)
    }
    fn smart_ne<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_ne(lhs, rhs)
    }
    fn smart_lt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_lt(lhs, rhs)
    }
    fn smart_le<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_le(lhs, rhs)
    }
    fn smart_gt<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_gt(lhs, rhs)
    }
    fn smart_ge<T: FixedCiphertextInner>(&self, lhs: &mut T, rhs: &mut T) -> BooleanBlock {
        propagate_if_needed_parallelized(&mut [lhs.bits_mut(), rhs.bits_mut()], &self.key);
        self.unchecked_ge(lhs, rhs)
    }

    fn unchecked_eq<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key
        .unchecked_eq_parallelized(lhs.bits(),  rhs.bits())
    }
    fn unchecked_ne<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        // this is the same regardless of sign
        self.key
            .unchecked_ne_parallelized(lhs.bits(),  rhs.bits())
    }
    fn unchecked_lt<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_lt_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_lt_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_le<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_le_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_le_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_gt<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_gt_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_gt_parallelized(lhs.bits(),  rhs.bits())
        }
    }
    fn unchecked_ge<T: FixedCiphertextInner>(&self, lhs:  &T, rhs:  &T) -> BooleanBlock {
        if T::IS_SIGNED {
            let lhs_signed = SignedRadixCiphertext::from_blocks(lhs.bits().clone().into_blocks());
            let rhs_signed = SignedRadixCiphertext::from_blocks(rhs.bits().clone().into_blocks());
            self.key.unchecked_ge_parallelized(&lhs_signed,  &rhs_signed)
        } else {
            self.key.unchecked_ge_parallelized(lhs.bits(),  rhs.bits())
        }
    }
}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
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
    /// let ct_res = a.smart_eq(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a == clear_b);
    /// ```
    pub fn smart_eq(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_eq(&mut self.inner, &mut rhs.inner)
    }
    pub fn smart_ne(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ne(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
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
    /// let ct_res = a.smart_lt(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a < clear_b);
    /// ```
    pub fn smart_lt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_lt(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
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
    /// let ct_res = a.smart_le(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a <= clear_b);
    /// ```
    pub fn smart_le(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_le(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
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
    /// let ct_res = a.smart_gt(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a > clear_b);
    /// ```
    pub fn smart_gt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_gt(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheU8F8;
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
    /// let ct_res = a.smart_ge(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a >= clear_b);
    /// ```
    pub fn smart_ge(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ge(&mut self.inner, &mut rhs.inner)
    }

    pub fn unchecked_eq(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_eq(&self.inner, &rhs.inner)
    }
    pub fn unchecked_ne(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ne(&self.inner, &rhs.inner)
    }
    pub fn unchecked_lt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_lt(&self.inner, &rhs.inner)
    }
    pub fn unchecked_le(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_le(&self.inner, &rhs.inner)
    }
    pub fn unchecked_gt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_gt(&self.inner, &rhs.inner)
    }
    pub fn unchecked_ge(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ge(&self.inner, &rhs.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
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
    /// let ct_res = a.smart_eq(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a == clear_b);
    /// ```
    pub fn smart_eq(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_eq(&mut self.inner, &mut rhs.inner)
    }
    pub fn smart_ne(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ne(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
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
    /// let ct_res = a.smart_lt(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a < clear_b);
    /// ```
    pub fn smart_lt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_lt(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
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
    /// let ct_res = a.smart_le(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a <= clear_b);
    /// ```
    pub fn smart_le(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_le(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
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
    /// let ct_res = a.smart_gt(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a > clear_b);
    /// ```
    pub fn smart_gt(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_gt(&mut self.inner, &mut rhs.inner)
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
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::aliases::FheI8F8;
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
    /// let ct_res = a.smart_ge(&mut b, &skey);
    ///
    /// // Decrypt:
    /// let dec_result = ckey.key.decrypt_bool(&ct_res);
    /// assert_eq!(dec_result, clear_a >= clear_b);
    /// ```
    pub fn smart_ge(&mut self, rhs: &mut Self, key: &FixedServerKey) -> BooleanBlock {
        key.smart_ge(&mut self.inner, &mut rhs.inner)
    }

    pub fn unchecked_eq(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_eq(&self.inner, &rhs.inner)
    }
    pub fn unchecked_ne(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ne(&self.inner, &rhs.inner)
    }
    pub fn unchecked_lt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_lt(&self.inner, &rhs.inner)
    }
    pub fn unchecked_le(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_le(&self.inner, &rhs.inner)
    }
    pub fn unchecked_gt(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_gt(&self.inner, &rhs.inner)
    }
    pub fn unchecked_ge(&self, rhs: &Self, key: &FixedServerKey) -> BooleanBlock {
        key.unchecked_ge(&self.inner, &rhs.inner)
    }
}
