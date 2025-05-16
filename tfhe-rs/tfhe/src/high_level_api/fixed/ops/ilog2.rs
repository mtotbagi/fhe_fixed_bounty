use crate::high_level_api::fixed::{FixedCiphertextInner, traits::{FixedFrac, FixedSize}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};

use crate::{
    integer::{IntegerCiphertext, ciphertext::BaseSignedRadixCiphertext},
    shortint::Ciphertext,
};


impl FixedServerKey {
    pub(crate) fn smart_ilog2<T: FixedCiphertextInner>(
        &self,
        c: &mut T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        self.unchecked_ilog2(c)
    }

    pub(crate) fn unchecked_ilog2<T: FixedCiphertextInner>(
        &self,
        c: &T,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        let tmp: Cipher = self.key.unchecked_ilog2_parallelized(c.bits());
        let len = tmp.blocks().len();
        let mut bits = self.key.cast_to_signed(tmp, len);
        self.key
            .smart_scalar_sub_assign_parallelized(&mut bits, c.frac());
        bits
    }
}


impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the integer logarithm (base 2) of a ciphertext encrypting a fixed point number.
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
    /// // Compute homomorphically an addition:
    /// let ct_res = a.smart_ilog2(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: i32 = ckey.key.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a.int_log2());
    /// ```
    pub fn smart_ilog2(
        &mut self,
        key: &FixedServerKey,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.smart_ilog2(&mut self.inner)
    }
    pub fn unchecked_ilog2(
        &self,
        key: &FixedServerKey,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.unchecked_ilog2(&self.inner)
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the integer logarithm (base 2) of a ciphertext encrypting a fixed point number.
    /// If the encrypted number is negative, the result will be undefined
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
    /// // Compute homomorphically an addition:
    /// let ct_res = a.smart_ilog2(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: i32 = ckey.key.decrypt(&ct_res);
    /// assert_eq!(dec_result, clear_a.int_log2());
    /// ```
    pub fn smart_ilog2(
        &mut self,
        key: &FixedServerKey,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.smart_ilog2(&mut self.inner)
    }
    pub fn unchecked_ilog2(
        &self,
        key: &FixedServerKey,
    ) -> BaseSignedRadixCiphertext<Ciphertext> {
        key.unchecked_ilog2(&self.inner)
    }
}