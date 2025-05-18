use crate::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use crate::shortint::Ciphertext;

use super::arb_fixed::{ArbFixedI, ArbFixedU};
use super::{FheFixedI, FixedClientKey};
use crate::FixedCiphertext;
use crate::FheFixedU;
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey
};

use crate::high_level_api::fixed::traits::{FixedFrac, FixedSize};

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Creates an FheFixedU whose bitwise representation is equal to what is encrypted in `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with trivial zeros.
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::FheU8F8;
    /// use fixed::types::U8F8;
    /// use crate::tfhe::FixedCiphertext;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    /// 
    /// let a_bits = ckey.key.encrypt_radix(clear_a.to_bits(), FheU8F8::SIZE as usize / 2);
    /// let a = FheU8F8::from_bits(a_bits, &skey);
    ///
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn from_bits(bits: Cipher, key: &FixedServerKey) -> Self {
        let len: usize = Size::USIZE / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let cur_len = blocks.len();
        let mut bits = Cipher::from_blocks(blocks);
        key.key
            .extend_radix_with_trivial_zero_blocks_msb_assign(&mut bits, len - cur_len);
        Self::new(bits)
    }
    // This may result in too short inner radix ciphertext!!!
    pub(crate) fn from_bits_inner(bits: Cipher) -> Self {
        let len: usize = Size::USIZE / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let bits = Cipher::from_blocks(blocks);
        Self::new(bits)
    }

    /// Creates an encrypted FheFixedU.
    /// `clear` can be any numeric or fixed type, however the encryption may be lossy.
    /// This operation can only be used if Size <= 128. If Size > 128, use encrypt_from_bits.
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
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    ///
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt<U>(clear: U, key: &FixedClientKey) -> Self
    where
        ArbFixedU<Size, Frac>: From<U>,
    {
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::<Size, Frac>::from(clear);
        // this encrypts 1 block
        // key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));

        let extract_bits = |x: &u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix
            .parts
            .iter()
            .flat_map(extract_bits)
            .take(Size::USIZE >> 1)
            .map(|x| key.key.encrypt_one_block(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::from_bits_inner(Cipher::from_blocks(blocks))
    }

    /// Creates an encrypted FheFixedU.
    /// The value encrypted has the same bitwise representation as the given `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with zeros.
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
    /// let mut a = FheU8F8::encrypt_from_bits(vec![clear_a.to_bits() as u64], &ckey);
    ///
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedU::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }

    /// Creates a trivially encrypted FheFixedU.
    /// `clear` can be any numeric or fixed type, however the encryption may be lossy.
    /// This operation can only be used if Size <= 128. If Size > 128, use encrypt_from_bits.
    ///
    /// # Warning
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
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
    /// let mut a = FheU8F8::encrypt_trivial(clear_a, &skey);
    ///
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial<U>(clear: U, key: &FixedServerKey) -> Self
    where
        ArbFixedU<Size, Frac>: From<U>,
    {
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::from(clear);
        /*this encrypts 1 block
        key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));*/

        let extract_bits = |x: &u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix
            .parts
            .iter()
            .flat_map(extract_bits)
            .take(Size::USIZE >> 1)
            .map(|x| key.key.key.create_trivial(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::new(Cipher::from_blocks(blocks))
    }

    /// Creates a trivially encrypted FheFixedU.
    /// The value encrypted has the same bitwise representation as the given `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with zeros.
    ///
    /// # Warning
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
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
    /// let mut a = FheU8F8::encrypt_trivial_from_bits(vec![clear_a.to_bits() as u64], &skey);
    ///
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::from_bits(bits);
        Self::encrypt_trivial(fix, key)
    }

    /// Decrypts an FheFixedU to a numeric type.
    ///
    /// The clear type has to be explicit.
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
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    ///
    /// // U8F8 is explicit
    /// let dec_result: U8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn decrypt<T: From<ArbFixedU<Size, Frac>>>(&self, key: &FixedClientKey) -> T {
        let blocks = &self.inner.bits().blocks();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| key.key.key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        T::from(ArbFixedU::from_bits(values))
    }

    /// Decrypts an FheFixedU to it's bitwise representation.
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
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    ///
    /// let dec_result = a.decrypt_to_bits(&ckey);
    /// assert_eq!(dec_result[0], clear_a.to_bits() as u64);
    /// ```
    pub fn decrypt_to_bits(&self, key: &FixedClientKey) -> Vec<u64> {
        let arb_result: ArbFixedU<Size, Frac> = self.decrypt(key);
        arb_result.parts
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Creates an FheFixedI whose bitwise representation is equal to what is encrypted in `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with trivial zeros.
    ///
    /// # Example
    /// ```rust
    /// use tfhe::{FixedClientKey, FixedServerKey};
    /// use tfhe::FheI8F8;
    /// use fixed::types::I8F8;
    /// use tfhe::FixedCiphertext;
    /// 
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    /// 
    /// let clear_a: I8F8 = I8F8::from_num(-12.8);
    /// 
    /// let a_bits = ckey.key.encrypt_radix(clear_a.to_bits() as u16, FheI8F8::SIZE as usize / 2);
    /// let a = FheI8F8::from_bits(a_bits, &skey);
    ///
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn from_bits(bits: Cipher, key: &FixedServerKey) -> Self {
        let len: usize = Size::USIZE / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let cur_len = blocks.len();
        let mut bits = Cipher::from_blocks(blocks);
        key.key
            .extend_radix_with_trivial_zero_blocks_msb_assign(&mut bits, len - cur_len);
        Self::new(bits)
    }
    // This may result in too short inner radix ciphertext!!!
    pub(crate) fn from_bits_inner(bits: Cipher) -> Self {
        let len: usize = Size::USIZE / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let bits = Cipher::from_blocks(blocks);
        Self::new(bits)
    }

    /// Creates an encrypted FheFixedI.
    /// `clear` can be any numeric or fixed type, however the encryption may be lossy.
    /// This operation can only be used if Size <= 128. If Size > 128, use encrypt_from_bits.
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
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    ///
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt<U>(clear: U, key: &FixedClientKey) -> Self
    where
        ArbFixedI<Size, Frac>: From<U>,
    {
        let fix: ArbFixedI<Size, Frac> = ArbFixedI::<Size, Frac>::from(clear);
        // this encrypts 1 block
        // key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));

        let extract_bits = |x: &u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix
            .parts
            .iter()
            .flat_map(extract_bits)
            .take(Size::USIZE >> 1)
            .map(|x| key.key.encrypt_one_block(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::from_bits_inner(Cipher::from_blocks(blocks))
    }

    /// Creates an encrypted FheFixedI.
    /// The value encrypted has the same bitwise representation as the given `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with zeros.
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
    /// let a = FheI8F8::encrypt_from_bits(vec![clear_a.to_bits() as u64], &ckey);
    ///
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedI::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }

    /// Creates a trivially encrypted FheFixedI.
    /// `clear` can be any numeric or fixed type, however the encryption may be lossy.
    /// This operation can only be used if Size <= 128. If Size > 128, use encrypt_from_bits.
    ///
    /// # Warning
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
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
    /// let mut a = FheI8F8::encrypt_trivial(clear_a, &skey);
    ///
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial<U>(clear: U, key: &FixedServerKey) -> Self
    where
        ArbFixedI<Size, Frac>: From<U>,
    {
        let fix: ArbFixedI<Size, Frac> = ArbFixedI::from(clear);
        /*this encrypts 1 block
        key.key.encrypt_one_block(to_be_encrypted (0,1,2 or 3));*/

        let extract_bits = |x: &u64| {
            let mut result = [0u8; 32];
            for i in 0..32 {
                result[i] = ((x >> (2 * i)) & 0b11) as u8;
            }
            result
        };

        let blocks = fix
            .parts
            .iter()
            .flat_map(extract_bits)
            .take(Size::USIZE >> 1)
            .map(|x| key.key.key.create_trivial(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::new(Cipher::from_blocks(blocks))
    }

    /// Creates a trivially encrypted FheFixedI.
    /// The value encrypted has the same bitwise representation as the given `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with zeros.
    ///
    /// # Warning
    ///
    /// A trivial encryption is not an encryption, the value can be retrieved
    /// by anyone as if it were a clear value.
    ///
    /// Thus no client or public key is needed to create a trivial encryption,
    /// this can be useful to initialize some values.
    ///
    /// As soon as a trivial encryption is used in an operation that involves
    /// non trivial encryption, the result will be non trivial (secure).
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
    /// let mut a = FheI8F8::encrypt_trivial_from_bits(vec![clear_a.to_bits() as u64], &skey);
    ///
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let fix: ArbFixedI<Size, Frac> = ArbFixedI::from_bits(bits);
        Self::encrypt_trivial(fix, key)
    }


    /// Decrypts an FheFixedI to a numeric type.
    ///
    /// The clear type has to be explicit.
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
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    ///
    /// // I8F8 is explicit
    /// let dec_result: I8F8 = a.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn decrypt<T: From<ArbFixedI<Size, Frac>>>(&self, key: &FixedClientKey) -> T {
        let blocks = &self.inner.bits().blocks();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| key.key.key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        T::from(ArbFixedI::from_bits(values))
    }

    /// Decrypts an FheFixedI to it's bitwise representation.
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
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    ///
    /// let dec_result = a.decrypt_to_bits(&ckey);
    /// assert_eq!(dec_result[0] as i16, clear_a.to_bits());
    /// ```
    pub fn decrypt_to_bits(&self, key: &FixedClientKey) -> Vec<u64> {
        let arb_result: ArbFixedI<Size, Frac> = self.decrypt(key);
        arb_result.parts
    }
}

/// ### NOTE
/// Currently the carry and the overflow from the msb block may or may not be lost. This may or may not change!
fn blocks_with_carry_to_u64(blocks: Vec<u8>) -> Vec<u64> {
    // The result vector
    let mut result = Vec::new();
    // The current element of the vector, stored as u128 to handle overflow
    let mut current_u64: u128 = 0;
    // The index of the current 2 bits that we are adding to
    let mut position = 0;

    for i in 0..blocks.len() {
        //extract value and carry from input block
        let value = blocks[i] & 0b11;
        let carry = (blocks[i] >> 2) & 0b11;

        // add value at current position
        current_u64 += (value as u128) << (position * 2);

        position += 1;

        // If position is 32, then we have filled in the current u64, so push it to the result
        if position == 32 {
            // This is the part of the result so far that fits in a u64
            let result_u64 = current_u64 & (u64::MAX as u128);
            // Push the result
            result.push(result_u64 as u64);
            // The next u64 will start as the overflow from the current
            current_u64 >>= 64;
            // Reset the position
            position = 0;
        }

        // Finally add the carry bits to the next position
        current_u64 += (carry as u128) << (position * 2);
    }

    // Add the last partially filled u64 if necessary
    if position > 0 {
        let result_u64 = current_u64 & (u64::MAX as u128);
        result.push(result_u64 as u64);
    }

    result
}
