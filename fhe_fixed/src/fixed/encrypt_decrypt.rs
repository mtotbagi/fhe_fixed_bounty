#![allow(private_bounds)]

use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::Ciphertext;

use super::arb_fixed::{ArbFixedI, ArbFixedU};
use super::{FheFixedI, FixedClientKey};
use crate::fixed::{Bits, FixedServerKey};
use crate::FheFixedU;
use crate::FixedCiphertext;

use crate::fixed::traits::{DecryptFixed, DecryptToBitsFixed, EncryptFixed, EncryptTrivialFixed, EncryptFromBitsFixed, FixedFrac, FixedSize};

impl FixedServerKey 
    {
    /// Creates an FheFixedU/I whose bitwise representation is equal to what is encrypted in `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with trivial zeros.
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
    /// let a_bits = ckey.key.encrypt_radix(clear_a.to_bits(), FheU8F8::SIZE as usize / 2);
    /// let a: FheU8F8 = skey.from_bits(a_bits);
    ///
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn from_bits<T: FixedCiphertext>(&self, bits: Bits) -> T {
        let len: usize = T::SIZE as usize / 2;
        let mut blocks = bits.into_blocks();
        blocks.truncate(len);
        let cur_len = blocks.len();
        let mut bits = Bits::from_blocks(blocks);
        self.key
            .extend_radix_with_trivial_zero_blocks_msb_assign(&mut bits, len - cur_len);
        T::new(bits)
    }

    /// Creates a trivially encrypted FheFixedU/I.
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
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = skey.encrypt_trivial(clear_a);
    ///
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial<U, T>(&self, clear: U) -> T where 
    T: EncryptTrivialFixed<U> {
        T::encrypt_trivial(clear, self)
    }

    /// Creates a trivially encrypted FheFixedU/I.
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
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key and the server key:
    /// let ckey = FixedClientKey::new();
    /// let skey = FixedServerKey::new(&ckey);
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = skey.encrypt_trivial_from_bits(vec![clear_a.to_bits() as u64]);
    ///
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_trivial_from_bits<T>(&self, bits: Vec<u64>) -> T where 
    T: EncryptFromBitsFixed {
        T::encrypt_trivial_from_bits(bits, self)
    }
}

impl FixedClientKey {
    /// Creates an encrypted FheFixedU/I.
    /// `clear` can be any numeric or fixed type, however the encryption may be lossy.
    /// This operation can only be used if Size <= 128. If Size > 128, use encrypt_from_bits.
    ///
    /// # Example
    /// ```rust
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key:
    /// let ckey = FixedClientKey::new();
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = ckey.encrypt(clear_a);
    ///
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt<U, T>(&self, clear: U) -> T where 
    T: EncryptFixed<U> {
        T::encrypt(clear, self)
    }

    /// Creates an encrypted FheFixedU/I.
    /// The value encrypted has the same bitwise representation as the given `bits`
    /// If `bits` is too long, it is truncated to the appropriate length thus losing the most significant bits.
    /// If `bits` is too short it is extended with zeros.
    ///
    /// # Example
    /// ```rust
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key:
    /// let ckey = FixedClientKey::new();
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = ckey.encrypt_from_bits(vec![clear_a.to_bits() as u64]);
    ///
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn encrypt_from_bits<T>(&self, bits: Vec<u64>) -> T where 
    T: EncryptFromBitsFixed {
        T::encrypt_from_bits(bits, self)
    }

    /// Decrypts an FheFixedU/I to a numeric type.
    ///
    /// The clear type has to be explicit.
    ///
    /// # Example
    /// ```rust
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key:
    /// let ckey = FixedClientKey::new();
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = ckey.encrypt(clear_a);
    ///
    /// // U8F8 is explicit
    /// let dec_result: U8F8 = ckey.decrypt(&a);
    /// assert_eq!(dec_result, clear_a);
    /// ```
    pub fn decrypt<U, T>(&self, cipher: &T) -> U where 
    T: DecryptFixed<U> {
        cipher.decrypt(&self)
    }

    /// Decrypts an FheFixedU/I to it's bitwise representation.
    ///
    /// # Example
    /// ```rust
    /// use fixed::types::U8F8;
    /// use fhe_fixed::*;
    ///
    /// // Generate the client key:
    /// let ckey = FixedClientKey::new();
    ///
    /// let clear_a: U8F8 = U8F8::from_num(12.8);
    ///
    /// let a: FheU8F8 = ckey.encrypt(clear_a);
    ///
    /// let dec_result = ckey.decrypt_to_bits(&a);
    /// assert_eq!(dec_result[0], clear_a.to_bits() as u64);
    /// ```
    pub fn decrypt_to_bits<T>(&self, cipher: &T) -> Vec<u64> where 
    T: DecryptToBitsFixed {
        cipher.decrypt_to_bits(&self)
    }
}


impl<U, Size, Frac> EncryptFixed<U> for FheFixedU<Size,Frac> where
    ArbFixedU<Size, Frac>: From<U>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt(clear: U, key: &FixedClientKey) -> FheFixedU<Size, Frac>
    {
        let fix: ArbFixedU<Size, Frac> = clear.into();

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

        Self::new(Bits::from_blocks(blocks))
    }

}

impl<U, Size, Frac> EncryptFixed<U> for FheFixedI<Size,Frac> where
    ArbFixedI<Size, Frac>: From<U>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt(clear: U, key: &FixedClientKey) -> FheFixedI<Size, Frac>
    {
        let fix: ArbFixedI<Size, Frac> = clear.into();

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

        Self::new(Bits::from_blocks(blocks))
    }

}

impl<U, Size, Frac> DecryptFixed<U> for FheFixedU<Size, Frac> where
    U: From<ArbFixedU<Size, Frac>>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn decrypt(&self, key: &FixedClientKey) -> U {
        let blocks = self.bits().blocks();
        let shortint_key: &tfhe::shortint::ClientKey = key.key.as_ref();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| shortint_key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        U::from(ArbFixedU::from_bits(values))
    }
}

impl<U, Size, Frac> DecryptFixed<U> for FheFixedI<Size, Frac> where
    U: From<ArbFixedI<Size, Frac>>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn decrypt(&self, key: &FixedClientKey) -> U {
        let blocks = self.bits().blocks();
        let shortint_key: &tfhe::shortint::ClientKey = key.key.as_ref();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| shortint_key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        U::from(ArbFixedI::from_bits(values))
    }
}

impl<U, Size, Frac> EncryptTrivialFixed<U> for FheFixedU<Size, Frac> where
    ArbFixedU<Size, Frac>: From<U>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt_trivial(clear: U, key: &FixedServerKey) -> Self
    {
        let fix: ArbFixedU<Size, Frac> = clear.into();

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
            .map(|x| key.key.as_ref().create_trivial(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::new(Bits::from_blocks(blocks))
    }
}

impl<U, Size, Frac> EncryptTrivialFixed<U> for FheFixedI<Size, Frac> where
    ArbFixedI<Size, Frac>: From<U>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt_trivial(clear: U, key: &FixedServerKey) -> Self
    {
        let fix: ArbFixedI<Size, Frac> = clear.into();

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
            .map(|x| key.key.as_ref().create_trivial(x as u64))
            .collect::<Vec<Ciphertext>>();

        Self::new(Bits::from_blocks(blocks))
    }
}

impl<Size, Frac> EncryptFromBitsFixed for FheFixedU<Size, Frac> where
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let arb = ArbFixedU::<Size, Frac>::from_bits(bits);
        Self::encrypt_trivial(arb, key)
    }

    fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedU::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }
}

impl<Size, Frac> EncryptFromBitsFixed for FheFixedI<Size, Frac> where
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let arb = ArbFixedI::<Size, Frac>::from_bits(bits);
        Self::encrypt_trivial(arb, key)
    }

    fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedI::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }
}

impl<Size, Frac> DecryptToBitsFixed for FheFixedU<Size, Frac> where
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn decrypt_to_bits(&self, key: &FixedClientKey) -> Vec<u64> {
        let arb_result: ArbFixedU<Size, Frac> = self.decrypt(key);
        arb_result.parts
    }
}

impl<Size, Frac> DecryptToBitsFixed for FheFixedI<Size, Frac> where
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
    fn decrypt_to_bits(&self, key: &FixedClientKey) -> Vec<u64> {
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
