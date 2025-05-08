use tfhe::integer::{IntegerCiphertext, IntegerRadixCiphertext};
use tfhe::shortint::Ciphertext;

use super::arb_fixed::ArbFixedI;
use super::{ArbFixedU, FheFixedI, FixedClientKey};
use crate::FixedCiphertext;
use crate::fixed::FheFixedU;
use crate::{
    Cipher, FixedServerKey,
    traits::{FixedFrac, FixedSize},
};

/*
impl FixedClientKey {
    pub(crate) fn encrypt<Size, Frac, U>(&self, clear: U) -> FheFixedU<Size, Frac>
    where ArbFixedU<Size, Frac>: From<U>,
    Size: FixedSize<Frac>,
    Frac: FixedFrac {
        FheFixedU::<Size, Frac>::encrypt(clear, self)
    }

    pub(crate) fn encrypt_from_bits<Size, Frac, U>(&self, bits: Vec<u64>) -> FheFixedU<Size, Frac>
    where Size: FixedSize<Frac>,
    Frac: FixedFrac {
        FheFixedU::<Size, Frac>::encrypt_from_bits(bits, self)
    }
}*/

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
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

    pub fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedU::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }

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

    pub fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let fix: ArbFixedU<Size, Frac> = ArbFixedU::from_bits(bits);
        Self::encrypt_trivial(fix, key)
    }

    pub fn decrypt<T: From<ArbFixedU<Size, Frac>>>(&self, key: &FixedClientKey) -> T {
        let blocks = &self.inner.bits().blocks();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| key.key.key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        T::from(ArbFixedU::from_bits(values))
    }

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

    pub fn encrypt_from_bits(bits: Vec<u64>, key: &FixedClientKey) -> Self {
        let arb = ArbFixedI::<Size, Frac>::from_bits(bits);
        Self::encrypt(arb, key)
    }

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

    pub fn encrypt_trivial_from_bits(bits: Vec<u64>, key: &FixedServerKey) -> Self {
        let fix: ArbFixedI<Size, Frac> = ArbFixedI::from_bits(bits);
        Self::encrypt_trivial(fix, key)
    }

    pub fn decrypt<T: From<ArbFixedI<Size, Frac>>>(&self, key: &FixedClientKey) -> T {
        let blocks = &self.inner.bits().blocks();
        let clear_blocks: Vec<u8> = blocks
            .iter()
            .map(|x| key.key.key.decrypt_message_and_carry(x) as u8)
            .collect();

        let values = blocks_with_carry_to_u64(clear_blocks);

        T::from(ArbFixedI::from_bits(values))
    }

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
