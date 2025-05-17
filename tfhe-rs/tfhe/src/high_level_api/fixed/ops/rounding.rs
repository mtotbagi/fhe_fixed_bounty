use crate::{high_level_api::fixed::{traits::{FixedFrac, FixedSize}, FixedCiphertextInner}, integer::{prelude::ServerKeyDefaultCMux, BooleanBlock}};
use crate::high_level_api::fixed::{
    Cipher, FixedServerKey,
};

use crate::{FheFixedI, FheFixedU};
use crate::{
    integer::{IntegerCiphertext, IntegerRadixCiphertext},
    shortint::Ciphertext,
};

impl FixedServerKey {
    fn smart_floor<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        self.smart_trunc(c, 0)
    }
    fn smart_ceil<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let frac = c.frac();
        if frac == 0 {
            return c.clone();
        } // Now we know frac > 0
        if frac == T::SIZE {
            // The only integer representable is 0, we always round to that
            let res_bits = self.key.create_trivial_zero_radix(T::SIZE as usize / 2usize);
            return T::new(res_bits);
        }
        
        let tmp = self.key.smart_scalar_sub_parallelized(c.bits_mut(), 1u64);
        let mut res = self.smart_floor(&mut T::new(tmp));
        let mut one: Cipher = self.key.create_trivial_radix(1, T::SIZE as usize/2);
        self.key.scalar_left_shift_assign_parallelized(&mut one, c.frac());

        self.key
            .smart_add_assign_parallelized(res.bits_mut(), &mut one);
        res
    }
    fn smart_round<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        let frac = c.frac();
        if frac == 0 {
            return c.clone();
        } // Now we know frac > 0
        if frac == T::SIZE {
            // The only integer representable is 0, we always round to that
            let res_bits = self.key.create_trivial_zero_radix(T::SIZE as usize / 2usize);
            return T::new(res_bits);
        }
        // This is needed because we need to extract the sign bit
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        if T::IS_SIGNED {
            // If the type is signed, the simple `round_tie_to_plus_infinity` does not work
            // Because in Rust, tie should be rounded away from 0
            // Thus we calculate a result which is always correct for negative numbers
            // And one which is always correct for non-negative number
            // Then do an if then else based on the sign bit

            // Extracting the sign bit
            let sign_bit_lut = self.key.key.generate_lookup_table(|x| {
                let x = x % 4;
                (x >> 1) & 1
            });

            let last_block = c.bits()
                .blocks()
                .last()
                .expect("Cannot sign extend an empty ciphertext");

            let sign_bit = self
                .key.key
                .apply_lookup_table(last_block, &sign_bit_lut);


            let (a, b) = rayon::join(
                || {
                    // c < 0
                    // We subtract the smallest number representable by the type (epsilon)
                    // Then perform the round_tie_to_plus_infinity
                    // This only differs from a simple round_tie_to_plus_infinity if c was tied
                    // If that is the case then this will result in c rounding towards -infinity
                    // This is exactly what we want when c < 0
                    let tmp = self.key.smart_scalar_sub_parallelized(c.clone().bits_mut(), 1u64);
                    self.round_tie_to_plus_infinity(&mut T::new(tmp))
                },
                || {
                    // c >= 0
                    self.round_tie_to_plus_infinity(&mut c.clone())
            });
            let res_bits = self.key
                .if_then_else_parallelized(&BooleanBlock::new_unchecked(sign_bit), a.bits(), b.bits());
            T::new(res_bits)
        } else {
            self.round_tie_to_plus_infinity(c)
        }
    }
    fn smart_trunc<T: FixedCiphertextInner>(&self, c: &mut T, prec: usize) -> T {
        let frac: usize = c.frac() as usize;
        if prec > frac {
            panic!("Prec cannot be greater then the Frac of self!");
        }
        let bits_to_lose = frac - prec;
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }
        let mut blocks = c.bits().clone().into_blocks();
        blocks.drain(0..bits_to_lose >> 1);
        if bits_to_lose % 2 == 1 {
            let block = blocks.drain(0..1).collect::<Vec<Ciphertext>>();
            let acc = self.key.key.generate_lookup_table(|x| x & 0b10);

            let ct_res = self.key.key.apply_lookup_table(&block[0], &acc);
            blocks.insert(0, ct_res);
        }
        let mut cipher = Cipher::from_blocks(blocks);
        self.key
            .extend_radix_with_trivial_zero_blocks_lsb_assign(&mut cipher, bits_to_lose >> 1);
        T::new(cipher)
    }

    fn round_tie_to_plus_infinity<T: FixedCiphertextInner>(&self, c: &mut T) -> T {
        if !c.bits().block_carries_are_empty() {
            self.key.full_propagate_parallelized(c.bits_mut());
        }

        let num_blocks = T::SIZE as usize / 2;

        // The main idea is that we take floor(c), then add 1 if the fractional part of c is >= 1/2
        // This is easy to test: just check whether the most significant factional bit is 1 or 0
        // Then create a ciphertext which represents either 1 or 0 (in the type T)
        // This can be done via a single pbs, then trivial blocks of 0

        let to_add_lut = self.key.key
            .generate_lookup_table(|half_block| {
            if T::FRAC % 2 == 1 {
                (half_block & 1) << 1
            } else {
                (half_block >> 1) & 1
            }
        });
        let half_block = &c.bits()
            .blocks()[((T::FRAC-1)/2) as usize];
        let (to_add_bits, mut truncated_c) = rayon::join(
            || {
            let to_add_block = self
                .key.key
                .apply_lookup_table(half_block, &to_add_lut);
            let mut to_add_bits = Cipher::from_blocks(vec![to_add_block]);
            self.key.extend_radix_with_trivial_zero_blocks_lsb_assign(&mut to_add_bits, (T::FRAC/2) as usize);
            self.key.extend_radix_with_trivial_zero_blocks_msb_assign
                (&mut to_add_bits, num_blocks - 1 - (T::FRAC/2) as usize);
            to_add_bits
            }, 
            || {
                self.smart_floor(&mut c.clone())
            }
        );
                    
        self.smart_add_assign(&mut truncated_c, &mut T::new(to_add_bits));
        truncated_c
    }

}

impl<Size, Frac> FheFixedU<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the floor of a ciphertext encrypting a fixed point number.
    /// Rounds to the next integer towards 0.
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_floor(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_floor());
    /// ```
    pub fn smart_floor(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_floor(&mut self.inner),
        }
    }

    /// Computes homomorphically the ceil of a ciphertext encrypting a fixed point number.
    /// Rounds to the next integer towards +∞, wrapping on overflow
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_floor(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_floor());
    /// ```
    pub fn smart_ceil(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_ceil(&mut self.inner),
        }
    }

    /// Homomorphically rounds a ciphertext encrypting a fixed point number to the nearest integer.
    /// Ties are rounded towards +∞, wrapping on overflow
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_round(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_round());
    /// ```
    pub fn smart_round(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_round(&mut self.inner),
        }
    }

    /// Homomorphically truncates a ciphertext encrypting a fixed point number to the given precision.
    /// `prec` has to be between 0 and `Frac`, the number of fractional bits this type has.
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// let clear_a: U8F8 = U8F8::from_num(12.625);
    /// 
    /// //Encrypt:
    /// let mut a = FheU8F8::encrypt(clear_a, &ckey);
    /// 
    /// // We truncate to prec = 1, meaning that only the most signifigant fractional bit is kept
    /// let ct_res = a.smart_trunc(1, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: U8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, U8F8::from_num(12.5));
    /// ```
    pub fn smart_trunc(&mut self, prec: usize, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_trunc(&mut self.inner, prec),
        }
    }
}

impl<Size, Frac> FheFixedI<Size, Frac>
where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
{
    /// Computes homomorphically the floor of a ciphertext encrypting a fixed point number.
    /// Rounds to the next integer towards −∞, wrapping on overflow
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// let clear_a: I8F8 = I8F8::from_num(12.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_floor(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_floor());
    /// ```
    pub fn smart_floor(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_floor(&mut self.inner),
        }
    }

    /// Computes homomorphically the ceil of a ciphertext encrypting a fixed point number.
    /// Rounds to the next integer towards +∞, wrapping on overflow
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// let clear_a: I8F8 = I8F8::from_num(12.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_floor(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_floor());
    /// ```
    pub fn smart_ceil(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_ceil(&mut self.inner),
        }
    }

    /// Homomorphically rounds a ciphertext encrypting a fixed point number to the nearest integer.
    /// Ties are rounded towards +∞, wrapping on overflow
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// let clear_a: I8F8 = I8F8::from_num(12.8);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// 
    /// let ct_res = a.smart_round(&skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, clear_a.wrapping_round());
    /// ```
    pub fn smart_round(&mut self, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_round(&mut self.inner),
        }
    }

    /// Homomorphically truncates a ciphertext encrypting a fixed point number to the given precision.
    /// `prec` has to be between 0 and `Frac`, the number of fractional bits this type has.
    ///
    /// # Warning
    ///
    /// - Multithreaded
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
    /// let clear_a: I8F8 = I8F8::from_num(12.625);
    /// 
    /// //Encrypt:
    /// let mut a = FheI8F8::encrypt(clear_a, &ckey);
    /// 
    /// // We truncate to prec = 1, meaning that only the most signifigant fractional bit is kept
    /// let ct_res = a.smart_trunc(1, &skey);
    ///
    /// // Decrypt:
    /// let dec_result: I8F8 = ct_res.decrypt(&ckey);
    /// assert_eq!(dec_result, I8F8::from_num(12.5));
    /// ```
    pub fn smart_trunc(&mut self, prec: usize, key: &FixedServerKey) -> Self {
        Self {
            inner: key.smart_trunc(&mut self.inner, prec),
        }
    }
}