#![allow(dead_code)]
use rayon::prelude::*;
use crate::integer::IntegerRadixCiphertext;
use crate::integer::{ClientKey, ServerKey};
use crate::shortint::ClassicPBSParameters;
use crate::shortint::parameters::Degree;

pub mod aliases;
pub mod traits;
mod arb_fixed;
mod types;
mod encrypt_decrypt;

mod ops;


pub use traits::{FixedCiphertext, FixedSize, FixedFrac};
pub use types::{FheFixedI, FheFixedU};
pub(crate) use traits::FixedCiphertextInner;

pub(crate) const PARAM: ClassicPBSParameters =
    crate::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub(crate) type Cipher = crate::integer::ciphertext::BaseRadixCiphertext<crate::shortint::Ciphertext>;

pub struct FixedServerKey {
    pub key: ServerKey,
}

impl FixedServerKey {
    pub fn new(cks: &FixedClientKey) -> FixedServerKey {
        FixedServerKey {
            key: ServerKey::new_radix_server_key(&cks.key),
        }
    }
}

pub(crate) fn print_if_trivial<T: FixedCiphertext>(c: &T) {
    if c.bits().is_trivial() {
        let a: u32 = c.bits().decrypt_trivial().unwrap();
        let size = c.size() as usize;
        println!("Size: {}, Frac: {}, Bits:", c.size(), c.frac());
        println!("{:0size$b}", a);
        println!("{}", a);
    }
}

pub struct FixedClientKey {
    pub key: ClientKey,
}

impl FixedClientKey {
    pub fn new() -> FixedClientKey {
        FixedClientKey {
            key: ClientKey::new(PARAM),
        }
    }
}

macro_rules! fhe_fixed_propagate {
    ($FheFixed:ident) => {
        impl<Size, Frac> $FheFixed<Size, Frac>
        where
            Size: traits::FixedSize<Frac>,
            Frac: traits::FixedFrac,
        {
            pub fn full_propagate_parallelized(&mut self, key: &FixedServerKey) {
                key.key.full_propagate_parallelized(self.inner.bits_mut());
            }
        }
    };
}

fhe_fixed_propagate!(FheFixedU);
fhe_fixed_propagate!(FheFixedI);



/// Given an array ciphertexts, propagates them in parallel, if their block carries are not empty
pub(crate) fn propagate_if_needed_parallelized<T: IntegerRadixCiphertext>(
    ciphertexts: &mut [&mut T],
    key: &ServerKey,
) {
    ciphertexts
        .par_iter_mut()
        .filter(|cipher| !cipher.block_carries_are_empty())
        .for_each(|cipher| key.full_propagate_parallelized(*cipher));
}

/// Performs a left shift by scalar amount on the input ciphertext.
///
/// If the scalar is negative it will perfom a right shift instead.
///
/// ## Extra Behaviour
/// Unlike normal shifts which change the degrees in a somewhat arbitrary fashion,
/// this function will give them a reliable value.
///
/// However this function does not parse degrees as the `max value` instead it
/// interprets degree as `bits potentially set`.
///
/// As an example if the degree is 2 (so 10b), then normally the encrypted number
/// can be 0 (00b), 1 (01b), or 2 (10b). For the purposes of this function however
/// a degree of 2 means that the encrypted number is either 2 or 0, since the
/// 2's bit could be set whereas the 1's bit can not be set.
///
/// ## Warning
/// This only works on unsigned ciphertexts right now, may change in the future
pub(crate) fn unchecked_signed_scalar_left_shift_parallelized<T>(
    key: &ServerKey,
    ct: &T,
    scalar: isize,
) -> T
where
    T: IntegerRadixCiphertext,
{
    // bunch of helper values for ease of use
    let mut result = ct.clone();
    let shift = scalar.abs() as usize;
    let modulus = key.message_modulus().0 as u64;
    let log_modulus = key.message_modulus().0.ilog2() as usize;
    let blocks_shifted = shift / log_modulus;
    let bits_shifted = shift % log_modulus;

    // save the old degrees, we do our own calculation on them
    let mut degrees = ct
        .blocks()
        .iter()
        .map(|block| block.degree.get())
        .collect::<Vec<u64>>();

    // if scalar is positive, it is a left shift, otherwise a right shift
    if scalar >= 0 {
        // use built-in shift for the cipher
        key.unchecked_scalar_left_shift_assign_parallelized(&mut result, shift);

        // numbering of blocks is backwards in this library, so we do a right rotate, by the amount of full blocks shifted
        degrees.rotate_right(blocks_shifted);
        //since there is no vec_shift, we manually set the start to 0 after a rotate
        for i in 0..blocks_shifted {
            degrees[i] = 0;
        }

        // we do a left shift on each block, propagating the bits that get moved between blocks
        let mut carry = 0u64;
        for i in 0..degrees.len() {
            (carry, degrees[i]) = (
                (degrees[i] << bits_shifted) >> log_modulus,
                (degrees[i] << bits_shifted) % modulus + carry,
            );
        }
    } else {
        // same as left shift, but in the other direction
        key.unchecked_scalar_right_shift_assign_parallelized(&mut result, shift);

        degrees.rotate_left(blocks_shifted);
        for i in degrees.len() - blocks_shifted..degrees.len() {
            degrees[i] = 0;
        }
        let mut carry = 0u64;
        for i in (0..degrees.len()).rev() {
            (carry, degrees[i]) = (
                ((degrees[i] << log_modulus) >> bits_shifted) % modulus,
                (degrees[i] >> bits_shifted) + carry,
            );
        }
    }

    // we overwrite the (potentially faulty) degrees of the built-in by our own (correct) degrees
    result
        .blocks_mut()
        .iter_mut()
        .zip(degrees.into_iter())
        .for_each(|(block, deg)| block.degree = Degree::new(deg));
    result
}
