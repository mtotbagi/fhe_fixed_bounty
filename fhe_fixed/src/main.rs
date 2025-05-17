use std::io;
use std::time::Instant;

extern crate fixed as fixed_crate;

#[allow(unused_imports)]
use fixed_crate::types::{U0F16, U8F8, U10F6, U11F5, U12F4, U16F0};
#[allow(unused_imports)]
use fixed_crate::{FixedU8, FixedU16, FixedU128};
#[allow(unused_imports)]
use tfhe::integer::IntegerCiphertext;
use tfhe::shortint::ClassicPBSParameters;
use typenum::U1;
#[allow(unused_imports)]
use typenum::{
    B0, B1, Bit, Cmp, Diff, IsGreater, IsGreaterOrEqual, PowerOfTwo, Same, True, U0, U2, U3, U4,
    U5, U6, U8, U10, U11, U15, U16, U32, U1000, UInt, Unsigned,
};

pub const PARAM: ClassicPBSParameters =
    tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
pub type Cipher = tfhe::integer::ciphertext::BaseRadixCiphertext<tfhe::shortint::Ciphertext>;

mod fhe_testing_macros;
mod fixed;
mod tests;
use crate::fixed::*;

fn main() {
    type FracType = U1;
    type ClearFixed = FixedU8<FracType>;
    test_func_manual!(U8, FracType, ck, server_key,          // Type of the operation, and key names
        {
            a.smart_round(&server_key)
            // let mut res = a.clone();
            // server_key.key.smart_div_assign_parallelized(res.inner.bits_mut(), b.inner.bits_mut());
            // res
        },               // The operation to test
        ClearFixed::from_num(clear_a).int_log2(),               // A ground truth to compare to, optional
        | clear_a, a |                      // The clear and encrypted name(s) of relevant variables
        // iters                                        // The name(s) of variables that are only used as clear
    );
}