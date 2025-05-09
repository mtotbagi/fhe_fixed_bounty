#![allow(dead_code)]

#[path = "../utilities.rs"]
mod utilities;

use crate::utilities::{BenchmarkType, BENCH_TYPE};
use criterion::{criterion_group, Criterion};
use rand::prelude::*;
use std::env;

use tfhe::{FheFixedU, FixedClientKey, FixedServerKey, FixedSize, FixedFrac};
use std::sync::LazyLock;

use typenum::{U8, U16, U32, U64};
/// The type used to hold scalar values
/// It must be as big as the largest bit size tested
type ScalarType = u128;

const PARAM: tfhe::shortint::ClassicPBSParameters =
    tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    static CKEY: LazyLock<FixedClientKey> = LazyLock::new(|| FixedClientKey::new());
    static SKEY: LazyLock<FixedServerKey> = LazyLock::new(|| FixedServerKey::new(&CKEY));


fn gen_random_u128(rng: &mut ThreadRng) -> u128 {
    rng.gen::<u128>()
}

/// Base function to bench a server key function that is a binary operation, input ciphertexts will
/// contain non zero carries
fn bench_server_key_binary_function_dirty_inputs<F, Size, Frac>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
    F: Fn(&mut FheFixedU<Size, Frac>, &mut FheFixedU<Size, Frac>, &FixedServerKey),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    let size = Size::USIZE;
    let frac = Frac::USIZE;
    let num_block = size / 2;

    let bench_id = format!("{bench_name}::{size}::{frac}");
    bench_group.bench_function(&bench_id, |b| {

        let encrypt_two_values = || {
            let clear_0 = gen_random_u128(&mut rng);
            let mut ct_0 = CKEY.key.encrypt_radix(clear_0, num_block);

            let clear_1 = gen_random_u128(&mut rng);
            let mut ct_1 = CKEY.key.encrypt_radix(clear_1, num_block);

            // Raise the degree, so as to ensure worst case path in operations
            let mut carry_mod = PARAM.carry_modulus.0;
            while carry_mod > 0 {
                // Raise the degree, so as to ensure worst case path in operations
                let clear_2 = gen_random_u128(&mut rng);
                let ct_2 = CKEY.key.encrypt_radix(clear_2, num_block);
                SKEY.key.unchecked_add_assign(&mut ct_0, &ct_2);
                SKEY.key.unchecked_add_assign(&mut ct_1, &ct_2);

                carry_mod -= 1;
            }

            (FheFixedU::<Size, Frac>::from_bits(ct_0, &SKEY), FheFixedU::<Size, Frac>::from_bits(ct_1, &SKEY))
        };

        b.iter_batched(
            encrypt_two_values,
            |(mut ct_0, mut ct_1)| {
                binary_op(&mut ct_0, &mut ct_1, &SKEY);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    bench_group.finish()
}

/// Base function to bench a server key function that is a binary operation, input ciphertext will
/// contain only zero carries
fn bench_server_key_binary_function_clean_inputs<F, Size, Frac>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    binary_op: F,
) where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
    F: Fn(&mut FheFixedU<Size, Frac>, &mut FheFixedU<Size, Frac>, &FixedServerKey),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    let size = Size::USIZE;
    let frac = Frac::USIZE;
    let num_block = size / 2;

    let bench_id = format!("{bench_name}::{size}::{frac}");
    bench_group.bench_function(&bench_id, |b| {

        let encrypt_two_values = || {
            let clear_0 = gen_random_u128(&mut rng);
            let ct_0 = CKEY.key.encrypt_radix(clear_0, num_block);

            let clear_1 = gen_random_u128(&mut rng);
            let ct_1 = CKEY.key.encrypt_radix(clear_1, num_block);

            (FheFixedU::<Size, Frac>::from_bits(ct_0, &SKEY), FheFixedU::<Size, Frac>::from_bits(ct_1, &SKEY))
        };

        b.iter_batched(
            encrypt_two_values,
            |(mut ct_0, mut ct_1)| {
                binary_op(&mut ct_0, &mut ct_1, &SKEY);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    bench_group.finish()
}

/// Base function to bench a server key function that is a unary operation, input ciphertexts will
/// contain non zero carries
fn bench_server_key_unary_function_dirty_inputs<F, Size, Frac>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    unary_op: F,
) where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
    F: Fn(&mut FheFixedU<Size, Frac>, &FixedServerKey),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    let size = Size::USIZE;
    let frac = Frac::USIZE;
    let num_block = size / 2;

    let bench_id = format!("{bench_name}::{size}::{frac}");
    bench_group.bench_function(&bench_id, |b| {

        let encrypt_value = || {
            let clear_0 = gen_random_u128(&mut rng);
            let mut ct_0 = CKEY.key.encrypt_radix(clear_0, num_block);

            // Raise the degree, so as to ensure worst case path in operations
            let mut carry_mod = PARAM.carry_modulus.0;
            while carry_mod > 0 {
                // Raise the degree, so as to ensure worst case path in operations
                let clear_2 = gen_random_u128(&mut rng);
                let ct_2 = CKEY.key.encrypt_radix(clear_2, num_block);
                SKEY.key.unchecked_add_assign(&mut ct_0, &ct_2);

                carry_mod -= 1;
            }

            FheFixedU::<Size, Frac>::from_bits(ct_0, &SKEY)
        };

        b.iter_batched(
            encrypt_value,
            |mut ct_0| {
                unary_op(&mut ct_0, &SKEY);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    bench_group.finish()
}

/// Base function to bench a server key function that is a unary operation, input ciphertext will
/// contain only zero carries
fn bench_server_key_unary_function_clean_inputs<F, Size, Frac>(
    c: &mut Criterion,
    bench_name: &str,
    display_name: &str,
    unary_op: F,
) where
    Size: FixedSize<Frac>,
    Frac: FixedFrac,
    F: Fn(&mut FheFixedU<Size, Frac>, &FixedServerKey),
{
    let mut bench_group = c.benchmark_group(bench_name);
    bench_group
        .sample_size(15)
        .measurement_time(std::time::Duration::from_secs(60));
    let mut rng = rand::thread_rng();

    let size = Size::USIZE;
    let frac = Frac::USIZE;
    let num_block = size / 2;

    let bench_id = format!("{bench_name}::{size}::{frac}");
    bench_group.bench_function(&bench_id, |b| {

        let encrypt_value = || {
            let clear_0 = gen_random_u128(&mut rng);
            let ct_0 = CKEY.key.encrypt_radix(clear_0, num_block);

            FheFixedU::<Size, Frac>::from_bits(ct_0, &SKEY)
        };

        b.iter_batched(
            encrypt_value,
            |mut ct_0| {
                unary_op(&mut ct_0, &SKEY);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    bench_group.finish()
}


macro_rules! define_server_key_bench_unary_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_dirty_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, server_key| {
                    lhs.$server_key_method(server_key);
            })
        }
    }
);

macro_rules! define_server_key_bench_unary_default_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_clean_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, server_key| {
                    lhs.$server_key_method(server_key);
            })
        }
    }
);

macro_rules! define_server_key_bench_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_function_dirty_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, rhs, server_key| {
                    lhs.$server_key_method(rhs, server_key);
                }
            )
        }
    }
);

macro_rules! define_server_key_bench_default_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_binary_function_clean_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, rhs, server_key| {
                    lhs.$server_key_method(rhs, server_key);
            })
        }
    }
);

macro_rules! define_server_key_bench_trunc_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_dirty_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, server_key| {
                    lhs.$server_key_method(5, server_key);
            })
        }
    }
);

macro_rules! define_server_key_bench_trunc_default_fn (
    (method_name: $server_key_method:ident, display_name:$name:ident) => {
        fn $server_key_method(c: &mut Criterion) {
            bench_server_key_unary_function_clean_inputs::<_, U16, U8>(
                c,
                concat!("fixed::", stringify!($server_key_method)),
                stringify!($name),
                |lhs, server_key| {
                    lhs.$server_key_method(5, server_key);
            })
        }
    }
);

// TODO roundings


define_server_key_bench_fn!(method_name: smart_add, display_name: add);
define_server_key_bench_fn!(method_name: smart_sub, display_name: sub);
define_server_key_bench_fn!(method_name: smart_mul, display_name: mul);
define_server_key_bench_fn!(method_name: smart_div, display_name: div);

define_server_key_bench_default_fn!(method_name: unchecked_add, display_name: add);
define_server_key_bench_default_fn!(method_name: unchecked_sub, display_name: sub);
define_server_key_bench_default_fn!(method_name: unchecked_mul, display_name: mul);
define_server_key_bench_default_fn!(method_name: unchecked_div, display_name: div);

define_server_key_bench_unary_fn!(method_name: smart_neg, display_name: negation);
define_server_key_bench_unary_fn!(method_name: smart_abs, display_name: abs);
define_server_key_bench_unary_fn!(method_name: smart_ilog2, display_name: ilog2);
define_server_key_bench_unary_fn!(method_name: smart_sqrt, display_name: sqrt);

define_server_key_bench_unary_default_fn!(method_name: unchecked_neg, display_name: negation);
define_server_key_bench_unary_default_fn!(method_name: unchecked_abs, display_name: abs);
define_server_key_bench_unary_default_fn!(method_name: unchecked_ilog2, display_name: ilog2);
define_server_key_bench_unary_default_fn!(method_name: unchecked_sqrt, display_name: sqrt);

define_server_key_bench_default_fn!(method_name: unchecked_eq, display_name: equal);
define_server_key_bench_default_fn!(method_name: unchecked_ne, display_name: not_equal);
define_server_key_bench_default_fn!(method_name: unchecked_lt, display_name: less_than);
define_server_key_bench_default_fn!(method_name: unchecked_le, display_name: less_or_equal);
define_server_key_bench_default_fn!(method_name: unchecked_gt, display_name: greater_than);
define_server_key_bench_default_fn!(method_name: unchecked_ge, display_name: greater_or_equal);

define_server_key_bench_fn!(method_name: smart_eq, display_name: equal);
define_server_key_bench_fn!(method_name: smart_ne, display_name: not_equal);
define_server_key_bench_fn!(method_name: smart_lt, display_name: less_than);
define_server_key_bench_fn!(method_name: smart_le, display_name: less_or_equal);
define_server_key_bench_fn!(method_name: smart_gt, display_name: greater_than);
define_server_key_bench_fn!(method_name: smart_ge, display_name: greater_or_equal);

define_server_key_bench_unary_fn!(method_name: smart_floor, display_name: floor);
define_server_key_bench_unary_fn!(method_name: smart_ceil, display_name: ceil);
define_server_key_bench_unary_fn!(method_name: smart_round, display_name: round);
define_server_key_bench_trunc_fn!(method_name: smart_trunc, display_name: trunc);

// define_server_key_bench_unary_default_fn!(method_name: unchecked_floor, display_name: floor);
// define_server_key_bench_unary_default_fn!(method_name: unchecked_ceil, display_name: ceil);
// define_server_key_bench_unary_default_fn!(method_name: unchecked_round, display_name: round);
// define_server_key_bench_trunc_default_fn!(method_name: unchecked_trunc, display_name: trunc);

criterion_group!(
    smart_ops,
    smart_neg,
    smart_add,
    smart_sub,
    smart_mul,
    smart_div,
    smart_sqrt,
    smart_abs,
    smart_ilog2,
);

criterion_group!(
    smart_ops_comp,
    smart_eq,
    smart_ne,
    smart_lt,
    smart_le,
    smart_gt,
    smart_ge,
);

criterion_group!(
    smart_ops_round,
    smart_floor,
    smart_ceil,
    smart_round,
    smart_trunc,
);

criterion_group!(
    unchecked_ops,
    unchecked_neg,
    unchecked_add,
    unchecked_sub,
    unchecked_mul,
    unchecked_div,
    unchecked_sqrt,
    unchecked_abs,
    unchecked_ilog2,
);

criterion_group!(
    unchecked_ops_comp,
    unchecked_eq,
    unchecked_ne,
    unchecked_lt,
    unchecked_le,
    unchecked_gt,
    unchecked_ge,
);

// criterion_group!(
//     unchecked_ops_round,
//     unchecked_floor,
//     unchecked_ceil,
//     unchecked_round,
//     unchecked_trunc,
// );

fn go_through_cpu_bench_groups(val: &str) {
    match val.to_lowercase().as_str() {
        "smart" => {
            smart_ops();
            smart_ops_comp();
            smart_ops_round();
        }
        "unchecked" => {
            unchecked_ops();
            unchecked_ops_comp();
            // unchecked_ops_round();
        }
        _ => {
            smart_ops();
            smart_ops_comp();
            smart_ops_round();
        },
    };
}


fn main() {
    BENCH_TYPE.get_or_init(|| BenchmarkType::from_env().unwrap());

    match env::var("__TFHE_RS_BENCH_OP_FLAVOR") {
        Ok(val) => {
            go_through_cpu_bench_groups(&val);
        }
        Err(_) => {
            smart_ops();
            smart_ops_comp();
            smart_ops_round();
        }
    };

    Criterion::default().configure_from_args().final_summary();
}
