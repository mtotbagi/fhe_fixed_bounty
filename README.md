# README

This repository contains our fully homomorphic implementation of fixed point arithmetic based on [TFHE-rs](https://github.com/zama-ai/tfhe-rs).


## Example usage
An example code using the library can be found in the `fhe_fixed` folder

```rust
use fixed::types::extra::LeEqU128;
use fixed::types::U4F12;
use tfhe::{FheFixedU, FixedCiphertext, FixedClientKey, FixedFrac, FixedServerKey, FixedSize};
use tfhe::FheU4F12;

fn main() {
    
    // Generate the client key and the server key:
    let ckey = FixedClientKey::new();
    let skey = FixedServerKey::new(&ckey);
    
    let clear_one: U4F12 = U4F12::from_num(1);
    let clear_five: U4F12 = U4F12::from_num(5);
    
    // Encrypt:
    let mut one = FheU4F12::encrypt(clear_one, &ckey);
    let mut five = FheU4F12::encrypt(clear_five, &ckey);
    
    // Calculate the golden ratio:
    let mut sqrt_five = five.smart_sqrt(&skey);
    let mut one_plus_sqrt_five = one.smart_add(&mut sqrt_five, &skey);
    let mut half = reciprocal(&mut FheU4F12::encrypt_trivial(2, &skey), &skey);
    let mut golden_ratio = one_plus_sqrt_five
        .smart_mul(&mut half, &skey);

    
    // Decrypt:
    let dec_golden_ratio_precise: U4F12 = golden_ratio.decrypt(&ckey);
    println!("Golden ratio to twelve bits of precision: {:.4}", dec_golden_ratio_precise);

    // We truncate to keep the 4 most significant fractional bits
    let golden_ratio_trunc = golden_ratio.smart_trunc(4, &skey);
    
    // Decrypt:
    let dec_golden_ratio_trunc: U4F12 = golden_ratio_trunc.decrypt(&ckey);
    println!("Golden ratio to four bits of precision: {:.4}", dec_golden_ratio_trunc);

    let golden_ratio_round = golden_ratio.smart_round(&skey);
    let clear_two: U4F12 = golden_ratio_round.decrypt(&ckey);
    println!("Golden ratio rounded is two: {}", clear_two);
}


// We can write functions that work on "any" FheFixedU type
fn reciprocal<Size, Frac>(c: &mut FheFixedU<Size, Frac>, key: &FixedServerKey) -> FheFixedU<Size, Frac>
where Size: FixedSize<Frac> + LeEqU128,
      Frac: FixedFrac + LeEqU128
{
    let trivial_one: FheFixedU::<Size, Frac> = FheFixedU::<Size, Frac>::encrypt_trivial(1u32, key);

    // If the carries are not empty, we propagate
    if c.bits().block_carries_are_empty() {
        c.full_propagate_parallelized(key);
    }

    FheFixedU::<Size, Frac>::unchecked_div(&trivial_one, c, key)
}
```

## API
Below is a list of implemented types and methods for the api.

### Types/Traits
- `FixedClientKey`: A client key for fixed numbers.
- `FixedServerKey`: A server key for fixed numbers.
- `FixedCiphertext`: A trait defining some of the basic operations on `FheFixedU/I`.
- `FheFixedU`: A generic type for unsigned fixed numbers, a specific type would be `FheFixedU<Size, Frac>` where `Size` is even and `Size > Frac`. This then expresses a fixed point number with `Size` bits of which `Frac` are fractional bits.
- `FheFixedI`: A generic type for signed fixed numbers, a specific type would be `FheFixedI<Size, Frac>` where `Size` is even and `Size > Frac`. This then expresses a fixed point number with `Size` bits of which `Frac` are fractional bits.
- `FixedSize`: A trait that expresses the constraints specified above for `Size`.
- `FixedFrac`: A trait that expresses the constraints specified above for `Frac`.
- `FheU{X}F{Y}`: An alias for `FheFixedU<U{X+Y}, U{Y}>`, with $X, Y \geq 0$ and $X+Y \in \{4, 8, 16, 32, 64, 128\}$. An example is `FheU3F5`.
- `FheI{X}F{Y}`: An alias for `FheFixedI<U{X+Y}, U{Y}>`, with $X, Y \geq 0$ and $X+Y \in \{4, 8, 16, 32, 64, 128\}$. An example is `FheI8F24`.

### Methods
All arithmetic operations that are implemented on the types `FheFixedU` and `FheFixedI` are detailed below:
- **add/sub/mul/div:** These come in two flavors `smart` or `unchecked`, and can either assign the result to the `lhs`, or return the result. An example is `smart_add_assign`.
- **eq/ne/gt/ge/lt/le:** The comparison operators also come in `smart` and `unchecked` flavors, but they always return a `BooleanBlock` as their result. An example is `unchecked_ne`.
- **neg/sqrt/sqr/dbl:** These also come in the same two flavors of `smart` and `unchecked`, and they also each have an assign variant that will assign the result to the input, and a normal variant that returns the result. An example is `unchecked_div`.
- **abs:** Absolute value has also has the `smart` and `unchecked` flavors, and will always return the result. The variants therefore are `smart_abs` and `unchecked_abs`.
- **floor/ceil/round/trunc:** These only have a `smart` version that returns the result. An example is `smart_floor`. 
- **ilog2:** This also has two flavors, `smart` and `unchecked`. Returns a *signed* integer (`BaseSignedRadixCiphertext<Ciphertext>`). The variants therefore are `smart_ilog2` and `unchecked_ilog2`.

#### Creating an `FheFixed(U/I)`
This can be done either via encryption, or using an encrypted unsigned integer (`BaseRadixCiphertext<Ciphertext>`) as `bits`

- `encrypt`
- `encrypt_from_bits`
- `encrypt_trivial`
- `encrypt_trivial_from_bits`
- `from_bits`

#### Decryption
There are two decryption functions available:
- `decrypt`

This method can decrypt into any native numeric type (u32, i32, f32,...) or into any `Fixed` type from the `fixed` crate. This may result in some precision lost depending on the input and output types. The result will be wrapped on overflow
- `decrypt_to_bits`

This function decrypts an `FheFixed(U/I)` into a `Vec<u64>` which will contain the bit representation of the input ciphertext. This may be useful if `Size > 128`, when there aren't any native of fixed types which can fully contain the value which was encrypted.

## Tests
We have extensively tested every arithmetic operation. They can be run from the `tfhe` folder with

```bash
cargo +nightly test --release --features=fixed,noise-asserts -- high_level_api::fixed::
```

## Benchmarks
All our benchmarks were tested with smart operations, with the inputs dirty.
Most of our operations have the same runtime as their corresponding integer operation on an integer with the same amount of bits. Below are the timings of those that are different, or have no corresponding integer operation.

The benchmarks can be run with:
```bash
make bench_fixed
make bench_fixed_signed
```


| Operation \ Size                                     | FheU8F8 | FheU16F16 | FheU32F32 |
|--------------------------------------------|---------|----------|----------|
| Double	        | 83.1 ms	| 107.5 ms	| 133.7 ms	| 
| Multiplication	| 275.4 ms	| 407.3 ms	| 781.2 ms	| 
| Square        	| 331.1 ms	| 471.2 ms	| 722.4 ms	| 
| Division			| 2.75 s	| 6.1 s    	| 14.5 s	|
| Square root		| 1.3 s	    | 2.88 s	| 7.18 s	|
| Log2				| 264.3 ms	| 312.8 ms	| 409.7 ms	|
| Floor				| 82.9 ms	| 106.7 ms	| 134.5 ms	|
| Ceil				| 165.9 ms	| 214.9 ms	| 270.2 ms	|
| Round				| 101.5 ms	| 125.4 ms	| 152.9 ms	|
| Truncate			| 98.3 ms	| 124.6 ms	| 155 ms	|


## Implementation

The types `FheFixedU<Size, Frac>` and `FheFixedI<Size, Frac>` are wrapper types around `InnerFheFixedU<Size, Frac>` and `InnerFheFixedI<Size, Frac>` respectively.

The need for wrapper types arises from the fact that for the implementation of the actual operations, one needs a mutable reference for the `bits` field of `InnerFheFixed(U/I)<Size, Frac>`, which is an encrypted unsigned integer (`BaseRadixCiphertext<Ciphertext>`). Through this one can modify the size of the `bits`, which would then not be equal to the `Size` type parameter!
Thus a mutable reference to `bits` cannot be exposed in the API, hence the wrapper types.

`FixedServerKey` and `FixedClientKey` are just wrappers around `integer::ServerKey` and `integer::ClientKey`, with the restriction that the parameter used is: `:shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`.


## Special operations

There are a few operations in our submission that are neither strictly better or worse than their alternatives but instead have a different scaling with the number of cores/size of the numbers on which they operate.

### Sqr

The square (`sqr`) opertation was implemented for the special case of multiplication when a number is multiplied by itself. While sqr has slightly worse performance on small numbers when many cores are availabe, however on larger numbers, or when one has only a few cores it has better performance.

On the aws server this gain is only visible on the largest benchmarked numbers, on personal computers (or servers with many of their cores already occupied) however `sqr` is always faster than `mul`.

### Div

Our implementation of `div` has almost the same performance as the already existing implementation on smaller numbers, however just like `sqr` it has better scaling in situations where there are limited computational resources available.

Furthermore our implementation could be sped up even more if there was a way to move a `BooleanBlock`'s bit into the carry space without incurring noise. This fix would make our implementation of div strictly faster than the already existing implementation.