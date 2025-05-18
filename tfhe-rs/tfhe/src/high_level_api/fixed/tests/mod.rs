macro_rules! encrypt_for_test {
    ($LhsBits:expr, $RhsBits:expr,
        $FheFixed:ty, $Fixed:ty, $TrivialEncrypt:expr) => {
        if $TrivialEncrypt {
            let (lhs_fixed, rhs_fixed) = (
                <$Fixed>::from_bits($LhsBits as _),
                <$Fixed>::from_bits($RhsBits as _),
            );
            (
                <$FheFixed>::encrypt_trivial(lhs_fixed, &SKEY),
                <$FheFixed>::encrypt_trivial(rhs_fixed, &SKEY),
                lhs_fixed,
                rhs_fixed,
            )
        } else {
            let (lhs_fixed, rhs_fixed) = (
                <$Fixed>::from_bits($LhsBits as _),
                <$Fixed>::from_bits($RhsBits as _),
            );
            (
                <$FheFixed>::encrypt(lhs_fixed, &CKEY),
                <$FheFixed>::encrypt(rhs_fixed, &CKEY),
                lhs_fixed,
                rhs_fixed,
            )
        }
    };

    ($ClearBits:expr, $FheFixed:ty,
        $Fixed:ty, $TrivialEncrypt:expr) => {
        if $TrivialEncrypt {
            let fixed = <$Fixed>::from_bits($ClearBits as _);
            (<$FheFixed>::encrypt_trivial(fixed, &SKEY), fixed)
        } else {
            let fixed = <$Fixed>::from_bits($ClearBits as _);
            (<$FheFixed>::encrypt(fixed, &CKEY), fixed)
        }
    };
}

// Basic op tests

macro_rules! test_unary_op {
    ($ClearBits:expr,
        $EncryptedMethod:ident, $ClearMethod:ident,
        $FheFixed:ty, $Fixed:ty,
        $TrivialEncrypt:expr) => {
        let (mut lhs, fixed) = encrypt_for_test!($ClearBits, $FheFixed, $Fixed, $TrivialEncrypt);

        let clear_res = <$Fixed>::$ClearMethod(fixed);
        let encrypted_res = <$FheFixed>::$EncryptedMethod(&mut lhs, &SKEY);
        let decrypted_res: $Fixed = <$FheFixed>::decrypt(&encrypted_res, &CKEY);

        assert_eq!(
            clear_res, decrypted_res,
            "expected: {}, got: {}, from: {}",
            clear_res, decrypted_res, $ClearBits,
        );
    };
}

macro_rules! test_bin_op {
    ($LhsBits:expr, $RhsBits:expr,
        $EncryptedMethod:ident, $ClearMethod:ident,
        $FheFixed:ty, $Fixed:ty, $TrivialEncrypt:expr) => {
        let (mut lhs, mut rhs, lhs_fixed, rhs_fixed) =
            encrypt_for_test!($LhsBits, $RhsBits, $FheFixed, $Fixed, $TrivialEncrypt);

        let clear_res = <$Fixed>::$ClearMethod(lhs_fixed, rhs_fixed);
        let encrypted_res = <$FheFixed>::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
        let decrypted_res: $Fixed = <$FheFixed>::decrypt(&encrypted_res, &CKEY);

        assert_eq!(
            clear_res, decrypted_res,
            "expected: {}, got: {}, from: {}, {}",
            clear_res, decrypted_res, $LhsBits, $RhsBits
        );
    };
}

macro_rules! test_sqr {
    ($ClearBits:expr,
        $EncryptedMethod:ident, $ClearMethod:ident,
        $FheFixed:ty, $Fixed:ty,
        $TrivialEncrypt:expr) => {
        let (mut lhs, fixed) = encrypt_for_test!($ClearBits, $FheFixed, $Fixed, $TrivialEncrypt);

        let clear_res = <$Fixed>::$ClearMethod(fixed, fixed);
        let encrypted_res = <$FheFixed>::$EncryptedMethod(&mut lhs, &SKEY);
        let decrypted_res: $Fixed = <$FheFixed>::decrypt(&encrypted_res, &CKEY);

        assert_eq!(
            clear_res, decrypted_res,
            "expected: {}, got: {}, from: {}",
            clear_res, decrypted_res, $ClearBits,
        );
    };
}

macro_rules! test_ilog2 {
    ($ClearBits:expr,
        $EncryptedMethod:ident, $ClearMethod:ident,
        $FheFixed:ty, $Fixed:ty,
        $TrivialEncrypt:expr) => {
        let (mut lhs, fixed) = encrypt_for_test!($ClearBits, $FheFixed, $Fixed, $TrivialEncrypt);

        let clear_res: i32 = <$Fixed>::$ClearMethod(fixed);
        let encrypted_res = <$FheFixed>::$EncryptedMethod(&mut lhs, &SKEY);
        let decrypted_res: i32 = CKEY.key.decrypt_signed_radix(&encrypted_res);

        assert_eq!(
            clear_res, decrypted_res,
            "expected: {}, got: {}, from: {}",
            clear_res, decrypted_res, $ClearBits,
        );
    };
}

macro_rules! test_comp {
    ($LhsBits:expr, $RhsBits:expr,
        $EncryptedMethod:ident, $ClearMethod:ident,
        $FheFixed:ty, $Fixed:ty,
        $TrivialEncrypt:expr) => {
        let (mut lhs, mut rhs, lhs_fixed, rhs_fixed) =
            encrypt_for_test!($LhsBits, $RhsBits, $FheFixed, $Fixed, $TrivialEncrypt);

        let clear_res = <$Fixed>::$ClearMethod(&lhs_fixed, &rhs_fixed);
        let encrypted_res = <$FheFixed>::$EncryptedMethod(&mut lhs, &mut rhs, &SKEY);
        let decrypted_res = CKEY.key.decrypt_bool(&encrypted_res);

        assert_eq!(
            clear_res, decrypted_res,
            "expected: {}, got: {}, from: {}, {}",
            clear_res, decrypted_res, $LhsBits, $RhsBits
        );
    };
}

// Set for unary

macro_rules! test_unary_op_extensive {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) && $MethodName == "sqrt" { continue; }
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_unary_op_exhaustive_u8 {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            if i >= 128 && $MethodName == "sqrt" { continue; }
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };

    (method_name: $MethodName:literal) => {
        test_unary_op_exhaustive_u8!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
    };
}

macro_rules! test_unary_op_random_encrypted {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }

                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) && $MethodName == "sqrt" { continue; }
                            test_unary_op!(i,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }
                )*
            )*
        }
    };
}

// Set for bin

macro_rules! test_bin_op_extensive {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            if $MethodName == "div" && j == 0 { continue; }
                            test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            if $MethodName == "div" && j == 0 { continue; }
                            test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_bin_op_exhaustive_u8 {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            for j in 0..=255u8 {
                                if $MethodName == "div" && j == 0 { continue; }
                                test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    }

                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            for j in 0..=255u8 {
                                if $MethodName == "div" && j == 0 { continue; }
                                test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                    FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    }
                )*
            )*
        }
    };

    (method_name: $MethodName:literal) => {
        test_bin_op_exhaustive_u8!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
    };
}

macro_rules! test_binary_op_random_encrypted {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            if $MethodName == "div" && j == 0 { continue; }
                            test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }

                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            if $MethodName == "div" && j == 0 { continue; }
                            test_bin_op!(i,j,[<smart_ $MethodName>],[<wrapping_ $MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }
                )*
            )*
        }
    };
}

// Set for sqr

macro_rules! test_sqr_extensive {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) { continue; }
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_sqr_exhaustive_u8 {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };

    (method_name: $MethodName:literal) => {
        test_sqr_exhaustive_u8!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
    };
}

macro_rules! test_sqr_random_encrypted {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }

                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) { continue; }
                            test_sqr!(i,[<smart_ $MethodName>],wrapping_mul,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }
                )*
            )*
        }
    };
}

// Set for ilog2

macro_rules! test_ilog2_extensive {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i == 0 {continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) || i == 0 { continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_ilog2_exhaustive_u8 {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            if i == 0 {continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            if i >= 1<<($Size-1) || i == 0 { continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };

    (method_name: $MethodName:literal) => {
        test_ilog2_exhaustive_u8!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
    };
}

macro_rules! test_ilog2_random_encrypted {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i == 0 {continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }

                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            if i >= 1<<($Size-1) || i == 0 { continue; }
                            test_ilog2!(i,[<smart_ $MethodName>],int_log2,
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }
                )*
            )*
        }
    };
}

// Set for comp

macro_rules! test_comp_random_encrypted {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }

                    #[test]
                    fn [<fixed_test_rand_encrypted_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,false);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_comp_extensive {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, iter: $Iter:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ u $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }

                    #[test]
                    fn [<fixed_test_extensive_ $MethodName _ i $Size f $Frac>]() {

                        for _ in 0..$Iter {
                            let i: [<u $Size>] = random();
                            let j: [<u $Size>] = random();
                            test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                        }
                    }
                )*
            )*
        }
    };
}

macro_rules! test_comp_exhaustive_u8 {
    (method_name: $MethodName:literal,
        $((size: $Size:literal, ($($Frac:literal),*))),* $(,)*) => {
        ::paste::paste! {
            $(
                $(
                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ u $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            for j in 0..=255u8 {
                                test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    FheFixedU<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                    ::fixed::[<FixedU $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    }

                    #[test]
                    fn [<fixed_test_exhaustive_ $MethodName _ i $Size f $Frac>]() {

                        for i in 0..=255u8 {
                            for j in 0..=255u8 {
                                test_comp!(i,j,[<smart_ $MethodName>],[<$MethodName>],
                                    FheFixedI<::typenum::[<U $Size>],::typenum::[<U $Frac>]>,
                                    ::fixed::[<FixedI $Size>]<typenum::[<U $Frac>]>,true);
                            }
                        }
                    }
                )*
            )*
        }
    };

    (method_name: $MethodName:literal) => {
        test_comp_exhaustive_u8!(method_name: $MethodName, (size: 8, (0,1,2,3,4,5,6,7,8)));
    };
}

use crate::high_level_api::fixed::{FheFixedI, FheFixedU, FixedClientKey, FixedServerKey};
use rand::random;
use std::sync::LazyLock;

static CKEY: LazyLock<FixedClientKey> = LazyLock::new(|| FixedClientKey::new());
static SKEY: LazyLock<FixedServerKey> = LazyLock::new(|| FixedServerKey::new(&CKEY));

// Testing add

test_bin_op_exhaustive_u8!(method_name: "add");
test_bin_op_extensive!(method_name: "add",
    (size: 64, iter: 1024, (0, 32, 64))
);
test_binary_op_random_encrypted!(method_name: "add",
    (size: 32, iter: 8,
        (0,1,2,4,7,8,16,29,31,32)),
    (size: 16, iter: 8,
        (0,2,3,5,6,8,12,15,16)),
    (size: 64, iter: 8,
        (0, 32, 48, 57, 64))
);

// Testing sub

test_bin_op_exhaustive_u8!(method_name: "sub");
test_bin_op_extensive!(method_name: "sub",
    (size: 64, iter: 1024, (0, 32, 64))
);
test_binary_op_random_encrypted!(method_name: "sub",
    (size: 32, iter: 8,
        (0,1,2,4,7,8,16,29,31,32)),
    (size: 16, iter: 8,
        (0,2,3,5,6,8,12,15,16)),
    (size: 64, iter: 8,
        (0, 32, 48, 57, 64))
);

// Testing mul

test_bin_op_exhaustive_u8!(method_name: "mul");
test_bin_op_extensive!(method_name: "mul",
    (size: 64, iter: 1024, (0, 32, 64))
);
test_binary_op_random_encrypted!(method_name: "mul",
    (size: 16, iter:8,
        (0,1,4,6,8,11,12,16)),
    (size: 32, iter:8,
        (0, 7, 18, 32)),
    (size: 64, iter:2,
        (0, 32, 64)),
    /*(size: 128, iter:2,
        (0, 128))*/
);

// Testing div

// test_bin_op_exhaustive_u8!(method_name: "div"); // This test alone takes absolute ages
test_bin_op_extensive!(method_name: "div",
    (size: 8, iter:1024, (0,1,2,3,4,5,6,7,8)),
    (size: 32, iter: 128, (0,32))
);
test_binary_op_random_encrypted!(method_name: "div",
    (size: 8, iter:8, (0,1,4,6,8)),
    (size: 32, iter:4, (0,32))
);

// Testing sqr

test_sqr_exhaustive_u8!(method_name: "sqr");
test_sqr_extensive!(method_name: "sqr",
    (size: 64, iter:1024, (32, 64))
);
test_sqr_random_encrypted!(method_name: "sqr",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing sqrt

test_unary_op_exhaustive_u8!(method_name: "sqrt");
test_unary_op_extensive!(method_name: "sqrt",
    (size: 64, iter:1024, (32, 64))
);
test_unary_op_random_encrypted!(method_name: "sqrt",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing ilog2

test_ilog2_exhaustive_u8!(method_name: "ilog2");
test_ilog2_extensive!(method_name: "ilog2",
    (size: 64, iter:1024, (32, 64))
);
test_ilog2_random_encrypted!(method_name: "ilog2",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing neg

test_unary_op_exhaustive_u8!(method_name: "neg");
test_unary_op_extensive!(method_name: "neg",
    (size: 64, iter:1024, (32, 64))
);
test_unary_op_random_encrypted!(method_name: "neg",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing floor

test_unary_op_exhaustive_u8!(method_name: "floor");
test_unary_op_extensive!(method_name: "floor",
    (size: 64, iter:1024, (32, 64))
);
test_unary_op_random_encrypted!(method_name: "floor",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing ceil

test_unary_op_exhaustive_u8!(method_name: "ceil");
test_unary_op_extensive!(method_name: "ceil",
    (size: 64, iter:1024, (32, 64))
);
test_unary_op_random_encrypted!(method_name: "ceil",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing round

test_unary_op_exhaustive_u8!(method_name: "round");
test_unary_op_extensive!(method_name: "round",
    (size: 64, iter:1024, (32, 64))
);
test_unary_op_random_encrypted!(method_name: "round",
    (size: 16, iter: 8, (0,1,2,3,4,6,8,12,15,16))
);

// Testing eq

test_comp_exhaustive_u8!(method_name: "eq");
test_comp_extensive!(method_name: "eq",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "eq",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);

// Testing ne

test_comp_exhaustive_u8!(method_name: "ne");
test_comp_extensive!(method_name: "ne",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "ne",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);

// Testing le

test_comp_exhaustive_u8!(method_name: "le");
test_comp_extensive!(method_name: "le",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "le",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);

// Testing lt

test_comp_exhaustive_u8!(method_name: "lt");
test_comp_extensive!(method_name: "lt",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "lt",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);

// Testing ge

test_comp_exhaustive_u8!(method_name: "ge");
test_comp_extensive!(method_name: "ge",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "ge",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);

// Testing gt

test_comp_exhaustive_u8!(method_name: "gt");
test_comp_extensive!(method_name: "gt",
    (size: 16, iter: 1024, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 128, (0, 64))
);
test_comp_random_encrypted!(method_name: "gt",
    (size: 16, iter: 8, (0, 1, 4, 8, 14, 16)),
    (size: 64, iter: 4, (0, 64))
);
