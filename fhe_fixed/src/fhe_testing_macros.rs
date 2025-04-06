#[macro_export]
macro_rules! print_request_for_line {
    ($input_str:expr) => {
        println!("Please input {}:", $input_str);
    };
    () => {
        println!("Please give next input:");
    }
}

#[macro_export]
macro_rules! read_line {
    ($input:ident) => {
        let mut $input = String::new();
        io::stdin()
            .read_line(&mut $input)
            .expect("Failed to read line");
    };
}

#[macro_export]
macro_rules! parse_num {
    // TODO maybe implement a binary parsing -> can't parse binary fractionals
    ($input:ident) => {
        $input.trim().parse().expect("Please type a number!")
    };
}


#[macro_export]
macro_rules! get_input_number {
    ($input_name:ident, $Input_type:ty, $input_str:expr) => {
        print_request_for_line!($input_str);
        read_line!(input);
        let $input_name: $Input_type = parse_num!(input);
    };
    ($input_name:ident, $input_str:expr) => {
        print_request_for_line!($input_str);
        read_line!(input);
        let $input_name = parse_num!(input);
    };
    ($input_name:ident, $Input_type:ty) => {
        print_request_for_line!();
        read_line!(input);
        let $input_name: $Input_type = parse_num!(input);
    };
    ($input_name:ident) => {
        print_request_for_line!();
        read_line!(input);
        let $input_name = parse_num!(input);
    };
    ($input_str:expr) => {
        {
            print_request_for_line!($input_str);
            read_line!(input);
            parse_num!(input);
        }
    };
    () => {
        {
            print_request_for_line!();
            read_line!(input);
            parse_num!(input);
        }
    };
}

#[macro_export]
macro_rules! measure_print {
    ($($action:stmt),*; $description:expr) => {
        let now = Instant::now();
        $(
            $action
        )*
        let elapsed = now.elapsed();
        println!("Time for {}: {:.2?}", $description, elapsed);
    };
}

#[macro_export]
macro_rules! print_result {
    ($client_key:ident, $encrypted:expr, $name:expr, $total_size:expr, $frac_size:expr) => {
        let clear = $encrypted.decrypt(&$client_key);
        print_result!(clear, $name, $total_size, $frac_size)
    };
    ($result:expr, $name:expr, $total_size:expr, $frac_size:expr) => {
        println!("{:0total$.frac$b}", $result, total = $total_size + 1, frac = $frac_size);
        println!("{}: {:name_length$}", $name, $result, name_length = $total_size - ($name).len() - 1);
    };
}

#[macro_export]
macro_rules! test_func_manual {
    ($Size:ty, $Frac:ty, $client_key:ident, $server_key:ident, $func:expr, | $( $clear:ident, $encrypted:ident );* | $( $always_clear:ident ),*) => {
        type FheType = FheFixedU<$Size, $Frac>;
        let $client_key = FixedClientKey::new();
        let $server_key = FixedServerKey::new(&$client_key);

        // Get the inputs
        $(
            get_input_number!($clear, f64, stringify!($clear));
        )*
        $(
            get_input_number!($always_clear, stringify!($always_clear));
        )*

        // encrypt inputs that should be encrypted
        measure_print!(
            $(
                #[allow(unused_mut)]
                let mut $encrypted = FheType::encrypt($clear, &$client_key)
            ),*
        ; "encrypting the inputs");

        println!("Please wait!");

        // get the result of the function we are testing
        measure_print!(
            let result = $func
        ; "computing the result");
            
        println!("Please inspect the results:");

        let u = <$Size>::USIZE;
        let f = <$Frac>::USIZE;
        
        $(
            print_result!($client_key, $encrypted, stringify!($encrypted), u, f);
        )*
        print_result!($client_key, result, "result", u, f);
    };
    ($Size:ty, $Frac:ty, $client_key:ident, $server_key:ident, $func:expr, $gt:expr, | $( $clear:ident, $encrypted:ident );* | $( $always_clear:ident ),*) => {
        test_func_manual!($Size, $Frac, $client_key, $server_key, $func, | $( $clear, $encrypted );* | $( $always_clear ),*);
        let u = <$Size>::USIZE;
        let f = <$Frac>::USIZE;
        print_result!($gt, "gt", u, f);
    };
}