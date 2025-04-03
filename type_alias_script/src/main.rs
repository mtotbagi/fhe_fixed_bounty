use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn generate_type_aliases(n: u32) -> String {
    let mut result = String::new();
    
    for i in 0..=n {
        let type_line = format!(
            "pub type FheU{}F{} = FheFixedU<U{}, U{}>;\n",
            n - i, i, n, i
        );
        result.push_str(&type_line);
    }
    
    result
}

fn generate_and_write_type_aliases(numbers: &[u32], output_file: &str) -> std::io::Result<()> {
    let path = Path::new(output_file);
    let mut file = File::create(path)?;
    
    let mut all_aliases = String::new();
    
    for i in 0..numbers.len() {
        let n = numbers[i];
        let aliases = generate_type_aliases(n);
        all_aliases.push_str(&aliases);
        if i != numbers.len()-1 {
            all_aliases.push('\n');
        }
    }
    
    file.write_all(all_aliases.as_bytes())?;
    Ok(())
}

fn main() -> std::io::Result<()>{
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Too few arguments!");
        return Ok(());
    }
    
    let output_file = &args[1];
    
    let numbers: Vec<u32> =
        args[2..].iter()
            .filter_map(|arg| arg.parse::<u32>().ok())
            .collect();
    
    generate_and_write_type_aliases(&numbers, output_file)
}