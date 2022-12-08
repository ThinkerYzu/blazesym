extern crate blazesym;

use blazesym::{BlazeSymbolizer, SymbolSrcCfg};
use std::env;
use std::path;

fn show_usage() {
    let args: Vec<String> = env::args().collect();
    println!("Usage: {} <bin> <src-file> <line>", args[0]);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        show_usage();
        return;
    }

    let bin_name = &args[1];
    let src_name = &args[2];
    let line_no = if let Ok(lno) = usize::from_str_radix(&args[3], 10) {
        lno
    } else {
        show_usage();
        return;
    };
    let sym_srcs = [SymbolSrcCfg::Elf {
        file_name: path::PathBuf::from(bin_name),
        base_address: 0x0,
    }];
    let resolver = BlazeSymbolizer::new().unwrap();

    let lines = resolver.find_line_addresses(&sym_srcs, &[(src_name, line_no)]);
    for addr in &lines[0] {
        println!("{:x}", addr);
    }
}
