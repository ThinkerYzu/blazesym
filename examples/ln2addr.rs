extern crate blazesym;

use blazesym::{BlazeSymbolizer, SymbolSrcCfg, SymbolizerFeature};
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

    let features = vec![SymbolizerFeature::DebugInfoSymbols(true)];
    let resolver = BlazeSymbolizer::new_opt(&features).unwrap();

    let sym_srcs = [SymbolSrcCfg::Elf {
        file_name: path::PathBuf::from(bin_name),
        base_address: 0x0,
    }];

    let lines = resolver.find_line_addresses(&sym_srcs, &[(src_name, line_no)]);
    println!("Addresses of {}:{}", src_name, line_no);
    for addr in &lines[0] {
        println!("    {:x}", addr);
    }
    println!("Total {}", lines[0].len());

    if !lines.is_empty() && !lines[0].is_empty() {
        let addr = lines[0][0];
        println!("");
        println!("Local Variables at {:x}:", addr);
        let all_vars = resolver.get_local_vars(&sym_srcs, &[addr]);
        let vars = &all_vars[0];
        for var in &vars.variables {
            println!("    {}", var.name);
        }
        println!("Total {}", vars.variables.len());
    }
}
