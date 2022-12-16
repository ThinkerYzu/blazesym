//! Find local variables of functions.
use super::constants;
use super::debug_info;
use crate::elf::Elf64Parser;
use crate::tools::{decode_udword, decode_uhalf, decode_uword, extract_string};
use std::collections::HashMap;

/// Check if a lexical block contains the given address.
///
/// The address ranges of a lexical block are defined by either
/// (lo_pc, hi_pc) or an address range list.
fn lex_contain_addr(
    parser: &Elf64Parser,
    uhdr: &debug_info::UnitHeader,
    base_addr: u64,
    die: &mut debug_info::DIE,
    address: u64,
) -> bool {
    let mut lo_pc: u64 = 0;
    let mut hi_pc: u64 = 0;
    let mut ranges_ptr: Option<usize> = None;
    let mut base_addr = base_addr;

    for (name, _form, _opt, value) in die {
        match name {
            constants::DW_AT_lo_pc => match value {
                debug_info::AttrValue::Unsigned(v) => {
                    lo_pc = v;
                }
                debug_info::AttrValue::Unsigned128(v) => {
                    lo_pc = v as u64;
                }
                _ => {}
            },
            constants::DW_AT_hi_pc => match value {
                debug_info::AttrValue::Unsigned(v) => {
                    hi_pc = v;
                }
                debug_info::AttrValue::Unsigned128(v) => {
                    hi_pc = v as u64;
                }
                _ => {}
            },
            constants::DW_AT_ranges => match value {
                debug_info::AttrValue::Unsigned(v) => {
                    ranges_ptr = Some(v as usize);
                }
                debug_info::AttrValue::Unsigned128(v) => {
                    ranges_ptr = Some(v as usize);
                }
                _ => {}
            },
            _ => {}
        }
    }

    // Have low & high PC.
    if hi_pc != 0 && lo_pc <= address && address <= (lo_pc + hi_pc) {
        return true;
    }

    // Have an address range list.
    if let Some(ranges_ptr) = ranges_ptr {
        let ranges_idx = if let Ok(idx) = parser.find_section(".debug_ranges") {
            idx
        } else {
            return false;
        };
        let ranges = if let Ok(data) = parser.read_section_raw_cache(ranges_idx) {
            data
        } else {
            return false;
        };
        let rnglst = &ranges[(ranges_ptr as usize)..];
        let mut off = 0;

        let addr_sz = uhdr.address_size();
        match addr_sz {
            0x4 => {
                while off < rnglst.len() {
                    if off + 4 > rnglst.len() {
                        return false;
                    }
                    let begin = decode_uword(&rnglst[off..]);
                    off += 4;

                    if off + 4 > rnglst.len() {
                        return false;
                    }
                    let end = decode_uword(&rnglst[off..]);
                    off += 4;

                    if begin == 0xffffffff {
                        // Change base address
                        base_addr = end as u64;
                    } else if begin == 0x0 && end == 0x0 {
                        // End of the list
                        break;
                    } else {
                        if (base_addr + begin as u64) <= address
                            && address < (base_addr + end as u64)
                        {
                            return true;
                        }
                    }
                }
            }
            0x8 => {
                while off < rnglst.len() {
                    if off + 8 > rnglst.len() {
                        return false;
                    }
                    let begin = decode_udword(&rnglst[off..]);
                    off += 8;

                    if off + 8 > rnglst.len() {
                        return false;
                    }
                    let end = decode_udword(&rnglst[off..]);
                    off += 8;

                    if begin == 0xffffffffffffffff {
                        // Change base address
                        base_addr = end;
                    } else if begin == 0x0 && end == 0x0 {
                        // End of the list
                        break;
                    } else {
                        if (base_addr + begin) <= address && address < (base_addr + end) {
                            return true;
                        }
                    }
                }
            }
            _ => {
                // Unsupported
                return false;
            }
        }
    }

    false
}

/// Find the given address in the location list and return the
/// expression.
///
/// Check p167 of <https://dwarfstd.org/doc/DWARF4.pdf>
fn find_loclist(
    loc_data: &[u8],
    address_size: usize,
    base_addr: u64,
    off: usize,
    address: u64,
) -> Option<&[u8]> {
    let mut base_addr = base_addr;
    let mut off = off;

    match address_size {
        0x4 => {
            while off < loc_data.len() {
                if (off + 4) > loc_data.len() {
                    break;
                }
                let begin = decode_uword(&loc_data[off..]);
                off += 4;

                if (off + 4) > loc_data.len() {
                    break;
                }
                let end = decode_uword(&loc_data[off..]);
                off += 4;

                if begin == 0xffffffff {
                    base_addr = end as u64;
                } else if begin == 0x0 && end == 0x0 {
                    break;
                } else {
                    if (off + 2) > loc_data.len() {
                        return None;
                    }
                    let expr_sz = decode_uhalf(&loc_data[off..]);
                    off += 2;

                    if (off + expr_sz as usize) > loc_data.len() {
                        break;
                    }
                    let expr = &loc_data[off..(off + expr_sz as usize)];
                    off += expr_sz as usize;

                    if (base_addr + begin as u64) <= address && address < (base_addr + end as u64) {
                        return Some(expr);
                    }
                }
            }
        }
        0x8 => {
            while off < loc_data.len() {
                if (off + 8) > loc_data.len() {
                    break;
                }
                let begin = decode_udword(&loc_data[off..]);
                off += 8;

                if (off + 8) > loc_data.len() {
                    break;
                }
                let end = decode_udword(&loc_data[off..]);
                off += 8;

                if begin == 0xffffffffffffffff {
                    base_addr = end;
                } else if begin == 0x0 && end == 0x0 {
                    break;
                } else {
                    if (off + 2) > loc_data.len() {
                        return None;
                    }
                    let expr_sz = decode_uhalf(&loc_data[off..]);
                    off += 2;

                    if (off + expr_sz as usize) > loc_data.len() {
                        break;
                    }
                    let expr = &loc_data[off..(off + expr_sz as usize)];
                    off += expr_sz as usize;

                    if (base_addr + begin) <= address && address < (base_addr + end) {
                        return Some(expr);
                    }
                }
            }
        }
        _ => {
            // Unsupported
        }
    }
    None
}

fn variable_name_loc<'a, 'b>(
    address_size: usize,
    base_addr: u64,
    die: &'a mut debug_info::DIE<'b>,
    debug_str: &'b [u8],
    loc_data: &'b [u8],
    address: u64,
) -> (String, &'b [u8]) {
    let mut expr: &[u8] = &[];
    let mut var_name = "";
    for (name, form, _opt, value) in die {
        match name {
            constants::DW_AT_location => {
                match form {
                    constants::DW_FORM_exprloc => {
                        if let debug_info::AttrValue::Bytes(ops) = value {
                            expr = ops;
                        } else {
                            // It should be a DWARF expression.
                            break;
                        }
                    }
                    constants::DW_FORM_sec_offset => {
                        if let debug_info::AttrValue::Unsigned(off) = value {
                            if let Some(ops) = find_loclist(
                                loc_data,
                                address_size,
                                base_addr,
                                off as usize,
                                address,
                            ) {
                                expr = ops;
                            }
                        } else {
                            break;
                        }
                    }
                    _ => {
                        break;
                    }
                }
            }
            constants::DW_AT_name => {
                if form == constants::DW_FORM_string {
                    if let debug_info::AttrValue::String(n) = value {
                        var_name = n;
                    }
                    continue;
                }
                if form != constants::DW_FORM_strp {
                    break;
                }
                let off = match value {
                    debug_info::AttrValue::Unsigned(v) => v as usize,
                    debug_info::AttrValue::Unsigned128(v) => v as usize,
                    _ => {
                        break;
                    }
                };
                if let Some(v) = extract_string(debug_str, off) {
                    var_name = v;
                } else {
                    break;
                }
            }
            _ => {}
        }
    }
    (var_name.to_string(), expr)
}

fn find_lo_pc(die: &mut debug_info::DIE) -> Option<u64> {
    for (name, _form, _opt, value) in die {
        if name == constants::DW_AT_lo_pc {
            let lo_pc = match value {
                debug_info::AttrValue::Unsigned(v) => v,
                debug_info::AttrValue::Unsigned128(v) => v as u64,
                _ => {
                    continue;
                }
            };
            return Some(lo_pc);
        }
    }

    None
}

fn find_frame_base<'a, 'b>(
    loc_data: &'b [u8],
    address_size: usize,
    base_addr: u64,
    address: u64,
    die: &'a mut debug_info::DIE<'b>,
) -> Option<&'b [u8]> {
    for (name, form, _opt, value) in die {
        if name == constants::DW_AT_frame_base {
            match form {
                constants::DW_FORM_exprloc => {
                    if let debug_info::AttrValue::Bytes(ops) = value {
                        return Some(ops);
                    }
                }
                constants::DW_FORM_sec_offset => {
                    let off = match value {
                        debug_info::AttrValue::Unsigned(v) => v as usize,
                        debug_info::AttrValue::Unsigned128(v) => v as usize,
                        _ => {
                            continue;
                        }
                    };
                    if let Some(ops) = find_loclist(loc_data, address_size, base_addr, off, address)
                    {
                        return Some(ops);
                    }
                }
                _ => {}
            }
        }
    }

    None
}

/// Keep the information of local variables defined in a lexical
/// block.
struct LexScope<'a> {
    depth: usize,
    variables: Vec<(String, &'a [u8])>,
}

/// Find the local variables in a DW_TAG_subprogram.
///
/// Get a list of local variables that avaiable at the given address
/// and their DWARF expressions, that define the ways to access them.
pub fn find_local_vars_subprog<'a, 'b>(
    parser: &'a Elf64Parser,
    uhdr: &'b debug_info::UnitHeader,
    die_cu: &'b mut debug_info::DIE<'a>,
    mut dieiter: debug_info::DIEIter<'a>,
    address: u64,
) -> Option<(&'a [u8], Vec<(String, &'a [u8])>)> {
    let mut subprog_die = dieiter.next().unwrap();
    let mut stack = vec![LexScope {
        depth: 0,
        variables: vec![],
    }];

    let debug_str_idx = if let Ok(idx) = parser.find_section(".debug_str") {
        idx
    } else {
        return None;
    };
    let debug_str = if let Ok(data) = parser.read_section_raw_cache(debug_str_idx) {
        data
    } else {
        return None;
    };
    let loc_data = if let Ok(loc_sect_idx) = parser.find_section(".debug_loc") {
        if let Ok(data) = parser.read_section_raw_cache(loc_sect_idx) {
            data
        } else {
            return None;
        }
    } else {
        &[]
    };

    let base_addr = if let Some(pc) = find_lo_pc(die_cu) {
        pc
    } else {
        0
    };

    let fb = if let Some(fb) = find_frame_base(
        loc_data,
        uhdr.address_size(),
        base_addr,
        address,
        &mut subprog_die,
    ) {
        fb
    } else {
        &[]
    };

    // Travel the DIE sub-tree to find all variables of matched
    // lexical blocks.
    while let Some(mut die) = dieiter.next() {
        if die.tag == 0 {
            if dieiter.get_current_depth() <= stack.last().unwrap().depth {
                // It should be at the most inner lexical scope.
                break;
            }
        }

        if die.tag == constants::DW_TAG_lexical_block {
            if die.abbrev.unwrap().has_children
                && lex_contain_addr(parser, uhdr, base_addr, &mut die, address)
            {
                stack.push(LexScope {
                    depth: dieiter.get_current_depth() - 1,
                    variables: vec![],
                });
            } else {
                if let Some(sibling_off) = super::find_die_sibling(&mut die) {
                    dieiter.seek_to_sibling(sibling_off);
                } else {
                    // Skip this DIE quickly, or the iterator will
                    // recalculate the size of the DIE.
                    die.exhaust().unwrap();
                    if die.abbrev.unwrap().has_children {
                        // Skip the subtree
                        let depth = dieiter.get_current_depth();
                        while dieiter.get_current_depth() >= depth {
                            if dieiter.next().is_none() {
                                // Something goes wrong
                                #[cfg(debug_assertions)]
                                eprintln!("The debug info stream ends unexpected.");
                                break;
                            }
                        }
                    }
                }
                continue;
            }
        } else if die.tag == constants::DW_TAG_variable
            || die.tag == constants::DW_TAG_formal_parameter
        {
            stack.last_mut().unwrap().variables.push(variable_name_loc(
                uhdr.address_size(),
                base_addr,
                &mut die,
                debug_str,
                loc_data,
                address,
            ));
        }
    }

    // Collect local variables
    let mut vartab = HashMap::<String, &[u8]>::new();
    for lex in stack.iter().rev() {
        for (name, expr) in &lex.variables {
            if !vartab.contains_key(name) {
                vartab.insert(name.clone(), expr);
            }
        }
    }

    Some((fb, vartab.into_iter().collect()))
}
