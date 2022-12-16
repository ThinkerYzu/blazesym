//! Parse .debug_aranges
use crate::elf::Elf64Parser;
use crate::tools::{decode_udword, decode_uhalf, decode_uword};

use std::io::{Error, ErrorKind};

pub struct ArangesCU {
    pub debug_line_off: usize,
    pub aranges: Vec<(u64, u64)>,
}

fn parse_aranges_cu(data: &[u8]) -> Result<(ArangesCU, usize), Error> {
    if data.len() < 12 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "invalid arange header (too small)",
        ));
    }
    let len = decode_uword(data);
    let version = decode_uhalf(&data[4..]);
    let offset = decode_uword(&data[6..]);
    let addr_sz = data[10];
    let _seg_sz = data[11];

    if data.len() < (len + 4) as usize {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "data is broken (too small)",
        ));
    }

    // Size of the header
    let mut pos = 12;

    // Padding to align with the size of addresses on the target system.
    pos += addr_sz as usize - 1;
    pos -= pos % addr_sz as usize;

    let mut aranges = Vec::<(u64, u64)>::new();
    match addr_sz {
        4 => {
            while pos < (len + 4 - 8) as usize {
                let start = decode_uword(&data[pos..]);
                pos += 4;
                let size = decode_uword(&data[pos..]);
                pos += 4;

                if start == 0 && size == 0 {
                    break;
                }
                aranges.push((start as u64, size as u64));
            }
        }
        8 => {
            while pos < (len + 4 - 16) as usize {
                let start = decode_udword(&data[pos..]);
                pos += 8;
                let size = decode_udword(&data[pos..]);
                pos += 8;

                if start == 0 && size == 0 {
                    break;
                }
                aranges.push((start, size));
            }
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                format!(
                    "unsupported address size {} ver {} off 0x{:x}",
                    addr_sz, version, offset
                ),
            ));
        }
    }

    Ok((
        ArangesCU {
            debug_line_off: offset as usize,
            aranges,
        },
        len as usize + 4,
    ))
}

fn parse_aranges_elf_parser(parser: &Elf64Parser) -> Result<Vec<ArangesCU>, Error> {
    let debug_aranges_idx = parser.find_section(".debug_aranges")?;

    let raw_data = parser.read_section_raw(debug_aranges_idx)?;

    let mut pos = 0;
    let mut acus = Vec::<ArangesCU>::new();
    while pos < raw_data.len() {
        let (acu, bytes) = parse_aranges_cu(&raw_data[pos..])?;
        acus.push(acu);
        pos += bytes;
    }

    Ok(acus)
}

pub fn parse_aranges_elf(filename: &str) -> Result<Vec<ArangesCU>, Error> {
    let parser = Elf64Parser::open(filename)?;
    parse_aranges_elf_parser(&parser)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_parse_aranges_elf() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];

        let r = parse_aranges_elf(bin_name);
        if r.is_err() {
            println!("{:?}", r.as_ref().err().unwrap());
        }
        assert!(r.is_ok());
        let _acus = r.unwrap();
    }
}
