//! Parse debug line information.
//!
//! DWARF debug line information provides the information of lines in
//! the source files.  It provide a way to map addresses to the source
//! file names and line numbers.
use super::constants;
use super::debug_info;
use crate::elf::Elf64Parser;
use crate::tools::{
    decode_leb128, decode_leb128_s, decode_udword, decode_uhalf, decode_uword, extract_string,
    search_address_key,
};

use std::io::{Error, ErrorKind};
use std::mem;

#[repr(C, packed)]
struct DebugLinePrologueV2 {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

#[repr(C, packed)]
struct DebugLinePrologueV4 {
    total_length: u32,
    version: u16,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

#[repr(C, packed)]
struct DebugLinePrologueV5 {
    total_length: u32,
    version: u16,
    address_size: u8,
    segment_selector_size: u8,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// DebugLinePrologue{V2,V4,V5} will be converted to this type.
struct DebugLinePrologue {
    total_length: u64,
    version: u16,
    address_size: u8,
    segment_selector_size: u8,
    prologue_length: u32,
    minimum_instruction_length: u8,
    maximum_ops_per_instruction: u8,
    default_is_stmt: u8,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
}

/// The file information of a file for a CU.
pub struct DebugLineFileInfo {
    pub name: String,
    pub dir_idx: u32, // Index to include_directories of DebugLineCU.
    #[allow(dead_code)]
    pub mod_tm: u64,
    #[allow(dead_code)]
    pub size: usize,
}

/// Represent a Compile Unit (CU) in a .debug_line section.
pub struct DebugLineCU {
    prologue: DebugLinePrologue,
    #[allow(dead_code)]
    standard_opcode_lengths: Vec<u8>,
    pub include_directories: Vec<String>,
    pub files: Vec<DebugLineFileInfo>,
    pub matrix: Vec<DebugLineStates>,
}

impl DebugLineCU {
    pub fn find_line(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = search_address_key(&self.matrix, address, &|x: &DebugLineStates| -> u64 {
            x.address
        })?;

        let states = &self.matrix[idx];
        if states.end_sequence {
            // This is the first byte after the last instruction
            return None;
        }

        self.stringify_row(idx)
    }

    pub fn stringify_row(&self, idx: usize) -> Option<(&str, &str, usize)> {
        let states = &self.matrix[idx];
        let (dir, file) = {
            if states.file > 0 {
                let file = &self.files[states.file - 1];
                let dir = {
                    if file.dir_idx == 0 {
                        ""
                    } else {
                        self.include_directories[file.dir_idx as usize - 1].as_str()
                    }
                };
                (dir, file.name.as_str())
            } else {
                ("", "")
            }
        };

        Some((dir, file, states.line))
    }

    pub fn find_line_addresses(&self, filename: &str, line_no: usize, addresses: &mut Vec<u64>) {
        let file_idx = if let Some((idx, _)) = self
            .files
            .iter()
            .enumerate()
            .find(|(_, x)| x.name == filename)
        {
            idx + 1 // file indices are 1 based.
        } else {
            return;
        };
        for dlstates in &self.matrix {
            if dlstates.file == file_idx && dlstates.line == line_no && dlstates.is_stmt {
                addresses.push(dlstates.address);
            }
        }
    }
}

/// Parse the list of directory paths for a CU.
fn parse_debug_line_dirs(data_buf: &[u8]) -> Result<(Vec<String>, usize), Error> {
    let mut strs = Vec::<String>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NULL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"))?;
            strs.push(str_r);
            end += 1;
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Do not found null string",
    ))
}

/// Parse the list of file information for a CU.
fn parse_debug_line_files(data_buf: &[u8]) -> Result<(Vec<DebugLineFileInfo>, usize), Error> {
    let mut strs = Vec::<DebugLineFileInfo>::new();
    let mut pos = 0;

    while pos < data_buf.len() {
        if data_buf[pos] == 0 {
            return Ok((strs, pos + 1));
        }

        // Find NULL byte
        let mut end = pos;
        while end < data_buf.len() && data_buf[end] != 0 {
            end += 1;
        }
        if end < data_buf.len() {
            // Null terminated file name string
            let mut str_vec = Vec::<u8>::with_capacity(end - pos);
            str_vec.extend_from_slice(&data_buf[pos..end]);

            let str_r = String::from_utf8(str_vec);
            if str_r.is_err() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid UTF-8 string"));
            }
            end += 1;

            // LEB128 directory index
            let dir_idx_r = decode_leb128(&data_buf[end..]);
            if dir_idx_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invliad directory index",
                ));
            }
            let (dir_idx, bytes) = dir_idx_r.unwrap();
            end += bytes as usize;

            // LEB128 last modified time
            let mod_tm_r = decode_leb128(&data_buf[end..]);
            if mod_tm_r.is_none() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid last modified time",
                ));
            }
            let (mod_tm, bytes) = mod_tm_r.unwrap();
            end += bytes as usize;

            // LEB128 file size
            let flen_r = decode_leb128(&data_buf[end..]);
            if flen_r.is_none() {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid file size"));
            }
            let (flen, bytes) = flen_r.unwrap();
            end += bytes as usize;

            strs.push(DebugLineFileInfo {
                name: str_r.unwrap(),
                dir_idx: dir_idx as u32,
                mod_tm,
                size: flen as usize,
            });
        }
        pos = end;
    }

    Err(Error::new(
        ErrorKind::InvalidData,
        "Do not found null string",
    ))
}

fn extract_debug_line_dirs_or_files_v5<'a, F>(
    prologue: &DebugLinePrologue,
    data_buf: &'a [u8],
    pos: usize,
    dwarf_sz: usize,
    mut handler: F,
) -> Result<usize, Error>
where
    F: FnMut(usize, u64, u64, debug_info::AttrValue<'a>) -> Result<(), Error>,
{
    let saved_pos = pos;
    let mut pos = pos;

    // Format descriptions
    let format_count = data_buf[pos];
    pos += 1;
    let mut formats = vec![];
    for _ in 0..format_count {
        if let Some((content_type_code, bytes)) = decode_leb128(&data_buf[pos..]) {
            pos += bytes as usize;
            if let Some((form_code, bytes)) = decode_leb128(&data_buf[pos..]) {
                pos += bytes as usize;
                formats.push((content_type_code, form_code));
                continue;
            }
        }
        return Err(Error::new(
            ErrorKind::InvalidData,
            "fail to parse directory or file entries",
        ));
    }

    // Entries
    let (count, bytes) = if let Some((v, bytes)) = decode_leb128(&data_buf[pos..]) {
        (v, bytes)
    } else {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "fail to parse directory entries",
        ));
    };
    pos += bytes as usize;
    for seq in 0..count {
        for (content_type_code, form_code) in &formats {
            if let Some((v, bytes)) = debug_info::extract_attr_value(
                &data_buf[pos..],
                *form_code as u8,
                dwarf_sz,
                prologue.address_size as usize,
            ) {
                pos += bytes;

                handler(seq as usize, *content_type_code, *form_code, v)?;
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "fail to parse directory entries",
                ));
            }
        }
    }
    Ok(pos - saved_pos)
}

/// Parse directories and files for DWARFv5
///
/// Before v5, directories and files in the debug line info section
/// are arrays that every element has a fixed number of members.
/// DWARFv5 defines additional format descriptions to define the
/// format of directory entries and file entries to allow compilers to
/// add or remove members of entries.
///
/// The format of directory entries and file entries.
///  - directory_entry_format_count (u8)
///  - directory_entry_format (pairs of uleb128)
///  - directory_count (uleb128)
///  - directories
///  - file_name_entry_format_count (u8)
///  - file_name_entry_format (pairs of uleb128)
///  - file_names_count (uleb128)
///  - file_names
///
/// Every entry in directories comprised members defined in
/// directory_entry_format.
///
/// Every entry in file_names comprised members defined in
/// file_name_entry_format.
///
/// Check the p156 & p157 in <https://dwarfstd.org/doc/DWARF5.pdf>
fn parse_debug_line_dirs_files_v5(
    prologue: &DebugLinePrologue,
    data_buf: &[u8],
    pos: usize,
    dlstr_buf: &[u8],
    dwarf_sz: usize,
) -> Result<((Vec<String>, Vec<DebugLineFileInfo>), usize), Error> {
    let mut pos = pos;
    let saved_pos = pos;

    // Directories
    let mut inc_dirs = vec![];
    let dirs_collector = |_seq, content_type_code, form_code, v| {
        let name = match v {
            debug_info::AttrValue::String(s) => s,
            debug_info::AttrValue::Unsigned(v_u64) => {
                if form_code as u8 == constants::DW_FORM_line_strp {
                    if let Some(name) = extract_string(dlstr_buf, v_u64 as usize) {
                        name
                    } else {
                        ""
                    }
                } else {
                    ""
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "fail to parse directory entries",
                ));
            }
        };

        if content_type_code as u32 == constants::DW_LNCT_path {
            inc_dirs.push(name.to_string());
        }
        Ok(())
    };
    let bytes =
        extract_debug_line_dirs_or_files_v5(prologue, data_buf, pos, dwarf_sz, dirs_collector)?;
    pos += bytes;

    // Files
    let mut files = vec![];
    let files_collector = |seq, content_type_code, form_code, v| {
        if seq >= files.len() {
            files.push(DebugLineFileInfo {
                name: "".to_string(),
                dir_idx: 0,
                mod_tm: 0,
                size: 0,
            });
        }
        match content_type_code as u32 {
            constants::DW_LNCT_path => {
                let name = match v {
                    debug_info::AttrValue::String(s) => s,
                    debug_info::AttrValue::Unsigned(v_u64) => {
                        let mut name = "";
                        if form_code as u8 == constants::DW_FORM_line_strp {
                            if let Some(v) = extract_string(dlstr_buf, v_u64 as usize) {
                                name = v;
                            }
                        }
                        name
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "fail to parse file entries",
                        ));
                    }
                };
                files.last_mut().unwrap().name = name.to_string();
            }
            constants::DW_LNCT_directory_index => {
                if let debug_info::AttrValue::Unsigned(v_u64) = v {
                    files.last_mut().unwrap().dir_idx = v_u64 as u32;
                } else if let debug_info::AttrValue::Unsigned128(v_u128) = v {
                    files.last_mut().unwrap().dir_idx = v_u128 as u32;
                } else {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse file entries",
                    ));
                }
            }
            _ => {
                // unknown type codes skip
            }
        }

        Ok(())
    };
    let bytes =
        extract_debug_line_dirs_or_files_v5(prologue, data_buf, pos, dwarf_sz, files_collector)?;
    pos += bytes;

    // DWARFv5, the file with the index 0 is the current
    // compilation file name.  But, it doesn't exist in the
    // earlier DWARF.  And, the indices start from 1 for the
    // earlier DWARF.  We drop the first entry (index 0) to
    // compatible with the earlier DWARF.  The dropped entry
    // should be saved somewhere if we need it.
    files.remove(0);

    Ok(((inc_dirs, files), pos - saved_pos))
}

fn parse_debug_line_cu(
    parser: &Elf64Parser,
    addresses: &[u64],
    reused_buf: &mut Vec<u8>,
    dlstr_buf: &[u8],
) -> Result<DebugLineCU, Error> {
    let mut prologue_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let prologue_v4_size: usize = mem::size_of::<DebugLinePrologueV4>();
    let prologue_v5_size: usize = mem::size_of::<DebugLinePrologueV5>();
    let buf = reused_buf;

    buf.resize(prologue_size, 0);

    unsafe { parser.read_raw(buf.as_mut_slice()) }?;
    let prologue_raw = buf.as_mut_ptr() as *mut DebugLinePrologueV2;
    // SAFETY: `prologue_raw` is valid for reads and `DebugLinePrologueV2` is
    //         comprised only of objects that are valid for any bit pattern.
    let mut v2 = unsafe { prologue_raw.read_unaligned() };

    let mut extra_bytes = 0;
    let mut dwarf_sz = 4;
    let total_length = if v2.total_length == 0xffffffff {
        buf.resize(prologue_size + 8, 0);
        unsafe { parser.read_raw(&mut buf.as_mut_slice()[prologue_size..])? };
        let prologue_raw = unsafe { buf.as_mut_ptr().add(8) } as *mut DebugLinePrologueV2;
        v2 = unsafe { prologue_raw.read_unaligned() };
        prologue_size += 8;
        extra_bytes = 8;
        dwarf_sz = 8;
        unsafe { (buf.as_mut_ptr().add(4) as *const u64).read_unaligned() }
    } else {
        v2.total_length as u64
    };

    if v2.version != 0x2 && v2.version != 0x4 && v2.version != 0x5 {
        let version = v2.version;
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("Support DWARF version 2, 4 & 5 (version: {})", version),
        ));
    }

    let prologue = if v2.version == 0x5 {
        // Convert V5
        buf.resize(prologue_v5_size + extra_bytes, 0);
        unsafe { parser.read_raw(&mut buf.as_mut_slice()[prologue_size..])? };
        let prologue_raw = unsafe { buf.as_mut_ptr().add(extra_bytes) } as *mut DebugLinePrologueV5;
        let v5 = unsafe { prologue_raw.read_unaligned() };
        let prologue = DebugLinePrologue {
            total_length,
            version: v5.version,
            address_size: v5.address_size,
            segment_selector_size: v5.segment_selector_size,
            prologue_length: v5.prologue_length,
            minimum_instruction_length: v5.minimum_instruction_length,
            maximum_ops_per_instruction: v5.maximum_ops_per_instruction,
            default_is_stmt: v5.default_is_stmt,
            line_base: v5.line_base,
            line_range: v5.line_range,
            opcode_base: v5.opcode_base,
        };
        prologue_size = prologue_v5_size + extra_bytes;
        prologue
    } else if v2.version == 0x4 {
        // Upgrade
        // V4 has more fields to read.
        buf.resize(prologue_v4_size + extra_bytes, 0);
        unsafe { parser.read_raw(&mut buf.as_mut_slice()[prologue_size..]) }?;
        let prologue_raw = unsafe { buf.as_mut_ptr().add(extra_bytes) } as *mut DebugLinePrologueV4;
        // SAFETY: `prologue_raw` is valid for reads and `DebugLinePrologue` is
        //         comprised only of objects that are valid for any bit pattern.
        let v4 = unsafe { prologue_raw.read_unaligned() };
        let prologue = DebugLinePrologue {
            total_length,
            version: v4.version,
            address_size: mem::size_of::<*const u8>() as u8,
            segment_selector_size: 0,
            prologue_length: v4.prologue_length,
            minimum_instruction_length: v4.minimum_instruction_length,
            maximum_ops_per_instruction: v4.maximum_ops_per_instruction,
            default_is_stmt: v4.default_is_stmt,
            line_base: v4.line_base,
            line_range: v4.line_range,
            opcode_base: v4.opcode_base,
        };
        prologue_size = prologue_v4_size + extra_bytes;
        prologue
    } else {
        // Convert V2
        let prologue = DebugLinePrologue {
            total_length,
            version: v2.version,
            address_size: mem::size_of::<*const u8>() as u8,
            segment_selector_size: 0,
            prologue_length: v2.prologue_length,
            minimum_instruction_length: v2.minimum_instruction_length,
            maximum_ops_per_instruction: 0,
            default_is_stmt: v2.default_is_stmt,
            line_base: v2.line_base,
            line_range: v2.line_range,
            opcode_base: v2.opcode_base,
        };
        prologue
    };

    let to_read = prologue.total_length as usize + 4 + extra_bytes - prologue_size;
    let data_buf = buf;
    if to_read <= data_buf.capacity() {
        // Gain better performance by skipping initialization.
        unsafe { data_buf.set_len(to_read) };
    } else {
        data_buf.resize(to_read, 0);
    }
    unsafe { parser.read_raw(data_buf.as_mut_slice())? };

    let mut pos = 0;

    let std_op_num = (prologue.opcode_base - 1) as usize;
    let mut std_op_lengths = Vec::<u8>::with_capacity(std_op_num);
    std_op_lengths.extend_from_slice(&data_buf[pos..pos + std_op_num]);
    pos += std_op_num;

    let (inc_dirs, files) = if prologue.version == 0x5 {
        let (dirs_files, bytes) =
            parse_debug_line_dirs_files_v5(&prologue, &data_buf, pos, dlstr_buf, dwarf_sz)?;
        pos += bytes;
        dirs_files
    } else {
        let (inc_dirs, bytes) = parse_debug_line_dirs(&data_buf[pos..])?;
        pos += bytes;

        let (files, bytes) = parse_debug_line_files(&data_buf[pos..])?;
        pos += bytes;

        (inc_dirs, files)
    };

    let matrix = run_debug_line_stmts(&data_buf[pos..], &prologue, addresses)?;

    #[cfg(debug_assertions)]
    for i in 1..matrix.len() {
        if matrix[i].address < matrix[i - 1].address && !matrix[i - 1].end_sequence {
            panic!(
                "Not in ascent order @ [{}] {:?} [{}] {:?}",
                i - 1,
                matrix[i - 1],
                i,
                matrix[i]
            );
        }
    }

    Ok(DebugLineCU {
        prologue,
        standard_opcode_lengths: std_op_lengths,
        include_directories: inc_dirs,
        files,
        matrix,
    })
}

#[derive(Clone, Debug)]
pub struct DebugLineStates {
    pub address: u64,
    pub file: usize,
    pub line: usize,
    pub column: usize,
    pub discriminator: u64,
    pub is_stmt: bool,
    pub basic_block: bool,
    pub end_sequence: bool,
    pub prologue_end: bool,
    should_reset: bool,
}

impl DebugLineStates {
    fn new(prologue: &DebugLinePrologue) -> DebugLineStates {
        DebugLineStates {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            discriminator: 0,
            is_stmt: prologue.default_is_stmt != 0,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            should_reset: false,
        }
    }

    fn reset(&mut self, prologue: &DebugLinePrologue) {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.discriminator = 0;
        self.is_stmt = prologue.default_is_stmt != 0;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.should_reset = false;
    }
}

/// Return `Ok((insn_bytes, emit))` if success.  `insn_bytes1 is the
/// size of the instruction at the position given by ip.  `emit` is
/// true if this instruction emit a new row to describe line
/// information of an address.  Not every instructions emit rows.
/// Some instructions create only intermediate states for the next row
/// going to emit.
fn run_debug_line_stmt(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    ip: usize,
    states: &mut DebugLineStates,
) -> Result<(usize, bool), Error> {
    // Standard opcodes
    const DW_LNS_EXT: u8 = 0;
    const DW_LNS_COPY: u8 = 1;
    const DW_LNS_ADVANCE_PC: u8 = 2;
    const DW_LNS_ADVANCE_LINE: u8 = 3;
    const DW_LNS_SET_FILE: u8 = 4;
    const DW_LNS_SET_COLUMN: u8 = 5;
    const DW_LNS_NEGATE_STMT: u8 = 6;
    const DW_LNS_SET_BASIC_BLOCK: u8 = 7;
    const DW_LNS_CONST_ADD_PC: u8 = 8;
    const DW_LNS_FIXED_ADVANCE_PC: u8 = 9;
    const DW_LNS_SET_PROLOGUE_END: u8 = 10;

    // Extended opcodes
    const DW_LINE_END_SEQUENCE: u8 = 1;
    const DW_LINE_SET_ADDRESS: u8 = 2;
    const DW_LINE_DEFINE_FILE: u8 = 3;
    const DW_LINE_SET_DISCRIMINATOR: u8 = 4;

    let opcode_base = prologue.opcode_base;
    let opcode = stmts[ip];

    match opcode {
        DW_LNS_EXT => {
            // Extended opcodes
            if let Some((insn_size, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                if insn_size < 1 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "invalid extended opcode (ip=0x{:x}, insn_size=0x{:x}",
                            ip, insn_size
                        ),
                    ));
                }
                let ext_opcode = stmts[ip + 1 + bytes as usize];
                match ext_opcode {
                    DW_LINE_END_SEQUENCE => {
                        states.end_sequence = true;
                        states.should_reset = true;
                        Ok((1 + bytes as usize + insn_size as usize, true))
                    }
                    DW_LINE_SET_ADDRESS => match insn_size - 1 {
                        4 => {
                            let address = decode_uword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address as u64;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        8 => {
                            let address = decode_udword(&stmts[(ip + 1 + bytes as usize + 1)..]);
                            states.address = address;
                            Ok((1 + bytes as usize + insn_size as usize, false))
                        }
                        _ => Err(Error::new(
                            ErrorKind::Unsupported,
                            format!("unsupported address size ({})", insn_size),
                        )),
                    },
                    DW_LINE_DEFINE_FILE => Err(Error::new(
                        ErrorKind::Unsupported,
                        "DW_LINE_define_file is not supported yet",
                    )),
                    DW_LINE_SET_DISCRIMINATOR => {
                        if let Some((discriminator, discr_bytes)) =
                            decode_leb128(&stmts[(ip + 1 + bytes as usize + 1)..])
                        {
                            if discr_bytes as u64 + 1 == insn_size {
                                states.discriminator = discriminator;
                                Ok((1 + bytes as usize + insn_size as usize, false))
                            } else {
                                Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "unmatched instruction size for DW_LINE_set_discriminator",
                                ))
                            }
                        } else {
                            Err(Error::new(
                                ErrorKind::InvalidData,
                                "discriminator is broken",
                            ))
                        }
                    }
                    _ => Err(Error::new(
                        ErrorKind::Unsupported,
                        format!(
                            "invalid extended opcode (ip=0x{:x}, ext_opcode=0x{:x})",
                            ip, ext_opcode
                        ),
                    )),
                }
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid extended opcode (ip=0x{:x})", ip),
                ))
            }
        }
        DW_LNS_COPY => Ok((1, true)),
        DW_LNS_ADVANCE_PC => {
            if let Some((adv, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.address += adv * prologue.minimum_instruction_length as u64;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_pc is broken",
                ))
            }
        }
        DW_LNS_ADVANCE_LINE => {
            if let Some((adv, bytes)) = decode_leb128_s(&stmts[(ip + 1)..]) {
                states.line = (states.line as i64 + adv) as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of advance_line is broken",
                ))
            }
        }
        DW_LNS_SET_FILE => {
            if let Some((file_idx, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.file = file_idx as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_file is broken",
                ))
            }
        }
        DW_LNS_SET_COLUMN => {
            if let Some((column, bytes)) = decode_leb128(&stmts[(ip + 1)..]) {
                states.column = column as usize;
                Ok((1 + bytes as usize, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of set_column is broken",
                ))
            }
        }
        DW_LNS_NEGATE_STMT => {
            states.is_stmt = !states.is_stmt;
            Ok((1, false))
        }
        DW_LNS_SET_BASIC_BLOCK => {
            states.basic_block = true;
            Ok((1, false))
        }
        DW_LNS_CONST_ADD_PC => {
            let addr_adv = (255 - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            Ok((1, false))
        }
        DW_LNS_FIXED_ADVANCE_PC => {
            if (ip + 3) < stmts.len() {
                let addr_adv = decode_uhalf(&stmts[(ip + 1)..]);
                states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
                Ok((1, false))
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "the operand of fixed_advance_pc is broken",
                ))
            }
        }
        DW_LNS_SET_PROLOGUE_END => {
            states.prologue_end = true;
            Ok((1, false))
        }
        _ => {
            // Special opcodes
            let desired_line_incr = (opcode - opcode_base) % prologue.line_range;
            let addr_adv = (opcode - opcode_base) / prologue.line_range;
            states.address += addr_adv as u64 * prologue.minimum_instruction_length as u64;
            states.line = (states.line as i64
                + (desired_line_incr as i16 + prologue.line_base as i16) as i64
                    * prologue.minimum_instruction_length as i64)
                as usize;
            Ok((1, true))
        }
    }
}

fn run_debug_line_stmts(
    stmts: &[u8],
    prologue: &DebugLinePrologue,
    addresses: &[u64],
) -> Result<Vec<DebugLineStates>, Error> {
    let mut ip = 0;
    let mut matrix = Vec::<DebugLineStates>::new();
    let mut should_sort = false;
    let mut states_cur = DebugLineStates::new(prologue);
    let mut states_last = states_cur.clone();
    let mut last_ip_pushed = false;
    let mut force_no_emit = false;

    while ip < stmts.len() {
        match run_debug_line_stmt(stmts, prologue, ip, &mut states_cur) {
            Ok((sz, emit)) => {
                ip += sz;
                if emit {
                    if states_cur.address == 0 {
                        // This is a speical case. Somehow, rust
                        // compiler generate debug_line for some
                        // builtin code starting from 0.  And, it
                        // causes incorrect behavior.
                        force_no_emit = true;
                    }
                    if !force_no_emit {
                        if !addresses.is_empty() {
                            let mut pushed = false;
                            for addr in addresses {
                                if *addr == states_cur.address
                                    || (states_last.address != 0
                                        && !states_last.end_sequence
                                        && *addr < states_cur.address
                                        && *addr > states_last.address)
                                {
                                    if !last_ip_pushed && *addr != states_cur.address {
                                        // The address falls between current and last emitted row.
                                        matrix.push(states_last.clone());
                                    }
                                    matrix.push(states_cur.clone());
                                    pushed = true;
                                    break;
                                }
                            }
                            last_ip_pushed = pushed;
                            states_last = states_cur.clone();
                        } else {
                            matrix.push(states_cur.clone());
                        }
                        if states_last.address > states_cur.address {
                            should_sort = true;
                        }
                    }
                }
                if states_cur.should_reset {
                    states_cur.reset(prologue);
                    force_no_emit = false;
                }
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    if should_sort {
        matrix.sort_by_key(|x| x.address);
    }

    Ok(matrix)
}

/// If addresses is empty, it return a full version of debug_line matrics.
/// If addresses is not empty, return only data needed to resolve given addresses .
pub fn parse_debug_line_elf_parser(
    parser: &Elf64Parser,
    addresses: &[u64],
) -> Result<Vec<DebugLineCU>, Error> {
    let dlstr_buf = if let Ok(dlstr_idx) = parser.find_section(".debug_line_str") {
        parser.read_section_raw_cache(dlstr_idx)?
    } else {
        &[]
    };

    let debug_line_idx = parser.find_section(".debug_line")?;
    let debug_line_sz = parser.get_section_size(debug_line_idx)?;
    let mut remain_sz = debug_line_sz;
    let prologue_size: usize = mem::size_of::<DebugLinePrologueV2>();
    let mut not_found = Vec::from(addresses);

    parser.section_seek(debug_line_idx)?;

    let mut all_cus = Vec::<DebugLineCU>::new();
    let mut buf = Vec::<u8>::new();
    while remain_sz > prologue_size {
        let debug_line_cu =
            if let Ok(cu) = parse_debug_line_cu(parser, &not_found, &mut buf, dlstr_buf) {
                cu
            } else {
                // Try to skip CU that we fail to parse.
                if buf.len() < 4 {
                    break;
                }
                let mut total_length = decode_uword(&buf[..4]) as u64;
                if total_length == 0xffffffff {
                    if buf.len() < 24 {
                        break;
                    }
                    total_length = decode_udword(&buf[4..]) + 8;
                }
                if remain_sz <= total_length as usize + 4 {
                    break;
                }
                let skip = total_length + 4 - buf.len() as u64;
                parser.skip(skip as i64)?;
                remain_sz -= total_length as usize + 4;
                continue;
            };

        let prologue = &debug_line_cu.prologue;
        remain_sz -= prologue.total_length as usize + 4;

        if debug_line_cu.matrix.is_empty() {
            continue;
        }

        if !addresses.is_empty() {
            let mut last_row = &debug_line_cu.matrix[0];
            for row in debug_line_cu.matrix.as_slice() {
                let mut i = 0;
                // Remove addresses found in this CU from not_found.
                while i < not_found.len() {
                    let addr = addresses[i];
                    if addr == row.address || (addr < row.address && addr > last_row.address) {
                        not_found.remove(i);
                    } else {
                        i += 1;
                    }
                }
                last_row = row;
            }

            all_cus.push(debug_line_cu);

            if not_found.is_empty() {
                return Ok(all_cus);
            }
        } else {
            all_cus.push(debug_line_cu);
        }
    }

    if remain_sz != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "remain garbage data at the end",
        ));
    }

    Ok(all_cus)
}

#[allow(dead_code)]
fn parse_debug_line_elf(filename: &str) -> Result<Vec<DebugLineCU>, Error> {
    let parser = Elf64Parser::open(filename)?;
    parse_debug_line_elf_parser(&parser, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[cfg(feature = "nightly")]
    use test::Bencher;

    fn parse_debug_line_elf(filename: &str) -> Result<Vec<DebugLineCU>, Error> {
        let parser = Elf64Parser::open(filename)?;
        parse_debug_line_elf_parser(&parser, &[])
    }

    #[test]
    fn test_parse_debug_line_elf() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];

        let r = parse_debug_line_elf(bin_name);
        if r.is_err() {
            println!("{:?}", r.as_ref().err().unwrap());
        }
        assert!(r.is_ok());
    }

    #[test]
    fn test_run_debug_line_stmts_1() {
        let stmts = [
            0x00, 0x09, 0x02, 0x30, 0x8b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xa0, 0x04,
            0x01, 0x05, 0x06, 0x0a, 0x08, 0x30, 0x02, 0x05, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            address_size: mem::size_of::<*const u8>() as u8,
            segment_selector_size: 0,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {:?}", e);
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();
        assert_eq!(matrix.len(), 3);
        assert_eq!(matrix[0].line, 545);
        assert_eq!(matrix[0].address, 0x18b30);
        assert_eq!(matrix[1].line, 547);
        assert_eq!(matrix[1].address, 0x18b43);
        assert_eq!(matrix[2].line, 547);
        assert_eq!(matrix[2].address, 0x18b48);
    }

    #[test]
    fn test_run_debug_line_stmts_2() {
        //	File name                            Line number    Starting address    View    Stmt
        //	    methods.rs                                   789             0x18c70               x
        //	    methods.rs                                   791             0x18c7c               x
        //	    methods.rs                                   791             0x18c81
        //	    methods.rs                                   790             0x18c86               x
        //	    methods.rs                                     0             0x18c88
        //	    methods.rs                                   791             0x18c8c               x
        //	    methods.rs                                     0             0x18c95
        //	    methods.rs                                   792             0x18c99               x
        //	    methods.rs                                   792             0x18c9d
        //	    methods.rs                                     0             0x18ca4
        //	    methods.rs                                   791             0x18ca8               x
        //	    methods.rs                                   792             0x18caf               x
        //	    methods.rs                                     0             0x18cb6
        //	    methods.rs                                   792             0x18cba
        //	    methods.rs                                     0             0x18cc4
        //	    methods.rs                                   792             0x18cc8
        //	    methods.rs                                   790             0x18cce               x
        //	    methods.rs                                   794             0x18cd0               x
        //	    methods.rs                                   794             0x18cde               x
        let stmts = [
            0x00, 0x09, 0x02, 0x70, 0x8c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x94, 0x06,
            0x01, 0x05, 0x0d, 0x0a, 0xbc, 0x05, 0x26, 0x06, 0x58, 0x05, 0x09, 0x06, 0x57, 0x06,
            0x03, 0xea, 0x79, 0x2e, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x06, 0x03, 0xe9,
            0x79, 0x90, 0x05, 0x0d, 0x06, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x12, 0x06, 0x4a, 0x03,
            0xe8, 0x79, 0x74, 0x05, 0x13, 0x06, 0x03, 0x97, 0x06, 0x4a, 0x05, 0x12, 0x75, 0x06,
            0x03, 0xe8, 0x79, 0x74, 0x05, 0x20, 0x03, 0x98, 0x06, 0x4a, 0x03, 0xe8, 0x79, 0x9e,
            0x05, 0x12, 0x03, 0x98, 0x06, 0x4a, 0x05, 0x09, 0x06, 0x64, 0x05, 0x06, 0x32, 0x02,
            0x0e, 0x00, 0x01, 0x01,
        ];
        let prologue = DebugLinePrologue {
            total_length: 0,
            version: 4,
            address_size: mem::size_of::<*const u8>() as u8,
            segment_selector_size: 0,
            prologue_length: 0,
            minimum_instruction_length: 1,
            maximum_ops_per_instruction: 1,
            default_is_stmt: 1,
            line_base: -5,
            line_range: 14,
            opcode_base: 13,
        };

        let result = run_debug_line_stmts(&stmts, &prologue, &[]);
        if result.is_err() {
            let e = result.as_ref().err().unwrap();
            println!("result {:?}", e);
        }
        assert!(result.is_ok());
        let matrix = result.unwrap();

        assert_eq!(matrix.len(), 19);
        assert_eq!(matrix[0].line, 789);
        assert_eq!(matrix[0].address, 0x18c70);
        assert!(matrix[0].is_stmt);

        assert_eq!(matrix[1].line, 791);
        assert_eq!(matrix[1].address, 0x18c7c);
        assert!(matrix[1].is_stmt);

        assert_eq!(matrix[2].line, 791);
        assert_eq!(matrix[2].address, 0x18c81);
        assert!(!matrix[2].is_stmt);

        assert_eq!(matrix[13].line, 792);
        assert_eq!(matrix[13].address, 0x18cba);
        assert!(!matrix[13].is_stmt);

        assert_eq!(matrix[14].line, 0);
        assert_eq!(matrix[14].address, 0x18cc4);
        assert!(!matrix[14].is_stmt);

        assert_eq!(matrix[18].line, 794);
        assert_eq!(matrix[18].address, 0x18cde);
        assert!(matrix[18].is_stmt);
    }
}
