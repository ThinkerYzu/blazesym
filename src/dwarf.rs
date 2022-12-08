use super::elf::Elf64Parser;
use super::tools::search_address_key;
use super::{FindAddrOpts, SymbolInfo, SymbolType};
use crossbeam_channel::unbounded;

use std::cell::RefCell;
use std::io::{Error, ErrorKind};
use std::iter::Iterator;
use std::mem;
use std::rc::Rc;

#[cfg(test)]
use std::env;

use std::clone::Clone;
use std::ffi::CStr;
use std::sync::mpsc;
use std::thread;

use regex::Regex;

use std::collections::HashMap;

#[allow(non_upper_case_globals)]
mod constants;
#[allow(non_upper_case_globals)]
mod debug_info;
mod debug_line;
mod local_vars;

mod aranges;

#[allow(dead_code)]
fn parse_debug_line_elf(filename: &str) -> Result<Vec<debug_line::DebugLineCU>, Error> {
    let parser = Elf64Parser::open(filename)?;
    debug_line::parse_debug_line_elf_parser(&parser, &[])
}

struct DwarfResolverBack {
    fnames: Vec<&'static str>,
    fname_to_dlcu: Vec<(u32, u32)>,
}

/// DwarfResolver provide abilities to query DWARF information of binaries.
pub struct DwarfResolver {
    parser: Rc<Elf64Parser>,
    debug_line_cus: Vec<debug_line::DebugLineCU>,
    addr_to_dlcu: Vec<(u64, u32)>,
    back: RefCell<DwarfResolverBack>,
    enable_debug_info_syms: bool,
    debug_info_syms: RefCell<Option<Vec<DWSymInfo<'static>>>>,
    addr_di_syms: RefCell<Vec<&'static DWSymInfo<'static>>>,
    // Offsets to the CUs.
    cu_offsets: RefCell<Vec<usize>>,
}

impl DwarfResolver {
    pub fn get_parser(&self) -> &Elf64Parser {
        &self.parser
    }

    pub fn from_parser_for_addresses(
        parser: Rc<Elf64Parser>,
        addresses: &[u64],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let debug_line_cus: Vec<debug_line::DebugLineCU> = if line_number_info {
            debug_line::parse_debug_line_elf_parser(&parser, addresses).unwrap_or_default()
        } else {
            vec![]
        };

        let mut addr_to_dlcu = Vec::with_capacity(debug_line_cus.len());
        for (idx, dlcu) in debug_line_cus.iter().enumerate() {
            if dlcu.matrix.is_empty() {
                continue;
            }
            let first_addr = dlcu.matrix[0].address;
            addr_to_dlcu.push((first_addr, idx as u32));
        }
        addr_to_dlcu.sort_by_key(|v| v.0);

        Ok(DwarfResolver {
            parser,
            debug_line_cus,
            addr_to_dlcu,
            back: RefCell::new(DwarfResolverBack {
                fnames: Vec::new(),
                fname_to_dlcu: Vec::new(),
            }),
            enable_debug_info_syms: debug_info_symbols,
            debug_info_syms: RefCell::new(None),
            addr_di_syms: RefCell::new(vec![]),
            cu_offsets: RefCell::new(vec![]),
        })
    }

    /// Open a binary to load .debug_line only enough for a given list of addresses.
    ///
    /// When `addresses` is not empty, the returned instance only has
    /// data that related to these addresses.  For this case, the
    /// isntance have the ability that can serve only these addresses.
    /// This would be much faster.
    ///
    /// If `addresses` is empty, the returned instance has all data
    /// from the given file.  If the instance will be used for long
    /// running, you would want to load all data into memory to have
    /// the ability of handling all possible addresses.
    #[cfg(test)]
    fn open_for_addresses(
        filename: &str,
        addresses: &[u64],
        line_number_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        let parser = Elf64Parser::open(filename)?;
        Self::from_parser_for_addresses(
            Rc::new(parser),
            addresses,
            line_number_info,
            debug_info_symbols,
        )
    }

    /// Open a binary to load and parse .debug_line for later uses.
    ///
    /// `filename` is the name of an ELF binary/or shared object that
    /// has .debug_line section.
    #[cfg(test)]
    fn open(
        filename: &str,
        debug_line_info: bool,
        debug_info_symbols: bool,
    ) -> Result<DwarfResolver, Error> {
        Self::open_for_addresses(filename, &[], debug_line_info, debug_info_symbols)
    }

    fn find_dlcu_index(&self, address: u64) -> Option<usize> {
        let a2a = &self.addr_to_dlcu;
        let a2a_idx = search_address_key(a2a, address, &|x: &(u64, u32)| -> u64 { x.0 })?;
        let dlcu_idx = a2a[a2a_idx].1 as usize;

        Some(dlcu_idx)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    pub fn find_line_as_ref(&self, address: u64) -> Option<(&str, &str, usize)> {
        let idx = self.find_dlcu_index(address)?;
        let dlcu = &self.debug_line_cus[idx];

        dlcu.find_line(address)
    }

    /// Find line information of an address.
    ///
    /// `address` is an offset from the head of the loaded binary/or
    /// shared object.  This function returns a tuple of `(dir_name, file_name, line_no)`.
    ///
    /// This function is pretty much the same as `find_line_as_ref()`
    /// except returning a copies of `String` instead of `&str`.
    #[cfg(test)]
    fn find_line(&self, address: u64) -> Option<(String, String, usize)> {
        let (dir, file, line_no) = self.find_line_as_ref(address)?;
        Some((String::from(dir), String::from(file), line_no))
    }

    /// Extract the symbol information from DWARf if having not did it
    /// before.
    fn ensure_debug_info_syms(&self) -> Result<(), Error> {
        if self.enable_debug_info_syms {
            let mut dis_ref = self.debug_info_syms.borrow_mut();
            if dis_ref.is_some() {
                return Ok(());
            }
            let mut debug_info_syms = debug_info_parse_symbols(&self.parser, None, 1)?;
            debug_info_syms.sort_by_key(|v: &DWSymInfo| -> &str { v.name });
            *dis_ref = Some(unsafe { mem::transmute(debug_info_syms) });
        }
        Ok(())
    }

    /// Create a sorted DWSymInfo list to map addresses to symbols.
    fn ensure_addr_di_syms(&self) -> Result<(), Error> {
        let mut addr_di_syms = self.addr_di_syms.borrow_mut();
        if !addr_di_syms.is_empty() {
            return Ok(());
        }

        self.ensure_debug_info_syms()?;
        let di_syms_ref = self.debug_info_syms.borrow();
        if let Some(ref di_syms) = *di_syms_ref {
            *addr_di_syms = di_syms
                .iter()
                .map(|x| unsafe { mem::transmute(x) })
                .collect();
            addr_di_syms.sort_by_key(|v| v.address);
        }
        Ok(())
    }

    /// Find the index of the DWSymInfo containing an address.
    fn find_di_sym_idx_addr(&self, address: u64) -> Option<usize> {
        self.ensure_addr_di_syms().ok()?;
        let addr_di_syms = self.addr_di_syms.borrow();
        let idx = match addr_di_syms.binary_search_by_key(&address, |sym| sym.address) {
            Ok(idx) => idx,
            Err(idx) => {
                if idx == 0 {
                    return None;
                }
                idx - 1
            }
        };
        let sym = addr_di_syms[idx];
        if address >= (sym.address + sym.size) {
            None
        } else {
            Some(idx)
        }
    }

    fn ensure_cu_offsets(&self) -> Result<(), Error> {
        let mut cu_offsets = self.cu_offsets.borrow_mut();
        if !cu_offsets.is_empty() {
            return Ok(());
        }

        let info_sect_idx = self.parser.find_section(".debug_info")?;
        let info_data = self.parser.read_section_raw_cache(info_sect_idx)?;
        let abbrev_sect_idx = self.parser.find_section(".debug_abbrev")?;
        let abbrev_data = self.parser.read_section_raw_cache(abbrev_sect_idx)?;
        let units = debug_info::UnitIter::new(info_data, abbrev_data);

        let mut offset = 0;
        for (uhdr, _) in units {
            cu_offsets.push(offset);
            offset += uhdr.unit_size();
        }
        // No CU beyond this offset.
        cu_offsets.push(offset);

        Ok(())
    }

    /// Find the offset of the CU containing the given offset.
    fn find_cu_offset(&self, offset: usize) -> Option<usize> {
        self.ensure_cu_offsets().ok()?;

        let cu_offsets = self.cu_offsets.borrow();
        if cu_offsets.is_empty() {
            return None;
        }

        match cu_offsets.binary_search(&offset) {
            Ok(idx) => {
                if idx == cu_offsets.len() - 1 {
                    None
                } else {
                    Some(cu_offsets[idx])
                }
            }
            Err(idx) => Some(cu_offsets[idx - 1]),
        }
    }

    /// Build a DIEIter for the DIE at an offset.
    fn build_dieiter_with_die_offset(
        &self,
        offset: usize,
    ) -> Option<(debug_info::UnitHeader, debug_info::DIEIter, debug_info::DIE)> {
        let cu_off = self.find_cu_offset(offset)?;
        let die_offset = offset - cu_off;

        let parser = &self.parser;
        let info_sect_idx = parser.find_section(".debug_info").ok()?;
        let info_data = parser.read_section_raw_cache(info_sect_idx).ok()?;
        let abbrev_sect_idx = parser.find_section(".debug_abbrev").ok()?;
        let abbrev_data = parser.read_section_raw_cache(abbrev_sect_idx).ok()?;
        let mut units = debug_info::UnitIter::new(&info_data[cu_off..], abbrev_data);
        let (uhdr, mut dieiter) = units.next()?;
        let die_cu = dieiter.next()?;
        if die_cu.tag != constants::DW_TAG_compile_unit {
            // The first DIE should be a compile unit.
            return None;
        }
        dieiter.seek_to_any(die_offset).ok()?;
        Some((uhdr, dieiter, die_cu))
    }

    pub fn get_local_vars(&self, address: u64) -> Option<(&[u8], Vec<(String, &[u8])>)> {
        let sym_idx = if let Some(idx) = self.find_di_sym_idx_addr(address) {
            idx
        } else {
            return None;
        };
        let addr_di_syms = self.addr_di_syms.borrow();
        let sym = addr_di_syms[sym_idx];
        let (uhdr, dieiter, mut die_cu) =
            if let Some((uhdr, itr, die_cu)) = self.build_dieiter_with_die_offset(sym.die_offset) {
                (uhdr, itr, die_cu)
            } else {
                return None;
            };

        if uhdr.version() != 0x4 {
            // V4 & V5 have different way to ahndle DW_AT_ranges.  V4
            // stores address ranges in the .debug_ranges section.  V5
            // stores them in the .debug_addr section.
            return None;
        };

        local_vars::find_local_vars_subprog(&self.parser, &uhdr, &mut die_cu, dieiter, address)
    }

    /// Find the address of a symbol from DWARF.
    ///
    /// # Arguments
    ///
    /// * `name` - is the symbol name to find.
    /// * `opts` - is the context giving additional parameters.
    pub fn find_address(&self, name: &str, opts: &FindAddrOpts) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }
        let elf_r = self.parser.find_address(name, opts)?;
        if !elf_r.is_empty() {
            // Since it is found from symtab, symtab should be
            // complete and DWARF shouldn't provide more information.
            return Ok(elf_r);
        }

        self.ensure_debug_info_syms()?;
        let dis_ref = self.debug_info_syms.borrow();
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut idx =
            match debug_info_syms.binary_search_by_key(&name.to_string(), |v| v.name.to_string()) {
                Ok(idx) => idx,
                _ => {
                    return Ok(vec![]);
                }
            };
        while idx > 0 && debug_info_syms[idx].name.eq(name) {
            idx -= 1;
        }
        if !debug_info_syms[idx].name.eq(name) {
            idx += 1;
        }
        let mut found = vec![];
        while debug_info_syms[idx].name.eq(name) {
            let DWSymInfo {
                address,
                size,
                sym_type,
                ..
            } = debug_info_syms[idx];
            found.push(SymbolInfo {
                name: name.to_string(),
                address,
                size,
                sym_type,
                ..Default::default()
            });
            idx += 1;
        }
        Ok(found)
    }

    /// Find the address of symbols matching a pattern from DWARF.
    ///
    /// #Arguments
    ///
    /// * `pattern` - is a regex pattern to match symbols.
    /// * `opts` - is the context giving additional parameters.
    ///
    /// Return a list of symbols including addresses and other information.
    pub fn find_address_regex(
        &self,
        pattern: &str,
        opts: &FindAddrOpts,
    ) -> Result<Vec<SymbolInfo>, Error> {
        if let SymbolType::Variable = opts.sym_type {
            return Err(Error::new(ErrorKind::Unsupported, "Not implemented"));
        }
        let r = self.parser.find_address_regex(pattern, opts)?;
        if !r.is_empty() {
            return Ok(r);
        }

        self.ensure_debug_info_syms()?;

        let dis_ref = self.debug_info_syms.borrow();
        if dis_ref.is_none() {
            return Ok(vec![]);
        }
        let debug_info_syms = dis_ref.as_ref().unwrap();
        let mut syms = vec![];
        let re = Regex::new(pattern).unwrap();
        for sym in debug_info_syms {
            if re.is_match(sym.name) {
                let DWSymInfo {
                    address,
                    size,
                    sym_type,
                    ..
                } = sym;
                syms.push(SymbolInfo {
                    name: sym.name.to_string(),
                    address: *address,
                    size: *size,
                    sym_type: *sym_type,
                    ..Default::default()
                });
            }
        }

        Ok(syms)
    }

    fn build_fname_to_dlcu(
        debug_line_cus: &Vec<debug_line::DebugLineCU>,
    ) -> (Vec<&'static str>, Vec<(u32, u32)>) {
        let mut fname_order = HashMap::<&str, u32>::new();
        let mut fname_to_dlcu = Vec::new();
        let mut entry_cnt = 0;
        for dlcu in debug_line_cus {
            for finfo in &dlcu.files {
                if fname_order.get(finfo.name.as_str()).is_none() {
                    fname_order.insert(finfo.name.as_str(), 0_u32);
                }
                entry_cnt += 1;
            }
        }
        let mut fnames: Vec<&'static str> = fname_order
            .keys()
            .map(|x| unsafe { mem::transmute(*x) })
            .collect();
        fnames.sort();
        for (order, fname) in fnames.iter().enumerate() {
            fname_order.insert(fname, order as u32);
        }
        fname_to_dlcu.reserve(entry_cnt);
        for (dlcuidx, dlcu) in debug_line_cus.iter().enumerate() {
            for finfo in &dlcu.files {
                let fnidx = fname_order.get(finfo.name.as_str()).unwrap();
                fname_to_dlcu.push((*fnidx, dlcuidx as u32));
            }
        }
        fname_to_dlcu.sort();
        (fnames, fname_to_dlcu)
    }

    fn ensure_fname_to_dlcu(&self) {
        let mut me = self.back.borrow_mut();
        let (fnames, fname_to_dlcu) = Self::build_fname_to_dlcu(&self.debug_line_cus);
        me.fnames = fnames;
        me.fname_to_dlcu = fname_to_dlcu;
    }

    pub fn find_line_addresses(&self, filename: &str, line_no: usize) -> Vec<u64> {
        self.ensure_fname_to_dlcu();

        let back = self.back.borrow();
        let mut addresses = vec![];
        if let Ok(str_order) = back.fnames.binary_search(&filename) {
            if let Ok(idx_found) = back
                .fname_to_dlcu
                .binary_search_by_key(&str_order, |x| x.0 as usize)
            {
                let mut idx = idx_found;
                while idx > 0 && back.fname_to_dlcu[idx - 1].0 as usize == str_order {
                    idx -= 1;
                    let dlcu_idx = back.fname_to_dlcu[idx].1 as usize;
                    let dlcu = &self.debug_line_cus[dlcu_idx];
                    dlcu.find_line_addresses(filename, line_no, &mut addresses);
                }
                idx = idx_found;
                while idx < back.fname_to_dlcu.len()
                    && back.fname_to_dlcu[idx].0 as usize == str_order
                {
                    let dlcu_idx = back.fname_to_dlcu[idx].1 as usize;
                    let dlcu = &self.debug_line_cus[dlcu_idx];
                    dlcu.find_line_addresses(filename, line_no, &mut addresses);
                    idx += 1;
                }
            }
        }
        addresses
    }

    #[cfg(test)]
    fn pick_address_for_test(&self) -> (u64, &str, &str, usize) {
        let (addr, idx) = self.addr_to_dlcu[self.addr_to_dlcu.len() / 3];
        let dlcu = &self.debug_line_cus[idx as usize];
        let (dir, file, line) = dlcu.stringify_row(0).unwrap();
        (addr, dir, file, line)
    }
}

/// The symbol information extracted out of DWARF.
#[derive(Clone)]
struct DWSymInfo<'a> {
    name: &'a str,
    address: u64,
    size: u64,
    sym_type: SymbolType, // A function or a variable.
    // The offset of the DIE from the start of the section.
    die_offset: usize,
}

fn find_die_sibling(die: &mut debug_info::DIE<'_>) -> Option<usize> {
    for (name, _form, _opt, value) in die {
        if name == constants::DW_AT_sibling {
            if let debug_info::AttrValue::Unsigned(off) = value {
                return Some(off as usize);
            }
            return None;
        }
    }
    None
}

/// Parse a DIE that declares a subprogram. (a function)
///
/// We already know the given DIE is a declaration of a subprogram.
/// This function trys to extract the address of the subprogram and
/// other information from the DIE.
///
/// # Arguments
///
/// * `die` - is a DIE.
/// * `str_data` - is the content of the `.debug_str` section.
///
/// Return a [`DWSymInfo`] if it finds the address of the subprogram.
fn parse_die_subprogram<'a>(
    die: &mut debug_info::DIE<'a>,
    str_data: &'a [u8],
) -> Result<Option<DWSymInfo<'a>>, Error> {
    let mut addr: Option<u64> = None;
    let mut name_str: Option<&str> = None;
    let mut size = 0;
    let die_offset = die.offset as usize;

    for (name, _form, _opt, value) in die {
        match name {
            constants::DW_AT_linkage_name | constants::DW_AT_name => {
                if name_str.is_some() {
                    continue;
                }
                name_str = Some(match value {
                    debug_info::AttrValue::Unsigned(str_off) => unsafe {
                        CStr::from_ptr(str_data[str_off as usize..].as_ptr() as *const i8)
                            .to_str()
                            .map_err(|_e| {
                                Error::new(
                                    ErrorKind::InvalidData,
                                    "fail to extract the name of a subprogram",
                                )
                            })?
                    },
                    debug_info::AttrValue::String(s) => s,
                    _ => {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            "fail to parse DW_AT_linkage_name {}",
                        ));
                    }
                });
            }
            constants::DW_AT_lo_pc => match value {
                debug_info::AttrValue::Unsigned(pc) => {
                    addr = Some(pc);
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ));
                }
            },
            constants::DW_AT_hi_pc => match value {
                debug_info::AttrValue::Unsigned(sz) => {
                    size = sz;
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "fail to parse DW_AT_lo_pc",
                    ));
                }
            },
            _ => {}
        }
    }

    match (addr, name_str) {
        (Some(address), Some(name)) => Ok(Some(DWSymInfo {
            name,
            address,
            size,
            sym_type: SymbolType::Function,
            die_offset,
        })),
        _ => Ok(None),
    }
}

/// Walk through all DIEs of a compile unit to extract symbols.
///
/// # Arguments
///
/// * `dieiter` - is an iterator returned by the iterator that is
///               returned by an [`UnitIter`].  [`UnitIter`] returns
///               an [`UnitHeader`] and an [`DIEIter`].
/// * `str_data` - is the content of the `.debug_str` section.
/// * `found_syms` - the Vec to append the found symbols.
fn debug_info_parse_symbols_cu<'a>(
    mut dieiter: debug_info::DIEIter<'a>,
    str_data: &'a [u8],
    found_syms: &mut Vec<DWSymInfo<'a>>,
) {
    while let Some(mut die) = dieiter.next() {
        if die.tag == 0 || die.tag == constants::DW_TAG_namespace {
            continue;
        }

        assert!(die.abbrev.is_some());
        if die.tag != constants::DW_TAG_subprogram {
            if die.abbrev.unwrap().has_children {
                if let Some(sibling_off) = find_die_sibling(&mut die) {
                    dieiter.seek_to_sibling(sibling_off);
                    continue;
                }
                // Skip this DIE quickly, or the iterator will
                // recalculate the size of the DIE.
                die.exhaust().unwrap();
            }
            continue;
        }

        if let Ok(Some(mut syminfo)) = parse_die_subprogram(&mut die, str_data) {
            syminfo.die_offset += dieiter.get_cu_offset();
            found_syms.push(syminfo);
        }
    }
}

/// The parse result of the `.debug_info` section.
///
/// This type is used by the worker threads to pass results to the
/// coordinator after finishing an Unit.  `Stop` is used to nofity the
/// coordinator that a matching condition is met.  It could be that
/// the given symbol is already found, so that the coordinator should
/// stop producing more tasks.
enum DIParseResult<'a> {
    Symbols(Vec<DWSymInfo<'a>>),
    Stop,
}

/// Parse the addresses of symbols from the `.debug_info` section.
///
/// # Arguments
///
/// * `parser` - is an ELF parser.
/// * `cond` - is a function to check if we have found the information
///            we need.  The function will stop earlier if the
///            condition is met.
/// * `nthreads` - is the number of worker threads to create. 0 or 1
///                means single thread.
fn debug_info_parse_symbols<'a>(
    parser: &'a Elf64Parser,
    cond: Option<&(dyn Fn(&DWSymInfo<'a>) -> bool + Send + Sync)>,
    nthreads: usize,
) -> Result<Vec<DWSymInfo<'a>>, Error> {
    let info_sect_idx = parser.find_section(".debug_info")?;
    let info_data = parser.read_section_raw_cache(info_sect_idx)?;
    let abbrev_sect_idx = parser.find_section(".debug_abbrev")?;
    let abbrev_data = parser.read_section_raw_cache(abbrev_sect_idx)?;
    let units = debug_info::UnitIter::new(info_data, abbrev_data);
    let str_sect_idx = parser.find_section(".debug_str")?;
    let str_data = parser.read_section_raw_cache(str_sect_idx)?;

    let mut syms = Vec::<DWSymInfo>::new();

    if nthreads > 1 {
        thread::scope(|s| {
            // Create worker threads to process tasks (Units) in a work
            // queue.
            let mut handles = vec![];
            let (qsend, qrecv) = unbounded::<debug_info::DIEIter<'a>>();
            let (result_tx, result_rx) = mpsc::channel::<DIParseResult>();

            for _ in 0..nthreads {
                let result_tx = result_tx.clone();
                let qrecv = qrecv.clone();

                let handle = s.spawn(move || {
                    let mut syms: Vec<DWSymInfo> = vec![];
                    if let Some(cond) = cond {
                        while let Ok(dieiterholder) = qrecv.recv() {
                            let saved_sz = syms.len();
                            debug_info_parse_symbols_cu(dieiterholder, str_data, &mut syms);
                            for sym in &syms[saved_sz..] {
                                if !cond(sym) {
                                    result_tx.send(DIParseResult::Stop).unwrap();
                                }
                            }
                        }
                    } else {
                        while let Ok(dieiterholder) = qrecv.recv() {
                            debug_info_parse_symbols_cu(dieiterholder, str_data, &mut syms);
                        }
                    }
                    result_tx.send(DIParseResult::Symbols(syms)).unwrap();
                });

                handles.push(handle);
            }

            for (uhdr, dieiter) in units {
                if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                    qsend.send(dieiter).unwrap();
                }

                if let Ok(result) = result_rx.try_recv() {
                    if let DIParseResult::Stop = result {
                        break;
                    } else {
                        return Err(Error::new(
                            ErrorKind::UnexpectedEof,
                            "Receive an unexpected result",
                        ));
                    }
                }
            }

            drop(qsend);

            drop(result_tx);
            while let Ok(result) = result_rx.recv() {
                if let DIParseResult::Symbols(mut thread_syms) = result {
                    syms.append(&mut thread_syms);
                }
            }
            for handle in handles {
                handle.join().unwrap();
            }
            Ok(())
        })?;
    } else if let Some(cond) = cond {
        'outer: for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                let saved_sz = syms.len();
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
                for sym in &syms[saved_sz..] {
                    if !cond(sym) {
                        break 'outer;
                    }
                }
            }
        }
    } else {
        for (uhdr, dieiter) in units {
            if let debug_info::UnitHeader::CompileV4(_) = uhdr {
                debug_info_parse_symbols_cu(dieiter, str_data, &mut syms);
            }
        }
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[cfg(feature = "nightly")]
    use test::Bencher;

    use crate::tools::{
        decode_leb128, decode_leb128_s, decode_shalf, decode_sword, decode_udword, decode_uhalf,
        decode_uword,
    };

    #[allow(unused)]
    struct ArangesCU {
        debug_line_off: usize,
        aranges: Vec<(u64, u64)>,
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

    fn parse_aranges_elf(filename: &str) -> Result<Vec<ArangesCU>, Error> {
        let parser = Elf64Parser::open(filename)?;
        parse_aranges_elf_parser(&parser)
    }

    #[test]
    fn test_decode_leb128() {
        let data = vec![0xf4, 0xf3, 0x75];
        let result = decode_leb128(&data);
        assert!(result.is_some());
        if let Some((v, s)) = result {
            assert_eq!(v, 0x1d79f4);
            assert_eq!(s, 3);
        }

        let result = decode_leb128_s(&data);
        assert!(result.is_some());
        if let Some((v, s)) = result {
            assert_eq!(v, -165388);
            assert_eq!(s, 3);
        }
    }

    #[test]
    fn test_decode_words() {
        let data = vec![0x7f, 0x85, 0x36, 0xf9];
        assert_eq!(decode_uhalf(&data), 0x857f);
        assert_eq!(decode_shalf(&data), -31361);
        assert_eq!(decode_uword(&data), 0xf936857f);
        assert_eq!(decode_sword(&data), -113867393);
    }

    #[test]
    fn test_dwarf_resolver() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let resolver_r = DwarfResolver::open(bin_name, true, false);
        assert!(resolver_r.is_ok());
        let resolver = resolver_r.unwrap();
        let (addr, dir, file, line) = resolver.pick_address_for_test();

        let line_info = resolver.find_line(addr);
        assert!(line_info.is_some());
        let (dir_ret, file_ret, line_ret) = line_info.unwrap();
        println!("{}/{} {}", dir_ret, file_ret, line_ret);
        assert_eq!(dir, dir_ret);
        assert_eq!(file, file_ret);
        assert_eq!(line, line_ret);
    }

    #[test]
    fn test_debug_info_parse_symbols() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let parser_r = Elf64Parser::open(bin_name);
        assert!(parser_r.is_ok());
        let parser = parser_r.unwrap();

        let result = debug_info_parse_symbols(&parser, None, 4);

        assert!(result.is_ok());
        let syms = result.unwrap();

        let mut myself_found = false;
        let mut myself_addr: u64 = 0;
        let mut parse_symbols_found = false;
        let mut parse_symbols_addr: u64 = 0;
        for sym in syms {
            if sym
                .name
                .starts_with("_ZN8blazesym5dwarf5tests29test_debug_info_parse_symbols17h")
            {
                myself_found = true;
                myself_addr = sym.address;
            } else if sym
                .name
                .starts_with("_ZN8blazesym5dwarf24debug_info_parse_symbols17h")
            {
                parse_symbols_found = true;
                parse_symbols_addr = sym.address;
            }
        }
        assert!(myself_found);
        assert!(parse_symbols_found);
        assert_eq!(
            (test_debug_info_parse_symbols as fn() as *const fn() as i64)
                - (debug_info_parse_symbols
                    as for<'a> fn(
                        &'a Elf64Parser,
                        Option<&(dyn Fn(&DWSymInfo<'a>) -> bool + Send + Sync)>,
                        usize,
                    ) -> Result<Vec<DWSymInfo<'a>>, Error>
                    as *const (
                        &'_ Elf64Parser,
                        Option<&(dyn Fn(&DWSymInfo<'_>) -> bool + Send + Sync)>,
                        usize,
                    ) as i64),
            myself_addr as i64 - parse_symbols_addr as i64
        );
    }

    #[test]
    fn test_dwarf_find_addr_regex() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let dwarf = DwarfResolver::open(bin_name, false, true).unwrap();
        let opts = FindAddrOpts {
            offset_in_file: false,
            obj_file_name: false,
            sym_type: SymbolType::Unknown,
        };
        let syms = dwarf
            .find_address_regex("DwarfResolver.*find_address_regex.*", &opts)
            .unwrap();
        assert!(!syms.is_empty());
    }

    /// Benchmark the [`debug_info_parse_symbols`] function.
    #[cfg(feature = "nightly")]
    #[bench]
    fn debug_info_parse_single_threaded(b: &mut Bencher) {
        let bin_name = env::args().next().unwrap();
        let parser = Elf64Parser::open(&bin_name).unwrap();

        let () = b.iter(|| debug_info_parse_symbols(&parser, None, 1).unwrap());
    }

    #[test]
    fn get_local_vars() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let example_path = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("fibonacci-v4");
        let example_s = example_path.as_path().to_str().unwrap();

        let resolver_r = DwarfResolver::open(example_s, true, true);
        assert!(resolver_r.is_ok());
        let resolver = resolver_r.unwrap();
        let addr = 0x1166;

        if let Some((fb, vars)) = resolver.get_local_vars(addr) {
            assert_eq!(fb.len(), 1);
            assert_eq!(vars.len(), 1);
            assert_eq!(vars[0].0, "n");
            assert_eq!(vars[0].1.len(), 2);
        } else {
            assert!(false, "fail to get the information of local variables");
        }
    }

    #[test]
    fn find_line_addresses() {
        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let example_path = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data")
            .join("fibonacci");
        let dwarf = DwarfResolver::open(example_path.to_str().unwrap(), true, true).unwrap();

        let addresses = dwarf.find_line_addresses("fibonacci.c", 11);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], 0x118c);
    }
}
