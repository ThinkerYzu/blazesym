use super::call_frame::{
    CFARule, CFInsnParser, CallFrameMachine, CallFrameParser, RegRule, CFCIE, CFFDE,
};
use super::decode_udword;
use super::dwarf_expr::{run_dwarf_expr, ExprResult, SysOperators};
use crate::elf::Elf64Parser;
use crate::{StackFrame, StackSession};
use std::io::{Error, ErrorKind};

pub struct DwarfStackFrame<'a> {
    stack: &'a [u8],
    stack_base: u64,
    regs: Vec<u64>,
    sp_reg: usize,
    ip_reg: usize,
}

impl<'a> StackFrame for DwarfStackFrame<'a> {
    fn get_ip(&self) -> u64 {
        self.regs[self.ip_reg]
    }

    fn get_frame_pointer(&self) -> u64 {
        0
    }

    fn get_stack_pointer(&self) -> u64 {
        self.regs[self.sp_reg]
    }
}

pub struct DwarfStackSession<'a> {
    stack: &'a [u8],
    stack_base: u64,
    reloc_base: u64,
    sp_reg: usize,
    ip_reg: usize,
    parser: &'a Elf64Parser,
    frame_idx: usize,
    saved_frames: Vec<DwarfStackFrame<'a>>,
    init_regs: Vec<u64>,
    is_debug_frame: bool,
    cies: Vec<CFCIE<'a>>,
    fdes: Vec<CFFDE<'a>>,
}

impl<'a> DwarfStackSession<'a> {
    /// Create a DwarfStackSession for the x86 architecture.
    fn new_x86<'b>(
        parser: &'b Elf64Parser,
        reloc_base: u64,
        stack: &'b [u8],
        stack_base: u64,
        regs: Vec<u64>,
        is_debug_frame: bool,
    ) -> DwarfStackSession<'b> {
        let mut session = DwarfStackSession {
            stack,
            stack_base,
            reloc_base,
            sp_reg: 7,
            ip_reg: 16,
            parser,
            frame_idx: 0,
            saved_frames: vec![],
            init_regs: regs,
            is_debug_frame,
            cies: vec![],
            fdes: vec![],
        };
        session.prepare_cies_fdes();
        session
    }

    fn prepare_cies_fdes(&mut self) {
        let cfparser = CallFrameParser::from_parser(self.parser, self.is_debug_frame);
        let cies_fdes = cfparser.parse_call_frames(self.parser);
        if cies_fdes.is_err() {
            return;
        }
        let (cies, fdes) = cies_fdes.unwrap();
        self.cies = cies;
        self.fdes = fdes;
    }

    /// Find the right CIE & FDE that cover the given address.
    ///
    /// It doesn't support the .eh_frame_hdr section yet.  Instead, it
    /// does lienar scaning.
    fn find_cie_fde(&mut self, addr: u64) -> Option<(&CFCIE, &CFFDE)> {
        for fde in &self.fdes {
            if addr >= fde.initial_location && addr < (fde.initial_location + fde.address_range) {
                for i in 0..self.cies.len() {
                    let cie = &mut self.cies[i];
                    if cie.offset == fde.cie_pointer as usize {
                        if let CFARule::invalid = cie.aux.init_cfa {
                            let insniter =
                                CFInsnParser::new(cie.init_instructions, cie.address_size as usize);
                            let mut state = CallFrameMachine::new(cie, self.init_regs.len());
                            for insn in insniter {
                                state.run_insn(insn);
                            }
                            cie.aux.init_cfa = state.cfa;
                            cie.aux.init_regs = state.regs;
                        }
                        let cie = &self.cies[i];
                        return Some((cie, fde));
                    }
                }
            }
        }
        None
    }

    /// Resolve RegRules to get new values of registers.
    ///
    /// RegRules are rules to compute the values of registers at an
    /// outter frame (caller frame) from the values of registers at an
    /// inner frame.
    fn resolve_reg_rules(
        &self,
        regs: &[u64],
        reg_rules: &[RegRule],
        cfa_rule: CFARule,
        fb_expr: &[u8],
        address_size: usize,
    ) -> Result<(Vec<u64>, u64), Error> {
        let cfa = match cfa_rule {
            CFARule::reg_offset(reg_no, delta) => (regs[reg_no as usize] as i64 + delta) as u64,
            CFARule::expression(expr) => {
                match run_dwarf_expr(&expr, fb_expr, 50, regs, address_size, self)? {
                    ExprResult::Value(v_u64) => v_u64,
                    ExprResult::Register(reg_no) => regs[reg_no as usize],
                    _ => {
                        return Err(Error::new(ErrorKind::InvalidData, "Invalid CFARule"));
                    }
                }
            }
            CFARule::invalid => 0,
        };
        let mut result_regs = vec![];
        for (r, reg_rule) in reg_rules.iter().enumerate() {
            let v = match reg_rule {
                RegRule::undefined => 0,
                RegRule::same_value => regs[r],
                RegRule::offset(off) => {
                    let off = (off + cfa as i64) as u64 - self.stack_base;
                    if (off as usize + 8) > self.stack.len() {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "the stack buffer is too small",
                        ));
                    }
                    decode_udword(&self.stack[off as usize..])
                }
                RegRule::val_offset(off) => (off + cfa as i64) as u64,
                RegRule::register(reg_no) => regs[*reg_no as usize],
                RegRule::expression(expr) => {
                    let addr = match run_dwarf_expr(expr, fb_expr, 50, regs, address_size, self)? {
                        ExprResult::Value(v_u64) => v_u64,
                        ExprResult::Register(reg_no) => regs[reg_no as usize],
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid RegRule::expression",
                            ));
                        }
                    };
                    let off = addr - self.stack_base;
                    if (off as usize + 8) >= self.stack.len() {
                        return Err(Error::new(
                            ErrorKind::Other,
                            "the stack buffer is too small",
                        ));
                    }
                    decode_udword(&self.stack[off as usize..])
                }
                RegRule::val_expression(expr) => {
                    match run_dwarf_expr(expr, fb_expr, 50, regs, address_size, self)? {
                        ExprResult::Value(v_u64) => v_u64,
                        ExprResult::Register(reg_no) => regs[reg_no as usize],
                        _ => {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "Invalid RegRule::expression",
                            ));
                        }
                    }
                }
                RegRule::architectural => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "RegRule::architectural is unsupported",
                    ));
                }
            };
            #[cfg(test)]
            println!("{} {:?} {:x}", r, reg_rule, v);
            result_regs.push(v);
        }
        Ok((result_regs, cfa))
    }

    /// Create the frame of the caller.
    ///
    /// Create a DwarfStackFrame for the caller from the information
    /// of the inner frame where the called function runs at.
    ///
    /// # Arguments
    ///
    /// * `addr` - is the address of the inner frame.
    /// * `regs` - is the list of the register values of the inner frame.
    /// * `fb_expr` - is the value of DW_AT_frame_base of the function
    ///               running at the inner frame.
    fn create_caller_frame(
        &mut self,
        addr: u64,
        regs: &[u64],
        fb_expr: &[u8],
    ) -> Result<DwarfStackFrame<'a>, Error> {
        let addr = addr - self.reloc_base;
        let (cie, fde) = self
            .find_cie_fde(addr)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "The address is not in the table"))?;
        let mut state = CallFrameMachine::new(cie, regs.len());
        let insniter = CFInsnParser::new(fde.instructions, cie.address_size as usize);
        state.loc = fde.initial_location;
        for insn in insniter {
            // run_insn() return previous location, not the location
            // after advancing.
            //
            // The content of the new row is what is defined between
            // the previous advancing and the latest advancign.
            if let Some(prev_loc) = state.run_insn(insn) {
                if addr >= prev_loc && addr < state.loc {
                    break;
                }
            }
        }
        let address_size = cie.address_size as usize;
        let (mut regs, cfa) =
            self.resolve_reg_rules(regs, &state.regs, state.cfa, fb_expr, address_size)?;

        // Update stack pointer register.  For some reason, gcc
        // compiler doesn't generate rules to update rsp.  I am not
        // sure if it is a general rule.
        regs[self.sp_reg] = cfa;

        Ok(DwarfStackFrame {
            stack: self.stack,
            stack_base: self.stack_base,
            regs,
            sp_reg: self.sp_reg,
            ip_reg: self.ip_reg,
        })
    }

    /// Get the current visiting frame.
    ///
    /// It will create an intance of DwarfStackFrame if necessary.
    fn get_call_frame(&mut self) -> Result<&DwarfStackFrame<'a>, Error> {
        if self.frame_idx < self.saved_frames.len() {
            return Ok(&self.saved_frames[self.frame_idx]);
        }
        let nframes = self.saved_frames.len();
        let frame = if nframes > 0 {
            let addr = self.saved_frames[nframes - 1].regs[self.ip_reg];
            let regs = self.saved_frames[nframes - 1].regs.clone();
            self.create_caller_frame(addr, &regs, &[])?
        } else {
            let regs = self.init_regs.clone();
            DwarfStackFrame {
                stack: self.stack,
                stack_base: self.stack_base,
                regs,
                sp_reg: self.sp_reg,
                ip_reg: self.ip_reg,
            }
        };
        self.saved_frames.push(frame);
        Ok(&self.saved_frames[nframes])
    }
}

impl<'a> SysOperators for DwarfStackSession<'a> {
    fn get_mem(&self, _addr: u64, _size: u64) -> u64 {
        panic!("get_mem");
    }

    fn debug_addr(&self, _base: u64, _addr: u64) -> u64 {
        panic!("debug_addr");
    }

    fn get_cfa(&self) -> Result<u64, Error> {
        Err(Error::new(ErrorKind::Unsupported, "unsupported"))
    }
}

impl<'a> StackSession for DwarfStackSession<'a> {
    fn next_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.frame_idx >= self.saved_frames.len() {
            return None;
        }
        self.frame_idx += 1;
        Some(self.get_call_frame().ok()?)
    }
    fn prev_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.frame_idx == 0 {
            return None;
        }
        self.frame_idx -= 1;
        Some(&self.saved_frames[self.frame_idx])
    }
    fn go_top(&mut self) -> Option<&dyn StackFrame> {
        self.frame_idx = 0;
        Some(self.get_call_frame().ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::env;
    use std::fs::File;
    use std::io::Read;
    use std::path::Path;

    use crate::elf::Elf64Parser;

    #[test]
    fn stack_walking() {
        // (gdb) info registers
        // rax            0x1                 1
        // rbx            0x1                 1
        // rcx            0x555555557dc0      93824992247232
        // rdx            0x7fffffffdb98      140737488346008
        // rsi            0x7fffffffdb88      140737488345992
        // rdi            0x1                 1
        // rbp            0x7fffffffc9d0      0x7fffffffc9d0
        // rsp            0x7fffffffc9b0      0x7fffffffc9b0
        // r8             0x7ffff7f92f10      140737353690896
        // r9             0x7ffff7fc9040      140737353912384
        // r10            0x7ffff7fc3908      140737353890056
        // r11            0x7ffff7fde680      140737354000000
        // r12            0x7fffffffdb88      140737488345992
        // r13            0x55555555518c      93824992235916
        // r14            0x555555557dc0      93824992247232
        // r15            0x7ffff7ffd040      140737354125376
        // rip            0x55555555515d      0x55555555515d <fibonacci+20>
        // eflags         0x297               [ CF PF AF SF IF ]
        // cs             0x33                51
        // ss             0x2b                43
        // ds             0x0                 0
        // es             0x0                 0
        // fs             0x0                 0
        // gs             0x0                 0
        //
        // (gdb) f 89
        // (gdb) info registers
        // rax            0x1                 1
        // rbx            0x0                 0
        // rcx            0x555555557dc0      93824992247232
        // rdx            0x7fffffffdb98      140737488346008
        // rsi            0x7fffffffdb88      140737488345992
        // rdi            0x1                 1
        // rbp            0x7fffffffda70      0x7fffffffda70
        // rsp            0x7fffffffda60      0x7fffffffda60
        // r8             0x7ffff7f92f10      140737353690896
        // r9             0x7ffff7fc9040      140737353912384
        // r10            0x7ffff7fc3908      140737353890056
        // r11            0x7ffff7fde680      140737354000000
        // r12            0x7fffffffdb88      140737488345992
        // r13            0x55555555518c      93824992235916
        // r14            0x555555557dc0      93824992247232
        // r15            0x7ffff7ffd040      140737354125376
        // rip            0x5555555551a9      0x5555555551a9 <main+29>
        // eflags         0x297               [ CF PF AF SF IF ]
        // cs             0x33                51
        // ss             0x2b                43
        // ds             0x0                 0
        // es             0x0                 0
        // fs             0x0                 0
        // gs             0x0                 0
        //
        // (gdb) p/x *(long long*)($rbp)
        // $1 = 0x1
        // (gdb) p/x *(long long*)($rbp + 8)
        // $2 = 0x7ffff7da1d90
        // (gdb) p/ $rbp + 8
        // $3 = 0x7fffffffda78
        // (gdb) dump memory data/fibonacci-stack1.dump 0x7fffffffc9b0 0x7fffffffda80
        let regs: Vec<u64> = vec![
            0x1,
            0x1,
            0x555555557dc0,
            0x7fffffffdb98,
            0x7fffffffdb88,
            0x1,
            0x7fffffffc9d0,
            0x7fffffffc9b0,
            0x7ffff7f92f10,
            0x7ffff7fc9040,
            0x7ffff7fc3908,
            0x7ffff7fde680,
            0x7fffffffdb88,
            0x55555555518c,
            0x555555557dc0,
            0x7ffff7ffd040,
            0x55555555515d,
        ];
        // The real address in the process.
        let addr_fibonacci: u64 = 0x555555555149;
        // The virtual address in the ELF file.
        let vaddr_fibonacci: u64 = 0x1149;
        let reloc_base: u64 = addr_fibonacci - vaddr_fibonacci;
        // The address of the first byte in the dump file of stack.
        let stack_base: u64 = 0x7fffffffc9b0;

        let args: Vec<String> = env::args().collect();
        let bin_name = &args[0];
        let data_dir = Path::new(bin_name)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("data");
        let bin_path = data_dir.join("fibonacci");

        let stack_dump_path = data_dir.join("fibonacci-stack.dump");
        let mut stack_dump = vec![];
        File::open(&stack_dump_path)
            .unwrap()
            .read_to_end(&mut stack_dump)
            .unwrap();
        let parser = Elf64Parser::open(bin_path.to_str().unwrap()).unwrap();

        println!(
            "{:?}, {:?}, {:?} {}",
            data_dir,
            bin_path,
            stack_dump_path,
            stack_dump.len()
        );

        let mut session =
            DwarfStackSession::new_x86(&parser, reloc_base, &stack_dump, stack_base, regs, false);
        let top_frame = session.go_top().unwrap();
        println!(
            "top: {:x} {:x}",
            top_frame.get_ip(),
            top_frame.get_stack_pointer()
        );
        for i in 1..89 {
            let frame = session.next_frame().unwrap();
            println!(
                "frame {}: {:x} {:x}",
                i,
                frame.get_ip(),
                frame.get_stack_pointer()
            );
        }
        let main_frame = session.next_frame().unwrap();
        println!(
            "main: {:x} {:x}",
            main_frame.get_ip(),
            main_frame.get_stack_pointer()
        );

        let init_frame = session.next_frame().unwrap();
        println!(
            "init: {:x} {:x}",
            init_frame.get_ip(),
            init_frame.get_stack_pointer()
        );
        assert_eq!(init_frame.get_ip(), 0x7ffff7da1d90);
        assert_eq!(init_frame.get_stack_pointer(), 0x7fffffffda80);
    }
}
