use crate::tools::{
    decode_leb128, decode_leb128_s, decode_sdword, decode_shalf, decode_sword, decode_uN,
    decode_udword, decode_uhalf, decode_uword,
};

use std::io::{Error, ErrorKind};
use std::mem;

#[derive(Debug, Clone)]
pub enum DwarfExprOp {
    #[allow(non_camel_case_types)]
    DW_OP_addr(u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref,
    #[allow(non_camel_case_types)]
    DW_OP_const1u(u8),
    #[allow(non_camel_case_types)]
    DW_OP_const1s(i8),
    #[allow(non_camel_case_types)]
    DW_OP_const2u(u16),
    #[allow(non_camel_case_types)]
    DW_OP_const2s(i16),
    #[allow(non_camel_case_types)]
    DW_OP_const4u(u32),
    #[allow(non_camel_case_types)]
    DW_OP_const4s(i32),
    #[allow(non_camel_case_types)]
    DW_OP_const8u(u64),
    #[allow(non_camel_case_types)]
    DW_OP_const8s(i64),
    #[allow(non_camel_case_types)]
    DW_OP_constu(u64),
    #[allow(non_camel_case_types)]
    DW_OP_consts(i64),
    #[allow(non_camel_case_types)]
    DW_OP_dup,
    #[allow(non_camel_case_types)]
    DW_OP_drop,
    #[allow(non_camel_case_types)]
    DW_OP_over,
    #[allow(non_camel_case_types)]
    DW_OP_pick(u8),
    #[allow(non_camel_case_types)]
    DW_OP_swap,
    #[allow(non_camel_case_types)]
    DW_OP_rot,
    #[allow(non_camel_case_types)]
    DW_OP_xderef,
    #[allow(non_camel_case_types)]
    DW_OP_abs,
    #[allow(non_camel_case_types)]
    DW_OP_and,
    #[allow(non_camel_case_types)]
    DW_OP_div,
    #[allow(non_camel_case_types)]
    DW_OP_minus,
    #[allow(non_camel_case_types)]
    DW_OP_mod,
    #[allow(non_camel_case_types)]
    DW_OP_mul,
    #[allow(non_camel_case_types)]
    DW_OP_neg,
    #[allow(non_camel_case_types)]
    DW_OP_not,
    #[allow(non_camel_case_types)]
    DW_OP_or,
    #[allow(non_camel_case_types)]
    DW_OP_plus,
    #[allow(non_camel_case_types)]
    DW_OP_plus_uconst(u64),
    #[allow(non_camel_case_types)]
    DW_OP_shl,
    #[allow(non_camel_case_types)]
    DW_OP_shr,
    #[allow(non_camel_case_types)]
    DW_OP_shra,
    #[allow(non_camel_case_types)]
    DW_OP_xor,
    #[allow(non_camel_case_types)]
    DW_OP_bra(i16),
    #[allow(non_camel_case_types)]
    DW_OP_eq,
    #[allow(non_camel_case_types)]
    DW_OP_ge,
    #[allow(non_camel_case_types)]
    DW_OP_gt,
    #[allow(non_camel_case_types)]
    DW_OP_le,
    #[allow(non_camel_case_types)]
    DW_OP_lt,
    #[allow(non_camel_case_types)]
    DW_OP_ne,
    #[allow(non_camel_case_types)]
    DW_OP_skip(i16),
    #[allow(non_camel_case_types)]
    DW_OP_lit(u8),
    #[allow(non_camel_case_types)]
    DW_OP_reg(u8),
    #[allow(non_camel_case_types)]
    DW_OP_breg(u8, i64),
    #[allow(non_camel_case_types)]
    DW_OP_regx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_fbreg(i64),
    #[allow(non_camel_case_types)]
    DW_OP_bregx(u64, i64),
    #[allow(non_camel_case_types)]
    DW_OP_piece(u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref_size(u8),
    #[allow(non_camel_case_types)]
    DW_OP_xderef_size(u8),
    #[allow(non_camel_case_types)]
    DW_OP_nop,
    #[allow(non_camel_case_types)]
    DW_OP_push_object_address,
    #[allow(non_camel_case_types)]
    DW_OP_call2(u16),
    #[allow(non_camel_case_types)]
    DW_OP_call4(u32),
    #[allow(non_camel_case_types)]
    DW_OP_call_ref(u64),
    #[allow(non_camel_case_types)]
    DW_OP_form_tls_address,
    #[allow(non_camel_case_types)]
    DW_OP_call_frame_cfa,
    #[allow(non_camel_case_types)]
    DW_OP_bit_piece(u64, u64),
    #[allow(non_camel_case_types)]
    DW_OP_implicit_value(Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_stack_value,
    #[allow(non_camel_case_types)]
    DW_OP_implicit_pointer(u64, i64),
    #[allow(non_camel_case_types)]
    DW_OP_addrx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_constx(u64),
    #[allow(non_camel_case_types)]
    DW_OP_entry_value(Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_const_type(u64, Vec<u8>),
    #[allow(non_camel_case_types)]
    DW_OP_regval_type(u64, u64),
    #[allow(non_camel_case_types)]
    DW_OP_deref_type(u8, u64),
    #[allow(non_camel_case_types)]
    DW_OP_xderef_type(u8, u64),
    #[allow(non_camel_case_types)]
    DW_OP_convert(u64),
    #[allow(non_camel_case_types)]
    DW_OP_reinterpret(u64),
    #[allow(non_camel_case_types)]
    DW_OP_lo_user,
    #[allow(non_camel_case_types)]
    DW_OP_hi_user,
}

pub struct DwarfExprParser<'a> {
    address_size: usize,
    offset: usize,
    raw: &'a [u8],
}

impl<'a> DwarfExprParser<'a> {
    pub fn from(raw: &'a [u8], address_size: usize) -> Self {
        DwarfExprParser {
            address_size,
            offset: 0,
            raw,
        }
    }
}

impl<'a> Iterator for DwarfExprParser<'a> {
    type Item = (u64, DwarfExprOp);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.raw.len() {
            return None;
        }

        let raw = self.raw;
        let op = raw[self.offset];
        let saved_offset = self.offset as u64;
        match op {
            0x3 => {
                let addr = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                self.offset += 1 + self.address_size;
                Some((saved_offset, DwarfExprOp::DW_OP_addr(addr)))
            }
            0x6 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_deref))
            }
            0x8 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const1u(raw[self.offset - 1]),
                ))
            }
            0x9 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const1s(raw[self.offset - 1] as i8),
                ))
            }
            0xa => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const2u(decode_uhalf(&raw[(self.offset - 2)..])),
                ))
            }
            0xb => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const2s(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0xc => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const4u(decode_uword(&raw[(self.offset - 4)..])),
                ))
            }
            0xd => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const4s(decode_sword(&raw[(self.offset - 4)..])),
                ))
            }
            0xe => {
                self.offset += 9;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const8u(decode_udword(&raw[(self.offset - 8)..])),
                ))
            }
            0xf => {
                self.offset += 9;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_const8s(decode_sdword(&raw[(self.offset - 8)..])),
                ))
            }
            0x10 => {
                let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_constu(v)))
            }
            0x11 => {
                let (v, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_consts(v)))
            }
            0x12 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_dup))
            }
            0x13 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_drop))
            }
            0x14 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_over))
            }
            0x15 => {
                self.offset += 2;
                Some((saved_offset, DwarfExprOp::DW_OP_pick(raw[self.offset - 1])))
            }
            0x16 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_swap))
            }
            0x17 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_rot))
            }
            0x18 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_xderef))
            }
            0x19 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_abs))
            }
            0x1a => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_and))
            }
            0x1b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_div))
            }
            0x1c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_minus))
            }
            0x1d => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_mod))
            }
            0x1e => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_mul))
            }
            0x1f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_neg))
            }
            0x20 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_not))
            }
            0x21 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_or))
            }
            0x22 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_plus))
            }
            0x23 => {
                let (addend, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_plus_uconst(addend)))
            }
            0x24 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shl))
            }
            0x25 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shr))
            }
            0x26 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_shra))
            }
            0x27 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_xor))
            }
            0x28 => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_bra(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x29 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_eq))
            }
            0x2a => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_ge))
            }
            0x2b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_gt))
            }
            0x2c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_le))
            }
            0x2d => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lt))
            }
            0x2e => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_ne))
            }
            0x2f => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_skip(decode_shalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x30..=0x4f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lit(op - 0x30)))
            }
            0x50..=0x6f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_reg(op - 0x50)))
            }
            0x70..=0x8f => {
                let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_breg(op - 0x70, offset)))
            }
            0x90 => {
                let (offset, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_regx(offset)))
            }
            0x91 => {
                let (offset, bytes) = decode_leb128_s(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_fbreg(offset)))
            }
            0x92 => {
                let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let (offset, obytes) =
                    decode_leb128_s(&raw[(self.offset + 1 + rbytes as usize)..]).unwrap();
                self.offset += 1 + rbytes as usize + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_bregx(reg, offset)))
            }
            0x93 => {
                let (piece_sz, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_piece(piece_sz)))
            }
            0x94 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_deref_size(raw[self.offset - 1]),
                ))
            }
            0x95 => {
                self.offset += 2;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_xderef_size(raw[self.offset - 1]),
                ))
            }
            0x96 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_nop))
            }
            0x97 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_push_object_address))
            }
            0x98 => {
                self.offset += 3;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_call2(decode_uhalf(&raw[(self.offset - 2)..])),
                ))
            }
            0x99 => {
                self.offset += 5;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_call4(decode_uword(&raw[(self.offset - 4)..])),
                ))
            }
            0x9a => {
                let off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                self.offset += 1 + self.address_size;
                Some((saved_offset, DwarfExprOp::DW_OP_call_ref(off)))
            }
            0x9b => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_form_tls_address))
            }
            0x9c => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_call_frame_cfa))
            }
            0x9d => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let (off, obytes) =
                    decode_leb128(&raw[(self.offset + 1 + sbytes as usize)..]).unwrap();
                self.offset += 1 + sbytes as usize + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_bit_piece(sz, off)))
            }
            0x9e => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let blk = Vec::from(
                    &raw[(self.offset + 1 + sbytes as usize)
                        ..(self.offset + 1 + sbytes as usize + sz as usize)],
                );
                Some((saved_offset, DwarfExprOp::DW_OP_implicit_value(blk)))
            }
            0x9f => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_stack_value))
            }
            0xa0 => {
                let die_off = decode_uN(self.address_size, &raw[(self.offset + 1)..]);
                let (const_off, bytes) =
                    decode_leb128_s(&raw[(self.offset + 1 + self.address_size)..]).unwrap();
                self.offset += 1 + self.address_size + bytes as usize;
                Some((
                    saved_offset,
                    DwarfExprOp::DW_OP_implicit_pointer(die_off, const_off),
                ))
            }
            0xa1 => {
                let (addr, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_addrx(addr)))
            }
            0xa2 => {
                let (v, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset += 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_constx(v)))
            }
            0xa3 => {
                let (sz, sbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let blk = Vec::from(
                    &raw[(self.offset + 1 + sbytes as usize)
                        ..(self.offset + 1 + sbytes as usize + sz as usize)],
                );
                self.offset += 1 + sbytes as usize + sz as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_entry_value(blk)))
            }
            0xa4 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let pos = self.offset + 1 + bytes as usize;
                let sz = raw[pos];
                let pos = pos + 1;
                let v = Vec::from(&raw[pos..(pos + sz as usize)]);
                self.offset += pos + sz as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_const_type(ent_off, v)))
            }
            0xa5 => {
                let (reg, rbytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                let pos = self.offset + 1 + rbytes as usize;
                let (off, obytes) = decode_leb128(&raw[pos..]).unwrap();
                self.offset += pos + obytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_regval_type(reg, off)))
            }
            0xa6 => {
                let sz = raw[self.offset + 1];
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
                self.offset = self.offset + 2 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_deref_type(sz, ent_off)))
            }
            0xa7 => {
                let sz = raw[self.offset + 1];
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 2)..]).unwrap();
                self.offset = self.offset + 2 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_xderef_type(sz, ent_off)))
            }
            0xa8 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset = self.offset + 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_convert(ent_off)))
            }
            0xa9 => {
                let (ent_off, bytes) = decode_leb128(&raw[(self.offset + 1)..]).unwrap();
                self.offset = self.offset + 1 + bytes as usize;
                Some((saved_offset, DwarfExprOp::DW_OP_reinterpret(ent_off)))
            }
            0xe0 => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_lo_user))
            }
            0xff => {
                self.offset += 1;
                Some((saved_offset, DwarfExprOp::DW_OP_hi_user))
            }
            _ => None,
        }
    }
}

pub trait SysOperators {
    fn get_mem(&self, addr: u64, size: u64) -> u64;
    fn debug_addr(&self, base: u64, addr: u64) -> u64;
    fn get_cfa(&self) -> Result<u64, Error>;
}

struct DummySysOps();

impl SysOperators for DummySysOps {
    fn get_mem(&self, _addr: u64, _size: u64) -> u64 {
        0
    }

    fn debug_addr(&self, _base: u64, _addr: u64) -> u64 {
        0
    }

    fn get_cfa(&self) -> Result<u64, Error> {
        Err(Error::new(ErrorKind::Unsupported, "unsupported"))
    }
}

#[derive(Clone)]
enum DwarfExprPCOp {
    #[allow(non_camel_case_types)]
    go_next,
    #[allow(non_camel_case_types)]
    skip(i64),
    #[allow(non_camel_case_types)]
    stack_value,
    #[allow(non_camel_case_types)]
    in_reg(u64),
    #[allow(non_camel_case_types)]
    implicit_value(Vec<u8>),
    #[allow(non_camel_case_types)]
    implicit_pointer(u64, u64),
}

fn run_dwarf_expr_insn(
    insn: DwarfExprOp,
    fb_expr: &[u8],
    stack: &mut Vec<u64>,
    regs: &[u64],
    address_size: usize,
    sysops: &dyn SysOperators,
) -> Result<DwarfExprPCOp, Error> {
    match insn {
        DwarfExprOp::DW_OP_addr(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_deref => {
            if let Some(addr) = stack.pop() {
                let val = sysops.get_mem(addr, 8);
                stack.push(val);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_const1u(v_u8) => {
            stack.push(v_u8 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const1s(v_i8) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i8 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const2u(v_u16) => {
            stack.push(v_u16 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const2s(v_i16) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i16 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const4u(v_u32) => {
            stack.push(v_u32 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const4s(v_i32) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i32 as i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const8u(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_const8s(v_i64) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_constu(v_u64) => {
            stack.push(v_u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_consts(v_i64) => {
            stack.push(unsafe { mem::transmute::<i64, u64>(v_i64) });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_dup => {
            if !stack.is_empty() {
                stack.push(stack[stack.len() - 1]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_drop => {
            if !stack.is_empty() {
                stack.pop();
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_over => {
            if stack.len() >= 2 {
                stack.push(stack[stack.len() - 2]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_pick(v_u8) => {
            if stack.len() >= (v_u8 as usize + 1) {
                stack.push(stack[stack.len() - 1 - v_u8 as usize]);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_swap => {
            let len = stack.len();
            stack.swap(len - 1, len - 2);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_rot => {
            let len = stack.len();
            let tmp = stack[len - 1];
            stack[len - 1] = stack[len - 2];
            stack[len - 2] = stack[len - 3];
            stack[len - 3] = tmp;
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_xderef => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef is not implemented",
        )),
        DwarfExprOp::DW_OP_abs => {
            let len = stack.len();
            stack[len - 1] = unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(stack[len - 1]).abs())
            };
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_and => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(first & second);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_div => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                if first != 0 {
                    stack.push(second / first);
                    return Ok(DwarfExprPCOp::go_next);
                }
            }
            Err(Error::new(ErrorKind::Other, "divide by zerror"))
        }
        DwarfExprOp::DW_OP_minus => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second - first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_mod => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second % first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_mul => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second * first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_neg => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] = unsafe {
                    mem::transmute::<i64, u64>(-mem::transmute::<u64, i64>(stack[len - 1]))
                };
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_not => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] = !stack[len - 1];
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_or => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second | first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_plus => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second + first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_plus_uconst(v_u64) => {
            let len = stack.len();
            if len >= 1 {
                stack[len - 1] += v_u64;
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shl => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second << first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shr => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second >> first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_shra => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();

                let mut val = second >> first;
                val |= 0 - ((second & 0x8000000000000000) >> first);
                stack.push(val);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xor => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(second ^ first);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_bra(v_i16) => {
            if let Some(top) = stack.pop() {
                if top == 0 {
                    Ok(DwarfExprPCOp::go_next)
                } else {
                    Ok(DwarfExprPCOp::skip(v_i16 as i64))
                }
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_eq => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second == first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_ge => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second >= first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_gt => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second > first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_le => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second <= first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_lt => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second < first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_ne => {
            if stack.len() >= 2 {
                let first = stack.pop().unwrap();
                let second = stack.pop().unwrap();
                stack.push(if second != first { 1 } else { 0 });
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_skip(v_i16) => Ok(DwarfExprPCOp::skip(v_i16 as i64)),
        DwarfExprOp::DW_OP_lit(v_u8) => {
            stack.push(v_u8 as u64);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_reg(v_u8) => Ok(DwarfExprPCOp::in_reg(v_u8 as u64)),
        DwarfExprOp::DW_OP_breg(v_u8, v_i64) => {
            stack.push(unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u8 as usize]) + v_i64)
            });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_regx(v_u64) => Ok(DwarfExprPCOp::in_reg(v_u64)),
        DwarfExprOp::DW_OP_fbreg(_v_i64) => {
            if fb_expr.is_empty() {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "The frame base expression is empty",
                ));
            }
            let result = run_dwarf_expr(fb_expr, &[], 32, regs, address_size, sysops)?;
            match result {
                ExprResult::Value(value) => {
                    stack.push(value);
                }
                ExprResult::Addr(addr) => {
                    stack.push(addr);
                }
                ExprResult::Register(no) => {
                    stack.push(regs[no as usize]);
                }
                ExprResult::ImplicitValue(_v_vu8) => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "Don't know how to handle a [u8]",
                    ));
                }
                ExprResult::ImplicitPointer(_v_u64, _v_u64_1) => {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "Don't know how to handle a [u8]",
                    ));
                }
            }
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_bregx(v_u64, v_i64) => {
            stack.push(unsafe {
                mem::transmute::<i64, u64>(mem::transmute::<u64, i64>(regs[v_u64 as usize]) + v_i64)
            });
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_piece(_v_u64) => Ok(DwarfExprPCOp::go_next),
        DwarfExprOp::DW_OP_deref_size(v_u8) => {
            if let Some(addr) = stack.pop() {
                let v = sysops.get_mem(addr, v_u8 as u64);
                stack.push(v);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xderef_size(_v_u8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef_size is not implemented",
        )),
        DwarfExprOp::DW_OP_nop => Ok(DwarfExprPCOp::go_next),
        DwarfExprOp::DW_OP_push_object_address => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_push_object_address is not implemented",
        )),
        DwarfExprOp::DW_OP_call2(_v_u16) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call2 is not implemented",
        )),
        DwarfExprOp::DW_OP_call4(_v_u32) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call4 is not implemented",
        )),
        DwarfExprOp::DW_OP_call_ref(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_call_ref is not implemented",
        )),
        DwarfExprOp::DW_OP_form_tls_address => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_form_tls_address is not implemented",
        )),
        DwarfExprOp::DW_OP_call_frame_cfa => {
            match sysops.get_cfa() {
                Ok(v) => {
                    stack.push(v);
                }
                Err(err) => {
                    return Err(err);
                }
            }
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_bit_piece(_v_u64, _v_u64_1) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_bit_piece is not implemented",
        )),
        DwarfExprOp::DW_OP_implicit_value(v_vu8) => Ok(DwarfExprPCOp::implicit_value(v_vu8)),
        DwarfExprOp::DW_OP_stack_value => Ok(DwarfExprPCOp::stack_value),
        DwarfExprOp::DW_OP_implicit_pointer(_v_u64, _v_i64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_implicit_pointer is not implemented",
        )),
        DwarfExprOp::DW_OP_addrx(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_addrx is not implemented",
        )),
        DwarfExprOp::DW_OP_constx(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_entry_value(_v_vu8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_const_type(_v_u64, _v_vu8) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_constx is not implemented",
        )),
        DwarfExprOp::DW_OP_regval_type(v_u64, _v_u64_1) => {
            stack.push(regs[v_u64 as usize]);
            Ok(DwarfExprPCOp::go_next)
        }
        DwarfExprOp::DW_OP_deref_type(v_u8, _v_u64) => {
            if let Some(addr) = stack.pop() {
                let v = sysops.get_mem(addr, v_u8 as u64);
                stack.push(v);
                Ok(DwarfExprPCOp::go_next)
            } else {
                Err(Error::new(ErrorKind::Other, "stack is empty"))
            }
        }
        DwarfExprOp::DW_OP_xderef_type(_v_u8, _v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_xderef_type is not implemented",
        )),
        DwarfExprOp::DW_OP_convert(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_convert is not implemented",
        )),
        DwarfExprOp::DW_OP_reinterpret(_v_u64) => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_reinterpret is not implemented",
        )),
        DwarfExprOp::DW_OP_lo_user => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_lo_user is not implemented",
        )),
        DwarfExprOp::DW_OP_hi_user => Err(Error::new(
            ErrorKind::Unsupported,
            "DW_OP_hi_user is not implemented",
        )),
    }
}

pub enum ExprResult {
    Value(u64),
    Addr(u64),
    Register(u32),
    ImplicitValue(Vec<u8>),
    ImplicitPointer(u64, u64),
}

/// Run DWARF Expression and return a result.
///
/// See https://dwarfstd.org/doc/DWARF5.pdf
///
/// # Arguments
///
/// * `max_rounds` - how many rounds (instructions) up to this function can run to limit the runtime of the expression.
/// * `regs` - The values of registers that the expressiopn will read.
/// * `address_size` - The size of a pointer/address.
/// * `sysops` - The call funciton to fetach the content of a given address.
pub fn run_dwarf_expr(
    expr: &[u8],
    fb_expr: &[u8],
    max_rounds: usize,
    regs: &[u64],
    address_size: usize,
    sysops: &dyn SysOperators,
) -> Result<ExprResult, Error> {
    let insns: Vec<(u64, DwarfExprOp)> = DwarfExprParser::from(expr, address_size).collect();
    let mut idx = 0;
    let mut stack = Vec::<u64>::new();
    let mut rounds = 0;

    while idx < insns.len() {
        if rounds >= max_rounds {
            return Err(Error::new(ErrorKind::Other, "spend too much time"));
        }
        rounds += 1;

        let (_offset, insn) = &insns[idx];

        match run_dwarf_expr_insn(
            insn.clone(),
            fb_expr,
            &mut stack,
            regs,
            address_size,
            sysops,
        ) {
            Err(err) => {
                return Err(err);
            }
            Ok(DwarfExprPCOp::go_next) => {
                idx += 1;
            }
            Ok(DwarfExprPCOp::skip(rel)) => {
                let tgt_offset = (if idx < (insns.len() - 1) {
                    insns[idx].0 as i64
                } else {
                    expr.len() as i64
                } + rel) as u64;

                if tgt_offset == expr.len() as u64 {
                    break;
                }

                while tgt_offset < insns[idx].0 && idx > 0 {
                    idx -= 1;
                }
                while tgt_offset > insns[idx].0 && idx < (insns.len() - 1) {
                    idx += 1;
                }
                if tgt_offset != insns[idx].0 {
                    return Err(Error::new(ErrorKind::Other, "invalid branch target"));
                }
            }
            Ok(DwarfExprPCOp::stack_value) => {
                if let Some(v) = stack.pop() {
                    return Ok(ExprResult::Value(v));
                } else {
                    return Err(Error::new(ErrorKind::Other, "stack is empty"));
                }
            }
            Ok(DwarfExprPCOp::in_reg(no)) => {
                return Ok(ExprResult::Register(no as u32));
            }
            Ok(DwarfExprPCOp::implicit_value(v_vu8)) => {
                return Ok(ExprResult::ImplicitValue(v_vu8));
            }
            Ok(DwarfExprPCOp::implicit_pointer(v_u64, v_u64_1)) => {
                return Ok(ExprResult::ImplicitPointer(v_u64, v_u64_1));
            }
        }
    }

    if let Some(v) = stack.pop() {
        println!("stack size {}", stack.len());
        Ok(ExprResult::Addr(v))
    } else {
        Err(Error::new(ErrorKind::Other, "stack is empty"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_run_dwarf_expr() {
        //  0 DW_OP_breg(7, 8)
        //  2 DW_OP_breg(16, 0)
        //  4 DW_OP_lit(15)
        //  5 DW_OP_and
        //  6 DW_OP_lit(11)
        //  7 DW_OP_ge
        //  8 DW_OP_lit(3)
        //  9 DW_OP_shl
        //  10 DW_OP_plus
        let expr = [119 as u8, 8, 128, 0, 63, 26, 59, 42, 51, 36, 34];
        let regs = [14 as u64; 32];
        let sysops = DummySysOps();

        let address_size = mem::size_of::<*const u8>();
        let v = run_dwarf_expr(&expr, &[], 9, &regs, address_size, &sysops);
        assert!(v.is_ok());
        assert!(if let ExprResult::Addr(30) = v.unwrap() {
            true
        } else {
            false
        });

        // max_rounds is too small.
        let v = run_dwarf_expr(&expr, &[], 8, &regs, address_size, &sysops);
        assert!(v.is_err());
    }
}
