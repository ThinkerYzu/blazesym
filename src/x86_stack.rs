use super::{StackFrame, StackSession};

#[doc(hidden)]
pub const REG_RAX: usize = 0;
#[doc(hidden)]
pub const REG_RBX: usize = 1;
#[doc(hidden)]
pub const REG_RCX: usize = 2;
#[doc(hidden)]
pub const REG_RDX: usize = 3;
#[doc(hidden)]
pub const REG_RSI: usize = 4;
#[doc(hidden)]
pub const REG_RDI: usize = 5;
#[doc(hidden)]
pub const REG_RSP: usize = 6;
#[doc(hidden)]
pub const REG_RBP: usize = 7;
#[doc(hidden)]
pub const REG_R8: usize = 8;
#[doc(hidden)]
pub const REG_R9: usize = 9;
#[doc(hidden)]
pub const REG_R10: usize = 10;
#[doc(hidden)]
pub const REG_R11: usize = 11;
#[doc(hidden)]
pub const REG_R12: usize = 12;
#[doc(hidden)]
pub const REG_R13: usize = 13;
#[doc(hidden)]
pub const REG_R14: usize = 14;
#[doc(hidden)]
pub const REG_R15: usize = 15;
#[doc(hidden)]
pub const REG_RIP: usize = 16;

struct X86_64StackFrame {
    rip: u64,
    rbp: u64,
    rsp: u64,
}

impl StackFrame for X86_64StackFrame {
    fn get_ip(&self) -> u64 {
        self.rip
    }
    fn get_frame_pointer(&self) -> u64 {
        self.rbp
    }
    fn get_stack_pointer(&self) -> u64 {
        self.rsp
    }
}

/// Do stacking unwind for x86_64
///
/// Parse a block of memory that is a copy of stack of thread to get frames.
///
#[doc(hidden)]
pub struct X86_64StackSession {
    frames: Vec<X86_64StackFrame>,
    stack: Vec<u8>,
    stack_base: u64, // The base address of the stack
    registers: [u64; 17],
    current_rsp: u64,
    current_rbp: u64,
    current_rip: u64,
    current_frame_idx: usize,
}

impl X86_64StackSession {
    fn _get_rbp_rel(&self) -> usize {
        (self.current_rbp - self.stack_base) as usize
    }

    fn _mark_at_bottom(&mut self) {
        self.current_rbp = 0;
    }

    fn _is_at_bottom(&self) -> bool {
        self.current_rbp == 0
    }

    fn _get_u64(&self, off: usize) -> u64 {
        let stack = &self.stack;
        (stack[off] as u64)
            | ((stack[off + 1] as u64) << 8)
            | ((stack[off + 2] as u64) << 16)
            | ((stack[off + 3] as u64) << 24)
            | ((stack[off + 4] as u64) << 32)
            | ((stack[off + 5] as u64) << 40)
            | ((stack[off + 6] as u64) << 48)
            | ((stack[off + 7] as u64) << 56)
    }

    fn _get_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.frames.len() > self.current_frame_idx {
            let frame = &self.frames[self.current_frame_idx];
            return Some(frame);
        }

        let frame = X86_64StackFrame {
            rip: self.current_rip,
            rbp: self.current_rbp,
            rsp: self.current_rsp,
        };
        self.frames.push(frame);

        if self._get_rbp_rel() <= (self.stack.len() - 16) {
            self.current_rsp = self.current_rbp + 16;
            let new_rbp = self._get_u64(self._get_rbp_rel());
            let new_rip = self._get_u64(self._get_rbp_rel() + 8);
            self.current_rbp = new_rbp;
            self.current_rip = new_rip;
        } else {
            self._mark_at_bottom();
        }

        Some(self.frames.last().unwrap() as &dyn StackFrame)
    }

    pub fn new(stack: Vec<u8>, stack_base: u64, registers: [u64; 17]) -> X86_64StackSession {
        X86_64StackSession {
            frames: Vec::new(),
            stack,
            stack_base,
            registers,
            current_rsp: registers[REG_RSP],
            current_rbp: registers[REG_RBP],
            current_rip: registers[REG_RIP],
            current_frame_idx: 0,
        }
    }
}

impl StackSession for X86_64StackSession {
    fn next_frame(&mut self) -> Option<&dyn StackFrame> {
        if self._is_at_bottom() {
            return None;
        }

        self.current_frame_idx += 1;
        self._get_frame()
    }

    fn prev_frame(&mut self) -> Option<&dyn StackFrame> {
        if self.current_frame_idx == 0 {
            return None;
        }

        self.current_frame_idx -= 1;
        self._get_frame()
    }

    fn go_top(&mut self) -> Option<&dyn StackFrame> {
        self.current_rip = self.registers[REG_RIP];
        self.current_rbp = self.registers[REG_RBP];
        self.current_rsp = self.registers[REG_RSP];
        self.current_frame_idx = 0;
        self._get_frame()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_world_stack() {
        // A stack sample from a Hello World proram.
        let stack = vec![
            0xb0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xaf, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
            0xd0, 0xd5, 0xff, 0xff, 0xff, 0x7f, 0x0, 0x0, 0xcb, 0x5, 0x40, 0x0, 0x0, 0x0, 0x0, 0x0,
        ];
        let expected_rips = vec![0x000000000040058a, 0x00000000004005af, 0x00000000004005cb];
        let base = 0x7fffffffd5a0;
        let mut registers: [u64; 17] = [0; 17];

        registers[REG_RIP] = expected_rips[0];
        registers[REG_RBP] = 0x7fffffffd5a0;

        let mut session = X86_64StackSession::new(stack, base, registers);
        let frame = session.go_top().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[0]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[1]);
        let frame = session.next_frame().unwrap();
        assert_eq!(frame.get_ip(), expected_rips[2]);
    }
}
