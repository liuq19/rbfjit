use libc::{
    mmap, mprotect, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE,
};
use std::fs;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::option::Option;
use std::{mem, ptr};

const MAX_MEMORY_SIZE: usize = 65536;

// 常用的寄存器
const _IN: u8 = 28; // 存放 getchar 函数地址
const _OUT: u8 = 27; // 存放 putchar 函数地址
const _PREG: u8 = 26;

// 临时寄存
const _VREG: u8 = 15; // 做指针deref的寄存器
const _WIMM: u8 = 14; // 做加减运算的imm寄存器
const _FP: u8 = 29;
const _LR: u8 = 30;

// 寄存器传参
// 只用到 X0 一个寄存器

type BfFunc = unsafe extern "C" fn(*mut i64);

fn getchar(p: *mut i64) {
    let mut buffer = [0; 1];
    io::stdin().read_exact(&mut buffer).unwrap();
    unsafe {
        *p = buffer[0] as i64;
    }
}

fn putchar(p: *const i64) {
    let u = unsafe { ((*p) & 0xff) as u8 };
    print!("{}", u as char);
    io::stdout().flush().unwrap();
}

#[derive(Debug)]
enum Instr {
    INCREMENT(u64),    // +
    DECREMENT(u64),    // -
    SHIFTRIGHT(usize), // >
    SHIFTLEFT(usize),  // <
    INPUT,             // ,
    OUTPUT,            // .
    LOOPSTART(usize),  // [
    LOOPEND(usize),    // ]
}

struct Interpreter<'a> {
    code: &'a Vec<Instr>,
    mem: Vec<i64>,
    ip: usize,
    mp: usize,
}

impl<'a> Interpreter<'a> {
    fn new(code: &'a Vec<Instr>) -> Self {
        let ret = Interpreter {
            code: code,
            mem: vec![0i64; MAX_MEMORY_SIZE],
            ip: 0usize,
            mp: 0usize,
        };
        ret
    }

    fn run(&mut self) {
        while self.ip < self.code.len() {
            match self.code[self.ip] {
                Instr::INCREMENT(size) => self.mem[self.mp] += size as i64,
                Instr::DECREMENT(size) => self.mem[self.mp] -= size as i64,
                Instr::SHIFTLEFT(shift) => {
                    if self.mp < shift {
                        eprintln!("Invalid memory shift");
                    }
                    self.mp -= shift;
                }
                Instr::SHIFTRIGHT(shift) => {
                    self.mp += shift;
                    if self.mp >= self.mem.len() {
                        self.mem.resize(2 * self.mp, 0)
                    }
                }
                Instr::LOOPSTART(end_ip) => {
                    if self.mem[self.mp] == 0 {
                        self.ip = end_ip
                    }
                }
                Instr::LOOPEND(start_ip) => {
                    if self.mem[self.mp] != 0 {
                        self.ip = start_ip
                    }
                }
                Instr::INPUT => {
                    getchar(&mut self.mem[self.mp] as *mut i64);
                }
                Instr::OUTPUT => {
                    putchar(&self.mem[self.mp] as *const i64);
                }
            }
            self.ip += 1;
        }
    }
}

struct JITExcutor<'a> {
    code: &'a Vec<Instr>,
    pctab: Vec<usize>,
    binary: Vec<u8>,
    mem: Vec<i64>,
}

#[allow(dead_code)]
fn disasemble(code: &Vec<Instr>) {
    println!("{:?}", code);
}

impl<'a> JITExcutor<'a> {
    fn new(code: &'a Vec<Instr>) -> JITExcutor<'a> {
        let len = code.len();
        let ret = JITExcutor {
            code: code,
            pctab: vec![0; len + 1],
            binary: Vec::new(),
            mem: vec![0i64; MAX_MEMORY_SIZE],
        };
        ret
    }

    // 编译后的BrainFuck 函数, 是一个 BfFunc 函数，
    // fn(*mut i64);
    fn compile(&mut self) {
        self.compile_prologue();
        self.compile_body();
        self.compile_epilogue();
    }

    // AArch64 PCS:
    // reference: https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
    //          8-byte
    //     +------------+
    //     |            | <-- old sp (16-byte alignment)
    //     +------------+
    //     |     x28    |
    //     +------------+
    //     |     x27    |
    //     +------------+
    //     |     x26    |
    //     +------------+
    //     |            | // local variable
    //     +------------+
    //     |     lr     |
    //     +------------+
    //     |     fp     | <-- sp (old sp - 0x30)
    //     +------------+
    //
    fn compile_prologue(&mut self) {
        // 需要保存的寄存器有: FP, LD, _IN, _OUT, _PREG
        self.emit_bytes(&[0xfd, 0x7b, 0xbd, 0xa9]); // stp fp,  lr, [sp, #-0x30]!
        self.emit_bytes(&[0xfc, 0x6f, 0x02, 0xa9]); // stp x27, x28, [sp, #0x20]
        self.emit_bytes(&[0xfa, 0x0f, 0x00, 0xf9]); // str x26, [sp, #0x18]
        self.emit_bytes(&[0xfd, 0x03, 0x00, 0x91]); // mov fp, sp
        self.emit_bytes(&[0xfa, 0x03, 0x00, 0xaa]); // mov x26(PREG), x0

        let in_addr =
            unsafe { std::mem::transmute::<*const u8, u64>(getchar as *const () as *const u8) };
        let out_addr =
            unsafe { std::mem::transmute::<*const u8, u64>(putchar as *const () as *const u8) };
        self.emit_imm64(_IN, in_addr);
        self.emit_imm64(_OUT, out_addr);
    }

    #[allow(dead_code)]
    fn emit_debug(&mut self) {
        self.emit_bytes(&[0x00, 0x00, 0x20, 0xd4]) // brk #0
    }

    fn compile_epilogue(&mut self) {
        self.emit_bytes(&[0xfa, 0x0f, 0x40, 0xf9]); // ldr x26, [sp, #0x18]
        self.emit_bytes(&[0xfb, 0x73, 0x42, 0xa9]); // ldp x27, x28, [sp], #20
        self.emit_bytes(&[0xfd, 0x7b, 0xc3, 0xa8]); // ldp fp, lr, [sp], #30
        self.emit_bytes(&[0xc0, 0x03, 0x5f, 0xd6]); // ret
    }

    fn emit_bytes(&mut self, bin: &[u8]) {
        self.binary.extend_from_slice(bin)
    }

    fn emit_word(&mut self, bin: u32) {
        self.emit_bytes(&bin.to_le_bytes())
    }

    // add reg, reg, #<n>
    fn emit_add(&mut self, reg: u8, n: u64) {
        if n < 4095 {
            let base = u32::from_le_bytes([0x00, 0x00, 0x00, 0x91]);
            // add reg, reg, #<n>
            self.emit_word(base | reg as u32 | ((reg as u32) << 5) | ((n as u32) << 10));
        } else {
            // mov _WIMM, #<n>
            // add reg, reg, _WIMM
            self.emit_imm64(_WIMM, n);
            let base = u32::from_le_bytes([0x00, 0x00, 0x0e, 0x8b]);
            self.emit_word(base | reg as u32 | ((reg as u32) << 5));
        }
    }

    // mov reg, #<n>
    fn emit_imm64(&mut self, reg: u8, n: u64) {
        let u0 = n & 0xffff;
        let base = u32::from_le_bytes([0x00, 0x00, 0x80, 0xd2]); // mov reg, u0
        self.emit_word(base | reg as u32 | ((u0 as u32) << 5));

        let u1 = (n >> 16) & 0xffff;
        if u1 != 0 {
            let base = u32::from_le_bytes([0x00, 0x00, 0xa0, 0xf2]);
            self.emit_word(base | reg as u32 | ((u1 as u32) << 5)); // movk reg, u1, LSL #16
        }

        let u2 = (n >> 32) & 0xffff;
        if u2 != 0 {
            let base = u32::from_le_bytes([0x00, 0x00, 0xc0, 0xf2]);
            self.emit_word(base | reg as u32 | ((u2 as u32) << 5)); // movk reg, u1, LSL #32
        }

        let u3 = n >> 48;
        if u3 != 0 {
            let base = u32::from_le_bytes([0x00, 0x00, 0xe0, 0xf2]);
            self.emit_word(base | reg as u32 | ((u3 as u32) << 5)); // movk reg, u1, LSL #48
        }
    }

    // sub reg, reg, #<n>
    fn emit_sub(&mut self, reg: u8, n: u64) {
        if n < 4095 {
            let base = u32::from_le_bytes([0x00, 0x00, 0x00, 0xd1]);
            self.emit_word(base | reg as u32 | ((reg as u32) << 5) | ((n as u32) << 10));
        // sub reg, reg, #<n>
        } else {
            self.emit_imm64(_WIMM, n); // mov _WIMM, #<n>
            let base = u32::from_le_bytes([0x00, 0x00, 0x0e, 0xcb]);
            self.emit_word(base | reg as u32 | ((reg as u32) << 5)); // sub reg, reg, _WIMM
        }
    }

    // ldr vreg, [xreg]
    fn emit_ldr(&mut self, vreg: u8, preg: u8) {
        let base = u32::from_le_bytes([0x00, 0x00, 0x40, 0xf9]);
        self.emit_word(base | vreg as u32 | ((preg as u32) << 5));
    }

    // str vreg [xreg]
    fn emit_str(&mut self, vreg: u8, preg: u8) {
        let base = u32::from_le_bytes([0x00, 0x00, 0x00, 0xf9]);
        self.emit_word(base | vreg as u32 | ((preg as u32) << 5));
    }

    fn compile_increment(&mut self, size: u64) {
        self.emit_ldr(_VREG, _PREG);
        self.emit_add(_VREG, size);
        self.emit_str(_VREG, _PREG);
    }

    fn compile_decrement(&mut self, size: u64) {
        self.emit_ldr(_VREG, _PREG);
        self.emit_sub(_VREG, size);
        self.emit_str(_VREG, _PREG);
    }

    fn compile_shiftleft(&mut self, shift: usize) {
        self.emit_sub(_PREG, (shift * size_of::<i64>()) as u64);
    }

    fn compile_shiftright(&mut self, shift: usize) {
        self.emit_add(_PREG, (shift * size_of::<i64>()) as u64);
    }

    fn compile_loopstart(&mut self, _: usize) {
        self.emit_ldr(_VREG, _PREG);
        self.emit_bytes(&[0x0f, 0x00, 0x00, 0xb4]); // cbz x15, ...
    }

    fn compile_loopend(&mut self, _: usize) {
        self.emit_ldr(_VREG, _PREG);
        self.emit_bytes(&[0x0f, 0x00, 0x00, 0xb5]); // cbnz x15, ...
    }

    fn compile_input(&mut self) {
        self.emit_bytes(&[0xe0, 0x03, 0x1a, 0xaa]); // mov x0, x26
        self.emit_bytes(&[0x80, 0x03, 0x3f, 0xd6]); // blr x28
    }

    fn compile_output(&mut self) {
        self.emit_bytes(&[0xe0, 0x03, 0x1a, 0xaa]); // mov x0, x26
        self.emit_bytes(&[0x60, 0x03, 0x3f, 0xd6]); // blr x27
    }

    fn compile_body(&mut self) {
        self.pctab[0] = self.binary.len();
        for i in 0..self.code.len() {
            match self.code[i] {
                Instr::INCREMENT(size) => self.compile_increment(size),
                Instr::DECREMENT(size) => self.compile_decrement(size),
                Instr::SHIFTLEFT(shift) => self.compile_shiftleft(shift),
                Instr::SHIFTRIGHT(shift) => self.compile_shiftright(shift),
                Instr::LOOPSTART(end_ip) => self.compile_loopstart(end_ip),
                Instr::LOOPEND(start_ip) => self.compile_loopend(start_ip),
                Instr::INPUT => self.compile_input(),
                Instr::OUTPUT => self.compile_output(),
            }
            self.pctab[i + 1] = self.binary.len();
        }
        self.patch_branch();
    }

    // check the branch instruction, PC-relative offset must < 1MB.
    // TODO: support larger PC-relative branches.
    fn patch_branch(&mut self) {
        for i in 0..self.code.len() {
            match self.code[i] {
                Instr::LOOPSTART(end_ip) => {
                    let pc = self.pctab[i] + 4;
                    let offset = self.pctab[end_ip + 1] - pc;

                    // check the branch instruction, PC-relative offset must < 1MB.
                    assert!(end_ip > i);
                    assert!(offset > 0 && (offset & 3) == 0 && (offset >> 21) == 0);

                    let base = u32::from_le_bytes(self.binary[pc..pc + 4].try_into().unwrap());
                    let bytes = (base | ((offset >> 2 << 5) as u32)).to_le_bytes();
                    self.binary[pc..pc + 4].copy_from_slice(&bytes);
                }
                Instr::LOOPEND(start_ip) => {
                    let pc = self.pctab[i] + 4;
                    let (mut offset, ov) = self.pctab[start_ip + 1].overflowing_sub(pc);
                    assert!(ov && (offset & 3) == 0);
                    offset = (offset >> 2) & ((1 << 20) - 1);
                    assert!(offset < (1 << 20));
                    let base = u32::from_le_bytes(self.binary[pc..pc + 4].try_into().unwrap());
                    let bytes = (base | ((offset << 5) as u32)).to_le_bytes();
                    self.binary[pc..pc + 4].copy_from_slice(&bytes);
                }
                _ => {}
            }
        }
    }

    fn load(&mut self) -> BfFunc {
        let size = self.binary.len();
        let ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0,
            )
        };
        if ptr == MAP_FAILED {
            panic!("Failed to allocate memory");
        }

        unsafe {
            ptr::copy_nonoverlapping(self.binary.as_ptr(), ptr as *mut u8, size);
        }

        /* make it executable */
        unsafe {
            if mprotect(ptr, size, PROT_READ | PROT_EXEC) < 0 {
                panic!("cannot lodding functions")
            }
        };

        /* export function symbol */
        unsafe { mem::transmute(ptr) }
    }

    fn run(&mut self) {
        unsafe {
            let f = self.load();
            f(self.mem.as_mut_ptr());
        }
    }
}

fn count_byte(bytes: &[u8], char: u8, idx: usize) -> usize {
    let mut i = idx;
    while i < bytes.len() && bytes[i] == char {
        i += 1;
    }
    i - idx
}

fn parse(str: &str) -> Option<Vec<Instr>> {
    let mut stack = Vec::new();
    let mut instrs = Vec::new();

    let mut i = 0;
    let bytes = str.as_bytes();
    while i < bytes.len() {
        i += 1;
        match bytes[i - 1] {
            b'+' => {
                // TODO: check the range of cnt in u8.
                let cnt = count_byte(bytes, b'+', i - 1);
                i += cnt - 1;
                instrs.push(Instr::INCREMENT(cnt as u64));
            }
            b'-' => {
                let cnt = count_byte(bytes, b'-', i - 1);
                i += cnt - 1;
                instrs.push(Instr::DECREMENT(cnt as u64));
            }
            b'<' => {
                let cnt = count_byte(bytes, b'<', i - 1);
                i += cnt - 1;
                instrs.push(Instr::SHIFTLEFT(cnt));
            }
            b'>' => {
                let cnt = count_byte(bytes, b'>', i - 1);
                i += cnt - 1;
                instrs.push(Instr::SHIFTRIGHT(cnt));
            }
            b',' => instrs.push(Instr::INPUT),
            b'.' => instrs.push(Instr::OUTPUT),
            b'[' => {
                // later push the end ip of the LOOPSTART instruction.
                instrs.push(Instr::LOOPSTART(0));
                stack.push(instrs.len() - 1);
            }
            b']' => {
                if let Some(start) = stack.pop() {
                    instrs.push(Instr::LOOPEND(start));
                    instrs[start] = Instr::LOOPSTART(instrs.len() - 1)
                } else {
                    eprintln!("Invalid syntax (unmatched loop)in code!");
                    return None;
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        eprintln!("Invalid syntax (unclosed loop)in code!");
        return None;
    }
    return Some(instrs);
}

mod command;
use clap::Parser;

fn main() {
    let args = command::Args::parse();

    if let Ok(code) = fs::read_to_string(&args.file) {
        if let Some(instr) = parse(&code) {
            match args.mode.as_str() {
                "jit" => {
                    let mut jit = JITExcutor::new(&instr);
                    jit.compile();
                    jit.run();
                }
                "intepret" => {
                    let mut ext = Interpreter::new(&instr);
                    ext.run();
                }
                _ => eprintln!("invalid mode, only support \"intepret\" or \"jit\" mode"),
            }
        }
    }
}
