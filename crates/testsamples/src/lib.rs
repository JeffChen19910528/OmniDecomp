//! Self-built binary samples for tests. Each contains the x86-64 code `push rbp; mov rbp,rsp; nop; pop rbp; ret`.

pub const CODE: [u8; 7] = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3];

fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

/// Minimal PE32+ with one `.text` section (VA 0x1000, raw 0x200), image base 0x140000000.
pub fn minimal_pe64() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x40u32.to_le_bytes());
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &0x8664u16.to_le_bytes()); // machine
    put(&mut b, 0x46, &1u16.to_le_bytes()); // sections
    put(&mut b, 0x54, &0xF0u16.to_le_bytes()); // optional header size
    put(&mut b, 0x58, &0x20bu16.to_le_bytes()); // PE32+
    put(&mut b, 0x58 + 16, &0x1000u32.to_le_bytes()); // entry RVA
    put(&mut b, 0x58 + 24, &0x1_4000_0000u64.to_le_bytes()); // image base
    let s = 0x148;
    put(&mut b, s, b".text");
    put(&mut b, s + 8, &7u32.to_le_bytes());
    put(&mut b, s + 12, &0x1000u32.to_le_bytes());
    put(&mut b, s + 16, &0x200u32.to_le_bytes());
    put(&mut b, s + 20, &0x200u32.to_le_bytes());
    put(&mut b, s + 36, &0x6000_0020u32.to_le_bytes());
    put(&mut b, 0x200, &CODE);
    b
}

/// ELF64 little-endian with `code` in `.text` (addr 0x401000, offset 0x40) and `.shstrtab`.
pub fn elf64_with_code(code: &[u8]) -> Vec<u8> {
    assert!(code.len() <= 16);
    let mut b = vec![0u8; 0x140];
    put(&mut b, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put(&mut b, 16, &2u16.to_le_bytes()); // ET_EXEC
    put(&mut b, 18, &62u16.to_le_bytes()); // x86-64
    put(&mut b, 20, &1u32.to_le_bytes());
    put(&mut b, 24, &0x40_1000u64.to_le_bytes()); // entry
    put(&mut b, 40, &0x80u64.to_le_bytes()); // shoff
    put(&mut b, 52, &64u16.to_le_bytes());
    put(&mut b, 58, &64u16.to_le_bytes()); // shentsize
    put(&mut b, 60, &3u16.to_le_bytes()); // shnum
    put(&mut b, 62, &2u16.to_le_bytes()); // shstrndx
    put(&mut b, 0x40, code);
    put(&mut b, 0x50, b"\0.text\0.shstrtab\0");
    let s1 = 0x80 + 64;
    put(&mut b, s1, &1u32.to_le_bytes());
    put(&mut b, s1 + 4, &1u32.to_le_bytes()); // PROGBITS
    put(&mut b, s1 + 8, &6u64.to_le_bytes()); // ALLOC|EXEC
    put(&mut b, s1 + 16, &0x40_1000u64.to_le_bytes());
    put(&mut b, s1 + 24, &0x40u64.to_le_bytes());
    put(&mut b, s1 + 32, &(code.len() as u64).to_le_bytes());
    let s2 = 0x80 + 128;
    put(&mut b, s2, &7u32.to_le_bytes());
    put(&mut b, s2 + 4, &3u32.to_le_bytes()); // STRTAB
    put(&mut b, s2 + 24, &0x50u64.to_le_bytes());
    put(&mut b, s2 + 32, &17u64.to_le_bytes());
    b
}

pub fn minimal_elf64() -> Vec<u8> {
    elf64_with_code(&CODE)
}

/// Code at 0x401000: `call 0x40100a; jmp 0x40100a; je 0x401009; ret; push rbp; ret`.
pub const CALL_CODE: [u8; 12] = [0xE8, 0x05, 0x00, 0x00, 0x00, 0xEB, 0x03, 0x74, 0x00, 0xC3, 0x55, 0xC3];

/// PE32 (x86) with `.text`; code is `push ebp; mov ebp,esp; nop; pop ebp; ret`.
pub fn minimal_pe32() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    put(&mut b, 0, b"MZ");
    put(&mut b, 0x3c, &0x40u32.to_le_bytes());
    put(&mut b, 0x40, b"PE\0\0");
    put(&mut b, 0x44, &0x14cu16.to_le_bytes());
    put(&mut b, 0x46, &1u16.to_le_bytes());
    put(&mut b, 0x54, &0xE0u16.to_le_bytes());
    put(&mut b, 0x58, &0x10bu16.to_le_bytes());
    put(&mut b, 0x58 + 16, &0x1000u32.to_le_bytes());
    put(&mut b, 0x58 + 28, &0x40_0000u32.to_le_bytes());
    let s = 0x58 + 0xE0;
    put(&mut b, s, b".text");
    put(&mut b, s + 8, &6u32.to_le_bytes());
    put(&mut b, s + 12, &0x1000u32.to_le_bytes());
    put(&mut b, s + 16, &0x200u32.to_le_bytes());
    put(&mut b, s + 20, &0x200u32.to_le_bytes());
    put(&mut b, s + 36, &0x6000_0020u32.to_le_bytes());
    put(&mut b, 0x200, &[0x55, 0x89, 0xE5, 0x90, 0x5D, 0xC3]);
    b
}

/// PE32+ with `.text` plus `.rdata` holding one export (`my_export`, RVA 0x1000)
/// and imports `KERNEL32.dll!ExitProcess` and `KERNEL32.dll` ordinal 5.
pub fn pe64_with_symbols() -> Vec<u8> {
    let mut b = minimal_pe64();
    b.resize(0x800, 0);
    put(&mut b, 0x46, &2u16.to_le_bytes());
    put(&mut b, 0x58 + 108, &16u32.to_le_bytes()); // NumberOfRvaAndSizes
    put(&mut b, 0x58 + 112, &0x2000u32.to_le_bytes()); // export dir RVA
    put(&mut b, 0x58 + 116, &0x28u32.to_le_bytes());
    put(&mut b, 0x58 + 120, &0x2200u32.to_le_bytes()); // import dir RVA
    put(&mut b, 0x58 + 124, &0x28u32.to_le_bytes());
    let s = 0x148 + 40;
    put(&mut b, s, b".rdata");
    put(&mut b, s + 8, &0x400u32.to_le_bytes());
    put(&mut b, s + 12, &0x2000u32.to_le_bytes());
    put(&mut b, s + 16, &0x400u32.to_le_bytes());
    put(&mut b, s + 20, &0x400u32.to_le_bytes());
    put(&mut b, s + 36, &0x4000_0040u32.to_le_bytes());
    let o = |rva: usize| rva - 0x2000 + 0x400;
    // export directory
    put(&mut b, o(0x2000) + 12, &0x2110u32.to_le_bytes());
    put(&mut b, o(0x2000) + 16, &1u32.to_le_bytes());
    put(&mut b, o(0x2000) + 20, &1u32.to_le_bytes());
    put(&mut b, o(0x2000) + 24, &1u32.to_le_bytes());
    put(&mut b, o(0x2000) + 28, &0x2100u32.to_le_bytes());
    put(&mut b, o(0x2000) + 32, &0x2104u32.to_le_bytes());
    put(&mut b, o(0x2000) + 36, &0x2108u32.to_le_bytes());
    put(&mut b, o(0x2100), &0x1000u32.to_le_bytes());
    put(&mut b, o(0x2104), &0x2120u32.to_le_bytes());
    put(&mut b, o(0x2108), &0u16.to_le_bytes());
    put(&mut b, o(0x2110), b"sample.dll\0");
    put(&mut b, o(0x2120), b"my_export\0");
    // import descriptor + thunks
    put(&mut b, o(0x2200), &0x2240u32.to_le_bytes());
    put(&mut b, o(0x2200) + 12, &0x2280u32.to_le_bytes());
    put(&mut b, o(0x2200) + 16, &0x2240u32.to_le_bytes());
    put(&mut b, o(0x2240), &0x22A0u64.to_le_bytes());
    put(&mut b, o(0x2248), &0x8000_0000_0000_0005u64.to_le_bytes());
    put(&mut b, o(0x2280), b"KERNEL32.dll\0");
    put(&mut b, o(0x22A0) + 2, b"ExitProcess\0");
    b
}

/// ELF64 LE with `.symtab`/`.strtab`: defined FUNC `main` at 0x401000 and undefined FUNC `puts`.
pub fn elf64_with_symbols() -> Vec<u8> {
    let mut b = vec![0u8; 0x220];
    put(&mut b, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put(&mut b, 16, &2u16.to_le_bytes());
    put(&mut b, 18, &62u16.to_le_bytes());
    put(&mut b, 24, &0x40_1000u64.to_le_bytes());
    put(&mut b, 40, &0xE0u64.to_le_bytes());
    put(&mut b, 58, &64u16.to_le_bytes());
    put(&mut b, 60, &5u16.to_le_bytes());
    put(&mut b, 62, &4u16.to_le_bytes());
    put(&mut b, 0x40, &CODE);
    put(&mut b, 0x50, b"\0.text\0.symtab\0.strtab\0.shstrtab\0");
    put(&mut b, 0x80, b"\0main\0puts\0");
    // symtab entries: [0] null, [1] main, [2] puts
    put(&mut b, 0x90 + 24, &1u32.to_le_bytes());
    b[0x90 + 24 + 4] = 0x12;
    put(&mut b, 0x90 + 24 + 6, &1u16.to_le_bytes());
    put(&mut b, 0x90 + 24 + 8, &0x40_1000u64.to_le_bytes());
    put(&mut b, 0x90 + 24 + 16, &7u64.to_le_bytes());
    put(&mut b, 0x90 + 48, &6u32.to_le_bytes());
    b[0x90 + 48 + 4] = 0x12;
    let sh = |b: &mut Vec<u8>, i: usize, name: u32, ty: u32, addr: u64, off: u64, size: u64, link: u32, ent: u64, flags: u64| {
        let base = 0xE0 + i * 64;
        put(b, base, &name.to_le_bytes());
        put(b, base + 4, &ty.to_le_bytes());
        put(b, base + 8, &flags.to_le_bytes());
        put(b, base + 16, &addr.to_le_bytes());
        put(b, base + 24, &off.to_le_bytes());
        put(b, base + 32, &size.to_le_bytes());
        put(b, base + 40, &link.to_le_bytes());
        put(b, base + 56, &ent.to_le_bytes());
    };
    sh(&mut b, 1, 1, 1, 0x40_1000, 0x40, 7, 0, 0, 6);
    sh(&mut b, 2, 7, 2, 0, 0x90, 72, 3, 24, 0);
    sh(&mut b, 3, 15, 3, 0, 0x80, 11, 0, 0, 0);
    sh(&mut b, 4, 23, 3, 0, 0x50, 33, 0, 0, 0);
    b
}

/// ELF32 big-endian (machine 8, MIPS) with `.text`; for parser tests only.
pub fn minimal_elf32_be() -> Vec<u8> {
    let mut b = vec![0u8; 0xF8];
    put(&mut b, 0, &[0x7f, b'E', b'L', b'F', 1, 2, 1]);
    put(&mut b, 16, &2u16.to_be_bytes());
    put(&mut b, 18, &8u16.to_be_bytes());
    put(&mut b, 24, &0x40_0000u32.to_be_bytes());
    put(&mut b, 32, &0x80u32.to_be_bytes());
    put(&mut b, 46, &40u16.to_be_bytes());
    put(&mut b, 48, &3u16.to_be_bytes());
    put(&mut b, 50, &2u16.to_be_bytes());
    put(&mut b, 0x40, &CODE);
    put(&mut b, 0x50, b"\0.text\0.shstrtab\0");
    let s1 = 0x80 + 40;
    put(&mut b, s1, &1u32.to_be_bytes());
    put(&mut b, s1 + 4, &1u32.to_be_bytes());
    put(&mut b, s1 + 8, &6u32.to_be_bytes());
    put(&mut b, s1 + 12, &0x40_0000u32.to_be_bytes());
    put(&mut b, s1 + 16, &0x40u32.to_be_bytes());
    put(&mut b, s1 + 20, &7u32.to_be_bytes());
    let s2 = 0x80 + 80;
    put(&mut b, s2, &7u32.to_be_bytes());
    put(&mut b, s2 + 4, &3u32.to_be_bytes());
    put(&mut b, s2 + 16, &0x50u32.to_be_bytes());
    put(&mut b, s2 + 20, &17u32.to_be_bytes());
    b
}

/// Code at 0x401000 with a diamond:
/// `xor eax,eax; test edi,edi; je 0x401009; inc eax; nop; ret`.
pub const CFG_CODE: [u8; 10] = [0x31, 0xC0, 0x85, 0xFF, 0x74, 0x03, 0xFF, 0xC0, 0x90, 0xC3];

/// `xor eax,eax; jmp +2; ret; int3; nop; ret`: function A (0x1000..0x1006) tail-jumps to B (0x1006..0x1008).
pub const JMP_CODE: [u8; 8] = [0x31, 0xC0, 0xEB, 0x02, 0xC3, 0xCC, 0x90, 0xC3];

/// PE32+ whose `.text` holds `code` at RVA 0x1000 and whose `.pdata` has one RUNTIME_FUNCTION
/// per `(begin_rva, end_rva, chained)` entry.
pub fn pe64_with_pdata(code: &[u8], entries: &[(u32, u32, bool)]) -> Vec<u8> {
    assert!(code.len() <= 0x200 && entries.len() <= 16);
    let mut b = minimal_pe64();
    b.resize(0x600, 0);
    b[0x200..0x300].fill(0);
    put(&mut b, 0x200, code);
    put(&mut b, 0x148 + 8, &(code.len() as u32).to_le_bytes());
    put(&mut b, 0x46, &2u16.to_le_bytes());
    put(&mut b, 0x58 + 108, &16u32.to_le_bytes());
    put(&mut b, 0x58 + 112 + 3 * 8, &0x2000u32.to_le_bytes());
    put(&mut b, 0x58 + 116 + 3 * 8, &((entries.len() * 12) as u32).to_le_bytes());
    let s = 0x148 + 40;
    put(&mut b, s, b".pdata");
    put(&mut b, s + 8, &0x200u32.to_le_bytes());
    put(&mut b, s + 12, &0x2000u32.to_le_bytes());
    put(&mut b, s + 16, &0x200u32.to_le_bytes());
    put(&mut b, s + 20, &0x400u32.to_le_bytes());
    put(&mut b, s + 36, &0x4000_0040u32.to_le_bytes());
    for (i, (begin, end, chained)) in entries.iter().enumerate() {
        let o = 0x400 + i * 12;
        let unwind_rva = 0x2100 + i as u32 * 8;
        put(&mut b, o, &begin.to_le_bytes());
        put(&mut b, o + 4, &end.to_le_bytes());
        put(&mut b, o + 8, &unwind_rva.to_le_bytes());
        b[0x500 + i * 8] = if *chained { 0x21 } else { 0x01 };
    }
    b
}

/// ELF64 LE with `code` in `.text` (addr 0x401000) and an `.eh_frame` (addr 0x402000) holding one CIE
/// (`zR`, pc-relative sdata4) and one FDE per `(function_addr, size)`.
pub fn elf64_with_eh_frame(code: &[u8], fdes: &[(u64, u32)]) -> Vec<u8> {
    assert!(code.len() <= 0x40 && fdes.len() <= 8);
    let mut b = vec![0u8; 0x300];
    put(&mut b, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put(&mut b, 16, &2u16.to_le_bytes());
    put(&mut b, 18, &62u16.to_le_bytes());
    put(&mut b, 24, &0x40_1000u64.to_le_bytes());
    put(&mut b, 40, &0x200u64.to_le_bytes());
    put(&mut b, 58, &64u16.to_le_bytes());
    put(&mut b, 60, &4u16.to_le_bytes());
    put(&mut b, 62, &3u16.to_le_bytes());
    put(&mut b, 0x40, code);
    put(&mut b, 0x80, b"\0.text\0.eh_frame\0.shstrtab\0");
    // CIE: len 16, id 0, v1, "zR", code align 1, data align -8, ra 16, aug len 1, enc pcrel|sdata4.
    let mut e = vec![0u8; 0x100];
    put(&mut e, 0, &16u32.to_le_bytes());
    put(&mut e, 8, &[1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b]);
    let mut at = 20usize;
    for (addr, size) in fdes {
        put(&mut e, at, &16u32.to_le_bytes());
        put(&mut e, at + 4, &((at + 4) as u32).to_le_bytes()); // CIE pointer: back to offset 0
        let field_va = 0x40_2000u64 + (at + 8) as u64;
        put(&mut e, at + 8, &((*addr as i64 - field_va as i64) as i32).to_le_bytes());
        put(&mut e, at + 12, &size.to_le_bytes());
        at += 20;
    }
    put(&mut b, 0x100, &e[..at + 4]);
    let sh = |b: &mut Vec<u8>, i: usize, name: u32, ty: u32, flags: u64, addr: u64, off: u64, size: u64| {
        let base = 0x200 + i * 64;
        put(b, base, &name.to_le_bytes());
        put(b, base + 4, &ty.to_le_bytes());
        put(b, base + 8, &flags.to_le_bytes());
        put(b, base + 16, &addr.to_le_bytes());
        put(b, base + 24, &off.to_le_bytes());
        put(b, base + 32, &size.to_le_bytes());
    };
    sh(&mut b, 1, 1, 1, 6, 0x40_1000, 0x40, code.len() as u64);
    sh(&mut b, 2, 7, 1, 2, 0x40_2000, 0x100, (at + 4) as u64);
    sh(&mut b, 3, 17, 3, 0, 0, 0x80, 27);
    b
}

/// PE32+ whose debug directory (data directory 6, in `.text` padding) holds one CodeView `RSDS`
/// record: GUID 00112233-4455-6677-8899-aabbccddeeff, age 3, and the given PDB path.
pub fn pe64_with_pdb(path: &str) -> Vec<u8> {
    assert!(path.len() < 0x80);
    let mut b = minimal_pe64();
    put(&mut b, 0x148 + 8, &0x200u32.to_le_bytes());
    put(&mut b, 0x58 + 108, &16u32.to_le_bytes());
    put(&mut b, 0x58 + 112 + 6 * 8, &0x1100u32.to_le_bytes());
    put(&mut b, 0x58 + 116 + 6 * 8, &28u32.to_le_bytes());
    put(&mut b, 0x300 + 12, &2u32.to_le_bytes());
    put(&mut b, 0x300 + 16, &((24 + path.len() + 1) as u32).to_le_bytes());
    put(&mut b, 0x300 + 20, &0x1140u32.to_le_bytes());
    put(&mut b, 0x300 + 24, &0x340u32.to_le_bytes());
    put(&mut b, 0x340, b"RSDS");
    put(&mut b, 0x344, &[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    put(&mut b, 0x354, &3u32.to_le_bytes());
    put(&mut b, 0x358, path.as_bytes());
    b
}

/// Thin x86-64 little-endian Mach-O: `__TEXT` (vmaddr 0x100000000) with `__text` holding `code` at
/// 0x100000100, `LC_MAIN` (entryoff 0x100) and `LC_SYMTAB` with defined `_main` and undefined `_puts`.
pub fn macho64_with_symbols(code: &[u8]) -> Vec<u8> {
    assert!(code.len() <= 0x40);
    let mut b = vec![0u8; 0x180];
    put(&mut b, 0, &0xFEED_FACFu32.to_le_bytes());
    put(&mut b, 4, &0x0100_0007u32.to_le_bytes());
    put(&mut b, 12, &2u32.to_le_bytes()); // MH_EXECUTE
    put(&mut b, 16, &3u32.to_le_bytes()); // ncmds
    put(&mut b, 20, &200u32.to_le_bytes()); // sizeofcmds
    let seg = 0x20;
    put(&mut b, seg, &0x19u32.to_le_bytes());
    put(&mut b, seg + 4, &152u32.to_le_bytes());
    put(&mut b, seg + 8, b"__TEXT");
    put(&mut b, seg + 24, &0x1_0000_0000u64.to_le_bytes()); // vmaddr
    put(&mut b, seg + 32, &0x1000u64.to_le_bytes()); // vmsize
    put(&mut b, seg + 48, &0x180u64.to_le_bytes()); // filesize
    put(&mut b, seg + 64, &1u32.to_le_bytes()); // nsects
    let sect = seg + 72;
    put(&mut b, sect, b"__text");
    put(&mut b, sect + 16, b"__TEXT");
    put(&mut b, sect + 32, &0x1_0000_0100u64.to_le_bytes());
    put(&mut b, sect + 40, &(code.len() as u64).to_le_bytes());
    put(&mut b, sect + 48, &0x100u32.to_le_bytes());
    put(&mut b, sect + 64, &0x8000_0400u32.to_le_bytes());
    let main = 0xB8;
    put(&mut b, main, &0x8000_0028u32.to_le_bytes());
    put(&mut b, main + 4, &24u32.to_le_bytes());
    put(&mut b, main + 8, &0x100u64.to_le_bytes());
    let st = 0xD0;
    put(&mut b, st, &2u32.to_le_bytes());
    put(&mut b, st + 4, &24u32.to_le_bytes());
    put(&mut b, st + 8, &0x140u32.to_le_bytes()); // symoff
    put(&mut b, st + 12, &2u32.to_le_bytes()); // nsyms
    put(&mut b, st + 16, &0x170u32.to_le_bytes()); // stroff
    put(&mut b, st + 20, &0x10u32.to_le_bytes()); // strsize
    put(&mut b, 0x100, code);
    put(&mut b, 0x140, &1u32.to_le_bytes());
    b[0x144] = 0x0f; // N_SECT | N_EXT
    b[0x145] = 1;
    put(&mut b, 0x148, &0x1_0000_0100u64.to_le_bytes());
    put(&mut b, 0x150, &7u32.to_le_bytes());
    b[0x154] = 0x01; // N_UNDF | N_EXT
    put(&mut b, 0x170, b"\0_main\0_puts\0");
    b
}

/// PE32+ with a CLR header and hand-laid ECMA-335 metadata (version v4.0.30319): assembly `Sample`
/// 1.2.3.4, reference `mscorlib` 4.0.0.0, types `<Module>` and `Demo.Program` (method `Main`).
pub fn pe64_dotnet() -> Vec<u8> {
    let mut b = minimal_pe64();
    b.resize(0x600, 0);
    put(&mut b, 0x148 + 8, &0x400u32.to_le_bytes());
    put(&mut b, 0x148 + 16, &0x400u32.to_le_bytes());
    put(&mut b, 0x58 + 108, &16u32.to_le_bytes());
    put(&mut b, 0x58 + 112 + 14 * 8, &0x1100u32.to_le_bytes());
    put(&mut b, 0x58 + 116 + 14 * 8, &72u32.to_le_bytes());
    // CLR header at file 0x300 (RVA 0x1100): cb, runtime 2.5, metadata RVA/size, flags IL_ONLY, entry token.
    put(&mut b, 0x300, &72u32.to_le_bytes());
    put(&mut b, 0x304, &2u16.to_le_bytes());
    put(&mut b, 0x306, &5u16.to_le_bytes());
    put(&mut b, 0x308, &0x1160u32.to_le_bytes());
    put(&mut b, 0x30c, &248u32.to_le_bytes());
    put(&mut b, 0x310, &1u32.to_le_bytes());
    put(&mut b, 0x314, &0x0600_0001u32.to_le_bytes());
    // Metadata root at file 0x360.
    let md = 0x360;
    put(&mut b, md, b"BSJB");
    put(&mut b, md + 4, &1u16.to_le_bytes());
    put(&mut b, md + 6, &1u16.to_le_bytes());
    put(&mut b, md + 12, &12u32.to_le_bytes());
    put(&mut b, md + 16, b"v4.0.30319\0");
    put(&mut b, md + 30, &2u16.to_le_bytes()); // stream count
    put(&mut b, md + 32, &64u32.to_le_bytes()); // #~ offset
    put(&mut b, md + 36, &140u32.to_le_bytes());
    put(&mut b, md + 40, b"#~\0");
    put(&mut b, md + 44, &204u32.to_le_bytes()); // #Strings offset
    put(&mut b, md + 48, &44u32.to_le_bytes());
    put(&mut b, md + 52, b"#Strings\0");
    // #~ stream at md+64: header, row counts, then Module, TypeDef, MethodDef, Assembly, AssemblyRef rows.
    let t = md + 64;
    put(&mut b, t + 4, &[2, 0, 0, 1]);
    let valid: u64 = 1 | 1 << 2 | 1 << 6 | 1 << 0x20 | 1 << 0x23;
    put(&mut b, t + 8, &valid.to_le_bytes());
    for (i, rows) in [1u32, 2, 1, 1, 1].iter().enumerate() {
        put(&mut b, t + 24 + i * 4, &rows.to_le_bytes());
    }
    let mut p = t + 44;
    put(&mut b, p + 2, &1u16.to_le_bytes()); // Module.Name = "Sample"
    p += 10;
    // TypeDef rows (14 bytes): flags, name, namespace, extends, fieldlist, methodlist.
    for (flags, name, ns) in [(0u32, 8u16, 0u16), (0x0010_0001, 17, 39)] {
        put(&mut b, p, &flags.to_le_bytes());
        put(&mut b, p + 4, &name.to_le_bytes());
        put(&mut b, p + 6, &ns.to_le_bytes());
        put(&mut b, p + 10, &1u16.to_le_bytes());
        put(&mut b, p + 12, &1u16.to_le_bytes());
        p += 14;
    }
    // MethodDef row (14 bytes): rva, implflags, flags, name, sig, paramlist.
    put(&mut b, p, &0x2050u32.to_le_bytes());
    put(&mut b, p + 8, &25u16.to_le_bytes());
    put(&mut b, p + 12, &1u16.to_le_bytes());
    p += 14;
    // Assembly row (22 bytes): hash alg, 1.2.3.4, flags, public key, name, culture.
    put(&mut b, p, &0x8004u32.to_le_bytes());
    for (i, v) in [1u16, 2, 3, 4].iter().enumerate() {
        put(&mut b, p + 4 + i * 2, &v.to_le_bytes());
    }
    put(&mut b, p + 18, &1u16.to_le_bytes());
    p += 22;
    // AssemblyRef row (20 bytes): 4.0.0.0, flags, public key, name, culture, hash.
    put(&mut b, p, &4u16.to_le_bytes());
    put(&mut b, p + 14, &30u16.to_le_bytes());
    // #Strings heap at md+204.
    put(&mut b, md + 204, b"\0Sample\0<Module>\0Program\0Main\0mscorlib\0Demo\0");
    b
}

/// Java 8 (major 52) class `Hello extends Object implements Runnable` with field `field:I`,
/// method `public static main([Ljava/lang/String;)V` and a `SourceFile` attribute `Hello.java`.
pub fn java_class() -> Vec<u8> {
    let mut b = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 13];
    let utf8 = |b: &mut Vec<u8>, s: &str| {
        b.push(1);
        b.extend((s.len() as u16).to_be_bytes());
        b.extend(s.as_bytes());
    };
    let class = |b: &mut Vec<u8>, name_idx: u16| {
        b.push(7);
        b.extend(name_idx.to_be_bytes());
    };
    utf8(&mut b, "Hello"); // 1
    class(&mut b, 1); // 2
    utf8(&mut b, "java/lang/Object"); // 3
    class(&mut b, 3); // 4
    utf8(&mut b, "main"); // 5
    utf8(&mut b, "([Ljava/lang/String;)V"); // 6
    utf8(&mut b, "field"); // 7
    utf8(&mut b, "I"); // 8
    utf8(&mut b, "SourceFile"); // 9
    utf8(&mut b, "Hello.java"); // 10
    utf8(&mut b, "java/lang/Runnable"); // 11
    class(&mut b, 11); // 12
    b.extend([0x00, 0x21, 0, 2, 0, 4]); // access public|super, this, super
    b.extend([0, 1, 0, 12]); // one interface
    b.extend([0, 1, 0, 2, 0, 7, 0, 8, 0, 0]); // field: private field I, no attributes
    b.extend([0, 1, 0, 9, 0, 5, 0, 6, 0, 0]); // method: public static main, no attributes
    b.extend([0, 1, 0, 9, 0, 0, 0, 2, 0, 10]); // SourceFile -> Hello.java
    b
}

/// ELF64 LE x86-64 whose `.text` (addr 0x401000, file offset 0x1000) is `unit` repeated until it is at
/// least `text_len` bytes. For large-input and performance tests.
pub fn elf64_large(unit: &[u8], text_len: usize) -> Vec<u8> {
    assert!(!unit.is_empty());
    let n = text_len.div_ceil(unit.len());
    let len = n * unit.len();
    let strtab_off = 0x1000 + len;
    let sh_off = (strtab_off + 17 + 7) & !7;
    let mut b = vec![0u8; sh_off + 3 * 64];
    put(&mut b, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put(&mut b, 16, &2u16.to_le_bytes());
    put(&mut b, 18, &62u16.to_le_bytes());
    put(&mut b, 24, &0x40_1000u64.to_le_bytes());
    put(&mut b, 40, &(sh_off as u64).to_le_bytes());
    put(&mut b, 58, &64u16.to_le_bytes());
    put(&mut b, 60, &3u16.to_le_bytes());
    put(&mut b, 62, &2u16.to_le_bytes());
    for i in 0..n {
        put(&mut b, 0x1000 + i * unit.len(), unit);
    }
    put(&mut b, strtab_off, b"\0.text\0.shstrtab\0");
    let s1 = sh_off + 64;
    put(&mut b, s1, &1u32.to_le_bytes());
    put(&mut b, s1 + 4, &1u32.to_le_bytes());
    put(&mut b, s1 + 8, &6u64.to_le_bytes());
    put(&mut b, s1 + 16, &0x40_1000u64.to_le_bytes());
    put(&mut b, s1 + 24, &0x1000u64.to_le_bytes());
    put(&mut b, s1 + 32, &(len as u64).to_le_bytes());
    let s2 = sh_off + 128;
    put(&mut b, s2, &7u32.to_le_bytes());
    put(&mut b, s2 + 4, &3u32.to_le_bytes());
    put(&mut b, s2 + 24, &(strtab_off as u64).to_le_bytes());
    put(&mut b, s2 + 32, &17u64.to_le_bytes());
    b
}

/// Path of the `fake-engine` test program (builds it on first use; a no-op when already built).
pub fn fake_engine_path() -> std::path::PathBuf {
    use std::sync::OnceLock;
    static PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = std::process::Command::new(cargo)
            .args(["build", "-q", "-p", "omnidecomp-testsamples", "--bin", "fake-engine"])
            .status()
            .expect("cargo is available when running tests");
        assert!(status.success(), "building fake-engine failed");
        // current_exe is target/<profile>/deps/<test>; the binary is in target/<profile>/.
        let mut dir = std::env::current_exe().unwrap();
        dir.pop();
        if dir.ends_with("deps") {
            dir.pop();
        }
        dir.join(format!("fake-engine{}", std::env::consts::EXE_SUFFIX))
    })
    .clone()
}
