//! Thin (single-architecture) Mach-O: header, segments/sections, entry point and `LC_SYMTAB` symbols.

use crate::reader::{malformed, sanitize_name, Reader};
use omnidecomp_core::{
    Arch, BinaryFormatInfo, Context, Endianness, Error, ErrorCode, Format, Result, Section, Symbol, SymbolsResult,
};

const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
const MAX_LOAD_COMMANDS: u32 = 4096;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x400;

/// True when the first four bytes are a thin Mach-O magic in any byte order / width.
pub fn is_macho(data: &[u8]) -> bool {
    matches!(
        data.get(..4),
        Some([0xCE, 0xFA, 0xED, 0xFE] | [0xCF, 0xFA, 0xED, 0xFE] | [0xFE, 0xED, 0xFA, 0xCE] | [0xFE, 0xED, 0xFA, 0xCF])
    )
}

struct Walk {
    bits: u8,
    big: bool,
    cputype: u32,
    sections: Vec<Section>,
    symtab: Option<(u64, u64, u64, u64)>,
    entryoff: Option<u64>,
    text_vmaddr: Option<u64>,
}

fn walk(data: &[u8], ctx: &Context) -> Result<Walk> {
    let (bits, big) = match data.get(..4) {
        Some([0xCE, 0xFA, 0xED, 0xFE]) => (32u8, false),
        Some([0xCF, 0xFA, 0xED, 0xFE]) => (64, false),
        Some([0xFE, 0xED, 0xFA, 0xCE]) => (32, true),
        Some([0xFE, 0xED, 0xFA, 0xCF]) => (64, true),
        _ => return Err(malformed("not a Mach-O magic")),
    };
    let r = Reader::new(data, big);
    let cputype = r.u32(4)?;
    let ncmds = r.u32(16)?;
    let sizeofcmds = u64::from(r.u32(20)?);
    if ncmds > MAX_LOAD_COMMANDS {
        return Err(Error::new(ErrorCode::LimitExceeded, "load command count exceeds limit"));
    }
    let start: u64 = if bits == 64 { 32 } else { 28 };
    r.bytes(start, sizeofcmds)?;
    let end = start + sizeofcmds;

    let mut w = Walk { bits, big, cputype, sections: Vec::new(), symtab: None, entryoff: None, text_vmaddr: None };
    let (seg_hdr, sect_size): (u64, u64) = if bits == 64 { (72, 80) } else { (56, 68) };
    let mut off = start;
    for _ in 0..ncmds {
        ctx.check()?;
        let (cmd, size) = (r.u32(off)?, u64::from(r.u32(off + 4)?));
        if size < 8 || off + size > end {
            return Err(malformed("load command overruns the command area"));
        }
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 if (cmd == LC_SEGMENT_64) == (bits == 64) => {
                if size < seg_hdr {
                    return Err(malformed("segment command too small"));
                }
                let segname = sanitize_name(r.bytes(off + 8, 16)?);
                let (vmaddr, fileoff, nsects) = if bits == 64 {
                    (r.u64(off + 24)?, r.u64(off + 40)?, u64::from(r.u32(off + 64)?))
                } else {
                    (u64::from(r.u32(off + 24)?), u64::from(r.u32(off + 32)?), u64::from(r.u32(off + 48)?))
                };
                if segname == "__TEXT" && fileoff == 0 {
                    w.text_vmaddr = Some(vmaddr);
                }
                if nsects.checked_mul(sect_size).is_none_or(|n| seg_hdr + n > size) {
                    return Err(malformed("section list overruns its segment command"));
                }
                for i in 0..nsects {
                    ctx.check()?;
                    if w.sections.len() >= ctx.limits.max_sections {
                        return Err(Error::new(ErrorCode::LimitExceeded, "section count exceeds configured limit"));
                    }
                    let b = off + seg_hdr + i * sect_size;
                    let sectname = sanitize_name(r.bytes(b, 16)?);
                    let (addr, ssize, offset, flags) = if bits == 64 {
                        (r.u64(b + 32)?, r.u64(b + 40)?, u64::from(r.u32(b + 48)?), r.u32(b + 64)?)
                    } else {
                        (u64::from(r.u32(b + 32)?), u64::from(r.u32(b + 36)?), u64::from(r.u32(b + 40)?), r.u32(b + 56)?)
                    };
                    let zerofill = matches!(flags & 0xff, 0x1 | 0xc | 0x12);
                    let file_size = if zerofill { 0 } else { ssize };
                    if file_size > 0 {
                        r.bytes(offset, file_size)?;
                    }
                    w.sections.push(Section {
                        name: format!("{segname},{sectname}"),
                        virtual_address: addr,
                        virtual_size: ssize,
                        file_offset: offset,
                        file_size,
                        executable: flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0,
                    });
                }
            }
            LC_SYMTAB if size >= 24 => {
                w.symtab = Some((
                    u64::from(r.u32(off + 8)?),
                    u64::from(r.u32(off + 12)?),
                    u64::from(r.u32(off + 16)?),
                    u64::from(r.u32(off + 20)?),
                ));
            }
            LC_MAIN if size >= 16 => w.entryoff = Some(r.u64(off + 8)?),
            _ => {}
        }
        off += size;
    }
    Ok(w)
}

pub fn parse(data: &[u8], ctx: &Context) -> Result<BinaryFormatInfo> {
    let w = walk(data, ctx)?;
    let arch = match w.cputype {
        7 => Arch::X86,
        0x0100_0007 => Arch::X86_64,
        12 => Arch::Arm,
        0x0100_000c => Arch::Aarch64,
        _ => Arch::Unknown,
    };
    let entry_point = w.entryoff.zip(w.text_vmaddr).map(|(e, base)| base.wrapping_add(e));
    Ok(BinaryFormatInfo {
        format: Format::MachO,
        bits: w.bits,
        endianness: if w.big { Endianness::Big } else { Endianness::Little },
        arch,
        machine: w.cputype,
        entry_point,
        image_base: w.text_vmaddr,
        sections: w.sections,
    })
}

/// `LC_SYMTAB` entries. Debugging (stab) entries, absolute and indirect symbols are skipped;
/// undefined external symbols are reported as imports.
pub fn symbols(data: &[u8], ctx: &Context) -> Result<SymbolsResult> {
    let w = walk(data, ctx)?;
    let Some((symoff, nsyms, stroff, strsize)) = w.symtab else {
        return Ok(SymbolsResult { symbols: Vec::new(), truncated: false });
    };
    let r = Reader::new(data, w.big);
    let strtab = r.bytes(stroff, strsize)?;
    let ent: u64 = if w.bits == 64 { 16 } else { 12 };
    r.bytes(symoff, nsyms.checked_mul(ent).ok_or_else(|| malformed("symbol table size overflow"))?)?;
    let mut symbols = Vec::new();
    for i in 0..nsyms {
        if i % 1024 == 0 {
            ctx.check()?;
        }
        let b = symoff + i * ent;
        let strx = r.u32(b)? as usize;
        let n_type = r.bytes(b + 4, 1)?[0];
        let n_sect = usize::from(r.bytes(b + 5, 1)?[0]);
        let value = if w.bits == 64 { r.u64(b + 8)? } else { u64::from(r.u32(b + 8)?) };
        if n_type & 0xe0 != 0 {
            continue;
        }
        let name = strtab.get(strx..).map(sanitize_name).unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let (address, kind) = match n_type & 0x0e {
            0x0e => {
                let exec = n_sect.checked_sub(1).and_then(|s| w.sections.get(s)).is_some_and(|s| s.executable);
                (Some(value), if exec { "function" } else { "object" })
            }
            0x00 => (None, "import"),
            _ => continue,
        };
        if symbols.len() >= ctx.limits.max_symbols {
            return Ok(SymbolsResult { symbols, truncated: true });
        }
        symbols.push(Symbol { name, address, kind, source: "macho_symtab" });
    }
    Ok(SymbolsResult { symbols, truncated: false })
}
