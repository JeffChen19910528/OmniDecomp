use crate::reader::{malformed, sanitize_name, sanitize_text, Reader};
use omnidecomp_core::{
    Arch, BinaryFormatInfo, DebugInfo, Context, Endianness, Error, ErrorCode, Format, Result, Section, Symbol, SymbolsResult,
};

const MAX_PE_SECTIONS: usize = 96;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

pub fn parse(data: &[u8], ctx: &Context) -> Result<BinaryFormatInfo> {
    let r = Reader::new(data, false);
    let pe_off = u64::from(r.u32(0x3c)?);
    if r.bytes(pe_off, 4)? != b"PE\0\0" {
        return Err(malformed("missing PE signature at e_lfanew"));
    }
    let coff = pe_off + 4;
    let machine = r.u16(coff)?;
    let nsec = usize::from(r.u16(coff + 2)?);
    let opt_size = u64::from(r.u16(coff + 16)?);
    if nsec > MAX_PE_SECTIONS {
        return Err(malformed(format!("section count {nsec} exceeds PE maximum {MAX_PE_SECTIONS}")));
    }
    if nsec > ctx.limits.max_sections {
        return Err(Error::new(ErrorCode::LimitExceeded, "section count exceeds configured limit"));
    }
    let opt = coff + 20;
    if opt_size < 32 {
        return Err(malformed("optional header missing or too small"));
    }
    r.bytes(opt, opt_size)?;
    let (bits, image_base) = match r.u16(opt)? {
        0x10b => (32u8, u64::from(r.u32(opt + 28)?)),
        0x20b => (64u8, r.u64(opt + 24)?),
        other => return Err(malformed(format!("unknown optional header magic {other:#x}"))),
    };
    let entry_rva = u64::from(r.u32(opt + 16)?);

    let table = opt + opt_size;
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec as u64 {
        ctx.check()?;
        let base = table + i * 40;
        let name = sanitize_name(r.bytes(base, 8)?);
        let virtual_size = u64::from(r.u32(base + 8)?);
        let virtual_address = u64::from(r.u32(base + 12)?);
        let raw_size = u64::from(r.u32(base + 16)?);
        let raw_ptr = u64::from(r.u32(base + 20)?);
        let characteristics = r.u32(base + 36)?;
        if raw_size > 0 {
            r.bytes(raw_ptr, raw_size)?;
        }
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            file_offset: raw_ptr,
            file_size: raw_size,
            executable: characteristics & SCN_MEM_EXECUTE != 0,
        });
    }

    let arch = match machine {
        0x14c => Arch::X86,
        0x8664 => Arch::X86_64,
        0x1c0 | 0x1c4 => Arch::Arm,
        0xaa64 => Arch::Aarch64,
        _ => Arch::Unknown,
    };
    Ok(BinaryFormatInfo {
        format: Format::Pe,
        bits,
        endianness: Endianness::Little,
        arch,
        machine: u32::from(machine),
        entry_point: if entry_rva == 0 { None } else { Some(image_base.wrapping_add(entry_rva)) },
        image_base: Some(image_base),
        sections,
    })
}

/// Maps an RVA to a file offset through the section table; `None` if no section holds it.
pub(crate) fn rva_to_offset(sections: &[Section], rva: u64) -> Option<u64> {
    sections.iter().find_map(|s| {
        let span = s.file_size.min(if s.virtual_size > 0 { s.virtual_size } else { s.file_size });
        let delta = rva.checked_sub(s.virtual_address)?;
        (delta < span).then(|| s.file_offset + delta)
    })
}

/// NUL-terminated name at `rva`, at most 256 bytes, bounded by the file.
fn name_at(r: &Reader, sections: &[Section], rva: u64) -> Result<String> {
    let off = rva_to_offset(sections, rva)
        .ok_or_else(|| malformed(format!("RVA {rva:#x} is not mapped by any section")))?;
    let mut len = 256u64;
    let bytes = loop {
        match r.bytes(off, len) {
            Ok(b) => break b,
            Err(_) if len > 1 => len /= 2,
            Err(e) => return Err(e),
        }
    };
    Ok(sanitize_name(bytes))
}

/// Function ranges `[start, end)` as absolute addresses from the x64 exception table (.pdata).
/// Chained unwind entries are fragments of another function and are skipped.
/// Returns an empty list for non-x64 PE files or when there is no exception directory.
pub fn function_ranges(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Vec<(u64, u64)>> {
    if info.arch != Arch::X86_64 || info.bits != 64 {
        return Ok(Vec::new());
    }
    let r = Reader::new(data, false);
    let dirs_off = u64::from(r.u32(0x3c)?) + 24 + 108;
    if u64::from(r.u32(dirs_off)?) <= 3 {
        return Ok(Vec::new());
    }
    let rva = u64::from(r.u32(dirs_off + 4 + 3 * 8)?);
    let size = u64::from(r.u32(dirs_off + 8 + 3 * 8)?);
    if rva == 0 || size == 0 {
        return Ok(Vec::new());
    }
    let base = rva_to_offset(&info.sections, rva).ok_or_else(|| malformed("exception directory not mapped"))?;
    let image_base = info.image_base.unwrap_or(0);
    let count = (size / 12).min(ctx.limits.max_symbols as u64);
    let mut ranges = Vec::new();
    for i in 0..count {
        if i % 1024 == 0 {
            ctx.check()?;
        }
        let e = base + i * 12;
        let (begin, end, unwind) = (u64::from(r.u32(e)?), u64::from(r.u32(e + 4)?), u64::from(r.u32(e + 8)?));
        if end <= begin {
            continue;
        }
        // UNWIND_INFO byte 0 = version (3 bits) | flags (5 bits); flag 4 = UNW_FLAG_CHAININFO.
        let chained = rva_to_offset(&info.sections, unwind & !1)
            .and_then(|o| r.bytes(o, 1).ok())
            .is_some_and(|b| (b[0] >> 3) & 4 != 0);
        if !chained {
            ranges.push((image_base.wrapping_add(begin), image_base.wrapping_add(end)));
        }
    }
    ranges.sort_unstable();
    Ok(ranges)
}

/// Export table and import table (by name or ordinal). Bound/delay imports are not read.
pub fn symbols(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<SymbolsResult> {
    let r = Reader::new(data, false);
    let opt = u64::from(r.u32(0x3c)?) + 4 + 20;
    let is64 = info.bits == 64;
    let dirs_off = if is64 { opt + 108 } else { opt + 92 };
    let ndirs = u64::from(r.u32(dirs_off)?).min(16);
    let dir = |i: u64| -> Result<(u64, u64)> {
        if i >= ndirs {
            return Ok((0, 0));
        }
        Ok((u64::from(r.u32(dirs_off + 4 + i * 8)?), u64::from(r.u32(dirs_off + 8 + i * 8)?)))
    };
    let image_base = info.image_base.unwrap_or(0);
    let max = ctx.limits.max_symbols;
    let mut symbols = Vec::new();
    let mut truncated = false;

    let (exp_rva, exp_size) = dir(0)?;
    if exp_rva != 0 {
        let e = rva_to_offset(&info.sections, exp_rva).ok_or_else(|| malformed("export directory not mapped"))?;
        let nfuncs = u64::from(r.u32(e + 20)?);
        let nnames = u64::from(r.u32(e + 24)?);
        let funcs = u64::from(r.u32(e + 28)?);
        let names = u64::from(r.u32(e + 32)?);
        let ords = u64::from(r.u32(e + 36)?);
        let at = |rva: u64, add: u64| {
            rva_to_offset(&info.sections, rva + add).ok_or_else(|| malformed("export table not mapped"))
        };
        for i in 0..nnames {
            if i % 1024 == 0 {
                ctx.check()?;
            }
            if symbols.len() >= max {
                truncated = true;
                break;
            }
            let name_rva = u64::from(r.u32(at(names, i * 4)?)?);
            let ord = u64::from(r.u16(at(ords, i * 2)?)?);
            if ord >= nfuncs {
                return Err(malformed("export ordinal out of range"));
            }
            let func_rva = u64::from(r.u32(at(funcs, ord * 4)?)?);
            let forwarded = func_rva >= exp_rva && func_rva < exp_rva + exp_size;
            symbols.push(Symbol {
                name: name_at(&r, &info.sections, name_rva)?,
                address: if forwarded { None } else { Some(image_base.wrapping_add(func_rva)) },
                kind: "export",
                source: "pe_export",
            });
        }
    }

    let (imp_rva, _) = dir(1)?;
    if imp_rva != 0 && !truncated {
        let base = rva_to_offset(&info.sections, imp_rva).ok_or_else(|| malformed("import directory not mapped"))?;
        let step = if is64 { 8 } else { 4 };
        'dlls: for d in 0..ctx.limits.max_sections.max(1024) as u64 {
            let desc = base + d * 20;
            let oft = u64::from(r.u32(desc)?);
            let name_rva = u64::from(r.u32(desc + 12)?);
            let ft = u64::from(r.u32(desc + 16)?);
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            let dll = name_at(&r, &info.sections, name_rva)?;
            let thunks = if oft != 0 { oft } else { ft };
            let t0 = rva_to_offset(&info.sections, thunks).ok_or_else(|| malformed("import thunks not mapped"))?;
            for i in 0u64.. {
                ctx.check()?;
                let at = t0 + i * step;
                let entry = if is64 { r.u64(at)? } else { u64::from(r.u32(at)?) };
                if entry == 0 {
                    break;
                }
                if symbols.len() >= max {
                    truncated = true;
                    break 'dlls;
                }
                let ordinal_flag = if is64 { 1u64 << 63 } else { 1u64 << 31 };
                let func = if entry & ordinal_flag != 0 {
                    format!("#{}", entry & 0xffff)
                } else {
                    name_at(&r, &info.sections, (entry & 0x7fff_ffff) + 2)?
                };
                symbols.push(Symbol {
                    name: format!("{dll}!{func}"),
                    address: None,
                    kind: "import",
                    source: "pe_import",
                });
            }
        }
    }
    Ok(SymbolsResult { symbols, truncated })
}

/// First CodeView `RSDS` record in the debug directory (data directory 6), if any.
/// Reads only the recorded PDB path, GUID and age; the PDB itself is never looked up.
pub fn debug_info(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Option<DebugInfo>> {
    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
    const MAX_ENTRIES: u64 = 32;
    let r = Reader::new(data, false);
    let dirs_off = u64::from(r.u32(0x3c)?) + 24 + if info.bits == 64 { 108 } else { 92 };
    if u64::from(r.u32(dirs_off)?) <= 6 {
        return Ok(None);
    }
    let rva = u64::from(r.u32(dirs_off + 4 + 6 * 8)?);
    let size = u64::from(r.u32(dirs_off + 8 + 6 * 8)?);
    if rva == 0 || size == 0 {
        return Ok(None);
    }
    let base = rva_to_offset(&info.sections, rva).ok_or_else(|| malformed("debug directory not mapped"))?;
    for i in 0..(size / 28).min(MAX_ENTRIES) {
        ctx.check()?;
        let e = base + i * 28;
        if r.u32(e + 12)? != IMAGE_DEBUG_TYPE_CODEVIEW {
            continue;
        }
        let (len, ptr) = (u64::from(r.u32(e + 16)?), u64::from(r.u32(e + 24)?));
        if len < 24 {
            continue;
        }
        let rec = r.bytes(ptr, len.min(24 + 512))?;
        if &rec[..4] != b"RSDS" {
            continue;
        }
        let g = &rec[4..20];
        let guid = format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
        );
        let age = u32::from_le_bytes([rec[20], rec[21], rec[22], rec[23]]);
        return Ok(Some(DebugInfo { kind: "codeview_pdb70", pdb_path: sanitize_text(&rec[24..], 260), guid, age }));
    }
    Ok(None)
}
