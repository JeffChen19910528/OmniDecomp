use crate::reader::{malformed, sanitize_name, Reader};
use omnidecomp_core::{
    Arch, BinaryFormatInfo, Context, Endianness, Error, ErrorCode, Format, Result, Section, Symbol, SymbolsResult,
};

const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHF_EXECINSTR: u64 = 0x4;

struct RawSection {
    name_off: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
}

pub fn parse(data: &[u8], ctx: &Context) -> Result<BinaryFormatInfo> {
    let ident = Reader::new(data, false).bytes(0, 16)?;
    let bits: u8 = match ident[4] {
        1 => 32,
        2 => 64,
        c => return Err(malformed(format!("invalid ELF class {c}"))),
    };
    let big = match ident[5] {
        1 => false,
        2 => true,
        d => return Err(malformed(format!("invalid ELF data encoding {d}"))),
    };
    let r = Reader::new(data, big);
    let machine = r.u16(18)?;
    let (entry, shstrndx) = if bits == 64 {
        (r.u64(24)?, usize::from(r.u16(62)?))
    } else {
        (u64::from(r.u32(24)?), usize::from(r.u16(50)?))
    };
    let raws = section_headers(&r, bits, ctx)?;

    let strtab: &[u8] = match raws.get(shstrndx) {
        Some(s) if s.sh_type != SHT_NOBITS => r.bytes(s.offset, s.size)?,
        _ => &[],
    };

    let mut sections = Vec::new();
    for s in raws.iter().filter(|s| s.sh_type != SHT_NULL) {
        let file_size = if s.sh_type == SHT_NOBITS { 0 } else { s.size };
        if file_size > 0 {
            r.bytes(s.offset, file_size)?;
        }
        let name = strtab.get(s.name_off as usize..).map(sanitize_name).unwrap_or_default();
        sections.push(Section {
            name,
            virtual_address: s.addr,
            virtual_size: s.size,
            file_offset: s.offset,
            file_size,
            executable: s.flags & SHF_EXECINSTR != 0,
        });
    }

    let arch = match machine {
        3 => Arch::X86,
        62 => Arch::X86_64,
        40 => Arch::Arm,
        183 => Arch::Aarch64,
        243 => Arch::Riscv,
        _ => Arch::Unknown,
    };
    Ok(BinaryFormatInfo {
        format: Format::Elf,
        bits,
        endianness: if big { Endianness::Big } else { Endianness::Little },
        arch,
        machine: u32::from(machine),
        entry_point: if entry == 0 { None } else { Some(entry) },
        image_base: None,
        sections,
    })
}

fn section_headers(r: &Reader, bits: u8, ctx: &Context) -> Result<Vec<RawSection>> {
    let (shoff, shentsize, shnum) = if bits == 64 {
        (r.u64(40)?, u64::from(r.u16(58)?), usize::from(r.u16(60)?))
    } else {
        (u64::from(r.u32(32)?), u64::from(r.u16(46)?), usize::from(r.u16(48)?))
    };
    let mut raws = Vec::new();
    if shoff != 0 && shnum != 0 {
        let min_ent = if bits == 64 { 64 } else { 40 };
        if shentsize < min_ent {
            return Err(malformed("section header entry size too small"));
        }
        if shnum > ctx.limits.max_sections {
            return Err(Error::new(ErrorCode::LimitExceeded, "section count exceeds configured limit"));
        }
        for i in 0..shnum as u64 {
            ctx.check()?;
            let base = shoff
                .checked_add(i * shentsize)
                .ok_or_else(|| malformed("section header offset overflow"))?;
            raws.push(if bits == 64 {
                RawSection {
                    name_off: r.u32(base)?,
                    sh_type: r.u32(base + 4)?,
                    flags: r.u64(base + 8)?,
                    addr: r.u64(base + 16)?,
                    offset: r.u64(base + 24)?,
                    size: r.u64(base + 32)?,
                    link: r.u32(base + 40)?,
                }
            } else {
                RawSection {
                    name_off: r.u32(base)?,
                    sh_type: r.u32(base + 4)?,
                    flags: u64::from(r.u32(base + 8)?),
                    addr: u64::from(r.u32(base + 12)?),
                    offset: u64::from(r.u32(base + 16)?),
                    size: u64::from(r.u32(base + 20)?),
                    link: r.u32(base + 24)?,
                }
            });
        }
    }
    Ok(raws)
}

/// Reads `.symtab` and `.dynsym`. Entries with empty names, and section/file symbols, are skipped.
pub fn symbols(data: &[u8], ctx: &Context) -> Result<SymbolsResult> {
    let info = parse(data, ctx)?;
    let (bits, big) = (info.bits, info.endianness == Endianness::Big);
    let r = Reader::new(data, big);
    let raws = section_headers(&r, bits, ctx)?;
    let ent: u64 = if bits == 64 { 24 } else { 16 };
    let mut symbols = Vec::new();
    for s in raws.iter().filter(|s| s.sh_type == SHT_SYMTAB || s.sh_type == SHT_DYNSYM) {
        let source = if s.sh_type == SHT_SYMTAB { "elf_symtab" } else { "elf_dynsym" };
        let strtab = match raws.get(s.link as usize) {
            Some(t) if t.sh_type != SHT_NOBITS => r.bytes(t.offset, t.size)?,
            _ => return Err(malformed("symbol table links to an invalid string table")),
        };
        r.bytes(s.offset, s.size)?;
        for i in 0..s.size / ent {
            if i % 1024 == 0 {
                ctx.check()?;
            }
            let b = s.offset + i * ent;
            let (name_off, info_b, shndx, value) = if bits == 64 {
                (r.u32(b)?, r.bytes(b + 4, 1)?[0], r.u16(b + 6)?, r.u64(b + 8)?)
            } else {
                (r.u32(b)?, r.bytes(b + 12, 1)?[0], r.u16(b + 14)?, u64::from(r.u32(b + 4)?))
            };
            let kind = match info_b & 0xf {
                1 => "object",
                2 => "function",
                3 | 4 => continue,
                _ => "unknown",
            };
            let name = strtab.get(name_off as usize..).map(sanitize_name).unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            if symbols.len() >= ctx.limits.max_symbols {
                return Ok(SymbolsResult { symbols, truncated: true });
            }
            let defined = shndx != 0;
            symbols.push(Symbol {
                name,
                address: if defined { Some(value) } else { None },
                kind: if defined { kind } else { "import" },
                source,
            });
        }
    }
    Ok(SymbolsResult { symbols, truncated: false })
}

/// Cursor over `.eh_frame` bytes; every read is bounds-checked and returns `Malformed` on overrun.
struct Cur<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.d.len())
            .ok_or_else(|| malformed("eh_frame record overruns section"))?;
        let s = &self.d[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn uleb(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(malformed("LEB128 value too long"))
    }
    fn sleb(&mut self) -> Result<i64> {
        let mut v = 0i64;
        for shift in (0..70).step_by(7) {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            if b & 0x80 == 0 {
                if shift + 7 < 64 && b & 0x40 != 0 {
                    v |= -1i64 << (shift + 7);
                }
                return Ok(v);
            }
        }
        Err(malformed("LEB128 value too long"))
    }
}

/// Reads one DWARF-encoded value (format = `enc & 0x0f`). `None` for an unsupported format.
fn read_encoded(c: &mut Cur, enc: u8, big: bool, ptr: usize) -> Result<Option<i64>> {
    fn fixed(c: &mut Cur, n: usize, big: bool) -> Result<u64> {
        let s = c.take(n)?;
        let mut a = [0u8; 8];
        if big {
            a[8 - n..].copy_from_slice(s);
            Ok(u64::from_be_bytes(a))
        } else {
            a[..n].copy_from_slice(s);
            Ok(u64::from_le_bytes(a))
        }
    }
    fn signed(c: &mut Cur, n: usize, big: bool) -> Result<i64> {
        let bits = 64 - 8 * n as u32;
        Ok(((fixed(c, n, big)? << bits) as i64) >> bits)
    }
    Ok(Some(match enc & 0x0f {
        0 => fixed(c, ptr, big)? as i64,
        1 => c.uleb()? as i64,
        2 => fixed(c, 2, big)? as i64,
        3 => fixed(c, 4, big)? as i64,
        4 => fixed(c, 8, big)? as i64,
        9 => c.sleb()?,
        0xa => signed(c, 2, big)?,
        0xb => signed(c, 4, big)?,
        0xc => signed(c, 8, big)?,
        _ => return Ok(None),
    }))
}

/// FDE pointer encoding from a CIE's `R` augmentation (0 = absptr when absent).
fn parse_cie(body: &[u8], big: bool, ptr: usize) -> Result<u8> {
    let mut c = Cur { d: body, pos: 0 };
    let version = c.u8()?;
    if version != 1 && version != 3 {
        return Err(malformed("unsupported CIE version"));
    }
    let mut aug = Vec::new();
    loop {
        let b = c.u8()?;
        if b == 0 {
            break;
        }
        if aug.len() >= 16 {
            return Err(malformed("CIE augmentation string too long"));
        }
        aug.push(b);
    }
    c.uleb()?;
    c.sleb()?;
    if version == 1 {
        c.u8()?;
    } else {
        c.uleb()?;
    }
    let mut fde_enc = 0;
    if aug.first() == Some(&b'z') {
        let len = usize::try_from(c.uleb()?).map_err(|_| malformed("CIE augmentation length"))?;
        let mut a = Cur { d: c.take(len)?, pos: 0 };
        for ch in &aug[1..] {
            match ch {
                b'R' => fde_enc = a.u8()?,
                b'L' => {
                    a.u8()?;
                }
                b'P' => {
                    let e = a.u8()?;
                    if read_encoded(&mut a, e, big, ptr)?.is_none() {
                        return Err(malformed("unsupported personality encoding"));
                    }
                }
                b'S' | b'B' => {}
                _ => break,
            }
        }
    }
    Ok(fde_enc)
}

/// Function ranges `[start, end)` from the `.eh_frame` FDEs, sorted, deduplicated by start and capped
/// at `max_symbols`. FDEs with an unsupported pointer encoding or an invalid CIE are skipped.
pub fn function_ranges(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Vec<(u64, u64)>> {
    let Some(sec) = info.sections.iter().find(|s| s.name == ".eh_frame" && s.file_size > 0) else {
        return Ok(Vec::new());
    };
    let big = info.endianness == Endianness::Big;
    let ptr = if info.bits == 64 { 8 } else { 4 };
    let eh = Reader::new(data, big).bytes(sec.file_offset, sec.file_size)?;
    let rd = Reader::new(eh, big);
    let mut out: Vec<(u64, u64)> = Vec::new();
    let mut cies: std::collections::HashMap<usize, Option<u8>> = std::collections::HashMap::new();
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos + 4 <= eh.len() {
        n += 1;
        if n.is_multiple_of(256) {
            ctx.check()?;
        }
        let len = u64::from(rd.u32(pos as u64)?);
        if len == 0 || len == 0xffff_ffff {
            break; // terminator, or the 64-bit length form (unsupported)
        }
        let start = pos + 4;
        let end = usize::try_from(len)
            .ok()
            .and_then(|l| start.checked_add(l))
            .filter(|e| *e <= eh.len())
            .ok_or_else(|| malformed("eh_frame record overruns section"))?;
        if len < 4 {
            return Err(malformed("eh_frame record too short"));
        }
        let id = rd.u32(start as u64)?;
        if id != 0 {
            let cie_pos = start.checked_sub(id as usize);
            let enc = cie_pos.and_then(|p| {
                *cies.entry(p).or_insert_with(|| {
                    let l = rd.u32(p as u64).ok()? as usize;
                    let e = p.checked_add(4)?.checked_add(l)?;
                    if rd.u32(p as u64 + 4).ok()? != 0 || e > eh.len() || p + 8 > e {
                        return None;
                    }
                    parse_cie(&eh[p + 8..e], big, ptr).ok()
                })
            });
            // Only absptr and pc-relative bases are supported; indirect and omitted encodings are skipped.
            if let Some(enc) = enc.filter(|e| *e != 0xff && e & 0x80 == 0 && matches!(e & 0x70, 0x00 | 0x10)) {
                let mut c = Cur { d: &eh[..end], pos: start + 4 };
                let field_va = sec.virtual_address.wrapping_add(c.pos as u64);
                if let Some(v) = read_encoded(&mut c, enc, big, ptr)? {
                    let begin = if enc & 0x70 == 0x10 { field_va.wrapping_add(v as u64) } else { v as u64 };
                    if let Some(range) = read_encoded(&mut c, enc & 0x0f, big, ptr)? {
                        if range > 0 {
                            out.push((begin, begin.wrapping_add(range as u64)));
                        }
                    }
                }
            }
        }
        pos = end;
    }
    out.retain(|(b, e)| e > b);
    out.sort_unstable();
    out.dedup_by_key(|r| r.0);
    out.truncate(ctx.limits.max_symbols);
    Ok(out)
}
