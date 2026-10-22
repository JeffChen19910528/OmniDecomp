//! .NET (ECMA-335) metadata: CLR header, metadata root, and the Assembly / AssemblyRef / TypeDef /
//! MethodDef tables. Nothing is executed or loaded; IL bodies are not decoded.

use crate::pe::rva_to_offset;
use crate::reader::{malformed, sanitize_text, Reader};
use omnidecomp_core::{BinaryFormatInfo, Context, DotnetAssembly, DotnetInfo, DotnetType, Format, Result};

const MAX_STREAMS: u16 = 32;
const MAX_ROWS: u32 = 0x00FF_FFFF;
const MAX_NAME: usize = 256;

#[derive(Clone, Copy)]
enum Col {
    /// Fixed-size column in bytes.
    Fixed(u64),
    Str,
    Guid,
    Blob,
    /// Index into one table.
    Table(usize),
    /// Coded index: tag bits and the tables it can point into.
    Coded(u32, &'static [usize]),
}
use Col::{Blob, Coded, Fixed, Guid, Str, Table};

const TYPE_DEF_OR_REF: Col = Coded(2, &[0x02, 0x01, 0x1B]);
const HAS_CONSTANT: Col = Coded(2, &[0x04, 0x08, 0x17]);
const HAS_CUSTOM_ATTRIBUTE: Col = Coded(
    5,
    &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B],
);
const HAS_FIELD_MARSHAL: Col = Coded(1, &[0x04, 0x08]);
const HAS_DECL_SECURITY: Col = Coded(2, &[0x02, 0x06, 0x20]);
const MEMBER_REF_PARENT: Col = Coded(3, &[0x02, 0x01, 0x1A, 0x06, 0x1B]);
const HAS_SEMANTICS: Col = Coded(1, &[0x14, 0x17]);
const METHOD_DEF_OR_REF: Col = Coded(1, &[0x06, 0x0A]);
const MEMBER_FORWARDED: Col = Coded(1, &[0x04, 0x06]);
const IMPLEMENTATION: Col = Coded(2, &[0x26, 0x23, 0x27]);
const CUSTOM_ATTRIBUTE_TYPE: Col = Coded(3, &[0x06, 0x0A]);
const RESOLUTION_SCOPE: Col = Coded(2, &[0x00, 0x1A, 0x23, 0x01]);
const TYPE_OR_METHOD_DEF: Col = Coded(1, &[0x02, 0x06]);

/// Column layout of metadata tables 0x00..=0x2C (ECMA-335 II.22).
fn schema(table: usize) -> Option<&'static [Col]> {
    Some(match table {
        0x00 => &[Fixed(2), Str, Guid, Guid, Guid],
        0x01 => &[RESOLUTION_SCOPE, Str, Str],
        0x02 => &[Fixed(4), Str, Str, TYPE_DEF_OR_REF, Table(0x04), Table(0x06)],
        0x03 => &[Table(0x04)],
        0x04 => &[Fixed(2), Str, Blob],
        0x05 => &[Table(0x06)],
        0x06 => &[Fixed(4), Fixed(2), Fixed(2), Str, Blob, Table(0x08)],
        0x07 => &[Table(0x08)],
        0x08 => &[Fixed(2), Fixed(2), Str],
        0x09 => &[Table(0x02), TYPE_DEF_OR_REF],
        0x0A => &[MEMBER_REF_PARENT, Str, Blob],
        0x0B => &[Fixed(2), HAS_CONSTANT, Blob],
        0x0C => &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob],
        0x0D => &[HAS_FIELD_MARSHAL, Blob],
        0x0E => &[Fixed(2), HAS_DECL_SECURITY, Blob],
        0x0F => &[Fixed(2), Fixed(4), Table(0x02)],
        0x10 => &[Fixed(4), Table(0x04)],
        0x11 => &[Blob],
        0x12 => &[Table(0x02), Table(0x14)],
        0x13 => &[Table(0x14)],
        0x14 => &[Fixed(2), Str, TYPE_DEF_OR_REF],
        0x15 => &[Table(0x02), Table(0x17)],
        0x16 => &[Table(0x17)],
        0x17 => &[Fixed(2), Str, Blob],
        0x18 => &[Fixed(2), Table(0x06), HAS_SEMANTICS],
        0x19 => &[Table(0x02), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF],
        0x1A => &[Str],
        0x1B => &[Blob],
        0x1C => &[Fixed(2), MEMBER_FORWARDED, Str, Table(0x1A)],
        0x1D => &[Fixed(4), Table(0x04)],
        0x1E => &[Fixed(8)],
        0x1F => &[Fixed(4)],
        0x20 => &[Fixed(4), Fixed(8), Fixed(4), Blob, Str, Str],
        0x21 => &[Fixed(4)],
        0x22 => &[Fixed(12)],
        0x23 => &[Fixed(8), Fixed(4), Blob, Str, Str, Blob],
        0x24 => &[Fixed(4), Table(0x23)],
        0x25 => &[Fixed(12), Table(0x23)],
        0x26 => &[Fixed(4), Str, Blob],
        0x27 => &[Fixed(8), Str, Str, IMPLEMENTATION],
        0x28 => &[Fixed(8), Str, IMPLEMENTATION],
        0x29 => &[Table(0x02), Table(0x02)],
        0x2A => &[Fixed(4), TYPE_OR_METHOD_DEF, Str],
        0x2B => &[METHOD_DEF_OR_REF, Blob],
        0x2C => &[Table(0x2A), TYPE_DEF_OR_REF],
        _ => return None,
    })
}

struct Tables {
    rows: [u32; 64],
    /// Absolute file offset of each table's first row.
    start: [u64; 64],
    row_size: [u64; 64],
    str_size: u64,
    blob_size: u64,
}

impl Tables {
    fn col_size(&self, c: Col, guid_size: u64) -> u64 {
        match c {
            Fixed(n) => n,
            Str => self.str_size,
            Guid => guid_size,
            Blob => self.blob_size,
            Table(t) => {
                if self.rows[t] > 0xFFFF {
                    4
                } else {
                    2
                }
            }
            Coded(bits, tables) => {
                let max = tables.iter().map(|t| self.rows[*t]).max().unwrap_or(0);
                if u64::from(max) >= 1u64 << (16 - bits) {
                    4
                } else {
                    2
                }
            }
        }
    }
}

fn read_uint(r: &Reader, off: u64, size: u64) -> Result<u32> {
    if size == 4 {
        r.u32(off)
    } else {
        r.u16(off).map(u32::from)
    }
}

struct Heap {
    start: u64,
    size: u64,
}

fn heap_string(r: &Reader, h: &Heap, idx: u32) -> Result<String> {
    let idx = u64::from(idx);
    if idx >= h.size {
        return Ok(String::new());
    }
    let len = (h.size - idx).min(MAX_NAME as u64);
    Ok(sanitize_text(r.bytes(h.start + idx, len)?, MAX_NAME))
}

fn version_of(r: &Reader, row: u64) -> Result<String> {
    Ok(format!("{}.{}.{}.{}", r.u16(row)?, r.u16(row + 2)?, r.u16(row + 4)?, r.u16(row + 6)?))
}

/// `None` when the file has no CLR header (not a .NET assembly).
pub fn dotnet_info(data: &[u8], info: &BinaryFormatInfo, ctx: &Context) -> Result<Option<DotnetInfo>> {
    if info.format != Format::Pe {
        return Ok(None);
    }
    let r = Reader::new(data, false);
    let dirs_off = u64::from(r.u32(0x3c)?) + 24 + if info.bits == 64 { 108 } else { 92 };
    if u64::from(r.u32(dirs_off)?) <= 14 {
        return Ok(None);
    }
    let (clr_rva, clr_size) = (u64::from(r.u32(dirs_off + 4 + 14 * 8)?), r.u32(dirs_off + 8 + 14 * 8)?);
    if clr_rva == 0 || clr_size == 0 {
        return Ok(None);
    }
    let clr = rva_to_offset(&info.sections, clr_rva).ok_or_else(|| malformed("CLR header not mapped"))?;
    if r.u32(clr)? < 72 {
        return Err(malformed("CLR header too small"));
    }
    let md_rva = u64::from(r.u32(clr + 8)?);
    let clr_flags = r.u32(clr + 16)?;
    let entry_token = r.u32(clr + 20)?;
    let md = rva_to_offset(&info.sections, md_rva).ok_or_else(|| malformed("CLR metadata not mapped"))?;

    if r.bytes(md, 4)? != b"BSJB" {
        return Err(malformed("missing metadata signature"));
    }
    let vlen = u64::from(r.u32(md + 12)?);
    if vlen > 255 {
        return Err(malformed("metadata version string too long"));
    }
    let runtime_version = sanitize_text(r.bytes(md + 16, vlen)?, 64);
    let nstreams = r.u16(md + 16 + vlen + 2)?;
    if nstreams > MAX_STREAMS {
        return Err(malformed("too many metadata streams"));
    }
    let mut p = md + 16 + vlen + 4;
    let (mut tilde, mut strings): (Option<Heap>, Option<Heap>) = (None, None);
    for _ in 0..nstreams {
        ctx.check()?;
        let (off, size) = (u64::from(r.u32(p)?), u64::from(r.u32(p + 4)?));
        let name_bytes = r.bytes(p + 8, 32.min((data.len() as u64).saturating_sub(p + 8)))?;
        let nlen = name_bytes.iter().position(|b| *b == 0).ok_or_else(|| malformed("unterminated stream name"))?;
        let name = &name_bytes[..nlen];
        p += 8 + ((nlen as u64 + 1 + 3) & !3);
        r.bytes(md + off, size)?;
        let heap = Heap { start: md + off, size };
        match name {
            b"#~" | b"#-" => tilde = Some(heap),
            b"#Strings" => strings = Some(heap),
            _ => {}
        }
    }
    let tilde = tilde.ok_or_else(|| malformed("no #~ metadata stream"))?;
    let strings = strings.unwrap_or(Heap { start: 0, size: 0 });

    // Table stream header.
    let heap_sizes = r.bytes(tilde.start + 6, 1)?[0];
    let valid = r.u64(tilde.start + 8)?;
    if valid >> 0x2D != 0 {
        return Err(malformed("metadata declares unknown tables"));
    }
    let mut t = Tables {
        rows: [0; 64],
        start: [0; 64],
        row_size: [0; 64],
        str_size: if heap_sizes & 1 != 0 { 4 } else { 2 },
        blob_size: if heap_sizes & 4 != 0 { 4 } else { 2 },
    };
    let guid_size = if heap_sizes & 2 != 0 { 4 } else { 2 };
    let mut pos = tilde.start + 24;
    for i in 0..0x2D {
        if valid >> i & 1 != 0 {
            let n = r.u32(pos)?;
            if n > MAX_ROWS {
                return Err(malformed("metadata table row count too large"));
            }
            t.rows[i] = n;
            pos += 4;
        }
    }
    if heap_sizes & 0x40 != 0 {
        pos += 4;
    }
    for i in 0..0x2D {
        if valid >> i & 1 == 0 {
            continue;
        }
        ctx.check()?;
        let cols = schema(i).ok_or_else(|| malformed("unknown metadata table"))?;
        t.row_size[i] = cols.iter().map(|c| t.col_size(*c, guid_size)).sum();
        t.start[i] = pos;
        pos = pos
            .checked_add(u64::from(t.rows[i]) * t.row_size[i])
            .ok_or_else(|| malformed("metadata table size overflow"))?;
    }
    if pos > tilde.start + tilde.size {
        return Err(malformed("metadata tables overrun the #~ stream"));
    }

    let row = |table: usize, i: u32| t.start[table] + u64::from(i) * t.row_size[table];
    let blob = t.blob_size;
    let ssz = t.str_size;

    let assembly = if t.rows[0x20] > 0 {
        let b = row(0x20, 0);
        let name_off = b + 4 + 8 + 4 + blob;
        Some(DotnetAssembly {
            name: heap_string(&r, &strings, read_uint(&r, name_off, ssz)?)?,
            version: version_of(&r, b + 4)?,
        })
    } else {
        None
    };

    let mut references = Vec::new();
    for i in 0..t.rows[0x23].min(ctx.limits.max_symbols as u32) {
        ctx.check()?;
        let b = row(0x23, i);
        references.push(DotnetAssembly {
            name: heap_string(&r, &strings, read_uint(&r, b + 8 + 4 + blob, ssz)?)?,
            version: version_of(&r, b)?,
        });
    }

    // TypeDef columns: Flags(4) Name Namespace Extends FieldList MethodList.
    let extends = t.col_size(TYPE_DEF_OR_REF, guid_size);
    let field_idx = t.col_size(Table(0x04), guid_size);
    let method_idx = t.col_size(Table(0x06), guid_size);
    let (type_rows, method_rows) = (t.rows[0x02], t.rows[0x06]);
    let mut types = Vec::new();
    let mut budget = ctx.limits.max_symbols;
    let mut truncated = false;
    for i in 0..type_rows {
        if i % 256 == 0 {
            ctx.check()?;
        }
        if budget == 0 {
            truncated = true;
            break;
        }
        budget -= 1;
        let b = row(0x02, i);
        let ml_off = 4 + 2 * ssz + extends + field_idx;
        let first = read_uint(&r, b + ml_off, method_idx)?;
        let last = if i + 1 < type_rows {
            read_uint(&r, row(0x02, i + 1) + ml_off, method_idx)?
        } else {
            method_rows + 1
        };
        let mut methods = Vec::new();
        for m in first.max(1)..last.min(method_rows + 1) {
            if budget == 0 {
                truncated = true;
                break;
            }
            budget -= 1;
            let mb = row(0x06, m - 1);
            methods.push(heap_string(&r, &strings, read_uint(&r, mb + 8, ssz)?)?);
        }
        types.push(DotnetType {
            namespace: heap_string(&r, &strings, read_uint(&r, b + 4 + ssz, ssz)?)?,
            name: heap_string(&r, &strings, read_uint(&r, b + 4, ssz)?)?,
            methods,
        });
    }

    Ok(Some(DotnetInfo {
        runtime_version,
        il_only: clr_flags & 1 != 0,
        entry_point_token: if entry_token == 0 { None } else { Some(entry_token) },
        assembly,
        references,
        type_count: type_rows,
        method_count: method_rows,
        types,
        truncated,
    }))
}
