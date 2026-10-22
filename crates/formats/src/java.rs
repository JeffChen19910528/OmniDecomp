//! Java `.class` structure (JVMS chapter 4): version, class/super/interface names, fields and methods.
//! Bytecode is not decoded and nothing is decompiled.

use crate::reader::{malformed, sanitize_text, Reader};
use omnidecomp_core::{Context, JavaClassInfo, JavaMember, Result};

const MAX_NAME: usize = 256;

/// Class files share 0xCAFEBABE with Mach-O fat headers; the minor/major version (major >= 45) tells them apart.
pub fn is_class(data: &[u8]) -> bool {
    data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) && data.get(6..8).is_some_and(|v| u16::from_be_bytes([v[0], v[1]]) >= 45)
}

/// Constant pool entry: the offset of its payload (after the tag) and its tag.
#[derive(Clone, Copy)]
struct Entry {
    tag: u8,
    off: u64,
}

struct Pool<'a> {
    r: Reader<'a>,
    entries: Vec<Option<Entry>>,
}

impl Pool<'_> {
    fn utf8(&self, idx: u16) -> Result<String> {
        match self.entries.get(usize::from(idx)).copied().flatten() {
            Some(Entry { tag: 1, off }) => {
                let len = u64::from(self.r.u16(off)?);
                Ok(sanitize_text(self.r.bytes(off + 2, len)?, MAX_NAME))
            }
            _ => Err(malformed("constant pool index is not a Utf8 entry")),
        }
    }

    fn class_name(&self, idx: u16) -> Result<String> {
        match self.entries.get(usize::from(idx)).copied().flatten() {
            Some(Entry { tag: 7, off }) => Ok(self.utf8(self.r.u16(off)?)?.replace('/', ".")),
            _ => Err(malformed("constant pool index is not a Class entry")),
        }
    }
}

fn flag_names(flags: u16, table: &[(u16, &'static str)]) -> Vec<&'static str> {
    table.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, n)| *n).collect()
}

const CLASS_FLAGS: &[(u16, &str)] = &[
    (0x1, "public"),
    (0x10, "final"),
    (0x200, "interface"),
    (0x400, "abstract"),
    (0x1000, "synthetic"),
    (0x2000, "annotation"),
    (0x4000, "enum"),
    (0x8000, "module"),
];
const FIELD_FLAGS: &[(u16, &str)] = &[
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x40, "volatile"),
    (0x80, "transient"),
    (0x1000, "synthetic"),
    (0x4000, "enum"),
];
const METHOD_FLAGS: &[(u16, &str)] = &[
    (0x1, "public"),
    (0x2, "private"),
    (0x4, "protected"),
    (0x8, "static"),
    (0x10, "final"),
    (0x20, "synchronized"),
    (0x40, "bridge"),
    (0x80, "varargs"),
    (0x100, "native"),
    (0x400, "abstract"),
    (0x800, "strict"),
    (0x1000, "synthetic"),
];

pub fn parse_class(data: &[u8], ctx: &Context) -> Result<JavaClassInfo> {
    let r = Reader::new(data, true);
    if !is_class(data) {
        return Err(malformed("not a Java class file"));
    }
    let (minor, major) = (r.u16(4)?, r.u16(6)?);
    let count = usize::from(r.u16(8)?);
    if count == 0 {
        return Err(malformed("constant pool count is zero"));
    }
    let mut pool = Pool { r, entries: vec![None; count] };
    let mut off = 10u64;
    let mut i = 1usize;
    while i < count {
        if i.is_multiple_of(256) {
            ctx.check()?;
        }
        let tag = r.bytes(off, 1)?[0];
        let payload = off + 1;
        let (size, slots) = match tag {
            1 => (2 + u64::from(r.u16(payload)?), 1),
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => (4, 1),
            5 | 6 => (8, 2),
            7 | 8 | 16 | 19 | 20 => (2, 1),
            15 => (3, 1),
            t => return Err(malformed(format!("unknown constant pool tag {t}"))),
        };
        r.bytes(payload, size)?;
        pool.entries[i] = Some(Entry { tag, off: payload });
        off = payload + size;
        i += slots;
    }

    let access = r.u16(off)?;
    let this_class = pool.class_name(r.u16(off + 2)?)?;
    let super_idx = r.u16(off + 4)?;
    let super_class = if super_idx == 0 { None } else { Some(pool.class_name(super_idx)?) };
    let n_ifaces = u64::from(r.u16(off + 6)?);
    r.bytes(off + 8, n_ifaces * 2)?;
    let mut interfaces = Vec::new();
    for k in 0..n_ifaces {
        interfaces.push(pool.class_name(r.u16(off + 8 + k * 2)?)?);
    }
    off += 8 + n_ifaces * 2;

    let mut budget = ctx.limits.max_symbols;
    let mut truncated = false;
    let mut members = |off: &mut u64, table: &[(u16, &'static str)]| -> Result<Vec<JavaMember>> {
        let n = r.u16(*off)?;
        *off += 2;
        let mut out = Vec::new();
        for _ in 0..n {
            ctx.check()?;
            let (flags, name, desc, attrs) = (r.u16(*off)?, r.u16(*off + 2)?, r.u16(*off + 4)?, r.u16(*off + 6)?);
            *off += 8;
            for _ in 0..attrs {
                *off = skip_attribute(&r, *off)?;
            }
            if budget == 0 {
                truncated = true;
                continue;
            }
            budget -= 1;
            out.push(JavaMember { name: pool.utf8(name)?, descriptor: pool.utf8(desc)?, access: flag_names(flags, table) });
        }
        Ok(out)
    };
    let fields = members(&mut off, FIELD_FLAGS)?;
    let methods = members(&mut off, METHOD_FLAGS)?;

    let mut source_file = None;
    let n_attrs = r.u16(off)?;
    off += 2;
    for _ in 0..n_attrs {
        ctx.check()?;
        let name = pool.utf8(r.u16(off)?)?;
        if name == "SourceFile" && r.u32(off + 2)? == 2 {
            source_file = Some(pool.utf8(r.u16(off + 6)?)?);
        }
        off = skip_attribute(&r, off)?;
    }

    Ok(JavaClassInfo {
        major,
        minor,
        java_version: if major >= 49 { format!("Java {}", major - 44) } else { format!("JDK 1.{}", major - 44) },
        class_name: this_class,
        super_class,
        access: flag_names(access, CLASS_FLAGS),
        interfaces,
        source_file,
        fields,
        methods,
        truncated,
    })
}

/// Skips one attribute (`name_index u2, length u4, bytes`) starting at `off`; returns the next offset.
fn skip_attribute(r: &Reader, off: u64) -> Result<u64> {
    let len = u64::from(r.u32(off + 2)?);
    r.bytes(off + 6, len)?;
    Ok(off + 6 + len)
}
