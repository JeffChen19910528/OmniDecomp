use omnidecomp_core::{Arch, Context, ErrorCode, Format, Limits};
use omnidecomp_formats::parse;
use omnidecomp_testsamples::{minimal_elf64, minimal_pe64};

fn ctx() -> Context {
    Context::new(Limits::default())
}

#[test]
fn pe64_fields() {
    let info = parse(&minimal_pe64(), &ctx()).unwrap();
    assert_eq!(info.format, Format::Pe);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.bits, 64);
    assert_eq!(info.image_base, Some(0x1_4000_0000));
    assert_eq!(info.entry_point, Some(0x1_4000_1000));
    assert_eq!(info.sections.len(), 1);
    let s = &info.sections[0];
    assert_eq!((s.name.as_str(), s.virtual_address, s.file_offset, s.file_size), (".text", 0x1000, 0x200, 0x200));
    assert!(s.executable);
}

#[test]
fn elf64_fields() {
    let info = parse(&minimal_elf64(), &ctx()).unwrap();
    assert_eq!(info.format, Format::Elf);
    assert_eq!(info.arch, Arch::X86_64);
    assert_eq!(info.bits, 64);
    assert_eq!(info.entry_point, Some(0x40_1000));
    let names: Vec<_> = info.sections.iter().map(|s| (s.name.as_str(), s.executable)).collect();
    assert_eq!(names, vec![(".text", true), (".shstrtab", false)]);
}

#[test]
fn unknown_magic_is_unsupported() {
    let err = parse(b"hello world, not a binary", &ctx()).unwrap_err();
    assert_eq!(err.code, ErrorCode::UnsupportedFormat);
}

#[test]
fn truncated_headers_error() {
    let pe = minimal_pe64();
    assert_eq!(parse(&pe[..0x100], &ctx()).unwrap_err().code, ErrorCode::Truncated); // section data cut
    assert_eq!(parse(&pe[..0x30], &ctx()).unwrap_err().code, ErrorCode::Truncated); // e_lfanew cut
    let elf = minimal_elf64();
    assert_eq!(parse(&elf[..0x60], &ctx()).unwrap_err().code, ErrorCode::Truncated);
}

#[test]
fn bad_pe_signature_is_malformed() {
    let mut pe = minimal_pe64();
    pe[0x40] = b'X';
    assert_eq!(parse(&pe, &ctx()).unwrap_err().code, ErrorCode::Malformed);
}

#[test]
fn section_limit_enforced() {
    let limits = Limits { max_sections: 1, ..Limits::default() };
    let c = Context::new(limits);
    assert_eq!(parse(&minimal_elf64(), &c).unwrap_err().code, ErrorCode::LimitExceeded);
}

#[test]
fn section_name_is_sanitized() {
    let mut pe = minimal_pe64();
    pe[0x148..0x150].copy_from_slice(b".t\x1b[31mx");
    let info = parse(&pe, &ctx()).unwrap();
    assert!(info.sections[0].name.chars().all(|c| !c.is_control()));
}

/// Deterministic mutation fuzz: every prefix and many byte flips must return Ok/Err, never panic.
#[test]
fn mutation_never_panics() {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for sample in [minimal_pe64(), minimal_elf64()] {
        for len in 0..sample.len() {
            let _ = parse(&sample[..len], &ctx());
        }
        for _ in 0..20_000 {
            let mut m = sample.clone();
            for _ in 0..1 + next() % 8 {
                let i = (next() % m.len() as u64) as usize;
                m[i] = next() as u8;
            }
            let _ = parse(&m, &ctx());
        }
    }
}
