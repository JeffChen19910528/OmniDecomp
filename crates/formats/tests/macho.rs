use omnidecomp_core::{Arch, Context, ErrorCode, Format, Limits};
use omnidecomp_formats::{function_ranges, parse, symbols};
use omnidecomp_testsamples::{macho64_with_symbols, CODE};

fn ctx() -> Context {
    Context::new(Limits::default())
}

#[test]
fn macho64_header_sections_and_entry() {
    let m = macho64_with_symbols(&CODE);
    let i = parse(&m, &ctx()).unwrap();
    assert_eq!(i.format, Format::MachO);
    assert_eq!((i.arch, i.bits), (Arch::X86_64, 64));
    assert_eq!(i.image_base, Some(0x1_0000_0000));
    assert_eq!(i.entry_point, Some(0x1_0000_0100));
    assert_eq!(i.sections.len(), 1);
    assert_eq!(i.sections[0].name, "__TEXT,__text");
    assert!(i.sections[0].executable);
    assert_eq!(i.sections[0].file_offset, 0x100);
    assert!(function_ranges(&m, &i, &ctx()).unwrap().is_empty());
}

#[test]
fn macho_symbols_defined_and_imported() {
    let m = macho64_with_symbols(&CODE);
    let i = parse(&m, &ctx()).unwrap();
    let s = symbols(&m, &i, &ctx()).unwrap();
    let got: Vec<_> = s.symbols.iter().map(|x| (x.name.as_str(), x.address, x.kind)).collect();
    assert_eq!(got, vec![("_main", Some(0x1_0000_0100), "function"), ("_puts", None, "import")]);
    let c = Context::new(Limits { max_symbols: 1, ..Limits::default() });
    assert!(symbols(&m, &i, &c).unwrap().truncated);
}

#[test]
fn fat_binary_is_refused_with_a_specific_error() {
    let mut fat = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2];
    fat.resize(64, 0);
    let e = parse(&fat, &ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedFormat);
    assert!(e.message.contains("fat"), "{}", e.message);
}

#[test]
fn oversized_load_command_count_is_a_limit_error() {
    let mut m = macho64_with_symbols(&CODE);
    m[16..20].copy_from_slice(&100_000u32.to_le_bytes());
    assert_eq!(parse(&m, &ctx()).unwrap_err().code, ErrorCode::LimitExceeded);
}

/// Every prefix and every single-byte corruption must return Ok or Err, never panic or hang.
#[test]
fn corrupted_macho_never_panics() {
    let sample = macho64_with_symbols(&CODE);
    for len in 0..sample.len() {
        if let Ok(i) = parse(&sample[..len], &ctx()) {
            let _ = symbols(&sample[..len], &i, &ctx());
        }
    }
    let mut m = sample.clone();
    for k in 0..m.len() {
        for flip in [0xffu8, 0x01, 0x80] {
            let old = m[k];
            m[k] ^= flip;
            if let Ok(i) = parse(&m, &ctx()) {
                let _ = symbols(&m, &i, &ctx());
            }
            m[k] = old;
        }
    }
}
