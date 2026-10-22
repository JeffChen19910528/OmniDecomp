use omnidecomp_core::{Arch, Context, Endianness, Limits};
use omnidecomp_formats::{parse, symbols};
use omnidecomp_testsamples::{
    elf64_with_symbols, minimal_elf32_be, minimal_elf64, minimal_pe32, minimal_pe64, pe64_with_symbols,
};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn syms(bytes: &[u8]) -> Vec<(String, Option<u64>, &'static str)> {
    let info = parse(bytes, &ctx()).unwrap();
    symbols(bytes, &info, &ctx()).unwrap().symbols.into_iter().map(|s| (s.name, s.address, s.kind)).collect()
}

#[test]
fn pe_exports_and_imports() {
    assert_eq!(
        syms(&pe64_with_symbols()),
        vec![
            ("my_export".to_string(), Some(0x1_4000_1000), "export"),
            ("KERNEL32.dll!ExitProcess".to_string(), None, "import"),
            ("KERNEL32.dll!#5".to_string(), None, "import"),
        ]
    );
}

#[test]
fn elf_symtab() {
    assert_eq!(
        syms(&elf64_with_symbols()),
        vec![("main".to_string(), Some(0x40_1000), "function"), ("puts".to_string(), None, "import")]
    );
}

#[test]
fn files_without_symbols_give_empty_list() {
    assert!(syms(&minimal_pe64()).is_empty());
    assert!(syms(&minimal_elf64()).is_empty());
}

#[test]
fn symbol_limit_truncates() {
    let bytes = pe64_with_symbols();
    let info = parse(&bytes, &ctx()).unwrap();
    let c = Context::new(Limits { max_symbols: 2, ..Limits::default() });
    let r = symbols(&bytes, &info, &c).unwrap();
    assert_eq!(r.symbols.len(), 2);
    assert!(r.truncated);
}

#[test]
fn pe32_fields() {
    let info = parse(&minimal_pe32(), &ctx()).unwrap();
    assert_eq!((info.arch, info.bits), (Arch::X86, 32));
    assert_eq!(info.image_base, Some(0x40_0000));
    assert_eq!(info.entry_point, Some(0x40_1000));
    assert!(info.sections[0].executable);
}

#[test]
fn elf32_big_endian_fields() {
    let info = parse(&minimal_elf32_be(), &ctx()).unwrap();
    assert_eq!((info.bits, info.endianness, info.arch, info.machine), (32, Endianness::Big, Arch::Unknown, 8));
    assert_eq!(info.entry_point, Some(0x40_0000));
    assert_eq!(info.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec![".text", ".shstrtab"]);
    assert_eq!(info.sections[0].file_offset, 0x40);
}

/// Every prefix and every single-byte corruption must give Ok or Err, never a panic or hang.
#[test]
fn corrupted_symbol_data_never_panics() {
    for sample in [pe64_with_symbols(), elf64_with_symbols()] {
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
}
