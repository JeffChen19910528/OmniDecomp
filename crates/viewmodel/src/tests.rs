use crate::*;
use omnidecomp_core::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use omnidecomp_testsamples::{elf64_with_code, elf64_with_symbols, CFG_CODE, macho64_with_symbols, minimal_elf32_be, minimal_pe64, CALL_CODE, CODE};

fn load_bytes(bytes: Vec<u8>) -> (tempfile::TempDir, Loaded) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("sample.bin");
    std::fs::write(&p, bytes).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let l = load(&p, Limits::default(), &cancel, &|_| {}).unwrap();
    (dir, l)
}

#[test]
fn elf_load_exposes_everything_the_views_need() {
    let (_d, l) = load_bytes(elf64_with_symbols());
    assert_eq!(l.name, "sample.bin");
    assert_eq!(l.instructions()[0].address, 0x40_1000);
    assert_eq!(l.instruction_at(0x40_1000), Some(0));
    assert_eq!(l.instruction_at(0x40_1002), None);
    assert_eq!(l.instruction_at_or_after(0x40_1002), Some(2));
    assert_eq!(l.name_at(0x40_1000), Some("main"));
    assert!(l.notes.is_empty(), "{:?}", l.notes);
    assert_eq!(l.file_offset_of(0x40_1000), Some(0x40));
    assert_eq!(l.address_of_offset(0x40), Some(0x40_1000));
    assert_eq!(l.hex_row(0x40, 4), &CODE[..4]);
    assert!(l.hex_row(u64::MAX, 16).is_empty());
}

#[test]
fn pe_addresses_include_the_image_base() {
    let (_d, l) = load_bytes(minimal_pe64());
    assert_eq!(l.instructions()[0].address, 0x1_4000_1000);
    assert_eq!(l.file_offset_of(0x1_4000_1000), Some(0x200));
    assert_eq!(l.address_of_offset(0x200), Some(0x1_4000_1000));
}

#[test]
fn macho_addresses_are_not_rebased_twice() {
    let (_d, l) = load_bytes(macho64_with_symbols(&CODE));
    assert_eq!(l.instructions()[0].address, 0x1_0000_0100);
    assert_eq!(l.file_offset_of(0x1_0000_0100), Some(0x100));
}

#[test]
fn unsupported_arch_is_explained_not_faked() {
    let mut elf = elf64_with_symbols();
    elf[18..20].copy_from_slice(&40u16.to_le_bytes()); // 32-bit ARM
    let (_d, l) = load_bytes(elf);
    assert!(l.disasm.is_none() && l.functions.is_none());
    assert!(l.notes[0].contains("disassembly unavailable"), "{:?}", l.notes);
    assert!(!l.symbols.is_empty());
}

#[test]
fn xrefs_both_directions() {
    let mut elf = omnidecomp_testsamples::elf64_with_code(&CALL_CODE);
    elf.truncate(elf.len());
    let (_d, l) = load_bytes(elf);
    let to = l.xrefs_to(0x40_100a);
    assert_eq!(to.len(), 2);
    assert_eq!(l.xrefs_from(0x40_1000).len(), 1);
    assert!(l.xrefs_to(0xdead).is_empty());
}

#[test]
fn search_scopes_and_limit() {
    let (_d, l) = load_bytes(elf64_with_symbols());
    let by_name = l.search("MAIN", Scope::Functions, 10);
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].address, Some(0x40_1000));
    assert!(l.search("puts", Scope::Symbols, 10).iter().any(|h| h.kind == HitKind::Symbol));
    assert!(l.search("push", Scope::Instructions, 10).iter().all(|h| h.kind == HitKind::Instruction));
    assert_eq!(l.search("p", Scope::All, 1).len(), 1);
    assert!(l.search("", Scope::All, 10).is_empty());
    let goto = l.search("0x401004", Scope::All, 5);
    assert_eq!(goto[0].kind, HitKind::Address);
    assert_eq!(goto[0].address, Some(0x40_1004));
}

#[test]
fn address_parsing() {
    assert_eq!(parse_address("0x401000"), Some(0x40_1000));
    assert_eq!(parse_address(" 401000 "), Some(0x40_1000));
    assert_eq!(parse_address("0x1_0000_0000"), Some(1 << 32));
    assert_eq!(parse_address("zz"), None);
    assert_eq!(parse_address(""), None);
    assert_eq!(parse_address("0x"), None);
    assert_eq!(parse_address("1ffffffffffffffff"), None);
}

#[test]
fn settings_are_clamped_and_addresses_formatted() {
    let s = Settings { font_size: 500.0, line_spacing: -3.0, ..Settings::default() }.sanitized();
    assert_eq!((s.font_size, s.line_spacing), (MAX_FONT, 0.0));
    let nan = Settings { font_size: f32::NAN, line_spacing: f32::INFINITY, ..Settings::default() }.sanitized();
    assert_eq!((nan.font_size, nan.line_spacing), (14.0, 2.0));
    assert_eq!(s.format_address(0x40_1000, 64), "0000000000401000");
    assert_eq!(s.format_address(0x40_1000, 32), "00401000");
    let short = Settings { address_format: AddressFormat::Short, ..s };
    assert_eq!(short.format_address(0x40_1000, 64), "401000");
}

#[test]
fn mnemonic_classes() {
    let (_d, l) = load_bytes(omnidecomp_testsamples::elf64_with_code(&CALL_CODE));
    let classes: Vec<_> = l.instructions().iter().map(mnemonic_class).collect();
    assert!(classes.contains(&MnemonicClass::Call) && classes.contains(&MnemonicClass::Return));
}

#[test]
fn background_load_reports_progress_and_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.bin");
    std::fs::write(&p, elf64_with_symbols()).unwrap();
    let mut t = start_load(p, Limits::default(), || {});
    let result = loop {
        if let Some(r) = t.poll() {
            break r;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(result.is_ok());
    assert!(t.poll().is_none(), "a finished task yields its result once");
    assert!(!t.status().is_empty());
}

#[test]
fn cancel_stops_a_load() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("a.bin");
    std::fs::write(&p, elf64_with_symbols()).unwrap();
    let cancel = Arc::new(AtomicBool::new(true));
    // The flag is already set, so the first check must fail.
    let err = load(&p, Limits::default(), &cancel, &|_| {}).err();
    assert_eq!(err.map(|e| e.code), Some(ErrorCode::Cancelled));
}

#[test]
fn bad_inputs_are_errors_not_panics() {
    let dir = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let missing = load(&dir.path().join("nope"), Limits::default(), &cancel, &|_| {});
    assert_eq!(missing.err().map(|e| e.code), Some(ErrorCode::Io));
    let p = dir.path().join("junk");
    std::fs::write(&p, b"not an executable").unwrap();
    assert_eq!(load(&p, Limits::default(), &cancel, &|_| {}).err().map(|e| e.code), Some(ErrorCode::UnsupportedFormat));
    let big = Limits { max_file_size: 4, ..Limits::default() };
    assert_eq!(load(&p, big, &cancel, &|_| {}).err().map(|e| e.code), Some(ErrorCode::LimitExceeded));
}

/// Large input: 8 MiB of repeated function bodies. Prints timings (run with `--nocapture`); the
/// bounds are deliberately loose so slow CI machines do not flake, but they catch quadratic blowups.
#[test]
fn large_input_loads_searches_and_looks_up_quickly() {
    use std::time::Instant;
    // call +0 (next), push rbp, mov rbp,rsp, nop, pop rbp, ret: every unit is a tiny function.
    let unit = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3];
    let bytes = omnidecomp_testsamples::elf64_large(&unit, 8 * 1024 * 1024);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.elf");
    std::fs::write(&p, &bytes).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));

    let t = Instant::now();
    let l = load(&p, Limits::default(), &cancel, &|_| {}).unwrap();
    let load_time = t.elapsed();
    assert!(l.instructions().len() >= 900_000, "{}", l.instructions().len());
    assert!(l.notes.iter().any(|n| n.contains("cut by a configured limit")), "{:?}", l.notes);

    let t = Instant::now();
    let hits = l.search("pop", Scope::Instructions, 5000);
    let search_time = t.elapsed();
    assert_eq!(hits.len(), 5000);

    let t = Instant::now();
    for k in 0..10_000u64 {
        assert!(l.instruction_at(0x40_1000 + (k % 1000) * 12).is_some());
    }
    let lookup_time = t.elapsed();
    println!("load {load_time:?} for {} instructions, search {search_time:?}, 10k lookups {lookup_time:?}", l.instructions().len());
    assert!(load_time.as_secs() < 120 && search_time.as_secs() < 10 && lookup_time.as_secs() < 5);

    // The graph views run on the UI thread, so their cost on a million instructions is measured too.
    let t = Instant::now();
    let first = l.functions.as_ref().unwrap().functions[0].address;
    let cfg = l.cfg(first, Limits::default()).unwrap();
    let cfg_time = t.elapsed();
    let t = Instant::now();
    let g = l.call_graph().unwrap();
    let lay = graph::call_layout(g, first, 3, graph::MAX_GRAPH_NODES);
    let call_time = t.elapsed();
    println!("cfg {cfg_time:?} ({} blocks), call graph + layout {call_time:?} ({} nodes)", cfg.blocks.len(), lay.nodes.len());
    assert!(cfg_time.as_secs() < 20 && call_time.as_secs() < 20);
}

#[test]
fn cfg_and_call_graph_come_from_the_loaded_model() {
    let (_d, l) = load_bytes(elf64_with_code(&CFG_CODE));
    let entry = l.analysis.info.entry_point.unwrap();
    assert_eq!(l.function_containing(entry + 7), Some(entry), "an address inside the function maps to its start");
    assert_eq!(l.function_containing(entry.saturating_sub(1)), None, "before the first function there is none");
    let cfg = l.cfg(entry, Limits::default()).unwrap();
    assert!(cfg.blocks.len() >= 2, "conditional branch splits the function: {cfg:?}");
    let lay = graph::cfg_layout(&cfg);
    assert_eq!(lay.nodes.len(), cfg.blocks.len());
    assert_eq!(lay.nodes[0].layer, 0);
    assert!(l.cfg(entry + 1, Limits::default()).is_err(), "a mid-instruction address is an error, not a guess");

    let (_d, l) = load_bytes(elf64_with_code(&CALL_CODE));
    let g = l.call_graph().unwrap();
    assert!(!g.nodes.is_empty());
    assert!(std::ptr::eq(g, l.call_graph().unwrap()), "computed once");
}

#[test]
fn no_disassembly_means_an_explicit_error_for_cfg() {
    let (_d, l) = load_bytes(minimal_elf32_be());
    assert!(l.cfg(0, Limits::default()).is_err());
    assert!(l.call_graph().is_none());
    assert_eq!(l.function_containing(0), None);
}
