use crate::*;
use omnidecomp_core::*;
use std::{fs, path::Path};
use omnidecomp_core::Limits;
use omnidecomp_testsamples::{minimal_elf64, minimal_pe64};

fn ctx() -> Context {
    Context::new(Limits::default())
}

fn analysis(bytes: Vec<u8>) -> (tempfile::TempDir, Analysis) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("sample.bin");
    fs::write(&p, bytes).unwrap();
    let a = analyze(&p, &ctx()).unwrap();
    (dir, a)
}

fn opts() -> DisasmOptions<'static> {
    DisasmOptions { engine: "iced-x86", arch: None, section: None, max_instructions: 100 }
}

#[test]
fn disasm_pe_addresses_and_mnemonics() {
    let (_d, a) = analysis(minimal_pe64());
    let d = disassemble(&a, &opts(), &ctx()).unwrap();
    let got: Vec<_> = d.instructions.iter().map(|i| (i.address, i.mnemonic.as_str())).collect();
    assert_eq!(
        got,
        vec![
            (0x1_4000_1000, "push"),
            (0x1_4000_1001, "mov"),
            (0x1_4000_1004, "nop"),
            (0x1_4000_1005, "pop"),
            (0x1_4000_1006, "ret"),
        ]
    );
    assert_eq!(d.instructions[1].operands, "rbp,rsp");
    assert_eq!(d.instructions[1].bytes, "4889e5");
}

#[test]
fn disasm_elf_addresses() {
    let (_d, a) = analysis(minimal_elf64());
    let d = disassemble(&a, &opts(), &ctx()).unwrap();
    assert_eq!(d.instructions.first().unwrap().address, 0x40_1000);
    assert_eq!(d.instructions.len(), 5);
}

#[test]
fn instruction_limit_truncates() {
    let (_d, a) = analysis(minimal_elf64());
    let o = DisasmOptions { max_instructions: 2, ..opts() };
    let d = disassemble(&a, &o, &ctx()).unwrap();
    assert_eq!(d.instructions.len(), 2);
    assert!(d.truncated);
}

#[test]
fn unknown_engine_and_arch_errors() {
    let (_d, a) = analysis(minimal_elf64());
    let e = disassemble(&a, &DisasmOptions { engine: "nope", ..opts() }, &ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownEngine);
    let e = disassemble(&a, &DisasmOptions { arch: Some("sparc"), ..opts() }, &ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = disassemble(&a, &DisasmOptions { arch: Some("x86"), ..opts() }, &ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedArch);
}

#[test]
fn unsupported_arch_is_refused_not_faked() {
    let mut elf = minimal_elf64();
    elf[18..20].copy_from_slice(&40u16.to_le_bytes()); // 32-bit ARM
    let (_d, a) = analysis(elf);
    let e = disassemble(&a, &opts(), &ctx()).unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedArch);
}

#[test]
fn cancelled_context_stops_work() {
    let (_d, a) = analysis(minimal_elf64());
    let c = ctx();
    c.cancel_handle().store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(disassemble(&a, &opts(), &c).unwrap_err().code, ErrorCode::Cancelled);
}

#[test]
fn strings_found_with_offsets() {
    let data = b"\x00\x01hello\x00ab\x00world!!\x00";
    let r = extract_strings(data, 4, &ctx()).unwrap();
    let got: Vec<_> = r.strings.iter().map(|s| (s.offset, s.text.as_str())).collect();
    assert_eq!(got, vec![(2, "hello"), (11, "world!!")]);
}

#[test]
fn oversized_input_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.bin");
    fs::write(&p, vec![0u8; 100]).unwrap();
    let limits = Limits { max_file_size: 10, ..Limits::default() };
    let e = analyze(&p, &Context::new(limits)).err().unwrap();
    assert_eq!(e.code, ErrorCode::LimitExceeded);
}

#[test]
fn output_path_validation() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.bin");
    fs::write(&input, b"x").unwrap();
    let code = |p: &Path| write_output(p, b"{}", &input).unwrap_err().code;
    assert_eq!(code(&dir.path().join("..").join("evil.json")), ErrorCode::InvalidOutputPath);
    assert_eq!(code(dir.path()), ErrorCode::InvalidOutputPath);
    assert_eq!(code(&dir.path().join("missing").join("o.json")), ErrorCode::InvalidOutputPath);
    assert_eq!(code(&input), ErrorCode::InvalidOutputPath);
    assert_eq!(fs::read(&input).unwrap(), b"x");
    let ok = dir.path().join("out.json");
    write_output(&ok, b"{}", &input).unwrap();
    assert_eq!(fs::read(&ok).unwrap(), b"{}");
}

#[test]
fn report_has_sha256_and_disassembly() {
    let bytes = minimal_pe64();
    let (_d, a) = analysis(bytes);
    let r = build_report(&a, &ctx()).unwrap();
    assert_eq!(r["info"]["format"], "pe");
    assert_eq!(r["disassembly"]["instruction_count"], 5);
    assert_eq!(r["artifact"]["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn functions_and_xrefs_from_calls() {
    use omnidecomp_testsamples::{elf64_with_code, CALL_CODE};
    let (_d, a) = analysis(elf64_with_code(&CALL_CODE));
    let r = functions(&a, &ctx()).unwrap();
    let funcs: Vec<_> = r.functions.iter().map(|f| (f.address, f.source, f.callers)).collect();
    assert_eq!(funcs, vec![(0x40_1000, "entry", 0), (0x40_100a, "call_target", 1)]);
    let xrefs: Vec<_> = r.xrefs.iter().map(|x| (x.from, x.to, x.kind)).collect();
    assert_eq!(
        xrefs,
        vec![(0x40_1000, 0x40_100a, "call"), (0x40_1005, 0x40_100a, "jump"), (0x40_1007, 0x40_1009, "branch")]
    );
}

#[test]
fn symbol_names_a_function() {
    let (_d, a) = analysis(omnidecomp_testsamples::elf64_with_symbols());
    let r = functions(&a, &ctx()).unwrap();
    assert_eq!(r.functions.len(), 1);
    let f = &r.functions[0];
    assert_eq!((f.address, f.name.as_deref(), f.source, f.confidence), (0x40_1000, Some("main"), "symbol", "high"));
}

#[test]
fn functions_refused_for_unsupported_arch() {
    let mut elf = minimal_elf64();
    elf[18..20].copy_from_slice(&40u16.to_le_bytes());
    let (_d, a) = analysis(elf);
    assert_eq!(functions(&a, &ctx()).unwrap_err().code, ErrorCode::UnsupportedArch);
}

#[test]
fn cfg_diamond_blocks_and_edges() {
    use omnidecomp_testsamples::{elf64_with_code, CFG_CODE};
    let (_d, a) = analysis(elf64_with_code(&CFG_CODE));
    let r = cfg(&a, 0x40_1000, &ctx()).unwrap();
    let blocks: Vec<_> = r
        .blocks
        .iter()
        .map(|b| {
            let succ: Vec<_> = b.successors.iter().map(|e| (e.to, e.kind)).collect();
            (b.start, b.end, b.instruction_count, succ, b.exits_graph)
        })
        .collect();
    assert_eq!(
        blocks,
        vec![
            (0x40_1000, 0x40_1006, 3, vec![(0x40_1009, "taken"), (0x40_1006, "fallthrough")], false),
            (0x40_1006, 0x40_1009, 2, vec![(0x40_1009, "fallthrough")], false),
            (0x40_1009, 0x40_100a, 1, vec![], false),
        ]
    );
    let dot = cfg_to_dot(&r);
    assert!(dot.contains("\"401000\" -> \"401009\" [label=\"taken\"]"), "{dot}");
}

#[test]
fn cfg_does_not_follow_tail_call_into_other_function() {
    use omnidecomp_testsamples::{elf64_with_code, CALL_CODE};
    let (_d, a) = analysis(elf64_with_code(&CALL_CODE));
    let r = cfg(&a, 0x40_1000, &ctx()).unwrap();
    assert_eq!(r.blocks.len(), 1);
    assert_eq!((r.blocks[0].start, r.blocks[0].instruction_count), (0x40_1000, 2));
    assert!(r.blocks[0].exits_graph && r.blocks[0].successors.is_empty());
}

#[test]
fn cfg_rejects_address_without_instruction() {
    let (_d, a) = analysis(minimal_elf64());
    assert_eq!(cfg(&a, 0x40_1002, &ctx()).unwrap_err().code, ErrorCode::InvalidArgument);
    assert_eq!(cfg(&a, 0xdead, &ctx()).unwrap_err().code, ErrorCode::InvalidArgument);
}

#[test]
fn call_graph_edges() {
    use omnidecomp_testsamples::{elf64_with_code, CALL_CODE};
    let (_d, a) = analysis(elf64_with_code(&CALL_CODE));
    let g = call_graph(&a, &ctx()).unwrap();
    assert_eq!(g.nodes.len(), 2);
    let edges: Vec<_> = g.edges.iter().map(|e| (e.from, e.to, e.count)).collect();
    assert_eq!(edges, vec![(0x40_1000, 0x40_100a, 1)]);
    assert!(call_graph_to_dot(&g).contains("\"401000\" -> \"40100a\";"));
}

#[test]
fn pdata_gives_function_sizes_and_skips_chained_fragments() {
    use omnidecomp_testsamples::{pe64_with_pdata, CALL_CODE};
    let mut code = CALL_CODE.to_vec();
    code.extend_from_slice(&[0xCC; 4]);
    let pe = pe64_with_pdata(&code, &[(0x1000, 0x100a, false), (0x100a, 0x100c, false), (0x100c, 0x1010, true)]);
    let (_d, a) = analysis(pe);
    let r = functions(&a, &ctx()).unwrap();
    let got: Vec<_> = r.functions.iter().map(|f| (f.address, f.source, f.size, f.callers)).collect();
    assert_eq!(got, vec![(0x1_4000_1000, "pdata", Some(10), 0), (0x1_4000_100a, "pdata", Some(2), 1)]);
    assert!(r.notes[0].contains(".pdata"));
    let g = call_graph(&a, &ctx()).unwrap();
    let edges: Vec<_> = g.edges.iter().map(|e| (e.from, e.to)).collect();
    assert_eq!(edges, vec![(0x1_4000_1000, 0x1_4000_100a)]);
}

#[test]
fn functions_for_matches_functions_without_resweeping() {
    use omnidecomp_testsamples::elf64_with_symbols;
    let (_d, a) = analysis(elf64_with_symbols());
    let d = disassemble(&a, &DisasmOptions { engine: "auto", ..opts() }, &ctx()).unwrap();
    let syms = symbols(&a, &ctx()).unwrap().symbols;
    let reused = functions_for(&a, &d, &syms, &ctx()).unwrap();
    let fresh = functions(&a, &ctx()).unwrap();
    let key = |r: &FunctionsResult| r.functions.iter().map(|f| (f.address, f.name.clone(), f.source, f.size)).collect::<Vec<_>>();
    assert_eq!(key(&reused), key(&fresh));
    assert_eq!(reused.xrefs.len(), fresh.xrefs.len());
}

#[test]
fn report_names_the_limit_that_truncated_output() {
    use omnidecomp_testsamples::{elf64_with_code, pe64_with_pdb, CALL_CODE};
    let (_d, a) = analysis(elf64_with_code(&CALL_CODE));
    let tight = Context::new(Limits { max_instructions: 2, max_strings: 1, ..Limits::default() });
    let r = build_report(&a, &tight).unwrap();
    assert_eq!(r["disassembly"]["limit"], "max_instructions");
    assert_eq!(r["functions"]["limit"], "max_instructions");
    let r = build_report(&a, &ctx()).unwrap();
    assert!(r["disassembly"]["limit"].is_null() && r["symbols"]["limit"].is_null());
    assert!(r["debug"].is_null());
    let (_d, a) = analysis(pe64_with_pdb("x.pdb"));
    assert_eq!(build_report(&a, &ctx()).unwrap()["debug"]["pdb_path"], "x.pdb");
}

#[test]
fn eh_frame_gives_elf_function_sizes_and_cfg_bounds() {
    use omnidecomp_testsamples::{elf64_with_eh_frame, CALL_CODE, JMP_CODE};
    let mut code = CALL_CODE.to_vec();
    code.extend_from_slice(&[0xCC; 4]);
    let (_d, a) = analysis(elf64_with_eh_frame(&code, &[(0x40_1000, 10), (0x40_100a, 2)]));
    let r = functions(&a, &ctx()).unwrap();
    let got: Vec<_> = r.functions.iter().map(|f| (f.address, f.source, f.size, f.callers)).collect();
    assert_eq!(got, vec![(0x40_1000, "eh_frame", Some(10), 0), (0x40_100a, "eh_frame", Some(2), 1)]);
    assert!(r.notes[0].contains(".eh_frame"));

    // The tail jump from A into B leaves A's graph once the FDE bounds are known.
    let (_d, a) = analysis(elf64_with_eh_frame(&JMP_CODE, &[(0x40_1000, 6), (0x40_1006, 2)]));
    let g = cfg(&a, 0x40_1000, &ctx()).unwrap();
    assert_eq!(g.blocks.len(), 1);
    assert!(g.blocks[0].exits_graph);
}

#[test]
fn pdata_makes_cfg_stop_at_function_boundary() {
    use omnidecomp_testsamples::{elf64_with_code, pe64_with_pdata, JMP_CODE};
    // Without exact ranges, the unreferenced tail-call target is absorbed into the graph.
    let (_d1, elf) = analysis(elf64_with_code(&JMP_CODE));
    assert_eq!(cfg(&elf, 0x40_1000, &ctx()).unwrap().blocks.len(), 2);
    // With .pdata, B (0x1006..0x1008) is its own function and the jump leaves the graph.
    let pe = pe64_with_pdata(&JMP_CODE, &[(0x1000, 0x1006, false), (0x1006, 0x1008, false)]);
    let (_d2, a) = analysis(pe);
    let r = cfg(&a, 0x1_4000_1000, &ctx()).unwrap();
    assert_eq!(r.blocks.len(), 1);
    assert_eq!((r.blocks[0].instruction_count, r.blocks[0].exits_graph), (2, true));
}
