use omnidecomp_testsamples::{macho64_with_symbols, CODE};
use std::process::Command;

fn json(args: &[&str]) -> serde_json::Value {
    let o = Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

#[test]
fn macho_info_disasm_and_functions() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.macho");
    std::fs::write(&f, macho64_with_symbols(&CODE)).unwrap();
    let p = f.to_str().unwrap();

    assert_eq!(json(&["info", p, "--format", "json"])["info"]["format"], "mach_o");
    let d = json(&["disasm", p, "--format", "json"]);
    assert_eq!(d["instructions"][0]["address"], 0x1_0000_0100u64);
    assert_eq!(d["instructions"][0]["mnemonic"], "push");
    let fns = json(&["functions", p, "--format", "json"]);
    assert_eq!(fns["functions"][0]["name"], "_main");
    assert_eq!(fns["functions"][0]["source"], "symbol");
}
