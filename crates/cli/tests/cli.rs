use omnidecomp_testsamples::{minimal_elf64, minimal_pe64};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

fn sample(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn stdout_json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("bad json: {e}\n{}", String::from_utf8_lossy(&o.stdout)))
}

#[test]
fn info_pe_json_matches_independent_hash() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = minimal_pe64();
    let f = sample(dir.path(), "a.exe", &bytes);
    let o = run(&["info", f.to_str().unwrap(), "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let v = stdout_json(&o);
    assert_eq!(v["info"]["format"], "pe");
    assert_eq!(v["info"]["arch"], "x86_64");
    assert_eq!(v["info"]["sections"][0]["name"], ".text");
    assert_eq!(v["artifact"]["sha256"], format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(v["artifact"]["size"], bytes.len());
}

#[test]
fn magic_wins_over_extension() {
    let dir = tempfile::tempdir().unwrap();
    let f = sample(dir.path(), "looks_like.txt", &minimal_elf64());
    let v = stdout_json(&run(&["info", f.to_str().unwrap(), "--format", "json"]));
    assert_eq!(v["info"]["format"], "elf");
}

#[test]
fn disasm_json_has_expected_instructions() {
    let dir = tempfile::tempdir().unwrap();
    let f = sample(dir.path(), "a.elf", &minimal_elf64());
    let o = run(&["disasm", f.to_str().unwrap(), "--arch", "x86_64", "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let v = stdout_json(&o);
    assert_eq!(v["engine"], "iced-x86");
    let ins = v["instructions"].as_array().unwrap();
    assert_eq!(ins.len(), 5);
    assert_eq!(ins[0]["mnemonic"], "push");
    assert_eq!(ins[0]["address"], 0x40_1000);
    assert_eq!(ins[4]["mnemonic"], "ret");
}

#[test]
fn error_exit_codes_are_stable() {
    let dir = tempfile::tempdir().unwrap();
    let pe = minimal_pe64();
    let good = sample(dir.path(), "g.exe", &pe);
    let trunc = sample(dir.path(), "t.exe", &pe[..0x100]);
    let junk = sample(dir.path(), "j.bin", b"not a binary at all");
    let code = |args: &[&str]| run(args).status.code();
    assert_eq!(code(&["info", trunc.to_str().unwrap()]), Some(10));
    assert_eq!(code(&["info", junk.to_str().unwrap()]), Some(12));
    assert_eq!(code(&["info", dir.path().join("missing").to_str().unwrap()]), Some(3));
    assert_eq!(code(&["disasm", good.to_str().unwrap(), "--engine", "ghidra"]), Some(15));
    assert_eq!(code(&["disasm", good.to_str().unwrap(), "--arch", "x86"]), Some(13));
    assert_eq!(code(&["disasm", good.to_str().unwrap(), "--arch", "sparc"]), Some(2));
    assert_eq!(code(&["--max-file-size-mb", "0", "info", good.to_str().unwrap()]), Some(14));
    let err = String::from_utf8_lossy(&run(&["info", trunc.to_str().unwrap()]).stderr).to_string();
    assert!(err.starts_with("error[truncated]"), "{err}");
}

#[test]
fn report_output_path_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let f = sample(dir.path(), "a.exe", &minimal_pe64());
    let out = dir.path().join("r.json");
    let o = run(&["report", f.to_str().unwrap(), "--output", out.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["disassembly"]["instruction_count"], 5);
    let evil = format!("{}/../x.json", dir.path().display());
    assert_eq!(run(&["report", f.to_str().unwrap(), "--output", &evil]).status.code(), Some(16));
    assert_eq!(run(&["report", f.to_str().unwrap(), "--output", f.to_str().unwrap()]).status.code(), Some(16));
}

#[test]
fn strings_and_engines_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = minimal_pe64();
    b[0x300..0x30b].copy_from_slice(b"HELLO_WORLD");
    let f = sample(dir.path(), "s.exe", &b);
    let v = stdout_json(&run(&["strings", f.to_str().unwrap(), "--format", "json"]));
    assert!(v["strings"].as_array().unwrap().iter().any(|s| s["text"] == "HELLO_WORLD" && s["offset"] == 0x300));
    let e = stdout_json(&run(&["engines", "list", "--format", "json"]));
    assert_eq!(e[0]["id"], "iced-x86");
}
