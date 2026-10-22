use omnidecomp_testsamples::{elf64_with_code, CALL_CODE, CFG_CODE};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

fn stdout(args: &[&str]) -> String {
    let o = run(args);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn cfg_json_dot_and_errors() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("cfg.elf");
    std::fs::write(&f, elf64_with_code(&CFG_CODE)).unwrap();
    let p = f.to_str().unwrap();

    let v: serde_json::Value = serde_json::from_str(&stdout(&["cfg", p, "--function", "0x401000", "--format", "json"])).unwrap();
    assert_eq!(v["blocks"].as_array().unwrap().len(), 3);
    assert_eq!(v["blocks"][0]["successors"][0]["kind"], "taken");

    let dot = stdout(&["cfg", p, "--function", "4198400", "--format", "dot"]);
    assert!(dot.starts_with("digraph cfg {"), "{dot}");
    assert!(dot.contains("\"401006\" -> \"401009\""), "{dot}");

    let text = stdout(&["cfg", p, "--function", "0x401000"]);
    assert!(text.contains("block 401000-401006 (3 instr)"), "{text}");

    assert_eq!(run(&["cfg", p, "--function", "0x401001"]).status.code(), Some(2));
    assert_eq!(run(&["cfg", p]).status.code(), Some(2));
}

#[test]
fn callgraph_formats() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("calls.elf");
    std::fs::write(&f, elf64_with_code(&CALL_CODE)).unwrap();
    let p = f.to_str().unwrap();

    let v: serde_json::Value = serde_json::from_str(&stdout(&["callgraph", p, "--format", "json"])).unwrap();
    assert_eq!(v["edges"][0]["from"], 0x40_1000);
    assert_eq!(v["edges"][0]["to"], 0x40_100a);
    assert_eq!(v["nodes"].as_array().unwrap().len(), 2);

    assert!(stdout(&["callgraph", p, "--format", "dot"]).contains("\"401000\" -> \"40100a\""));
    assert!(stdout(&["callgraph", p]).contains("0000000000401000 -> 000000000040100a  x1"));
}
