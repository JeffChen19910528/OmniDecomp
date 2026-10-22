use omnidecomp_testsamples::{elf64_with_code, CALL_CODE};
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

fn json(args: &[&str]) -> serde_json::Value {
    let o = run(args);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

#[test]
fn functions_and_xrefs_commands() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("calls.elf");
    std::fs::write(&f, elf64_with_code(&CALL_CODE)).unwrap();
    let p = f.to_str().unwrap();

    let v = json(&["functions", p, "--format", "json"]);
    let addrs: Vec<_> = v["functions"].as_array().unwrap().iter().map(|x| x["address"].as_u64().unwrap()).collect();
    assert_eq!(addrs, vec![0x40_1000, 0x40_100a]);
    assert_eq!(v["functions"][1]["callers"], 1);

    let v = json(&["xrefs", p, "--to", "0x40100a", "--format", "json"]);
    assert_eq!(v["xrefs"].as_array().unwrap().len(), 2);
    let v = json(&["xrefs", p, "--from", "0x401007", "--format", "json"]);
    assert_eq!(v["xrefs"][0]["kind"], "branch");

    let r = json(&["report", p]);
    assert_eq!(r["functions"]["count"], 2);
    assert_eq!(r["functions"]["xref_count"], 3);

    let d = json(&["disasm", p, "--format", "json"]);
    assert_eq!(d["instructions"][0]["flow"], "call");
    assert_eq!(d["instructions"][0]["target"], 0x40_100a);
}

#[test]
fn bad_address_is_invalid_argument_and_arm_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.elf");
    std::fs::write(&f, elf64_with_code(&CALL_CODE)).unwrap();
    assert_eq!(run(&["xrefs", f.to_str().unwrap(), "--to", "zzz"]).status.code(), Some(2));

    let mut arm = elf64_with_code(&CALL_CODE);
    arm[18..20].copy_from_slice(&40u16.to_le_bytes());
    let g = dir.path().join("arm.elf");
    std::fs::write(&g, arm).unwrap();
    assert_eq!(run(&["functions", g.to_str().unwrap()]).status.code(), Some(13));
}
