use omnidecomp_testsamples::{elf64_with_symbols, pe64_with_symbols};
use std::process::Command;

fn json(args: &[&str]) -> serde_json::Value {
    let o = Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

#[test]
fn symbols_command_pe_and_elf() {
    let dir = tempfile::tempdir().unwrap();
    let pe = dir.path().join("s.dll");
    std::fs::write(&pe, pe64_with_symbols()).unwrap();
    let v = json(&["symbols", pe.to_str().unwrap(), "--format", "json"]);
    let names: Vec<_> = v["symbols"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["my_export", "KERNEL32.dll!ExitProcess", "KERNEL32.dll!#5"]);

    let elf = dir.path().join("s.elf");
    std::fs::write(&elf, elf64_with_symbols()).unwrap();
    let v = json(&["symbols", elf.to_str().unwrap(), "--format", "json"]);
    assert_eq!(v["symbols"][0]["name"], "main");
    assert_eq!(v["symbols"][0]["address"], 0x40_1000);

    let r = json(&["report", elf.to_str().unwrap()]);
    assert_eq!(r["symbols"]["count"], 2);
}
