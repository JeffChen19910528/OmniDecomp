use omnidecomp_testsamples::elf64_with_code;
use std::process::Command;

fn json(args: &[&str]) -> serde_json::Value {
    let o = Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap()
}

/// `bl +8; ret; mov x0,x1; ret` as an AArch64 ELF (EM_AARCH64 = 183) loaded at 0x401000.
fn aarch64_elf() -> Vec<u8> {
    let code: Vec<u8> = [0x9400_0002u32, 0xd65f_03c0, 0xaa01_03e0, 0xd65f_03c0].iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut elf = elf64_with_code(&code);
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    elf
}

#[test]
fn aarch64_disasm_functions_and_arm32_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a64.elf");
    std::fs::write(&f, aarch64_elf()).unwrap();
    let p = f.to_str().unwrap();

    let d = json(&["disasm", p, "--format", "json"]);
    assert_eq!(d["engine"], "yaxpeax-arm");
    assert_eq!(d["instructions"][0]["mnemonic"], "bl");
    assert_eq!(d["instructions"][0]["target"], 0x40_1008);
    assert_eq!(d["instructions"][2]["operands"], "x0, x1");

    let fns = json(&["functions", p, "--format", "json"]);
    let addrs: Vec<_> = fns["functions"].as_array().unwrap().iter().map(|x| x["address"].as_u64().unwrap()).collect();
    assert_eq!(addrs, vec![0x40_1000, 0x40_1008]);

    assert_eq!(json(&["report", p])["disassembly"]["engine"], "yaxpeax-arm");

    let bad = Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(["disasm", p, "--engine", "iced-x86"]).output().unwrap();
    assert_eq!(bad.status.code(), Some(13));

    let mut arm32 = aarch64_elf();
    arm32[18..20].copy_from_slice(&40u16.to_le_bytes());
    let g = dir.path().join("arm32.elf");
    std::fs::write(&g, arm32).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(["disasm", g.to_str().unwrap()]).output().unwrap();
    assert_eq!(o.status.code(), Some(13));
}
