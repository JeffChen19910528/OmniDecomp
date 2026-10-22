use omnidecomp_testsamples::{minimal_pe64, pe64_with_pdb};
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

#[test]
fn info_reports_pdb_reference() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.exe");
    std::fs::write(&f, pe64_with_pdb("app.pdb")).unwrap();
    let p = f.to_str().unwrap();

    let o = run(&["info", p, "--format", "json"]);
    assert_eq!(o.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["debug"]["pdb_path"], "app.pdb");
    assert_eq!(v["debug"]["guid"], "00112233-4455-6677-8899-aabbccddeeff");
    assert_eq!(v["debug"]["age"], 3);

    let text = String::from_utf8(run(&["info", p]).stdout).unwrap();
    assert!(text.contains("PDB:         app.pdb (guid 00112233-4455-6677-8899-aabbccddeeff, age 3)"), "{text}");

    let g = dir.path().join("b.exe");
    std::fs::write(&g, minimal_pe64()).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&run(&["info", g.to_str().unwrap(), "--format", "json"]).stdout).unwrap();
    assert!(v["debug"].is_null());
}
