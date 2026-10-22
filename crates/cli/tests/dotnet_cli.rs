use omnidecomp_testsamples::{minimal_pe64, pe64_dotnet};
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

#[test]
fn dotnet_command_and_report() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("a.dll");
    std::fs::write(&f, pe64_dotnet()).unwrap();
    let p = f.to_str().unwrap();

    let text = String::from_utf8(run(&["dotnet", p]).stdout).unwrap();
    assert!(text.contains("assembly Sample 1.2.3.4"), "{text}");
    assert!(text.contains("type Demo.Program") && text.contains("  method Main"), "{text}");

    let v: serde_json::Value = serde_json::from_slice(&run(&["dotnet", p, "--format", "json"]).stdout).unwrap();
    assert_eq!(v["references"][0]["name"], "mscorlib");

    let r: serde_json::Value = serde_json::from_slice(&run(&["report", p]).stdout).unwrap();
    assert_eq!(r["dotnet"]["assembly"]["name"], "Sample");
    assert!(r["dotnet"]["decompilation"].as_str().unwrap().contains("not available"));

    let g = dir.path().join("native.exe");
    std::fs::write(&g, minimal_pe64()).unwrap();
    assert_eq!(run(&["dotnet", g.to_str().unwrap()]).status.code(), Some(12));
}
