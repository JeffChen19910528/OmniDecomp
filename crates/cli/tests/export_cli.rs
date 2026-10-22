use omnidecomp_testsamples::elf64_with_symbols;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

fn out(args: &[&str]) -> String {
    let o = run(args);
    assert_eq!(o.status.code(), Some(0), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn report_csv_html_text_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("s.elf");
    std::fs::write(&f, elf64_with_symbols()).unwrap();
    let p = f.to_str().unwrap();

    let csv = out(&["report", p, "--format", "csv"]);
    assert!(csv.starts_with("kind,name,address,size,detail\n"), "{csv}");
    assert!(csv.contains("symbol,main,0x401000,,function;elf_symtab"), "{csv}");
    assert!(csv.contains("function,main,0x401000,"), "{csv}");
    assert!(csv.contains("section,.text,0x401000,"), "{csv}");

    let html = out(&["report", p, "--format", "html"]);
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(!html.contains("<script"));
    assert!(html.contains("<td>main</td>"));

    let text = out(&["report", p, "--format", "text"]);
    assert!(text.contains("Format           Elf"), "{text}");
    assert!(text.contains("main"));

    let v: serde_json::Value = serde_json::from_str(&out(&["report", p])).unwrap();
    assert_eq!(v["symbols"]["status"], "ok");

    let target = dir.path().join("r.html");
    out(&["report", p, "--format", "html", "--output", target.to_str().unwrap()]);
    assert!(std::fs::read_to_string(&target).unwrap().contains("<h1>OmniDecomp report</h1>"));
}
