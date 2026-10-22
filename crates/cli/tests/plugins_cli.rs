use omnidecomp_testsamples::{fake_engine_path, java_class, minimal_pe64, pe64_dotnet};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    dir: tempfile::TempDir,
    plugins: PathBuf,
    state: PathBuf,
}

fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let plugins = dir.path().join("plugins");
    let p = plugins.join("fake");
    std::fs::create_dir_all(p.join("bin")).unwrap();
    let exe = format!("bin/fake-engine{}", std::env::consts::EXE_SUFFIX);
    std::fs::copy(fake_engine_path(), p.join(&exe)).unwrap();
    std::fs::write(
        p.join("plugin.json"),
        format!(
            r#"{{"id":"fake","name":"Fake engine","version":"0.3.0","api_version":1,"license":"MIT","source":"tests",
            "kind":"decompiler","runtimes":["dotnet","java"],"command":"{exe}","args":["ok","{{input}}"]}}"#
        ),
    )
    .unwrap();
    let state = dir.path().join("cfg").join("plugins.json");
    Env { dir, plugins, state }
}

impl Env {
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omnidecomp"))
            .args(["--plugins-dir", self.plugins.to_str().unwrap(), "--state-file", self.state.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap()
    }
    fn file(&self, name: &str, bytes: Vec<u8>) -> String {
        let p = self.dir.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p.to_str().unwrap().to_string()
    }
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn plugins_list_enable_disable_round_trip() {
    let e = setup();
    let v: serde_json::Value = serde_json::from_slice(&e.run(&["plugins", "list", "--format", "json"]).stdout).unwrap();
    let rows = v.as_array().unwrap();
    assert_eq!(rows.iter().filter(|r| r["origin"] == "builtin").count(), 7);
    let fake = rows.iter().find(|r| r["id"] == "fake").unwrap();
    assert_eq!((fake["status"].as_str(), fake["license"].as_str(), fake["version"].as_str()), (Some("disabled"), Some("MIT"), Some("0.3.0")));

    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    let text = out(&e.run(&["plugins", "list"]));
    assert!(text.contains("fake 0.3.0 [external/decompiler] enabled - license: MIT"), "{text}");
    assert!(text.contains("source: tests"));

    assert!(e.run(&["plugins", "disable", "fake"]).status.success());
    assert!(out(&e.run(&["plugins", "list"])).contains("fake 0.3.0 [external/decompiler] disabled"));

    let missing = e.run(&["plugins", "enable", "nope"]);
    assert_eq!(missing.status.code(), Some(19), "{}", err(&missing));
    assert!(err(&missing).starts_with("error[unknown_plugin]"));
}

#[test]
fn decompile_needs_enable_and_explicit_consent() {
    let e = setup();
    let dll = e.file("a.dll", pe64_dotnet());

    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec"]);
    assert_eq!(r.status.code(), Some(20), "not enabled yet: {}", err(&r));

    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    let r = e.run(&["decompile", &dll, "--engine", "fake"]);
    assert_eq!(r.status.code(), Some(2), "{}", err(&r));
    assert!(err(&r).contains("--allow-external-exec"), "{}", err(&r));
    assert!(out(&r).is_empty(), "nothing ran and nothing was printed");

    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec"]);
    assert!(r.status.success(), "{}", err(&r));
    let text = out(&r);
    assert!(text.contains("engine fake 0.3.0 (dotnet)") && text.contains("// decompiled by fake-engine"), "{text}");
    assert!(!text.contains('\u{1b}'));

    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&r.stdout).unwrap();
    assert_eq!((v["runtime"].as_str(), v["engine"].as_str()), (Some("dotnet"), Some("fake")));
    assert!(v["notes"][0].as_str().unwrap().contains("untrusted"));

    let class = e.file("A.class", java_class());
    let r = e.run(&["decompile", &class, "--engine", "fake", "--allow-external-exec"]);
    assert!(out(&r).contains("(java)"), "{} {}", out(&r), err(&r));
}

#[test]
fn decompile_refuses_native_unknown_engine_and_bad_input() {
    let e = setup();
    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    let exe = e.file("n.exe", minimal_pe64());
    let r = e.run(&["decompile", &exe, "--engine", "fake", "--allow-external-exec"]);
    assert_eq!(r.status.code(), Some(12), "native code has no decompiler: {}", err(&r));

    let dll = e.file("a.dll", pe64_dotnet());
    assert_eq!(e.run(&["decompile", &dll, "--engine", "ghost", "--allow-external-exec"]).status.code(), Some(15));
    assert_eq!(e.run(&["decompile", &e.file("junk", b"junk".to_vec()), "--engine", "fake", "--allow-external-exec"]).status.code(), Some(12));
    assert_eq!(e.run(&["decompile", "no/such/file.dll", "--engine", "fake", "--allow-external-exec"]).status.code(), Some(3));
    // A built-in id is not a decompiler.
    assert_eq!(e.run(&["decompile", &dll, "--engine", "runtime-dotnet", "--allow-external-exec"]).status.code(), Some(15));
}

#[test]
fn decompile_output_file_is_validated() {
    let e = setup();
    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    let dll = e.file("a.dll", pe64_dotnet());
    let ok = e.dir.path().join("out.java");
    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec", "--output", ok.to_str().unwrap()]);
    assert!(r.status.success(), "{}", err(&r));
    assert!(std::fs::read_to_string(&ok).unwrap().contains("decompiled by fake-engine"));
    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec", "--output", "../escape.txt"]);
    assert_eq!(r.status.code(), Some(16), "{}", err(&r));
    // Overwriting the input is refused too.
    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec", "--output", &dll]);
    assert_eq!(r.status.code(), Some(16), "{}", err(&r));
}

#[test]
fn disabled_builtin_plugins_block_their_format_and_runtime() {
    let e = setup();
    let exe = e.file("n.exe", minimal_pe64());
    assert!(e.run(&["info", &exe]).status.success());
    assert!(e.run(&["plugins", "disable", "format-pe"]).status.success());
    let r = e.run(&["info", &exe]);
    assert_eq!(r.status.code(), Some(20), "{}", err(&r));
    assert!(err(&r).contains("format-pe"));
    assert!(e.run(&["plugins", "enable", "format-pe"]).status.success());
    assert!(e.run(&["info", &exe]).status.success());

    let class = e.file("A.class", java_class());
    assert!(e.run(&["java", &class]).status.success());
    assert!(e.run(&["plugins", "disable", "runtime-java"]).status.success());
    assert_eq!(e.run(&["java", &class]).status.code(), Some(20));

    let dll = e.file("a.dll", pe64_dotnet());
    assert!(e.run(&["plugins", "disable", "runtime-dotnet"]).status.success());
    assert_eq!(e.run(&["dotnet", &dll]).status.code(), Some(20));
    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    assert_eq!(e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec"]).status.code(), Some(20), "runtime plugin gates decompile too");
}

#[test]
fn tampering_after_enable_is_caught_before_anything_runs() {
    let e = setup();
    assert!(e.run(&["plugins", "enable", "fake"]).status.success());
    let exe = e.plugins.join("fake").join(format!("bin/fake-engine{}", std::env::consts::EXE_SUFFIX));
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes.push(0);
    std::fs::write(&exe, bytes).unwrap();
    let dll = e.file("a.dll", pe64_dotnet());
    let r = e.run(&["decompile", &dll, "--engine", "fake", "--allow-external-exec"]);
    assert_eq!(r.status.code(), Some(21), "{}", err(&r));
    assert!(out(&r).is_empty());
}

#[test]
fn a_corrupt_state_file_stops_commands_with_a_clear_message() {
    let e = setup();
    std::fs::create_dir_all(e.state.parent().unwrap()).unwrap();
    std::fs::write(&e.state, "{{{").unwrap();
    let r = e.run(&["plugins", "list"]);
    assert_eq!(r.status.code(), Some(11));
    assert!(err(&r).contains("delete it"), "{}", err(&r));
}
