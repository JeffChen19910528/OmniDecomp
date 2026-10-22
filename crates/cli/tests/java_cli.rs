use omnidecomp_testsamples::java_class;
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_omnidecomp")).args(args).output().unwrap()
}

#[test]
fn java_command_and_jar_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("Hello.class");
    std::fs::write(&f, java_class()).unwrap();
    let p = f.to_str().unwrap();

    let text = String::from_utf8(run(&["java", p]).stdout).unwrap();
    assert!(text.contains("class Hello [public]"), "{text}");
    assert!(text.contains("method main([Ljava/lang/String;)V [public static]"), "{text}");

    let v: serde_json::Value = serde_json::from_slice(&run(&["java", p, "--format", "json"]).stdout).unwrap();
    assert_eq!(v["class"]["java_version"], "Java 8");

    let jar = dir.path().join("a.jar");
    std::fs::write(&jar, b"PK\x03\x04 rest").unwrap();
    assert_eq!(run(&["java", jar.to_str().unwrap()]).status.code(), Some(12));

    // `info` on a class file names the right command instead of guessing.
    let o = run(&["info", p]);
    assert_eq!(o.status.code(), Some(12));
    assert!(String::from_utf8_lossy(&o.stderr).contains("`java` command"));
}
