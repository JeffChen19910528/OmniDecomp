use omnidecomp_core::{Arch, Context, ErrorCode, Format, Limits};
use omnidecomp_plugins::*;
use omnidecomp_testsamples::fake_engine_path;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn manifest_json(id: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"Fake","version":"1.2.3","api_version":1,"license":"MIT","kind":"decompiler",
        "runtimes":["dotnet","java"],"command":"engine/fake-engine{}","args":["ok","{{input}}"]}}"#,
        std::env::consts::EXE_SUFFIX
    )
}

struct Env {
    _dir: tempfile::TempDir,
    plugins: PathBuf,
    state: PathBuf,
}

/// A plugins directory with one valid plugin "fake" whose engine is a copy of the test program.
fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let plugins = dir.path().join("plugins");
    let p = plugins.join("fake");
    std::fs::create_dir_all(p.join("engine")).unwrap();
    std::fs::write(p.join("plugin.json"), manifest_json("fake")).unwrap();
    std::fs::copy(fake_engine_path(), p.join(format!("engine/fake-engine{}", std::env::consts::EXE_SUFFIX))).unwrap();
    let state = dir.path().join("state").join("plugins.json");
    Env { _dir: dir, plugins, state }
}

fn load(e: &Env) -> Registry {
    Registry::load(&e.plugins, &e.state).unwrap()
}

fn status_of(r: &Registry, id: &str) -> (&'static str, Option<String>) {
    let rec = r.list().into_iter().find(|p| p.id == id).unwrap();
    (rec.status, rec.reason)
}

// ---- manifest validation ----

fn m(patch: impl Fn(&mut serde_json::Value)) -> Result<Manifest, omnidecomp_core::Error> {
    let mut v: serde_json::Value = serde_json::from_str(&manifest_json("fake")).unwrap();
    patch(&mut v);
    let man = parse_manifest(v.to_string().as_bytes())?;
    validate(&man, "fake", &builtin_ids())?;
    Ok(man)
}

#[test]
fn a_good_manifest_validates() {
    let man = m(|_| {}).unwrap();
    assert_eq!((man.id.as_str(), man.version.as_str()), ("fake", "1.2.3"));
    check_compat(&man, HOST_VERSION).unwrap();
}

type Patch = Box<dyn Fn(&mut serde_json::Value)>;

#[test]
fn bad_manifests_are_rejected_with_a_reason() {
    let cases: Vec<(&str, Patch)> = vec![
        ("id uppercase", Box::new(|v| v["id"] = "Fake".into())),
        ("id other dir", Box::new(|v| v["id"] = "other".into())),
        ("reserved id", Box::new(|v| v["id"] = "format-pe".into())),
        ("version", Box::new(|v| v["version"] = "1.2".into())),
        ("version suffix", Box::new(|v| v["version"] = "1.2.3-beta".into())),
        ("missing license", Box::new(|v| v["license"] = "  ".into())),
        ("kind", Box::new(|v| v["kind"] = "format".into())),
        ("runtimes empty", Box::new(|v| v["runtimes"] = serde_json::json!([]))),
        ("runtime unknown", Box::new(|v| v["runtimes"] = serde_json::json!(["wasm"]))),
        ("command absolute", Box::new(|v| v["command"] = "/bin/sh".into())),
        ("command dotdot", Box::new(|v| v["command"] = "../x".into())),
        ("command backslash", Box::new(|v| v["command"] = "a\\b".into())),
        ("command drive", Box::new(|v| v["command"] = "C:/x.exe".into())),
        ("command option-like", Box::new(|v| v["command"] = "-rf".into())),
        ("command shell", Box::new(|v| v["command"] = "sh -c x".into())),
        ("no input placeholder", Box::new(|v| v["args"] = serde_json::json!(["x"]))),
        ("other placeholder", Box::new(|v| v["args"] = serde_json::json!(["{input}", "{home}"]))),
        ("too many args", Box::new(|v| v["args"] = serde_json::json!(vec!["{input}"; 17]))),
        ("control char arg", Box::new(|v| v["args"] = serde_json::json!(["{input}", "a\nb"]))),
        ("unknown field", Box::new(|v| v["run_as_admin"] = true.into())),
        ("missing field", Box::new(|v| {
            v.as_object_mut().unwrap().remove("command");
        })),
    ];
    for (name, patch) in cases {
        let e = m(patch).expect_err(name);
        assert_eq!(e.code, ErrorCode::Malformed, "{name}: {}", e.message);
    }
    assert!(parse_manifest(b"not json").is_err());
    assert_eq!(parse_manifest(&vec![b' '; 70_000]).unwrap_err().code, ErrorCode::LimitExceeded);
}

#[test]
fn compatibility_checks_api_and_host_versions() {
    let old_api = m(|v| v["api_version"] = 2.into()).unwrap();
    assert_eq!(check_compat(&old_api, HOST_VERSION).unwrap_err().code, ErrorCode::PluginIncompatible);
    let too_new = m(|v| v["min_host_version"] = "99.0.0".into()).unwrap();
    assert_eq!(check_compat(&too_new, "0.1.0").unwrap_err().code, ErrorCode::PluginIncompatible);
    assert!(check_compat(&too_new, "99.0.1").is_ok());
    let exact = m(|v| v["min_host_version"] = "0.1.0".into()).unwrap();
    assert!(check_compat(&exact, "0.1.0").is_ok());
    assert_eq!(parse_version("1.10.3"), Some((1, 10, 3)));
    assert!(parse_version("1.2").is_none() && parse_version("1.2.3.4").is_none() && parse_version("a.b.c").is_none() && parse_version("1..3").is_none());
}

// ---- registry ----

#[test]
fn builtins_are_listed_and_can_be_disabled_and_enabled() {
    let e = env();
    let mut r = load(&e);
    let rows = r.list();
    assert!(rows.iter().filter(|p| p.origin == "builtin").count() == BUILTINS.len());
    assert!(rows.iter().filter(|p| p.origin == "builtin").all(|p| p.status == "enabled" && !p.license.is_empty()));
    r.check_analysis(Format::Pe, Arch::X86_64).unwrap();

    r.disable("arch-arm64").unwrap();
    assert_eq!(r.check_analysis(Format::Elf, Arch::Aarch64).unwrap_err().code, ErrorCode::PluginDisabled);
    r.check_analysis(Format::Elf, Arch::X86_64).unwrap();
    // The choice survives a restart.
    let mut r2 = load(&e);
    assert_eq!(status_of(&r2, "arch-arm64").0, "disabled");
    r2.disable("format-pe").unwrap();
    assert_eq!(r2.check_analysis(Format::Pe, Arch::X86).unwrap_err().code, ErrorCode::PluginDisabled);
    r2.enable("format-pe", None).unwrap();
    r2.check_analysis(Format::Pe, Arch::X86).unwrap();
    assert_eq!(r2.enable("nope", None).unwrap_err().code, ErrorCode::UnknownPlugin);
    assert_eq!(r2.disable("nope").unwrap_err().code, ErrorCode::UnknownPlugin);
}

#[test]
fn external_plugins_start_disabled_and_need_an_explicit_enable() {
    let e = env();
    let mut r = load(&e);
    assert_eq!(status_of(&r, "fake").0, "disabled");
    assert_eq!(r.resolve_for_run("fake", "dotnet", None).unwrap_err().code, ErrorCode::PluginDisabled);
    assert_eq!(r.resolve_for_run("missing", "dotnet", None).unwrap_err().code, ErrorCode::UnknownEngine);
    r.enable("fake", None).unwrap();
    assert_eq!(status_of(&r, "fake").0, "enabled");
    let res = r.resolve_for_run("fake", "java", None).unwrap();
    assert_eq!(res.version, "1.2.3");
    assert_eq!(r.resolve_for_run("fake", "wasm", None).unwrap_err().code, ErrorCode::UnsupportedFormat);
    r.disable("fake").unwrap();
    assert_eq!(r.resolve_for_run("fake", "java", None).unwrap_err().code, ErrorCode::PluginDisabled);
}

#[test]
fn a_plugin_directory_cannot_enable_itself() {
    // A state file shipped inside the plugins directory is ignored: only the per-user state file counts.
    let e = env();
    let mut r = load(&e);
    r.enable("fake", None).unwrap();
    let stolen = std::fs::read(&e.state).unwrap();
    std::fs::write(e.plugins.join("fake").join("plugins.json"), stolen).unwrap();
    let fresh_state = e.state.with_file_name("other.json");
    let r2 = Registry::load(&e.plugins, &fresh_state).unwrap();
    assert_eq!(status_of(&r2, "fake").0, "disabled");
}

#[test]
fn changing_the_manifest_or_the_program_after_enable_blocks_a_run() {
    let e = env();
    let mut r = load(&e);
    r.enable("fake", None).unwrap();
    let exe = e.plugins.join("fake").join(format!("engine/fake-engine{}", std::env::consts::EXE_SUFFIX));
    let original = std::fs::read(&exe).unwrap();
    let mut tampered = original.clone();
    tampered.push(0);
    std::fs::write(&exe, tampered).unwrap();
    let err = load(&e).resolve_for_run("fake", "java", None).unwrap_err();
    assert_eq!(err.code, ErrorCode::PluginIncompatible, "{}", err.message);
    std::fs::write(&exe, original).unwrap();
    load(&e).resolve_for_run("fake", "java", None).unwrap();

    std::fs::write(e.plugins.join("fake/plugin.json"), manifest_json("fake").replace("\"MIT\"", "\"GPL-3.0\"")).unwrap();
    let r3 = load(&e);
    let (status, reason) = status_of(&r3, "fake");
    assert_eq!(status, "disabled");
    assert!(reason.unwrap().contains("changed"));
    assert_eq!(r3.resolve_for_run("fake", "java", None).unwrap_err().code, ErrorCode::PluginDisabled);
}

#[test]
fn invalid_and_incompatible_plugins_are_reported_not_fatal() {
    let e = env();
    let bad = e.plugins.join("broken");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::write(bad.join("plugin.json"), "{ nope").unwrap();
    std::fs::create_dir_all(e.plugins.join("empty")).unwrap();
    std::fs::write(e.plugins.join("not-a-dir.txt"), "x").unwrap();
    let newer = e.plugins.join("newer");
    std::fs::create_dir_all(newer.join("engine")).unwrap();
    std::fs::write(newer.join("plugin.json"), manifest_json("newer").replace("\"api_version\":1", "\"api_version\":7")).unwrap();
    let mut r = load(&e);
    assert_eq!(status_of(&r, "broken").0, "invalid");
    assert_eq!(status_of(&r, "empty").0, "invalid");
    assert_eq!(status_of(&r, "newer").0, "incompatible");
    assert_eq!(status_of(&r, "fake").0, "disabled", "the good plugin is unaffected");
    assert_eq!(r.enable("broken", None).unwrap_err().code, ErrorCode::Malformed);
    assert_eq!(r.enable("newer", None).unwrap_err().code, ErrorCode::PluginIncompatible);
}

#[test]
fn enabling_fails_when_the_engine_program_cannot_be_found() {
    let e = env();
    std::fs::remove_file(e.plugins.join("fake").join(format!("engine/fake-engine{}", std::env::consts::EXE_SUFFIX))).unwrap();
    let mut r = load(&e);
    assert_eq!(r.enable("fake", None).unwrap_err().code, ErrorCode::ExternalEngineFailed);
    // A bare name is looked up on PATH only; an empty or missing PATH finds nothing.
    let d = e.plugins.join("pathy");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("plugin.json"), manifest_json("pathy").replace(&format!("engine/fake-engine{}", std::env::consts::EXE_SUFFIX), "no-such-program-xyz")).unwrap();
    let mut r = load(&e);
    assert_eq!(r.enable("pathy", Some(std::ffi::OsStr::new(""))).unwrap_err().code, ErrorCode::ExternalEngineFailed);
}

#[test]
fn corrupt_or_huge_state_files_are_errors_not_silently_ignored() {
    let e = env();
    std::fs::create_dir_all(e.state.parent().unwrap()).unwrap();
    std::fs::write(&e.state, "garbage").unwrap();
    assert_eq!(Registry::load(&e.plugins, &e.state).err().unwrap().code, ErrorCode::Malformed);
    std::fs::write(&e.state, vec![b' '; 2 * 1024 * 1024]).unwrap();
    assert_eq!(Registry::load(&e.plugins, &e.state).err().unwrap().code, ErrorCode::LimitExceeded);
    // A missing plugins directory is fine: only built-ins are listed.
    let r = Registry::load(Path::new("definitely/not/here"), Path::new("also/not/here.json")).unwrap();
    assert_eq!(r.list().len(), BUILTINS.len());
}

#[test]
fn mutated_manifests_never_panic() {
    let good = manifest_json("fake").into_bytes();
    for cut in 0..good.len() {
        let _ = parse_manifest(&good[..cut]).and_then(|m| validate(&m, "fake", &[]));
    }
    for i in 0..good.len() {
        for flip in [0x00u8, 0xFF, b'"', b'{'] {
            let mut b = good.clone();
            b[i] = flip;
            let _ = parse_manifest(&b).and_then(|m| validate(&m, "fake", &[]));
        }
    }
}

// ---- running ----

fn resolved(e: &Env, mode: &str) -> Resolved {
    let mut r = load(e);
    r.enable("fake", None).unwrap();
    let mut res = r.resolve_for_run("fake", "dotnet", None).unwrap();
    res.args = vec![mode.to_string(), "{input}".to_string()];
    res
}

fn input(e: &Env) -> PathBuf {
    let p = e.plugins.join("input with space.dll");
    std::fs::write(&p, vec![0u8; 123]).unwrap();
    p
}

#[test]
fn a_successful_run_returns_sanitized_text() {
    let e = env();
    let ctx = Context::new(Limits::default());
    let out = run_decompiler(&resolved(&e, "ok"), &input(&e), 1 << 20, &ctx).unwrap();
    assert!(out.text.contains("input bytes: 123"), "{}", out.text);
    assert!(!out.text.contains('\u{1b}'), "terminal escapes are neutralised: {:?}", out.text);
    assert!(out.text.contains("?[31mescape"));
}

#[test]
fn the_path_is_one_argument_and_the_environment_is_cleared() {
    let e = env();
    std::env::set_var("SECRET_TOKEN", "hunter2");
    let ctx = Context::new(Limits::default());
    let env_out = run_decompiler(&resolved(&e, "env"), &input(&e), 1 << 20, &ctx).unwrap();
    assert!(env_out.text.contains("token=None"), "secrets must not reach the engine: {}", env_out.text);
    let args = run_decompiler(&resolved(&e, "args"), &input(&e), 1 << 20, &ctx).unwrap();
    assert!(args.text.contains("input with space.dll\"]"), "one argv entry, no shell splitting: {}", args.text);
}

#[test]
fn engine_failure_timeout_cancel_and_flood_are_all_contained() {
    let e = env();
    let ctx = Context::new(Limits::default());
    let err = run_decompiler(&resolved(&e, "fail"), &input(&e), 1 << 20, &ctx).unwrap_err();
    assert_eq!(err.code, ErrorCode::ExternalEngineFailed);
    assert!(err.message.contains("boom"), "{}", err.message);

    let t = Instant::now();
    let quick = Context::new(Limits { timeout: Duration::from_millis(300), ..Limits::default() });
    let err = run_decompiler(&resolved(&e, "sleep"), &input(&e), 1 << 20, &quick).unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout);
    assert!(t.elapsed() < Duration::from_secs(10), "child was killed, not waited for");

    let ctx = Context::new(Limits::default());
    let flag = ctx.cancel_handle();
    let h = std::thread::spawn({
        let flag = flag.clone();
        move || {
            std::thread::sleep(Duration::from_millis(200));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });
    let err = run_decompiler(&resolved(&e, "sleep"), &input(&e), 1 << 20, &ctx).unwrap_err();
    h.join().unwrap();
    assert_eq!(err.code, ErrorCode::Cancelled);

    let ctx = Context::new(Limits::default());
    let err = run_decompiler(&resolved(&e, "flood"), &input(&e), 1 << 20, &ctx).unwrap_err();
    assert_eq!(err.code, ErrorCode::LimitExceeded);

    let mut missing = resolved(&e, "ok");
    missing.exe = e.plugins.join("nothing-here.exe");
    assert_eq!(run_decompiler(&missing, &input(&e), 1 << 20, &ctx).unwrap_err().code, ErrorCode::ExternalEngineFailed);
}

#[test]
fn every_shipped_plugin_manifest_is_valid_licensed_and_has_a_notice() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../plugins");
    let mut seen = 0;
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let m = parse_manifest(&std::fs::read(dir.join("plugin.json")).unwrap()).unwrap_or_else(|e| panic!("{name}: {}", e.message));
        validate(&m, &name, &builtin_ids()).unwrap_or_else(|e| panic!("{name}: {}", e.message));
        check_compat(&m, HOST_VERSION).unwrap_or_else(|e| panic!("{name}: {}", e.message));
        assert!(!m.license.is_empty() && m.source.is_some(), "{name}: license and source are required for shipped plugins");
        let notice = std::fs::read_to_string(dir.join("NOTICE.md")).unwrap_or_else(|_| panic!("{name}: NOTICE.md missing"));
        assert!(notice.contains(&m.license), "{name}: NOTICE.md must state the license");
        seen += 1;
    }
    assert!(seen >= 2);
}

#[test]
fn crlf_line_endings_survive_but_lone_carriage_returns_do_not() {
    assert_eq!(sanitize_output(b"a\r\nb\tc\n"), "a\nb\tc\n");
    assert_eq!(sanitize_output(b"over\rwrite\x1b[2J\x07"), "over?write?[2J?");
    assert_eq!(sanitize_output(&[0xff, b'x']), "\u{fffd}x");
}
