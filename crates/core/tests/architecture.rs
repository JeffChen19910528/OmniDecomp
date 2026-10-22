//! Guards the layering so coupling cannot creep back in unnoticed. It reads the workspace manifests and
//! sources, so a violation fails `cargo test` with the offending crate or file named.
//!
//! Allowed direction (non-dev dependencies only):
//!   core <- formats, engines, plugins <- app <- viewmodel <- gui ;  app, plugins <- cli
//! Front ends (cli, gui) never reach formats or engines directly; the GUI never reaches app or plugins directly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// crate name (without the `omnidecomp-` prefix) -> its non-dev workspace dependencies.
fn dependencies() -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(workspace().join("crates")).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let manifest = std::fs::read_to_string(entry.path().join("Cargo.toml")).unwrap();
        let mut deps = BTreeSet::new();
        let mut section = String::new();
        for line in manifest.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.to_string();
            } else if section.ends_with("dependencies]") && !section.contains("dev-") && !section.contains("build-") {
                if let Some(dep) = t.strip_prefix("omnidecomp-").and_then(|r| r.split(['.', ' ', '=']).next()) {
                    deps.insert(dep.to_string());
                }
            }
        }
        out.insert(name, deps);
    }
    out
}

#[test]
fn crate_dependencies_follow_the_layering() {
    let allowed: BTreeMap<&str, &[&str]> = BTreeMap::from([
        ("core", &[][..]),
        ("formats", &["core"][..]),
        ("engines", &["core"][..]),
        ("plugins", &["core"][..]),
        ("app", &["core", "formats", "engines", "plugins"][..]),
        ("viewmodel", &["core", "app", "plugins"][..]),
        ("cli", &["core", "app", "plugins"][..]),
        ("gui", &["core", "viewmodel"][..]),
        ("testsamples", &[][..]),
    ]);
    let actual = dependencies();
    assert_eq!(actual.keys().map(String::as_str).collect::<BTreeSet<_>>(), allowed.keys().copied().collect(), "a crate was added or removed: update this table and docs/ARCHITECTURE.md");
    // The manifest reader itself must work, otherwise the checks below would pass on empty sets.
    assert!(actual["cli"].contains("app") && actual["gui"].contains("viewmodel") && actual["app"].contains("formats"), "{actual:?}");
    for (krate, deps) in &actual {
        let ok: BTreeSet<&str> = allowed[krate.as_str()].iter().copied().collect();
        for d in deps {
            assert!(ok.contains(d.as_str()), "crate `{krate}` must not depend on `{d}` (allowed: {ok:?})");
        }
    }
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_production_source_file_grows_past_the_size_limit() {
    const LIMIT: usize = 700;
    let mut files = Vec::new();
    rust_sources(&workspace().join("crates"), &mut files);
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().into_owned();
        // Test files, the translation table and sample builders are data-like; the rule is about logic.
        if name == "tests.rs" || name == "i18n.rs" || f.components().any(|c| c.as_os_str() == "tests" || c.as_os_str() == "testsamples") {
            continue;
        }
        let lines = std::fs::read_to_string(&f).unwrap().lines().count();
        assert!(lines <= LIMIT, "{} has {lines} lines (limit {LIMIT}); split it by responsibility", f.display());
    }
}

#[test]
fn only_the_plugins_crate_starts_processes() {
    let mut files = Vec::new();
    rust_sources(&workspace().join("crates"), &mut files);
    for f in files {
        let rel = f.strip_prefix(workspace()).unwrap_or(&f).to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(&f).unwrap();
        // The test helper that builds the stand-in engine and the plugin runner are the only exceptions.
        let exempt = rel.starts_with("crates/plugins/src/run.rs") || rel.starts_with("crates/testsamples/") || rel.contains("/tests/") || rel.ends_with("/tests.rs") || rel.ends_with("core/tests/architecture.rs");
        if !exempt {
            assert!(!text.contains("Command::new"), "{rel} starts a process; only plugins/src/run.rs may (see docs/PLUGIN_API.md)");
        }
    }
}
