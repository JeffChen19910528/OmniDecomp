//! Registered engines plus detection (never execution) of optional external decompilers.

use omnidecomp_core::EngineCapability;
use std::path::{Path, PathBuf};

/// True when `name` (or `name.exe`) is a regular file in one of the `path_var` directories.
/// Detection only looks at the file system; nothing is executed.
fn on_path(name: &str, path_var: &std::ffi::OsStr) -> bool {
    std::env::split_paths(path_var).any(|d| d.join(name).is_file() || d.join(format!("{name}.exe")).is_file())
}

/// Optional external decompilers. They are only detected here; no `decompile` command drives them yet,
/// so even an installed engine is reported with the "detection only" limitation.
fn external_engines(path_var: &std::ffi::OsStr, cfr_jar: Option<&Path>) -> Vec<EngineCapability> {
    let missing = |ok: bool| if ok { "available" } else { "not_installed" }.to_string();
    let ilspy = on_path("ilspycmd", path_var);
    let cfr = on_path("java", path_var) && cfr_jar.is_some_and(|p| p.is_file());
    vec![
        EngineCapability {
            id: "ilspycmd".into(),
            name: "ILSpy command line (.NET to C#)".into(),
            version: "unknown (not queried)".into(),
            kind: "decompiler".into(),
            formats: vec!["pe (.NET assembly)".into()],
            architectures: vec!["cil".into()],
            limitations: vec!["detection only: no `decompile` command drives it yet".into()],
            status: missing(ilspy),
            install_hint: (!ilspy).then(|| "install the .NET SDK, run `dotnet tool install -g ilspycmd`, and make sure ilspycmd is on PATH".into()),
        },
        EngineCapability {
            id: "cfr".into(),
            name: "CFR (Java bytecode to Java)".into(),
            version: "unknown (not queried)".into(),
            kind: "decompiler".into(),
            formats: vec!["java class".into()],
            architectures: vec!["jvm".into()],
            limitations: vec!["detection only: no `decompile` command drives it yet".into()],
            status: missing(cfr),
            install_hint: (!cfr).then(|| "install a JRE (java on PATH) and set OMNIDECOMP_CFR_JAR to the path of cfr.jar".into()),
        },
    ]
}

pub fn engines() -> Vec<EngineCapability> {
    let mut list: Vec<EngineCapability> = omnidecomp_engines::all().iter().map(|e| e.capability()).collect();
    let path = std::env::var_os("PATH").unwrap_or_default();
    let jar = std::env::var_os("OMNIDECOMP_CFR_JAR").map(PathBuf::from);
    list.extend(external_engines(&path, jar.as_deref()));
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_engines_are_detected_without_running_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        let none = external_engines(&path, None);
        assert!(none.iter().all(|e| e.status == "not_installed" && e.install_hint.is_some()));
        std::fs::write(dir.path().join("ilspycmd.exe"), b"not a real program").unwrap();
        std::fs::write(dir.path().join("java"), b"x").unwrap();
        let jar = dir.path().join("cfr.jar");
        std::fs::write(&jar, b"x").unwrap();
        let found = external_engines(&path, Some(&jar));
        assert!(found.iter().all(|e| e.status == "available" && e.install_hint.is_none()));
        // A jar without java on PATH is not enough.
        let empty = tempfile::tempdir().unwrap();
        let only_jar = external_engines(&std::env::join_paths([empty.path()]).unwrap(), Some(&jar));
        assert_eq!(only_jar[1].status, "not_installed");
    }
}
