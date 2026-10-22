//! Plugin manifests. A plugin is a directory with a `plugin.json`; nothing in it is ever loaded into this
//! process. The only thing a plugin can do is describe an external decompiler program that the user has
//! enabled and explicitly allowed to run (see `run`).

use omnidecomp_core::{Error, ErrorCode};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Version of the manifest format this host understands.
pub const PLUGIN_API_VERSION: u32 = 1;
pub const HOST_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
/// Language runtimes a decompiler plugin may claim to handle.
pub const RUNTIMES: [&str; 2] = ["dotnet", "java"];
const MAX_ARGS: usize = 16;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: u32,
    #[serde(default)]
    pub min_host_version: Option<String>,
    /// SPDX expression or plain licence name of the plugin itself. Required.
    pub license: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Only "decompiler" exists today.
    pub kind: String,
    pub runtimes: Vec<String>,
    /// Bare program name (looked up on PATH) or a path relative to the plugin directory.
    pub command: String,
    /// Arguments passed as separate argv entries (never through a shell). `{input}` is replaced.
    pub args: Vec<String>,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::Malformed, msg)
}

/// Replaces control characters and truncates, because manifest text is shown in lists.
pub fn clean(s: &str, max: usize) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).take(max).collect()
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, Error> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::new(ErrorCode::LimitExceeded, format!("plugin.json is larger than {MAX_MANIFEST_BYTES} bytes")));
    }
    serde_json::from_slice(bytes).map_err(|e| bad(format!("plugin.json is not valid: {}", clean(&e.to_string(), 200))))
}

/// `major.minor.patch` with plain numbers; no pre-release or build suffix.
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split('.');
    let mut next = || -> Option<u32> {
        let p = it.next()?;
        (!p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit())).then(|| p.parse().ok())?
    };
    let v = (next()?, next()?, next()?);
    it.next().is_none().then_some(v)
}

pub fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRef {
    /// Looked up on PATH.
    OnPath(String),
    /// Relative path inside the plugin directory.
    InDir(PathBuf),
}

pub fn classify_command(cmd: &str) -> Result<CommandRef, Error> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/');
    if cmd.is_empty() || cmd.len() > 128 || !cmd.chars().all(ok_char) || cmd.starts_with('-') || cmd.starts_with('/') {
        return Err(bad("command must be a program name or a relative path of letters, digits and . _ - /"));
    }
    if cmd.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
        return Err(bad("command path must not contain empty, '.' or '..' components"));
    }
    Ok(if cmd.contains('/') { CommandRef::InDir(cmd.split('/').collect()) } else { CommandRef::OnPath(cmd.to_string()) })
}

/// Structural checks. `dir_name` must equal the id so a directory cannot masquerade as another plugin.
pub fn validate(m: &Manifest, dir_name: &str, reserved_ids: &[&str]) -> Result<(), Error> {
    if !valid_id(&m.id) {
        return Err(bad("id must be 1-64 characters of a-z 0-9 . _ - and start with a letter or digit"));
    }
    if m.id != dir_name {
        return Err(bad(format!("id '{}' does not match the directory name '{}'", m.id, clean(dir_name, 64))));
    }
    if reserved_ids.contains(&m.id.as_str()) {
        return Err(bad(format!("id '{}' is reserved for a built-in plugin", m.id)));
    }
    if parse_version(&m.version).is_none() {
        return Err(bad("version must look like 1.2.3"));
    }
    if m.min_host_version.as_deref().is_some_and(|v| parse_version(v).is_none()) {
        return Err(bad("min_host_version must look like 1.2.3"));
    }
    if m.name.trim().is_empty() || m.name.chars().count() > 80 {
        return Err(bad("name must be 1-80 characters"));
    }
    if m.license.trim().is_empty() || m.license.chars().count() > 64 || m.license.chars().any(char::is_control) {
        return Err(bad("license is required (an SPDX identifier or a license name, at most 64 characters)"));
    }
    if m.description.as_ref().is_some_and(|d| d.chars().count() > 400) || m.source.as_ref().is_some_and(|d| d.chars().count() > 300) {
        return Err(bad("description is limited to 400 characters and source to 300"));
    }
    if m.kind != "decompiler" {
        return Err(bad(format!("unsupported plugin kind '{}' (only 'decompiler' exists)", clean(&m.kind, 40))));
    }
    if m.runtimes.is_empty() || m.runtimes.iter().any(|r| !RUNTIMES.contains(&r.as_str())) {
        return Err(bad("runtimes must be a non-empty list of: dotnet, java"));
    }
    classify_command(&m.command)?;
    if m.args.len() > MAX_ARGS || m.args.iter().any(|a| a.len() > 256 || a.chars().any(char::is_control)) {
        return Err(bad("args: at most 16 entries of at most 256 printable characters"));
    }
    for a in &m.args {
        let stripped = a.replace("{input}", "");
        if stripped.contains('{') || stripped.contains('}') {
            return Err(bad("args may only use the {input} placeholder"));
        }
    }
    if !m.args.iter().any(|a| a.contains("{input}")) {
        return Err(bad("args must contain {input} so the engine receives the file"));
    }
    Ok(())
}

/// Host compatibility: same manifest API version and host new enough.
pub fn check_compat(m: &Manifest, host: &str) -> Result<(), Error> {
    if m.api_version != PLUGIN_API_VERSION {
        return Err(Error::new(
            ErrorCode::PluginIncompatible,
            format!("plugin API version {} is not supported (this host speaks {PLUGIN_API_VERSION})", m.api_version),
        ));
    }
    if let (Some(min), Some(h)) = (m.min_host_version.as_deref().and_then(parse_version), parse_version(host)) {
        if h < min {
            return Err(Error::new(
                ErrorCode::PluginIncompatible,
                format!("plugin needs host {}.{}.{} or newer; this is {host}", min.0, min.1, min.2),
            ));
        }
    }
    Ok(())
}

/// Finds the program. Windows batch files are refused because running them goes through `cmd.exe`,
/// which re-parses arguments.
pub fn resolve_command(m: &Manifest, plugin_dir: &Path, path_var: Option<&std::ffi::OsStr>) -> Result<PathBuf, Error> {
    let not_found = || Error::new(ErrorCode::ExternalEngineFailed, format!("engine program '{}' was not found", clean(&m.command, 128)));
    let is_file = |p: &Path| std::fs::symlink_metadata(p).map(|md| md.is_file()).unwrap_or(false);
    let exe_ok = |p: &Path| {
        if cfg!(windows) {
            p.extension().and_then(|e| e.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("exe") || e.eq_ignore_ascii_case("com"))
        } else {
            true
        }
    };
    match classify_command(&m.command)? {
        CommandRef::InDir(rel) => {
            let p = plugin_dir.join(rel);
            if !is_file(&p) {
                return Err(not_found());
            }
            // Symlinks were excluded above; this also guards against a symlinked parent directory.
            let (a, b) = (p.canonicalize().map_err(|_| not_found())?, plugin_dir.canonicalize().map_err(|_| not_found())?);
            if !a.starts_with(&b) {
                return Err(bad("command resolves outside the plugin directory"));
            }
            if !exe_ok(&p) {
                return Err(bad("on Windows the command must be an .exe or .com file (batch files are refused)"));
            }
            Ok(p)
        }
        CommandRef::OnPath(name) => {
            let path = path_var.ok_or_else(not_found)?;
            for dir in std::env::split_paths(path) {
                let mut cands = vec![dir.join(&name)];
                if cfg!(windows) && Path::new(&name).extension().is_none() {
                    cands.insert(0, dir.join(format!("{name}.exe")));
                }
                for c in cands {
                    // PATH entries are commonly symlinks (alternatives, package managers), so follow them.
                    if std::fs::metadata(&c).map(|md| md.is_file()).unwrap_or(false) && exe_ok(&c) {
                        return Ok(c);
                    }
                }
            }
            Err(not_found())
        }
    }
}
