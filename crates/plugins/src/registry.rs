//! Plugin discovery, enable/disable state and the checks that gate a run.
//!
//! Enabled state lives in a per-user state file, NOT inside the plugins directory: a directory that
//! arrives from elsewhere (an archive, a repository) must not be able to enable itself. Enabling records
//! the SHA-256 of the manifest and of the engine program; a run is refused when either changed.

use crate::manifest::{
    check_compat, clean, parse_manifest, resolve_command, validate, Manifest, HOST_VERSION, PLUGIN_API_VERSION,
};
use omnidecomp_core::{Arch, Error, ErrorCode, Format};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_PLUGIN_DIRS: usize = 256;
const MAX_STATE_BYTES: u64 = 1024 * 1024;

/// Built-in plugins: id, display name, kind, licence, what they handle.
pub const BUILTINS: [(&str, &str, &str, &str, &[&str]); 7] = [
    ("format-pe", "PE parser", "format", "MIT OR Apache-2.0 (this project)", &["pe"]),
    ("format-elf", "ELF parser", "format", "MIT OR Apache-2.0 (this project)", &["elf"]),
    ("format-macho", "Mach-O parser (thin)", "format", "MIT OR Apache-2.0 (this project)", &["macho"]),
    ("arch-x86", "x86 / x86_64 disassembly (iced-x86)", "architecture", "MIT (iced-x86)", &["x86", "x86_64"]),
    ("arch-arm64", "AArch64 disassembly (yaxpeax-arm)", "architecture", "0BSD (yaxpeax-arm)", &["aarch64"]),
    ("runtime-dotnet", ".NET metadata reader", "runtime", "MIT OR Apache-2.0 (this project)", &["dotnet"]),
    ("runtime-java", "Java class reader", "runtime", "MIT OR Apache-2.0 (this project)", &["java"]),
];

pub fn builtin_ids() -> Vec<&'static str> {
    BUILTINS.iter().map(|b| b.0).collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Approval {
    version: String,
    manifest_sha256: String,
    command_path: String,
    command_sha256: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    enabled: BTreeMap<String, Approval>,
    #[serde(default)]
    disabled_builtins: BTreeSet<String>,
}

struct External {
    id: String,
    dir: PathBuf,
    manifest: Result<Manifest, Error>,
    manifest_sha256: String,
}

/// One row of `plugins list`.
#[derive(Debug, Clone, Serialize)]
pub struct PluginRecord {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: String,
    /// "builtin" or "external".
    pub origin: &'static str,
    pub license: String,
    pub source: Option<String>,
    /// "enabled", "disabled", "invalid" or "incompatible".
    pub status: &'static str,
    pub reason: Option<String>,
    pub handles: Vec<String>,
    pub api_version: u32,
}

/// A plugin that passed every check and may be run.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub id: String,
    pub name: String,
    pub version: String,
    pub exe: PathBuf,
    pub args: Vec<String>,
    pub dir: PathBuf,
}

pub struct Registry {
    state_path: PathBuf,
    state: State,
    externals: Vec<External>,
}

pub fn sha256_file(p: &Path) -> Result<String, Error> {
    let io = |e: std::io::Error| Error::new(ErrorCode::Io, format!("cannot read {}: {e}", clean(&p.to_string_lossy(), 200)));
    let mut f = std::fs::File::open(p).map_err(io)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

impl Registry {
    /// Reads the state file (missing = defaults) and scans `plugins_dir` (missing = no external plugins).
    pub fn load(plugins_dir: &Path, state_path: &Path) -> Result<Registry, Error> {
        let state = match std::fs::metadata(state_path) {
            Ok(md) => {
                if md.len() > MAX_STATE_BYTES {
                    return Err(Error::new(ErrorCode::LimitExceeded, "plugin state file is too large; delete it to reset"));
                }
                let bytes = std::fs::read(state_path).map_err(|e| Error::new(ErrorCode::Io, format!("cannot read plugin state: {e}")))?;
                serde_json::from_slice(&bytes)
                    .map_err(|_| Error::new(ErrorCode::Malformed, "plugin state file is corrupt; delete it to reset (all external plugins become disabled)"))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(Error::new(ErrorCode::Io, format!("cannot read plugin state: {e}"))),
        };
        let mut externals = Vec::new();
        if let Ok(rd) = std::fs::read_dir(plugins_dir) {
            let mut dirs: Vec<(String, PathBuf)> = Vec::new();
            for entry in rd.flatten() {
                // Symlinked plugin directories are not followed.
                let Ok(ft) = entry.file_type() else { continue };
                if ft.is_dir() && !ft.is_symlink() {
                    dirs.push((entry.file_name().to_string_lossy().into_owned(), entry.path()));
                }
            }
            dirs.sort();
            dirs.truncate(MAX_PLUGIN_DIRS);
            for (name, dir) in dirs {
                let mf = dir.join("plugin.json");
                let (manifest, sha) = match std::fs::symlink_metadata(&mf) {
                    Ok(md) if md.is_file() => match std::fs::read(&mf) {
                        Ok(bytes) => {
                            let sha = hex(&bytes);
                            let m = parse_manifest(&bytes).and_then(|m| validate(&m, &name, &builtin_ids()).map(|()| m));
                            (m, sha)
                        }
                        Err(e) => (Err(Error::new(ErrorCode::Io, format!("cannot read plugin.json: {e}"))), String::new()),
                    },
                    _ => (Err(Error::new(ErrorCode::Malformed, "plugin.json is missing or not a regular file")), String::new()),
                };
                externals.push(External { id: name, dir, manifest, manifest_sha256: sha });
            }
        }
        Ok(Registry { state_path: state_path.to_path_buf(), state, externals })
    }

    fn external(&self, id: &str) -> Option<&External> {
        self.externals.iter().find(|e| e.id == id)
    }

    fn external_status(&self, e: &External) -> (&'static str, Option<String>) {
        let m = match &e.manifest {
            Ok(m) => m,
            Err(err) => return ("invalid", Some(clean(&err.message, 300))),
        };
        if let Err(err) = check_compat(m, HOST_VERSION) {
            return ("incompatible", Some(err.message));
        }
        match self.state.enabled.get(&e.id) {
            None => ("disabled", None),
            Some(a) if a.manifest_sha256 == e.manifest_sha256 && a.version == m.version => ("enabled", None),
            Some(_) => ("disabled", Some("plugin.json changed since it was enabled; review it and enable it again".to_string())),
        }
    }

    pub fn list(&self) -> Vec<PluginRecord> {
        let mut out: Vec<PluginRecord> = BUILTINS
            .iter()
            .map(|(id, name, kind, license, handles)| PluginRecord {
                id: id.to_string(),
                name: name.to_string(),
                version: HOST_VERSION.to_string(),
                kind: kind.to_string(),
                origin: "builtin",
                license: license.to_string(),
                source: None,
                status: if self.state.disabled_builtins.contains(*id) { "disabled" } else { "enabled" },
                reason: None,
                handles: handles.iter().map(|s| s.to_string()).collect(),
                api_version: PLUGIN_API_VERSION,
            })
            .collect();
        for e in &self.externals {
            let (status, reason) = self.external_status(e);
            let rec = match &e.manifest {
                Ok(m) => PluginRecord {
                    id: m.id.clone(),
                    name: clean(&m.name, 80),
                    version: m.version.clone(),
                    kind: m.kind.clone(),
                    origin: "external",
                    license: clean(&m.license, 64),
                    source: m.source.as_ref().map(|s| clean(s, 300)),
                    status,
                    reason,
                    handles: m.runtimes.clone(),
                    api_version: m.api_version,
                },
                Err(_) => PluginRecord {
                    id: clean(&e.id, 64),
                    name: "(invalid plugin)".to_string(),
                    version: String::new(),
                    kind: String::new(),
                    origin: "external",
                    license: String::new(),
                    source: None,
                    status,
                    reason,
                    handles: Vec::new(),
                    api_version: 0,
                },
            };
            out.push(rec);
        }
        out
    }

    fn save(&self) -> Result<(), Error> {
        let io = |e: std::io::Error| Error::new(ErrorCode::Io, format!("cannot write plugin state: {e}"));
        if let Some(parent) = self.state_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let tmp = self.state_path.with_extension("tmp");
        let text = serde_json::to_string_pretty(&self.state).unwrap_or_default();
        std::fs::write(&tmp, text).map_err(io)?;
        std::fs::rename(&tmp, &self.state_path).map_err(io)
    }

    fn unknown(id: &str) -> Error {
        Error::new(ErrorCode::UnknownPlugin, format!("no plugin with id '{}'", clean(id, 64)))
    }

    /// Enables a built-in plugin, or an external one after validating it and recording hashes.
    pub fn enable(&mut self, id: &str, path_var: Option<&std::ffi::OsStr>) -> Result<(), Error> {
        if BUILTINS.iter().any(|b| b.0 == id) {
            self.state.disabled_builtins.remove(id);
            return self.save();
        }
        let e = self.external(id).ok_or_else(|| Self::unknown(id))?;
        let m = e.manifest.as_ref().map_err(|err| Error::new(err.code, format!("plugin '{id}' is invalid: {}", err.message)))?;
        check_compat(m, HOST_VERSION)?;
        let exe = resolve_command(m, &e.dir, path_var)?;
        let approval = Approval {
            version: m.version.clone(),
            manifest_sha256: e.manifest_sha256.clone(),
            command_path: exe.to_string_lossy().into_owned(),
            command_sha256: sha256_file(&exe)?,
        };
        self.state.enabled.insert(id.to_string(), approval);
        self.save()
    }

    pub fn disable(&mut self, id: &str) -> Result<(), Error> {
        if BUILTINS.iter().any(|b| b.0 == id) {
            self.state.disabled_builtins.insert(id.to_string());
            return self.save();
        }
        if self.external(id).is_none() && !self.state.enabled.contains_key(id) {
            return Err(Self::unknown(id));
        }
        self.state.enabled.remove(id);
        self.save()
    }

    pub fn require_builtin(&self, id: &str, what: &str) -> Result<(), Error> {
        if self.state.disabled_builtins.contains(id) {
            return Err(Error::new(ErrorCode::PluginDisabled, format!("{what} is handled by plugin '{id}', which is disabled (omnidecomp plugins enable {id})")));
        }
        Ok(())
    }

    /// Refuses input whose format or architecture belongs to a disabled built-in plugin.
    pub fn check_analysis(&self, format: Format, arch: Arch) -> Result<(), Error> {
        let (fid, fname) = match format {
            Format::Pe => ("format-pe", "PE files"),
            Format::Elf => ("format-elf", "ELF files"),
            Format::MachO => ("format-macho", "Mach-O files"),
        };
        self.require_builtin(fid, fname)?;
        let aid = match arch {
            Arch::X86 | Arch::X86_64 => Some(("arch-x86", "x86 code")),
            Arch::Aarch64 => Some(("arch-arm64", "AArch64 code")),
            _ => None,
        };
        if let Some((id, what)) = aid {
            self.require_builtin(id, what)?;
        }
        Ok(())
    }

    /// Everything that must hold before an external engine is started, re-verified at run time.
    pub fn resolve_for_run(&self, id: &str, runtime: &str, path_var: Option<&std::ffi::OsStr>) -> Result<Resolved, Error> {
        let e = self.external(id).ok_or_else(|| {
            Error::new(ErrorCode::UnknownEngine, format!("no decompiler plugin '{}' (see: omnidecomp plugins list)", clean(id, 64)))
        })?;
        let m = e.manifest.as_ref().map_err(|err| Error::new(err.code, format!("plugin '{id}' is invalid: {}", err.message)))?;
        check_compat(m, HOST_VERSION)?;
        let (status, reason) = self.external_status(e);
        if status != "enabled" {
            return Err(Error::new(
                ErrorCode::PluginDisabled,
                format!("plugin '{id}' is not enabled{} (omnidecomp plugins enable {id})", reason.map_or(String::new(), |r| format!(": {r}"))),
            ));
        }
        if !m.runtimes.iter().any(|r| r == runtime) {
            return Err(Error::new(ErrorCode::UnsupportedFormat, format!("plugin '{id}' does not handle {runtime} input (it handles: {})", m.runtimes.join(", "))));
        }
        let approval = &self.state.enabled[id];
        let exe = resolve_command(m, &e.dir, path_var)?;
        if exe.to_string_lossy() != approval.command_path || sha256_file(&exe)? != approval.command_sha256 {
            return Err(Error::new(
                ErrorCode::PluginIncompatible,
                format!("the engine program for '{id}' changed since it was enabled; verify it, then enable the plugin again"),
            ));
        }
        Ok(Resolved { id: m.id.clone(), name: clean(&m.name, 80), version: m.version.clone(), exe, args: m.args.clone(), dir: e.dir.clone() })
    }
}
