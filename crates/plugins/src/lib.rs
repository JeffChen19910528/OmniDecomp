//! Plugin layer: manifests, enable/disable state, compatibility checks and the sandboxed-as-far-as-we-can
//! child-process runner for external decompilers. Depends on `core` only. Nothing is loaded into the
//! host process; see docs/PLUGIN_API.md for the threat model.

mod locations;
mod manifest;
mod registry;
mod run;

pub use locations::Locations;
pub use manifest::{
    check_compat, classify_command, parse_manifest, parse_version, resolve_command, valid_id, validate, CommandRef, Manifest,
    HOST_VERSION, MAX_MANIFEST_BYTES, PLUGIN_API_VERSION, RUNTIMES,
};
pub use registry::{builtin_ids, sha256_file, PluginRecord, Registry, Resolved, BUILTINS};
pub use run::{run_decompiler, sanitize_output, EngineOutput};
