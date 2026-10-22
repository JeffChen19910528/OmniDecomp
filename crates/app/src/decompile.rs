//! Decompilation through an enabled external plugin: runtime detection, pre-flight plan and the run.

use omnidecomp_core::{
    Context, Error, ErrorCode, InputArtifact, Result,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use crate::analysis::read_input;

/// Result of an external decompiler run. `text` comes from a third-party program and is untrusted.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DecompileResult {
    pub engine: String,
    pub engine_name: String,
    pub engine_version: String,
    /// "dotnet" or "java".
    pub runtime: &'static str,
    pub input: InputArtifact,
    pub text: String,
    pub notes: Vec<&'static str>,
}

/// Which language runtime a file belongs to. Native code has no decompiler here and is refused.
pub fn detect_runtime(path: &Path, ctx: &Context) -> Result<(&'static str, InputArtifact)> {
    let data = read_input(path, ctx)?;
    let artifact = InputArtifact { size: data.len() as u64, sha256: format!("{:x}", Sha256::digest(&data)) };
    if data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        match omnidecomp_formats::parse_java_class(&data, ctx) {
            Ok(_) => return Ok(("java", artifact)),
            // Not a class file after all (0xCAFEBABE is also a universal Mach-O): fall through to the other checks.
            Err(e) if matches!(e.code, ErrorCode::Malformed | ErrorCode::Truncated | ErrorCode::UnsupportedFormat) => {}
            // A deadline, cancel or limit must be reported as such, not as "unsupported format".
            Err(e) => return Err(e),
        }
    }
    let not_managed = || {
        Error::new(
            ErrorCode::UnsupportedFormat,
            "decompilation is available for .NET assemblies and Java .class files only; native code can be inspected with disasm",
        )
    };
    let info = omnidecomp_formats::parse(&data, ctx).map_err(|e| if matches!(e.code, ErrorCode::UnsupportedFormat) { not_managed() } else { e })?;
    match omnidecomp_formats::dotnet_info(&data, &info, ctx)? {
        Some(_) => Ok(("dotnet", artifact)),
        None => Err(not_managed()),
    }
}

/// Every check that must pass before a decompiler is started, without starting it: runtime detection, the
/// runtime's built-in plugin, and the engine plugin (enabled, compatible, hashes unchanged). The caller
/// may show the result to the user before asking for consent.
pub fn plan_decompile(
    path: &Path,
    registry: &omnidecomp_plugins::Registry,
    engine: &str,
    ctx: &Context,
) -> Result<(&'static str, InputArtifact, omnidecomp_plugins::Resolved)> {
    let (runtime, artifact) = detect_runtime(path, ctx)?;
    registry.require_builtin(if runtime == "java" { "runtime-java" } else { "runtime-dotnet" }, "this runtime")?;
    let path_var = std::env::var_os("PATH");
    let plugin = registry.resolve_for_run(engine, runtime, path_var.as_deref())?;
    Ok((runtime, artifact, plugin))
}

/// Runs an enabled decompiler plugin on `.NET` / Java input. Starting a third-party program needs the
/// caller's explicit consent (`allow_external`); nothing is started otherwise.
pub fn decompile(
    path: &Path,
    registry: &omnidecomp_plugins::Registry,
    engine: &str,
    allow_external: bool,
    max_output: usize,
    ctx: &Context,
) -> Result<DecompileResult> {
    let (runtime, artifact, plugin) = plan_decompile(path, registry, engine, ctx)?;
    if !allow_external {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            format!(
                "decompiling starts the external program '{}' (plugin {} {}); pass --allow-external-exec to allow it",
                plugin.exe.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                plugin.id,
                plugin.version
            ),
        ));
    }
    let out = omnidecomp_plugins::run_decompiler(&plugin, path, max_output, ctx)?;
    Ok(DecompileResult {
        engine: plugin.id,
        engine_name: plugin.name,
        engine_version: plugin.version,
        runtime,
        input: artifact,
        text: out.text,
        notes: vec![
            "output was produced by an external decompiler and is untrusted text",
            "the analysed file itself was not executed",
        ],
    })
}
