//! Core data model, error codes and resource limits.
//! No I/O, no engine or UI dependencies.

use serde::Serialize;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidArgument,
    Io,
    Truncated,
    Malformed,
    UnsupportedFormat,
    UnsupportedArch,
    LimitExceeded,
    UnknownEngine,
    InvalidOutputPath,
    Cancelled,
    Timeout,
    UnknownPlugin,
    PluginDisabled,
    PluginIncompatible,
    ExternalEngineFailed,
}

impl ErrorCode {
    /// Stable process exit code for the CLI.
    pub fn exit_code(self) -> i32 {
        match self {
            ErrorCode::InvalidArgument => 2,
            ErrorCode::Io => 3,
            ErrorCode::Truncated => 10,
            ErrorCode::Malformed => 11,
            ErrorCode::UnsupportedFormat => 12,
            ErrorCode::UnsupportedArch => 13,
            ErrorCode::LimitExceeded => 14,
            ErrorCode::UnknownEngine => 15,
            ErrorCode::InvalidOutputPath => 16,
            ErrorCode::Cancelled => 17,
            ErrorCode::Timeout => 18,
            ErrorCode::UnknownPlugin => 19,
            ErrorCode::PluginDisabled => 20,
            ErrorCode::PluginIncompatible => 21,
            ErrorCode::ExternalEngineFailed => 22,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::Io => "io",
            ErrorCode::Truncated => "truncated",
            ErrorCode::Malformed => "malformed",
            ErrorCode::UnsupportedFormat => "unsupported_format",
            ErrorCode::UnsupportedArch => "unsupported_arch",
            ErrorCode::LimitExceeded => "limit_exceeded",
            ErrorCode::UnknownEngine => "unknown_engine",
            ErrorCode::InvalidOutputPath => "invalid_output_path",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::Timeout => "timeout",
            ErrorCode::UnknownPlugin => "unknown_plugin",
            ErrorCode::PluginDisabled => "plugin_disabled",
            ErrorCode::PluginIncompatible => "plugin_incompatible",
            ErrorCode::ExternalEngineFailed => "external_engine_failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_file_size: u64,
    pub max_sections: usize,
    pub max_strings: usize,
    pub max_symbols: usize,
    pub max_instructions: usize,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 256 * 1024 * 1024,
            max_sections: 4096,
            max_strings: 100_000,
            max_symbols: 100_000,
            max_instructions: 1_000_000,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Per-job execution context: limits, cooperative cancellation and a wall-clock deadline.
#[derive(Clone)]
pub struct Context {
    pub limits: Limits,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}

impl Context {
    pub fn new(limits: Limits) -> Self {
        let deadline = Instant::now() + limits.timeout;
        Self { limits, cancel: Arc::new(AtomicBool::new(false)), deadline }
    }

    /// Like `new`, but cancellation is driven by a flag the caller already owns (e.g. a UI button).
    pub fn with_cancel(limits: Limits, cancel: Arc<AtomicBool>) -> Self {
        let deadline = Instant::now() + limits.timeout;
        Self { limits, cancel, deadline }
    }

    pub fn cancel_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    /// Long-running loops must call this periodically.
    pub fn check(&self) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(Error::new(ErrorCode::Cancelled, "analysis cancelled"));
        }
        if Instant::now() >= self.deadline {
            return Err(Error::new(ErrorCode::Timeout, "analysis timed out"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe,
    Elf,
    MachO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Riscv,
    Unknown,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm => "arm",
            Arch::Aarch64 => "aarch64",
            Arch::Riscv => "riscv",
            Arch::Unknown => "unknown",
        }
    }

    pub fn from_cli(s: &str) -> Option<Arch> {
        match s.to_ascii_lowercase().as_str() {
            "x86" | "i386" | "i686" => Some(Arch::X86),
            "x86_64" | "x64" | "amd64" => Some(Arch::X86_64),
            "arm" => Some(Arch::Arm),
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            "riscv" => Some(Arch::Riscv),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub executable: bool,
}

/// CodeView PDB reference from the PE debug directory. Informational only; nothing is fetched.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DebugInfo {
    /// Always "codeview_pdb70" (an `RSDS` record).
    pub kind: &'static str,
    /// Path as recorded by the linker; untrusted text, sanitized and capped.
    pub pdb_path: String,
    /// Lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    pub guid: String,
    pub age: u32,
}

/// One assembly identity from the .NET Assembly / AssemblyRef tables.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DotnetAssembly {
    pub name: String,
    /// `major.minor.build.revision`.
    pub version: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DotnetType {
    pub namespace: String,
    pub name: String,
    pub methods: Vec<String>,
}

/// .NET metadata summary. IL bodies are not decoded and nothing is decompiled.
#[derive(Debug, Clone, Serialize)]
pub struct DotnetInfo {
    /// Metadata version string such as "v4.0.30319".
    pub runtime_version: String,
    pub il_only: bool,
    pub entry_point_token: Option<u32>,
    pub assembly: Option<DotnetAssembly>,
    pub references: Vec<DotnetAssembly>,
    pub type_count: u32,
    pub method_count: u32,
    pub types: Vec<DotnetType>,
    /// True when `types` was cut by the symbol limit.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct JavaMember {
    pub name: String,
    /// JVM descriptor such as `([Ljava/lang/String;)V`.
    pub descriptor: String,
    pub access: Vec<&'static str>,
}

/// Java `.class` structure. Bytecode is not decoded and nothing is decompiled.
#[derive(Debug, Clone, Serialize)]
pub struct JavaClassInfo {
    pub major: u16,
    pub minor: u16,
    pub java_version: String,
    /// Dotted binary name, e.g. `java.lang.String`.
    pub class_name: String,
    pub super_class: Option<String>,
    pub access: Vec<&'static str>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    pub fields: Vec<JavaMember>,
    pub methods: Vec<JavaMember>,
    /// True when fields/methods were cut by the symbol limit.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryFormatInfo {
    pub format: Format,
    pub bits: u8,
    pub endianness: Endianness,
    pub arch: Arch,
    /// Raw machine field from the header.
    pub machine: u32,
    /// Absolute entry address; `None` when the header has none.
    pub entry_point: Option<u64>,
    /// PE only; `None` for ELF.
    pub image_base: Option<u64>,
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputArtifact {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub section: String,
    pub engine: String,
    /// "call", "jump", "branch" (conditional) or "return" for control-flow instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<&'static str>,
    /// Direct branch/call target; `None` for indirect transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Disassembly {
    pub engine: String,
    pub engine_version: String,
    pub arch: Arch,
    pub instructions: Vec<Instruction>,
    /// True when the instruction limit stopped decoding early.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringHit {
    pub offset: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsResult {
    pub encoding: &'static str,
    pub min_length: usize,
    pub strings: Vec<StringHit>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    /// Absolute address; `None` for imports, undefined or forwarded symbols.
    pub address: Option<u64>,
    /// "export", "import", "function", "object" or "unknown".
    pub kind: &'static str,
    /// Where the symbol came from: pe_export, pe_import, elf_symtab, elf_dynsym.
    pub source: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolsResult {
    pub symbols: Vec<Symbol>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: Option<String>,
    /// Strongest evidence: "symbol", "pdata", "entry" or "call_target".
    pub source: &'static str,
    /// "high" for symbols, pdata and the entry point, "medium" for call targets.
    pub confidence: &'static str,
    /// Size in bytes; known only from the PE x64 exception table (.pdata).
    pub size: Option<u64>,
    /// Number of direct calls to this address found in the disassembly.
    pub callers: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrossReference {
    pub from: u64,
    pub to: u64,
    /// "call", "jump" or "branch".
    pub kind: &'static str,
    /// Always "medium": linear-sweep disassembly can decode data as code.
    pub confidence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionsResult {
    pub functions: Vec<FunctionInfo>,
    pub xrefs: Vec<CrossReference>,
    /// True when the underlying disassembly hit the instruction limit.
    pub truncated: bool,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgEdge {
    pub to: u64,
    /// "fallthrough", "jump" or "taken" (conditional branch taken).
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicBlock {
    pub start: u64,
    /// Address just past the last instruction.
    pub end: u64,
    pub instruction_count: usize,
    pub successors: Vec<CfgEdge>,
    /// True when control can leave this block to a target outside the graph
    /// (indirect jump, tail call, return into unknown code, undecoded bytes).
    pub exits_graph: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgResult {
    pub function: u64,
    pub blocks: Vec<BasicBlock>,
    pub truncated: bool,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallEdge {
    pub from: u64,
    pub to: u64,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallGraph {
    pub nodes: Vec<FunctionInfo>,
    pub edges: Vec<CallEdge>,
    pub truncated: bool,
    pub notes: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineCapability {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: String,
    pub formats: Vec<String>,
    pub architectures: Vec<String>,
    pub limitations: Vec<String>,
    /// "available" or "not_installed". Built-in engines are always available.
    pub status: String,
    /// What to install (and how it is detected) when `status` is "not_installed".
    pub install_hint: Option<String>,
}
