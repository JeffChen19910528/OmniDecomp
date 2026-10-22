//! Command-line grammar: flags, subcommands and output formats. No behaviour lives here.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "omnidecomp", version, about = "Static binary analysis toolkit")]
pub(crate) struct Cli {
    /// Maximum input file size in MiB.
    #[arg(long, global = true, default_value_t = 256)]
    pub(crate) max_file_size_mb: u64,
    /// Wall-clock timeout for the whole command, in seconds.
    #[arg(long, global = true, default_value_t = 60)]
    pub(crate) timeout_secs: u64,
    /// Directory scanned for external plugins (default: `plugins` next to the executable, or
    /// $OMNIDECOMP_PLUGINS_DIR).
    #[arg(long, global = true)]
    pub(crate) plugins_dir: Option<PathBuf>,
    /// Per-user file that records which plugins are enabled (default: the user config directory, or
    /// $OMNIDECOMP_STATE_FILE).
    #[arg(long, global = true)]
    pub(crate) state_file: Option<PathBuf>,
    #[command(subcommand)]
    pub(crate) command: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Fmt {
    Text,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ReportFmt {
    Json,
    Text,
    Csv,
    Html,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum GraphFmt {
    Text,
    Json,
    Dot,
}

#[derive(Subcommand)]
pub(crate) enum Cmd {
    /// Identify the file and print format, sections and hash.
    Info {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Disassemble executable sections (static, linear sweep).
    Disasm {
        file: PathBuf,
        /// Expected architecture; must match the file (x86, x86_64).
        #[arg(long)]
        arch: Option<String>,
        #[arg(long, default_value = "auto")]
        engine: String,
        /// Only this section (default: all executable sections).
        #[arg(long)]
        section: Option<String>,
        #[arg(long, default_value_t = 10_000)]
        max_instructions: usize,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Extract printable ASCII strings.
    Strings {
        file: PathBuf,
        #[arg(long, default_value_t = 4)]
        min_length: usize,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// List PE imports/exports or ELF symbols.
    Symbols {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Detected functions (entry point, symbols, direct call targets).
    Functions {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Direct call/jump/branch cross-references, optionally filtered by address.
    Xrefs {
        file: PathBuf,
        /// Only references to this address (hex with 0x, or decimal).
        #[arg(long, value_parser = parse_addr)]
        to: Option<u64>,
        /// Only references from this address.
        #[arg(long, value_parser = parse_addr)]
        from: Option<u64>,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Control-flow graph (basic blocks) of one function.
    Cfg {
        file: PathBuf,
        /// Function address (hex with 0x, or decimal).
        #[arg(long, value_parser = parse_addr)]
        function: u64,
        #[arg(long, value_enum, default_value = "text")]
        format: GraphFmt,
    },
    /// Function-to-function call graph.
    Callgraph {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: GraphFmt,
    },
    /// Report export: json (default), text, csv or html.
    Report {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "json")]
        format: ReportFmt,
        /// Write to this file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// .NET metadata: assembly identity, references, types and methods (no decompilation).
    Dotnet {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Java .class structure: version, names, fields and methods (no decompilation).
    Java {
        file: PathBuf,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Decompile a .NET assembly or Java class with an enabled external decompiler plugin.
    Decompile {
        file: PathBuf,
        /// Plugin id of the decompiler (see `plugins list`).
        #[arg(long)]
        engine: String,
        /// Consent to starting the external decompiler program. Nothing runs without it.
        #[arg(long)]
        allow_external_exec: bool,
        /// Largest decompiler output accepted, in MiB.
        #[arg(long, default_value_t = 16)]
        max_output_mb: usize,
        /// Write to this file instead of stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// List, enable and disable plugins.
    Plugins {
        #[command(subcommand)]
        action: PluginsCmd,
    },
    /// Inspect registered engines.
    Engines {
        #[command(subcommand)]
        action: EnginesCmd,
    },
}

#[derive(Subcommand)]
pub(crate) enum PluginsCmd {
    /// Built-in and external plugins with status, version and licence.
    List {
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
    /// Enable a plugin (external plugins are validated and their files hashed first).
    Enable { id: String },
    /// Disable a plugin.
    Disable { id: String },
}

#[derive(Subcommand)]
pub(crate) enum EnginesCmd {
    List {
        #[arg(long, value_enum, default_value = "text")]
        format: Fmt,
    },
}

pub(crate) fn parse_addr(s: &str) -> Result<u64, String> {
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    };
    parsed.map_err(|_| format!("invalid address '{s}'"))
}
