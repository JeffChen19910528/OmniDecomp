//! One module per group of commands. `dispatch` is the only place that knows every subcommand; each
//! handler gets the session and its own typed arguments, and prints through `crate::output`.

mod binary;
mod graphs;
mod managed;
mod plugins;
mod report;

use crate::args::Cmd;
use crate::session::Session;
use omnidecomp_core::Error;

pub(crate) fn dispatch(cmd: Cmd, s: &Session) -> Result<(), Error> {
    match cmd {
        Cmd::Info { file, format } => binary::info(s, &file, format),
        Cmd::Disasm { file, arch, engine, section, max_instructions, format } => {
            binary::disasm(s, &file, arch.as_deref(), &engine, section.as_deref(), max_instructions, format)
        }
        Cmd::Strings { file, min_length, format } => binary::strings(s, &file, min_length, format),
        Cmd::Symbols { file, format } => binary::symbols(s, &file, format),
        Cmd::Functions { file, format } => binary::functions(s, &file, format),
        Cmd::Xrefs { file, to, from, format } => binary::xrefs(s, &file, to, from, format),
        Cmd::Cfg { file, function, format } => graphs::cfg(s, &file, function, format),
        Cmd::Callgraph { file, format } => graphs::callgraph(s, &file, format),
        Cmd::Java { file, format } => managed::java(s, &file, format),
        Cmd::Dotnet { file, format } => managed::dotnet(s, &file, format),
        Cmd::Decompile { file, engine, allow_external_exec, max_output_mb, output, format } => {
            managed::decompile(s, &file, &engine, allow_external_exec, max_output_mb, output.as_deref(), format)
        }
        Cmd::Report { file, format, output } => report::report(s, &file, format, output.as_deref()),
        Cmd::Plugins { action } => plugins::plugins(s, action),
        Cmd::Engines { action } => plugins::engines(action),
    }
}
