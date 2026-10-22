//! .NET and Java: metadata views and decompilation through an enabled external plugin.

use crate::args::Fmt;
use crate::output::{json_out, warn_if};
use crate::session::Session;
use omnidecomp_app as app;
use omnidecomp_core::Error;
use serde_json::json;
use std::path::Path;

pub(super) fn java(s: &Session, file: &Path, format: Fmt) -> Result<(), Error> {
    s.registry()?.require_builtin("runtime-java", "Java classes")?;
    let (artifact, c) = app::java_class(file, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&json!({ "artifact": artifact, "class": c })),
        Fmt::Text => {
            println!("; Java class structure (not decompilation) {} (major {})", c.java_version, c.major);
            println!("class {} [{}]", c.class_name, c.access.join(" "));
            if let Some(x) = &c.super_class {
                println!("extends {x}");
            }
            for i in &c.interfaces {
                println!("implements {i}");
            }
            if let Some(x) = &c.source_file {
                println!("source {x}");
            }
            for f in &c.fields {
                println!("  field {} {} [{}]", f.name, f.descriptor, f.access.join(" "));
            }
            for m in &c.methods {
                println!("  method {}{} [{}]", m.name, m.descriptor, m.access.join(" "));
            }
            warn_if(c.truncated, "symbol limit reached; member list truncated");
        }
    }
    Ok(())
}

pub(super) fn dotnet(s: &Session, file: &Path, format: Fmt) -> Result<(), Error> {
    let a = s.analyze(file)?;
    s.registry()?.require_builtin("runtime-dotnet", ".NET assemblies")?;
    let d = app::dotnet(&a, &s.ctx)?;
    match format {
        Fmt::Json => json_out(&d),
        Fmt::Text => {
            println!("; .NET metadata (not decompilation) runtime {}", d.runtime_version);
            if let Some(x) = &d.assembly {
                println!("assembly {} {}", x.name, x.version);
            }
            for r in &d.references {
                println!("reference {} {}", r.name, r.version);
            }
            println!("types {} methods {}", d.type_count, d.method_count);
            for t in &d.types {
                let ns = if t.namespace.is_empty() { String::new() } else { format!("{}.", t.namespace) };
                println!("type {ns}{}", t.name);
                for m in &t.methods {
                    println!("  method {m}");
                }
            }
            warn_if(d.truncated, "symbol limit reached; type list truncated");
        }
    }
    Ok(())
}

pub(super) fn decompile(
    s: &Session,
    file: &Path,
    engine: &str,
    allow_external_exec: bool,
    max_output_mb: usize,
    output: Option<&Path>,
    format: Fmt,
) -> Result<(), Error> {
    let reg = s.registry()?;
    let max = max_output_mb.clamp(1, 256) * 1024 * 1024;
    let r = app::decompile(file, &reg, engine, allow_external_exec, max, &s.ctx)?;
    if let Some(path) = output {
        let body = match format {
            Fmt::Json => serde_json::to_string_pretty(&r).unwrap_or_default(),
            Fmt::Text => r.text.clone(),
        };
        app::write_output(path, body.as_bytes(), file)?;
    } else {
        match format {
            Fmt::Json => json_out(&r),
            Fmt::Text => {
                println!("// engine {} {} ({}), external decompiler output, untrusted", r.engine, r.engine_version, r.runtime);
                print!("{}", r.text);
            }
        }
    }
    Ok(())
}
