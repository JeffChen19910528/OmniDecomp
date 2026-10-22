//! `plugins list|enable|disable` and `engines list`.

use crate::args::{EnginesCmd, Fmt, PluginsCmd};
use crate::output::json_out;
use crate::session::Session;
use omnidecomp_app as app;
use omnidecomp_core::Error;

pub(super) fn plugins(s: &Session, action: PluginsCmd) -> Result<(), Error> {
    match action {
        PluginsCmd::List { format } => {
            let rows = s.registry()?.list();
            match format {
                Fmt::Json => json_out(&rows),
                Fmt::Text => {
                    for r in &rows {
                        println!("{} {} [{}/{}] {} - license: {}", r.id, r.version, r.origin, r.kind, r.status, r.license);
                        println!("  {}  handles: {}  api {}", r.name, r.handles.join(", "), r.api_version);
                        if let Some(src) = &r.source {
                            println!("  source: {src}");
                        }
                        if let Some(why) = &r.reason {
                            println!("  note: {why}");
                        }
                    }
                }
            }
        }
        PluginsCmd::Enable { id } => {
            s.writable_registry()?.enable(&id, std::env::var_os("PATH").as_deref())?;
            println!("enabled {id}");
        }
        PluginsCmd::Disable { id } => {
            s.writable_registry()?.disable(&id)?;
            println!("disabled {id}");
        }
    }
    Ok(())
}

pub(super) fn engines(action: EnginesCmd) -> Result<(), Error> {
    let EnginesCmd::List { format } = action;
    let list = app::engines();
    match format {
        Fmt::Json => json_out(&list),
        Fmt::Text => {
            for e in &list {
                println!("{} {} [{}] {}", e.id, e.version, e.kind, e.status);
                if let Some(h) = &e.install_hint {
                    println!("  install: {h}");
                }
                println!("  formats: {}", e.formats.join(", "));
                println!("  architectures: {}", e.architectures.join(", "));
                for l in &e.limitations {
                    println!("  limitation: {l}");
                }
            }
        }
    }
    Ok(())
}
