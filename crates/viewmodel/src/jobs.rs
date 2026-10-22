//! Plugin management and decompilation as view-model operations: a generic background `Job`, the plugin
//! table, enable/disable, and the two-step decompile (plan, then run after the user consents).
//!
//! Nothing here starts a third-party program except `start_decompile`, and the front end must call that only
//! after the user confirmed the exact program shown by `plan`.

use omnidecomp_app::{self as app, DecompileResult};
use omnidecomp_core::{Context, Error, ErrorCode, Limits};
use omnidecomp_plugins::{Locations, PluginRecord};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;

/// Output cap for one decompilation, matching the CLI default (16 MiB).
pub const MAX_DECOMPILE_OUTPUT: usize = 16 * 1024 * 1024;
/// Wall-clock limit for one decompilation. Longer than analysis because real decompilers are slow.
pub const DECOMPILE_TIMEOUT: Duration = Duration::from_secs(300);

/// A computation on a worker thread: poll it each frame, cancel it, or drop it.
pub struct Job<T> {
    rx: Receiver<Result<T, Error>>,
    cancel: Arc<AtomicBool>,
    done: bool,
}

pub fn spawn_job<T: Send + 'static>(
    on_done: impl Fn() + Send + 'static,
    work: impl FnOnce(&Arc<AtomicBool>) -> Result<T, Error> + Send + 'static,
) -> Job<T> {
    let (tx, rx) = channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let c = Arc::clone(&cancel);
    std::thread::spawn(move || {
        let r = work(&c);
        let _ = tx.send(r);
        on_done();
    });
    Job { rx, cancel, done: false }
}

impl<T> Job<T> {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// `Some` exactly once, when the worker has finished.
    pub fn poll(&mut self) -> Option<Result<T, Error>> {
        if self.done {
            return None;
        }
        match self.rx.try_recv() {
            Ok(r) => {
                self.done = true;
                Some(r)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.done = true;
                Some(Err(Error::new(ErrorCode::Cancelled, "worker stopped unexpectedly")))
            }
        }
    }
}

/// The plugin table (built-ins and externals) as the CLI's `plugins list` shows it.
pub fn plugin_rows(loc: &Locations) -> Result<Vec<PluginRecord>, Error> {
    Ok(loc.registry()?.list())
}

/// Enables or disables a plugin and saves the choice. Enabling an external plugin records the SHA-256 of its
/// manifest and engine program, exactly as `omnidecomp plugins enable` does.
pub fn set_plugin_enabled(loc: &Locations, id: &str, enable: bool) -> Result<(), Error> {
    let mut reg = loc.writable_registry()?;
    if enable {
        reg.enable(id, std::env::var_os("PATH").as_deref())
    } else {
        reg.disable(id)
    }
}

/// Ids of external plugins that are enabled and are decompilers, in list order.
pub fn enabled_decompilers(rows: &[PluginRecord]) -> Vec<&PluginRecord> {
    rows.iter().filter(|r| r.origin == "external" && r.kind == "decompiler" && r.status == "enabled").collect()
}

/// What will run, shown to the user before consent.
#[derive(Debug, Clone)]
pub struct Plan {
    pub input: PathBuf,
    pub engine: String,
    pub engine_name: String,
    pub engine_version: String,
    pub runtime: &'static str,
    /// Full path of the program that will be started.
    pub program: String,
    pub args: Vec<String>,
}

/// Runs every pre-flight check (runtime, built-in plugin, engine enabled, hashes unchanged) without
/// starting anything.
pub fn plan_decompile(input: PathBuf, loc: Locations, engine: String, on_done: impl Fn() + Send + 'static) -> Job<Plan> {
    spawn_job(on_done, move |cancel| {
        let ctx = Context::with_cancel(Limits::default(), Arc::clone(cancel));
        let reg = loc.registry()?;
        let (runtime, _artifact, r) = app::plan_decompile(&input, &reg, &engine, &ctx)?;
        Ok(Plan {
            input,
            engine: r.id,
            engine_name: r.name,
            engine_version: r.version,
            runtime,
            program: r.exe.to_string_lossy().into_owned(),
            args: r.args,
        })
    })
}

/// Starts the engine. Call only after the user consented to running `plan.program` on `plan.input`; the
/// registry is read again here so a program changed in between is caught by the hash check.
pub fn start_decompile(plan: &Plan, loc: Locations, on_done: impl Fn() + Send + 'static) -> Job<DecompileResult> {
    let (input, engine) = (plan.input.clone(), plan.engine.clone());
    spawn_job(on_done, move |cancel| {
        let ctx = Context::with_cancel(Limits { timeout: DECOMPILE_TIMEOUT, ..Limits::default() }, Arc::clone(cancel));
        let reg = loc.registry()?;
        app::decompile(&input, &reg, &engine, true, MAX_DECOMPILE_OUTPUT, &ctx)
    })
}

/// Lines of decompiled text for virtualized display (the text can be hundreds of KB).
pub fn split_lines(text: &str) -> Vec<String> {
    text.lines().map(str::to_string).collect()
}

/// Display name of a path without directories, for headers and the log.
pub fn file_label(p: &Path) -> String {
    p.file_name().map_or_else(|| "(unnamed)".to_string(), |n| n.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnidecomp_testsamples::{fake_engine_path, java_class, minimal_pe64, pe64_dotnet};

    struct Env {
        dir: tempfile::TempDir,
        loc: Locations,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let plugins = dir.path().join("plugins");
        let p = plugins.join("fake");
        std::fs::create_dir_all(p.join("bin")).unwrap();
        let exe = format!("bin/fake-engine{}", std::env::consts::EXE_SUFFIX);
        std::fs::copy(fake_engine_path(), p.join(&exe)).unwrap();
        std::fs::write(
            p.join("plugin.json"),
            format!(
                r#"{{"id":"fake","name":"Fake engine","version":"0.3.0","api_version":1,"license":"MIT","source":"tests",
                "kind":"decompiler","runtimes":["dotnet","java"],"command":"{exe}","args":["ok","{{input}}"]}}"#
            ),
        )
        .unwrap();
        let loc = Locations { dir: plugins, state: Some(dir.path().join("cfg").join("plugins.json")) };
        Env { dir, loc }
    }

    fn wait<T>(mut j: Job<T>) -> Result<T, Error> {
        let t = std::time::Instant::now();
        loop {
            if let Some(r) = j.poll() {
                return r;
            }
            assert!(t.elapsed() < Duration::from_secs(60), "job did not finish");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn file(e: &Env, name: &str, bytes: Vec<u8>) -> PathBuf {
        let p = e.dir.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn table_enable_disable_round_trip_and_decompiler_choices() {
        let e = env();
        let rows = plugin_rows(&e.loc).unwrap();
        assert_eq!(rows.iter().filter(|r| r.origin == "builtin").count(), 7);
        assert!(enabled_decompilers(&rows).is_empty(), "external plugins start disabled");
        set_plugin_enabled(&e.loc, "fake", true).unwrap();
        let rows = plugin_rows(&e.loc).unwrap();
        assert_eq!(enabled_decompilers(&rows).iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["fake"]);
        set_plugin_enabled(&e.loc, "fake", false).unwrap();
        assert!(enabled_decompilers(&plugin_rows(&e.loc).unwrap()).is_empty());
        assert_eq!(set_plugin_enabled(&e.loc, "nope", true).unwrap_err().code, ErrorCode::UnknownPlugin);
        set_plugin_enabled(&e.loc, "runtime-java", false).unwrap();
        let rows = plugin_rows(&e.loc).unwrap();
        assert_eq!(rows.iter().find(|r| r.id == "runtime-java").unwrap().status, "disabled");
    }

    #[test]
    fn saving_needs_a_state_file() {
        let e = env();
        let loc = Locations { state: None, ..e.loc.clone() };
        assert_eq!(set_plugin_enabled(&loc, "fake", true).unwrap_err().code, ErrorCode::InvalidArgument);
        assert!(plugin_rows(&loc).is_ok(), "reading still works");
    }

    #[test]
    fn plan_shows_the_program_and_runs_nothing() {
        let e = env();
        let dll = file(&e, "a.dll", pe64_dotnet());
        // Not enabled: refused before anything else.
        let err = wait(plan_decompile(dll.clone(), e.loc.clone(), "fake".into(), || {})).unwrap_err();
        assert_eq!(err.code, ErrorCode::PluginDisabled);
        set_plugin_enabled(&e.loc, "fake", true).unwrap();
        let plan = wait(plan_decompile(dll.clone(), e.loc.clone(), "fake".into(), || {})).unwrap();
        assert_eq!((plan.engine.as_str(), plan.runtime, plan.engine_version.as_str()), ("fake", "dotnet", "0.3.0"));
        assert!(plan.program.contains("fake-engine"), "{}", plan.program);
        let class = file(&e, "A.class", java_class());
        assert_eq!(wait(plan_decompile(class, e.loc.clone(), "fake".into(), || {})).unwrap().runtime, "java");
        // Native code has no decompiler.
        let exe = file(&e, "n.exe", minimal_pe64());
        assert_eq!(wait(plan_decompile(exe, e.loc.clone(), "fake".into(), || {})).unwrap_err().code, ErrorCode::UnsupportedFormat);
    }

    #[test]
    fn decompile_runs_after_plan_and_catches_a_program_changed_in_between() {
        let e = env();
        let dll = file(&e, "a.dll", pe64_dotnet());
        set_plugin_enabled(&e.loc, "fake", true).unwrap();
        let plan = wait(plan_decompile(dll, e.loc.clone(), "fake".into(), || {})).unwrap();
        let r = wait(start_decompile(&plan, e.loc.clone(), || {})).unwrap();
        assert!(r.text.contains("decompiled by fake-engine"), "{}", r.text);
        assert_eq!((r.engine.as_str(), r.runtime), ("fake", "dotnet"));

        let mut bytes = std::fs::read(&plan.program).unwrap();
        bytes.push(0);
        std::fs::write(&plan.program, bytes).unwrap();
        let err = wait(start_decompile(&plan, e.loc.clone(), || {})).unwrap_err();
        assert_eq!(err.code, ErrorCode::PluginIncompatible);
    }

    #[test]
    fn a_disabled_runtime_plugin_blocks_the_plan_and_loading() {
        let e = env();
        let dll = file(&e, "a.dll", pe64_dotnet());
        set_plugin_enabled(&e.loc, "fake", true).unwrap();
        set_plugin_enabled(&e.loc, "runtime-dotnet", false).unwrap();
        assert_eq!(wait(plan_decompile(dll, e.loc.clone(), "fake".into(), || {})).unwrap_err().code, ErrorCode::PluginDisabled);

        let exe = file(&e, "n.exe", minimal_pe64());
        let cancel = Arc::new(AtomicBool::new(false));
        assert!(crate::load_gated(&exe, Limits::default(), &cancel, &|_| {}, Some(&e.loc)).is_ok());
        set_plugin_enabled(&e.loc, "format-pe", false).unwrap();
        let err = crate::load_gated(&exe, Limits::default(), &cancel, &|_| {}, Some(&e.loc)).err().unwrap();
        assert_eq!(err.code, ErrorCode::PluginDisabled);
        assert!(crate::load_gated(&exe, Limits::default(), &cancel, &|_| {}, None).is_ok(), "ungated load is unaffected");
    }

    #[test]
    fn cancelling_a_running_job_stops_the_engine() {
        let e = env();
        // Rewrite the plugin so the stand-in sleeps.
        let mf = e.loc.dir.join("fake").join("plugin.json");
        let s = std::fs::read_to_string(&mf).unwrap().replace("\"ok\"", "\"sleep\"");
        std::fs::write(&mf, s).unwrap();
        let dll = file(&e, "a.dll", pe64_dotnet());
        set_plugin_enabled(&e.loc, "fake", true).unwrap();
        let plan = wait(plan_decompile(dll, e.loc.clone(), "fake".into(), || {})).unwrap();
        let job = start_decompile(&plan, e.loc.clone(), || {});
        std::thread::sleep(Duration::from_millis(300));
        let t = std::time::Instant::now();
        job.cancel();
        let err = wait(job).unwrap_err();
        assert_eq!(err.code, ErrorCode::Cancelled);
        assert!(t.elapsed() < Duration::from_secs(5), "cancel took {:?}", t.elapsed());
    }

    #[test]
    fn long_output_is_split_for_virtualized_display() {
        let lines = split_lines(&"x\n".repeat(50_000));
        assert_eq!(lines.len(), 50_000);
        assert_eq!(file_label(Path::new("C:\\a\\b\\c.dll")), if cfg!(windows) { "c.dll" } else { "C:\\a\\b\\c.dll" });
    }

    /// Manual check with the real ilspycmd: `OMNIDECOMP_REAL_DLL=<assembly> cargo test -p omnidecomp-viewmodel -- --ignored real_ilspycmd`.
    /// Uses the shipped plugin manifest, a temporary state file, and the same two calls the GUI makes.
    #[test]
    #[ignore = "needs ilspycmd on PATH and OMNIDECOMP_REAL_DLL"]
    fn real_ilspycmd_through_the_gui_calls() {
        let dll = PathBuf::from(std::env::var_os("OMNIDECOMP_REAL_DLL").expect("set OMNIDECOMP_REAL_DLL"));
        let dir = tempfile::tempdir().unwrap();
        let loc = Locations {
            dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../plugins"),
            state: Some(dir.path().join("plugins.json")),
        };
        set_plugin_enabled(&loc, "ilspycmd", true).unwrap();
        let plan = wait(plan_decompile(dll, loc.clone(), "ilspycmd".into(), || {})).unwrap();
        eprintln!("program: {}", plan.program);
        let r = wait(start_decompile(&plan, loc, || {})).unwrap();
        eprintln!("{} lines from {} {}", split_lines(&r.text).len(), r.engine, r.engine_version);
        assert!(r.text.contains("class"), "{}", &r.text[..r.text.len().min(300)]);
        assert!(r.text.chars().all(|c| c != char::from(13u8)), "carriage returns survived");
    }
}
