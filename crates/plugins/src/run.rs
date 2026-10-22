//! Runs an approved external decompiler as a child process: no shell, cleared environment, no stdin,
//! bounded output, and the job's timeout and cancel flag enforced by killing the child. The analysed file
//! is only passed as a path argument; this host never executes it.

use crate::registry::Resolved;
use omnidecomp_core::{Context, Error, ErrorCode};
use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Environment variables passed through; everything else (tokens, proxies, ...) is dropped.
const ENV_ALLOW: [&str; 10] =
    ["PATH", "SystemRoot", "SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "JAVA_HOME", "DOTNET_ROOT"];

#[derive(Debug)]
pub struct EngineOutput {
    /// Decompiled text. Untrusted: control characters other than newline and tab are replaced.
    pub text: String,
    pub stderr: String,
}

/// Replaces control characters (except \n and \t) so output cannot drive a terminal. Windows line
/// endings (\r\n, which ilspycmd emits) become \n first; a lone \r could overwrite a line, so it is replaced.
pub fn sanitize_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .chars()
        .map(|c| if c.is_control() && c != '\n' && c != '\t' { '?' } else { c })
        .collect()
}

fn substitute(arg: &str, input: &Path) -> OsString {
    let mut out = OsString::new();
    for (i, part) in arg.split("{input}").enumerate() {
        if i > 0 {
            out.push(input);
        }
        out.push(part);
    }
    out
}

/// Reads up to `cap` bytes; sets `over` when more arrives (the caller then kills the child).
fn spawn_reader<R: Read + Send + 'static>(mut r: R, cap: usize, over: Arc<AtomicBool>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            match r.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() + n > cap {
                        buf.extend_from_slice(&chunk[..cap.saturating_sub(buf.len())]);
                        over.store(true, Ordering::Relaxed);
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
        }
        buf
    })
}

pub fn run_decompiler(p: &Resolved, input: &Path, max_output: usize, ctx: &Context) -> Result<EngineOutput, Error> {
    let input = std::path::absolute(input).map_err(|e| Error::new(ErrorCode::Io, format!("cannot resolve input path: {e}")))?;
    let mut cmd = Command::new(&p.exe);
    cmd.args(p.args.iter().map(|a| substitute(a, &input)))
        .current_dir(&p.dir)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for k in ENV_ALLOW {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| Error::new(ErrorCode::ExternalEngineFailed, format!("cannot start engine '{}': {e}", p.id)))?;
    let over = Arc::new(AtomicBool::new(false));
    let out_h = spawn_reader(child.stdout.take().expect("piped"), max_output, Arc::clone(&over));
    let err_h = spawn_reader(child.stderr.take().expect("piped"), 64 * 1024, Arc::new(AtomicBool::new(false)));

    let kill = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
    };
    let status = loop {
        if over.load(Ordering::Relaxed) {
            kill(&mut child);
            return Err(Error::new(ErrorCode::LimitExceeded, format!("engine output exceeded {max_output} bytes; it was stopped")));
        }
        if let Err(e) = ctx.check() {
            kill(&mut child);
            return Err(e);
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                kill(&mut child);
                return Err(Error::new(ErrorCode::ExternalEngineFailed, format!("cannot wait for engine: {e}")));
            }
        }
    };
    let out = out_h.join().unwrap_or_default();
    let err = err_h.join().unwrap_or_default();
    if over.load(Ordering::Relaxed) {
        return Err(Error::new(ErrorCode::LimitExceeded, format!("engine output exceeded {max_output} bytes")));
    }
    let stderr = sanitize_output(&err);
    if !status.success() {
        let snippet: String = stderr.chars().take(500).collect();
        return Err(Error::new(ErrorCode::ExternalEngineFailed, format!("engine '{}' failed ({status}): {}", p.id, snippet.trim())));
    }
    Ok(EngineOutput { text: sanitize_output(&out), stderr })
}
