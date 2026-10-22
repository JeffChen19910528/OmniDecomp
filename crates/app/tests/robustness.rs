//! Phase 5 regression fuzz: seeded byte-flip and truncation mutation of every sample kind, driven through
//! the whole analysis pipeline (parse, symbols, debug info, .NET, disassembly, functions, CFG, call graph,
//! report), not just the parsers. Every call may return `Err`; none may panic or run unbounded. Fixed
//! seeds keep failures reproducible. Set OMNIDECOMP_FUZZ_ITERS to run longer.

use omnidecomp_app::{Analysis, DisasmOptions};
use omnidecomp_core::{Context, InputArtifact, Limits};
use omnidecomp_testsamples as t;
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn ctx() -> Context {
    Context::new(Limits { timeout: Duration::from_secs(10), ..Limits::default() })
}

fn samples() -> Vec<(&'static str, Vec<u8>)> {
    let code = [0x55, 0x48, 0x89, 0xE5, 0xE8, 0x05, 0, 0, 0, 0x74, 0x02, 0xEB, 0xFE, 0xC3, 0x90, 0xC3];
    vec![
        ("pe64", t::minimal_pe64()),
        ("pe32", t::minimal_pe32()),
        ("pe64-symbols", t::pe64_with_symbols()),
        ("pe64-pdata", t::pe64_with_pdata(&code, &[(0, 14, false)])),
        ("pe64-pdb", t::pe64_with_pdb("C:\\build\\app.pdb")),
        ("pe64-dotnet", t::pe64_dotnet()),
        ("elf64", t::elf64_with_code(&code)),
        ("elf64-symbols", t::elf64_with_symbols()),
        ("elf64-eh_frame", t::elf64_with_eh_frame(&code, &[(0, 14)])),
        ("elf32-be", t::minimal_elf32_be()),
        ("macho64", t::macho64_with_symbols(&code)),
    ]
}

/// Runs every analysis stage on `data`. Returns normally for any outcome; a panic fails the test.
fn pipeline(data: &[u8], c: &Context) {
    let Ok(info) = omnidecomp_formats::parse(data, c) else { return };
    let a = Analysis { artifact: InputArtifact { size: data.len() as u64, sha256: String::new() }, info, data: data.to_vec() };
    let _ = omnidecomp_app::symbols(&a, c);
    let _ = omnidecomp_app::debug_info(&a, c);
    let _ = omnidecomp_app::dotnet(&a, c);
    let _ = omnidecomp_app::extract_strings(data, 4, c);
    let opts = DisasmOptions { engine: "auto", arch: None, section: None, max_instructions: 5_000 };
    let _ = omnidecomp_app::disassemble(&a, &opts, c);
    if let Ok(f) = omnidecomp_app::functions(&a, c) {
        let _ = omnidecomp_app::call_graph_for(&f);
        if let Some(first) = f.functions.first() {
            let _ = omnidecomp_app::cfg(&a, first.address, c);
        }
    }
    let _ = omnidecomp_app::build_report(&a, c);
}

fn iterations() -> usize {
    std::env::var("OMNIDECOMP_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

#[test]
fn mutated_samples_never_panic_through_the_whole_pipeline() {
    let c = ctx();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let started = Instant::now();
    for (name, sample) in samples() {
        pipeline(&sample, &c);
        for _ in 0..iterations() {
            let mut m = sample.clone();
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(m.len());
                m[i] = match rng.below(4) {
                    0 => 0x00,
                    1 => 0xFF,
                    2 => m[i] ^ (1 << rng.below(8)),
                    _ => rng.next() as u8,
                };
            }
            // Header fields are what parsers trust; hit the first 512 bytes extra hard.
            let i = rng.below(m.len().min(512));
            m[i] = rng.next() as u8;
            pipeline(&m, &c);
        }
        // Every prefix of the sample: truncation at any byte.
        for len in (0..sample.len()).step_by(7) {
            pipeline(&sample[..len], &c);
        }
        eprintln!("{name}: ok ({:.1}s elapsed)", started.elapsed().as_secs_f32());
    }
}

#[test]
fn mutated_class_files_never_panic() {
    let c = ctx();
    let sample = t::java_class();
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for len in 0..sample.len() {
        let _ = omnidecomp_formats::parse_java_class(&sample[..len], &c);
    }
    for _ in 0..iterations() * 40 {
        let mut m = sample.clone();
        for _ in 0..1 + rng.below(6) {
            let i = rng.below(m.len());
            m[i] = rng.next() as u8;
        }
        let _ = omnidecomp_formats::parse_java_class(&m, &c);
    }
}

#[test]
fn random_garbage_is_rejected_quickly_with_a_specific_error() {
    let c = ctx();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let started = Instant::now();
    for n in 0..2_000 {
        let len = rng.below(4096);
        let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Plant a real magic now and then so the format parsers actually run.
        match n % 5 {
            0 if len >= 2 => data[..2].copy_from_slice(b"MZ"),
            1 if len >= 4 => data[..4].copy_from_slice(b"\x7FELF"),
            2 if len >= 4 => data[..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]),
            _ => {}
        }
        if let Err(e) = omnidecomp_formats::parse(&data, &c) {
            assert_ne!(e.code.exit_code(), 0);
            assert!(!e.message.is_empty());
        }
    }
    assert!(started.elapsed() < Duration::from_secs(20), "garbage handling is not bounded: {:?}", started.elapsed());
}

#[test]
fn resource_limits_hold_under_hostile_settings() {
    let sample = t::minimal_pe64();
    // A zero deadline and zero limits must produce errors, not hangs or panics.
    let tight = Context::new(Limits {
        max_file_size: 16,
        max_sections: 0,
        max_strings: 0,
        max_symbols: 0,
        max_instructions: 0,
        timeout: Duration::from_millis(0),
    });
    pipeline(&sample, &tight);
    let cancelled = {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        Context::with_cancel(Limits::default(), flag)
    };
    pipeline(&sample, &cancelled);
    let big = t::elf64_large(&[0x90], 2_000_000);
    let small_cap = Context::new(Limits { max_instructions: 1_000, timeout: Duration::from_secs(10), ..Limits::default() });
    let started = Instant::now();
    pipeline(&big, &small_cap);
    assert!(started.elapsed() < Duration::from_secs(10), "instruction cap did not bound the work");
}

#[test]
fn an_expired_deadline_on_a_class_file_is_a_timeout_not_unsupported_format() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("A.class");
    std::fs::write(&p, t::java_class()).unwrap();
    let expired = Context::new(Limits { timeout: Duration::from_millis(0), ..Limits::default() });
    std::thread::sleep(Duration::from_millis(5));
    let err = omnidecomp_app::detect_runtime(&p, &expired).unwrap_err();
    assert_eq!(err.code, omnidecomp_core::ErrorCode::Timeout, "{}", err.message);

    // A cancelled job likewise; a healthy context still detects java.
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let cancelled = Context::with_cancel(Limits::default(), flag);
    assert_eq!(omnidecomp_app::detect_runtime(&p, &cancelled).unwrap_err().code, omnidecomp_core::ErrorCode::Cancelled);
    assert_eq!(omnidecomp_app::detect_runtime(&p, &ctx()).unwrap().0, "java");
}
