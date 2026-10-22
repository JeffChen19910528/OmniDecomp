//! Stand-in decompiler for plugin tests. `fake-engine <mode> <file>`; never part of the product.

use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("ok", String::as_str);
    let file = args.get(2).cloned().unwrap_or_default();
    match mode {
        "ok" => {
            let len = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            println!("// decompiled by fake-engine\n// input bytes: {len}\n\u{1b}[31mescape\u{1b}[0m");
        }
        "env" => println!("token={:?} path_set={}", std::env::var("SECRET_TOKEN").ok(), std::env::var_os("PATH").is_some()),
        "args" => println!("argv={:?}", &args[1..]),
        "fail" => {
            eprintln!("boom: cannot decompile");
            std::process::exit(3);
        }
        "sleep" => std::thread::sleep(std::time::Duration::from_secs(60)),
        "flood" => {
            let chunk = vec![b'A'; 64 * 1024];
            let mut out = std::io::stdout();
            for _ in 0..100_000 {
                if out.write_all(&chunk).is_err() {
                    break;
                }
            }
        }
        _ => std::process::exit(9),
    }
}
