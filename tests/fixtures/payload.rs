//! Standalone executable oracle, compiled by rustc without project dependencies.

use std::{env, io::{self, Read, Write}, os::unix::ffi::OsStrExt, process::ExitCode};

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    let mode = args.get(1).and_then(|a| a.to_str()).unwrap_or("context");
    match mode {
        "exit" => ExitCode::from(args[2].to_str().unwrap().parse::<u8>().unwrap()),
        "key-environment" => {
            println!("{}", env::var_os("PS_KEY_FILE").is_some());
            ExitCode::SUCCESS
        }
        "pid" | "wait" => {
            println!("{}", std::process::id());
            io::stdout().flush().unwrap();
            if mode == "wait" {
                let mut byte = [0];
                let _ = io::stdin().read_exact(&mut byte);
            }
            ExitCode::SUCCESS
        }
        _ => {
            let label = if cfg!(variant_a) { b"a" } else { b"b" };
            let mut out = io::stdout().lock();
            out.write_all(label).unwrap();
            out.write_all(&[0]).unwrap();
            for arg in args {
                out.write_all(arg.as_bytes()).unwrap();
                out.write_all(&[0]).unwrap();
            }
            if let Some(value) = env::var_os("FATELF_PROBE") {
                out.write_all(value.as_bytes()).unwrap();
            }
            ExitCode::SUCCESS
        }
    }
}
