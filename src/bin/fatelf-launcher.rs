//! Entry point prepended to the container's payload pool.

use std::error::Error as _;

fn main() {
    if let Err(error) = fatelf::run_launcher() {
        eprint!("fatelf: {error}");
        let mut source = error.source();
        while let Some(cause) = source {
            eprint!(": {cause}");
            source = cause.source();
        }
        eprintln!();
        std::process::exit(1);
    }
}
