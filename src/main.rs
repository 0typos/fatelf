//! Command-line entry point for building containers.

use color_eyre::eyre::Result;

fn main() -> Result<()> {
    color_eyre::install()?;
    fatelf::run_cli()?;
    Ok(())
}
