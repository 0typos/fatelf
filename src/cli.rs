//! Packer commands and concise machine-readable container inspection.

use std::{
    ffi::OsString,
    io::{self, Write},
    os::unix::process::CommandExt,
    path::{PathBuf, absolute},
    process::Command as ProcessCommand,
};

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::{
    codec::{StoredCodec, random_xor_mask},
    config::Document,
    container::Container,
    doctor,
    error::Error,
    pack::{PackOptions, extract},
    tui,
};

/// User-facing commands; runtime payload selection lives solely in the launcher.
#[derive(Parser)]
#[command(
    version,
    about = "Pack selectable, byte-exact Linux ELF executables into one binary"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Build a container or inspect/recover one without executing its payloads.
#[derive(Subcommand)]
enum Command {
    /// Build a new executable container.
    Pack(Box<PackOptions>),
    /// Build from a TOML file; relative paths use the config's directory.
    Build {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Validate and measure a build without publishing its executable.
    Plan {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Diagnose build inputs and host conditions without launching payloads.
    Doctor {
        #[arg(short, long)]
        config: PathBuf,
        /// Emit a versioned JSON report.
        #[arg(long)]
        json: bool,
        /// Try allocating an empty executable memfd when configured.
        #[arg(long)]
        probe: bool,
        /// Treat deployment warnings as failures.
        #[arg(long)]
        strict: bool,
    },
    /// Edit build settings interactively, save TOML, and optionally run build.
    Configure {
        /// Existing config to edit; its file may be replaced on Save.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Destination (defaults to the loaded config, or bundle.toml).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Generate a random public XOR mask for a TOML storage table.
    XorMask { length: usize },
    /// Print selection policy, payloads, and storage statistics as JSON.
    Inspect { input: PathBuf },
    /// Verify every payload without running it or writing extracted files.
    Verify { input: PathBuf },
    /// Run one trusted bundle variant with explicit smoke-test arguments.
    Smoke {
        input: PathBuf,
        #[arg(long)]
        variant: String,
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Recover an original executable byte-for-byte to a new output path.
    Extract {
        input: PathBuf,
        #[arg(long)]
        variant: String,
        #[arg(short, long)]
        output: PathBuf,
    },
}

/// Parse and execute the requested packer operation.
pub(crate) fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::Pack(options) => options.pack(),
        Command::XorMask { length } => {
            let mask = random_xor_mask(length)?;
            writeln!(io::stdout().lock(), "xor_mask = {mask:?}")?;
            Ok(())
        }
        Command::Build { config } => Document::load(&config)?.build(),
        Command::Plan { config } => {
            let document = Document::load(&config)?;
            let options = document.config.options(
                document
                    .path
                    .parent()
                    .expect("invariant: canonical config parent"),
            )?;
            let mut stdout = io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &options.plan()?)?;
            writeln!(stdout)?;
            Ok(())
        }
        Command::Doctor {
            config,
            json,
            probe,
            strict,
        } => doctor::run(&config, json, probe, strict),
        Command::Configure { config, output } => tui::run(config.as_deref(), output.as_deref()),
        Command::Extract {
            input,
            variant,
            output,
        } => extract(&input, &variant, &output),
        Command::Smoke {
            input,
            variant,
            args,
        } => {
            let path = absolute(&input)?;
            let container = Container::open_path(&path)?;
            container.payload_index(&variant)?;
            let selector = container.manifest.select_env.clone();
            drop(container);
            Err(ProcessCommand::new(path)
                .arg0(input)
                .args(args)
                .env(selector, variant)
                .exec()
                .into())
        }
        Command::Verify { input } => {
            let mut container = Container::open_path(&input)?;
            let mut output = io::sink();
            for index in 0..container.manifest.payloads.len() {
                container.reconstruct(index, &mut output).map_err(|error| {
                    let name = &container.manifest.payloads[index].name;
                    error.context(format!("verifying payload {name:?}"))
                })?;
            }
            Ok(())
        }
        Command::Inspect { input } => {
            let container = Container::open_path(&input)?;
            let manifest = &container.manifest;
            let logical_bytes: u64 = manifest.payloads.iter().map(|p| p.length).sum();
            let summary = json!({
                "version": manifest.version,
                "select_env": manifest.select_env,
                "default": manifest.default,
                "exec": manifest.backend,
                "manifest_position": manifest.manifest_position,
                "launcher_bytes": container.launcher_length,
                "manifest_bytes": container.manifest_length,
                "pool_offset": container.pool_start,
                "encrypted_objects": manifest.chunks.iter().filter(|chunk| chunk.encryption.is_some()).count(),
                "lz4_objects": manifest.chunks.iter().filter(|chunk| chunk.codec == StoredCodec::Lz4Block).count(),
                "zstd_objects": manifest.chunks.iter().filter(|chunk| chunk.codec.uses_zstd()).count(),
                "delta_objects": manifest.chunks.iter().filter(|chunk| matches!(chunk.codec, StoredCodec::ZstdDelta { .. })).count(),
                "logical_bytes": logical_bytes,
                "stored_bytes": container.pool_length,
                "unique_chunks": manifest.chunks.len(),
                "payloads": manifest.payloads.iter().map(|p| json!({
                    "name": p.name, "length": p.length, "hash": p.hash,
                    "chunk_references": p.chunks.len()
                })).collect::<Vec<_>>()
            });
            let mut stdout = io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &summary)?;
            writeln!(stdout)?;
            Ok(())
        }
    }
}
