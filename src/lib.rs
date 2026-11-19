//! Build and launch Linux containers of byte-exact ELF payloads.

#[cfg(not(target_os = "linux"))]
compile_error!("fatelf currently supports Linux only");

mod capabilities;
#[cfg(feature = "builder")]
mod cli;
mod codec;
#[cfg(feature = "builder")]
mod config;
mod container;
#[cfg(feature = "builder")]
mod doctor;
mod elf;
mod error;
mod launch;
#[cfg(feature = "builder")]
mod pack;
#[cfg(feature = "builder")]
mod tui;

#[cfg(feature = "fuzzing")]
use container::{FOOTER_LEN, Footer, MAGIC};
#[cfg(feature = "fuzzing")]
use std::io::{Cursor, sink};

pub use error::Error;

/// Run the packer command line, including inspection, verification, and extraction.
#[cfg(feature = "builder")]
pub fn run_cli() -> Result<(), Error> {
    cli::run()
}

/// Select and execute the payload attached to the running launcher.
pub fn run_launcher() -> Result<(), Error> {
    capabilities::retain();
    launch::run()
}

/// Exercise both container metadata validation and reconstruction for fuzzing.
#[cfg(feature = "fuzzing")]
pub fn fuzz_container(bytes: &[u8]) {
    // Exercise codec input directly even when container mutations fail metadata validation.
    if let Some(prefix) = bytes.get(..3) {
        let decoded_length = usize::from(u16::from_le_bytes([prefix[1], prefix[2]])) + 1;
        let codec = if prefix[0] & 1 == 0 {
            codec::StoredCodec::Raw
        } else {
            codec::StoredCodec::Lz4Block
        };
        let encoding = if prefix[0] & 4 != 0 {
            codec::Encoding::XorA5
        } else if prefix[0] & 2 == 0 {
            codec::Encoding::Identity
        } else {
            codec::Encoding::ElfHeaderXorA5
        };
        let _ = codec::decode(bytes[3..].to_vec(), decoded_length, codec, encoding);
        #[cfg(feature = "encryption")]
        let _ = codec::decrypt(&mut bytes[3..].to_vec(), &[0; 32], &[0; 24], &[0; 32], 0);
    }
    let exercise = |input: &[u8]| {
        if let Ok(mut container) = container::Container::open(Cursor::new(input)) {
            for index in 0..container.manifest.payloads.len() {
                // Fuzzing never resolves process environment names into arbitrary key files.
                if container.manifest.payloads[index]
                    .chunks
                    .iter()
                    .any(|&id| container.manifest.chunks[id].encryption.is_some())
                {
                    continue;
                }
                let _ = container.reconstruct(index, &mut sink());
            }
        }
    };
    exercise(bytes);
    // Also repair the manifest digest so mutations exercise semantic validation
    // instead of always stopping at the integrity boundary. Fuzz builds only.
    let Some(footer_start) = bytes.len().checked_sub(FOOTER_LEN as usize) else {
        return;
    };
    let Ok(mut footer) = Footer::decode_exact(&bytes[footer_start..]) else {
        return;
    };
    if &footer.magic != MAGIC {
        return;
    }
    let Ok(start) = usize::try_from(footer.manifest_start) else {
        return;
    };
    let Ok(length) = usize::try_from(footer.manifest_length) else {
        return;
    };
    let Some(end) = start.checked_add(length).filter(|end| *end <= footer_start) else {
        return;
    };
    let Some(manifest) = bytes.get(start..end) else {
        return;
    };
    footer.manifest_hash = *blake3::hash(manifest).as_bytes();
    if let Ok(encoded) = footer.to_bytes() {
        let mut repaired = bytes.to_vec();
        repaired[footer_start..].copy_from_slice(&encoded);
        exercise(&repaired);
    }
}

/// Exercise bounded TOML decoding and shared semantic checks without filesystem access.
#[cfg(feature = "fuzzing")]
pub fn fuzz_config(bytes: &[u8]) {
    if bytes.len() <= config::MAX_CONFIG
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        let _ = config::BuildConfig::parse(text);
    }
}
