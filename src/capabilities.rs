//! Explicit format and decoder capabilities carried in each matching launcher.

#[cfg(feature = "builder")]
use crate::error::Error;
#[cfg(feature = "builder")]
use object::{Object, ObjectSection};

/// Allocated descriptor survives stripping; the entrypoint references it as well.
#[used]
#[unsafe(link_section = ".fatelf")]
static DESCRIPTOR: [u8; 16] = [
    b'F',
    b'A',
    b'T',
    b'C',
    b'A',
    b'P',
    b'0',
    b'2',
    (cfg!(feature = "compression") as u8) | ((cfg!(feature = "encryption") as u8) << 1),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

/// Keep the capability descriptor reachable when the runtime is linked and stripped.
pub(crate) fn retain() {
    std::hint::black_box(&DESCRIPTOR);
}

/// Reject old or insufficient supplied launchers before constructing a new container.
#[cfg(feature = "builder")]
pub(crate) fn validate_launcher(
    bytes: &[u8],
    compression: bool,
    encryption: bool,
) -> Result<(), Error> {
    let supported = launcher_codecs(bytes)?;
    let required = u8::from(compression) | (u8::from(encryption) << 1);
    if supported & required != required {
        return Err(Error::Invalid(
            "launcher does not support the selected codecs".into(),
        ));
    }
    Ok(())
}

/// Read the launcher capability bits without executing it.
#[cfg(feature = "builder")]
pub(crate) fn launcher_codecs(bytes: &[u8]) -> Result<u8, Error> {
    let elf = object::File::parse(bytes)?;
    let mut sections = elf
        .sections()
        .filter(|section| section.name() == Ok(".fatelf"));
    let descriptor = sections
        .next()
        .ok_or_else(|| Error::Invalid("launcher lacks v2 capability descriptor".into()))?
        .data()?;
    if sections.next().is_some()
        || descriptor.len() != 16
        || &descriptor[..8] != b"FATCAP02"
        || descriptor[8] & !3 != 0
        || descriptor[9..].iter().any(|&byte| byte != 0)
    {
        return Err(Error::Invalid(
            "invalid launcher capability descriptor".into(),
        ));
    }
    Ok(descriptor[8])
}
