//! Explicit format and decoder capabilities carried in each matching launcher.

#[cfg(feature = "builder")]
use crate::error::Error;
#[cfg(feature = "builder")]
use object::{Object, ObjectSection};

const COMPRESSION: u8 = 1;
const ENCRYPTION: u8 = 2;

/// Separate marker keeps the original descriptor readable by older builders.
#[used]
#[unsafe(link_section = ".fatelf.xor")]
static XOR_DESCRIPTOR: [u8; 8] = *b"FATXOR01";

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
    (cfg!(feature = "compression") as u8 * COMPRESSION)
        | (cfg!(feature = "encryption") as u8 * ENCRYPTION),
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
    std::hint::black_box((&DESCRIPTOR, &XOR_DESCRIPTOR));
}

/// Reject old or insufficient supplied launchers before constructing a new container.
#[cfg(feature = "builder")]
pub(crate) fn validate_launcher(bytes: &[u8], required: LauncherCodecs) -> Result<(), Error> {
    let supported = launcher_codecs(&object::File::parse(bytes)?)?;
    if required.xor && !supported.xor {
        return Err(Error::Invalid(
            "launcher does not support payload XOR".into(),
        ));
    }
    if required.compression && !supported.compression
        || required.encryption && !supported.encryption
    {
        return Err(Error::Invalid(
            "launcher does not support the selected codecs".into(),
        ));
    }
    Ok(())
}

/// Named decoder support declared by a launcher.
#[cfg(feature = "builder")]
pub(crate) struct LauncherCodecs {
    pub(crate) compression: bool,
    pub(crate) encryption: bool,
    pub(crate) xor: bool,
}

/// Read the launcher descriptor without executing it.
#[cfg(feature = "builder")]
pub(crate) fn launcher_codecs<'data>(elf: &impl Object<'data>) -> Result<LauncherCodecs, Error> {
    let mut sections = elf
        .sections()
        .filter(|section| section.name() == Ok(".fatelf"));
    let section = sections
        .next()
        .ok_or_else(|| Error::Invalid("launcher lacks v2 capability descriptor".into()))?;
    if section.size() != DESCRIPTOR.len() as u64 {
        return Err(Error::Invalid(
            "invalid launcher capability descriptor".into(),
        ));
    }
    let descriptor = section.data()?;
    if sections.next().is_some()
        || descriptor.len() != 16
        || &descriptor[..8] != b"FATCAP02"
        || descriptor[8] & !(COMPRESSION | ENCRYPTION) != 0
        || descriptor[9..].iter().any(|&byte| byte != 0)
    {
        return Err(Error::Invalid(
            "invalid launcher capability descriptor".into(),
        ));
    }
    Ok(LauncherCodecs {
        compression: descriptor[8] & COMPRESSION != 0,
        encryption: descriptor[8] & ENCRYPTION != 0,
        xor: elf
            .section_by_name(".fatelf.xor")
            .is_some_and(|section| section.data() == Ok(XOR_DESCRIPTOR.as_slice())),
    })
}
