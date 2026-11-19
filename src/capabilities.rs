//! Explicit format and decoder capabilities carried in each matching launcher.

#[cfg(feature = "builder")]
use crate::error::Error;
#[cfg(feature = "builder")]
use object::{Object, ObjectSection};

const COMPRESSION: u8 = 1;
const ENCRYPTION: u8 = 2;

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
    b'3',
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
    std::hint::black_box(&DESCRIPTOR);
}

/// Decoder options of a launcher with the current compatibility revision.
#[cfg(feature = "builder")]
pub(crate) struct LauncherCodecs {
    pub(crate) compression: bool,
    pub(crate) encryption: bool,
}

#[cfg(feature = "builder")]
impl LauncherCodecs {
    /// Check the optional codecs actually used by the prepared bundle.
    pub(crate) fn validate(&self, required: Self) -> Result<(), Error> {
        if required.compression && !self.compression || required.encryption && !self.encryption {
            return Err(Error::Invalid(
                "launcher does not support the selected codecs".into(),
            ));
        }
        Ok(())
    }
}

/// Read the launcher descriptor without executing it.
#[cfg(feature = "builder")]
pub(crate) fn launcher_codecs<'data>(elf: &impl Object<'data>) -> Result<LauncherCodecs, Error> {
    let mut sections = elf
        .sections()
        .filter(|section| section.name() == Ok(".fatelf"));
    let section = sections
        .next()
        .ok_or_else(|| Error::Invalid("launcher lacks a capability descriptor; rebuild or install the launcher paired with this fatelf".into()))?;
    if section.size() != DESCRIPTOR.len() as u64 {
        return Err(Error::Invalid(
            "invalid launcher capability descriptor".into(),
        ));
    }
    let descriptor = section.data()?;
    if sections.next().is_some()
        || descriptor.len() != 16
        || &descriptor[..6] != b"FATCAP"
        || descriptor[8] & !(COMPRESSION | ENCRYPTION) != 0
        || descriptor[9..].iter().any(|&byte| byte != 0)
    {
        return Err(Error::Invalid(
            "invalid launcher capability descriptor".into(),
        ));
    }
    if descriptor[..8] != DESCRIPTOR[..8] {
        let expected = String::from_utf8_lossy(&DESCRIPTOR[..8]);
        let actual = String::from_utf8_lossy(&descriptor[..8]);
        return Err(Error::Invalid(format!(
            "launcher compatibility revision {actual:?} does not match {expected}; rebuild or install the launcher paired with this fatelf"
        )));
    }
    Ok(LauncherCodecs {
        compression: descriptor[8] & COMPRESSION != 0,
        encryption: descriptor[8] & ENCRYPTION != 0,
    })
}
