//! Explicit format and decoder capabilities carried in each matching launcher.

#[cfg(feature = "builder")]
use crate::error::Error;
#[cfg(feature = "builder")]
use object::{Object, ObjectSection};

const COMPRESSION: u8 = 1;
const ENCRYPTION: u8 = 2;
const ZSTANDARD: u8 = 4;

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
        | (cfg!(feature = "encryption") as u8 * ENCRYPTION)
        | (cfg!(feature = "zstandard") as u8 * ZSTANDARD),
    0,
    0,
    0,
    0,
    0,
    0,
    0,
];

const IDENTITY_TAG: &[u8; 8] = b"FATID01\0";
const IDENTITY_FIELD_SIZE: usize = 65;

#[used]
#[unsafe(link_section = ".fatelf.identity")]
static IDENTITY: [u8; IDENTITY_TAG.len() + 2 * IDENTITY_FIELD_SIZE] = {
    let mut bytes = [0; IDENTITY_TAG.len() + 2 * IDENTITY_FIELD_SIZE];
    let (tag, _) = bytes.split_at_mut(IDENTITY_TAG.len());
    tag.copy_from_slice(IDENTITY_TAG);
    bytes
};

/// Keep the launcher metadata reachable when the runtime is linked and stripped.
pub(crate) fn retain() {
    std::hint::black_box((&DESCRIPTOR, &IDENTITY));
}

/// Fill the identity slot in a copy of an unbundled launcher.
#[cfg(feature = "builder")]
pub(crate) fn set_launcher_identity(
    bytes: &mut [u8],
    name: Option<&str>,
    version: Option<&str>,
) -> Result<(), Error> {
    let elf = object::File::parse(&*bytes)?;
    let mut sections = elf
        .sections()
        .filter(|section| section.name() == Ok(".fatelf.identity"));
    let slot = sections.next().ok_or_else(|| {
        Error::Invalid(
            "launcher lacks a build identity slot; install the launcher paired with this fatelf"
                .into(),
        )
    })?;
    let invalid = || Error::Invalid("invalid launcher build identity slot".into());
    if sections.next().is_some() || slot.data()? != IDENTITY {
        return Err(invalid());
    }
    let (offset, _) = slot.file_range().ok_or_else(invalid)?;
    let offset = usize::try_from(offset).map_err(|_| invalid())?;
    let fields = bytes
        .get_mut(offset..)
        .and_then(|slot| slot.get_mut(IDENTITY_TAG.len()..IDENTITY.len()))
        .ok_or_else(invalid)?;
    let (name_field, version_field) = fields.split_at_mut(IDENTITY_FIELD_SIZE);
    for (field, value) in [(name_field, name), (version_field, version)] {
        if let Some(value) = value {
            let prefix = field
                .get_mut(..IDENTITY_FIELD_SIZE - 1)
                .and_then(|field| field.get_mut(..value.len()))
                .ok_or_else(invalid)?;
            prefix.copy_from_slice(value.as_bytes());
        }
    }
    Ok(())
}

/// Decoder options of a launcher with the current compatibility revision.
#[cfg(feature = "builder")]
pub(crate) struct LauncherCodecs {
    pub(crate) compression: bool,
    pub(crate) encryption: bool,
    pub(crate) zstandard: bool,
}

#[cfg(feature = "builder")]
impl LauncherCodecs {
    /// Check the optional codecs actually used by the prepared bundle.
    pub(crate) fn validate(&self, required: Self) -> Result<(), Error> {
        if required.compression && !self.compression
            || required.encryption && !self.encryption
            || required.zstandard && !self.zstandard
        {
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
        || descriptor[8] & !(COMPRESSION | ENCRYPTION | ZSTANDARD) != 0
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
        zstandard: descriptor[8] & ZSTANDARD != 0,
    })
}
