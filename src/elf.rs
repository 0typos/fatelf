//! ELF validation and file-backed section selection using the object parser.

use std::mem::size_of;
#[cfg(feature = "builder")]
use std::{fs::OpenOptions, io::Read, ops::Range, os::unix::fs::OpenOptionsExt, path::Path};

#[cfg(feature = "builder")]
use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection,
    read::elf::{ElfFile, ProgramHeader},
};
use object::{
    Endianness,
    elf::{FileHeader32, FileHeader64},
    read::elf::FileHeader,
};

#[cfg(feature = "builder")]
use crate::container::MAX_PAYLOAD;
use crate::error::Error;

/// Parsed ELF plus its original bytes, retained only while packing one input.
#[cfg(feature = "builder")]
pub(crate) struct Elf {
    pub(crate) bytes: Vec<u8>,
    pub(crate) architecture: Architecture,
    pub(crate) little_endian: bool,
}

#[cfg(feature = "builder")]
impl Elf {
    /// Read a bounded input and require an executable ELF, including PIE.
    pub(crate) fn read(path: &Path) -> Result<Self, Error> {
        Self::read_bounded(path, MAX_PAYLOAD)
    }

    /// Apply the build's size limit before allocating an input's bytes.
    pub(crate) fn read_bounded(path: &Path, max_bytes: u64) -> Result<Self, Error> {
        let limit = max_bytes.min(MAX_PAYLOAD);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(Error::Invalid(format!(
                "{} is not a regular file within the input budget",
                path.display()
            )));
        }
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(Error::Invalid("ELF exceeds input budget".into()));
        }
        header_length(&bytes)?;
        let elf = object::File::parse(bytes.as_slice())?;
        if elf.format() != BinaryFormat::Elf
            || !matches!(elf.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
        {
            return Err(Error::Invalid(format!(
                "{} is not an executable ELF",
                path.display()
            )));
        }
        let architecture = elf.architecture();
        let little_endian = elf.is_little_endian();
        Ok(Self {
            bytes,
            architecture,
            little_endian,
        })
    }

    /// Compare the architecture and byte order used by the Linux execution path.
    pub(crate) fn matches(&self, launcher: &Self) -> bool {
        self.architecture == launcher.architecture && self.little_endian == launcher.little_endian
    }

    /// Read the interpreter named by the executable, when it has a PT_INTERP segment.
    pub(crate) fn interpreter(&self) -> Result<Option<&[u8]>, Error> {
        match object::File::parse(self.bytes.as_slice())? {
            object::File::Elf32(file) => interpreter(&file),
            object::File::Elf64(file) => interpreter(&file),
            _ => Err(Error::Invalid("expected an ELF executable".into())),
        }
    }

    /// Return the canonical complete ELF header that must be obscured in storage.
    pub(crate) fn header_length(&self) -> Result<usize, Error> {
        header_length(&self.bytes)
    }

    /// Resolve file ranges from section names, rejecting missing or zero-file-size sections.
    pub(crate) fn section_ranges(&self, names: &[String]) -> Result<Vec<Range<usize>>, Error> {
        let elf = object::File::parse(self.bytes.as_slice())?;
        let mut ranges = Vec::new();
        for name in names {
            let section = elf
                .section_by_name(name)
                .ok_or_else(|| Error::Invalid(format!("ELF section {name:?} does not exist")))?;
            let (offset, length) = section
                .file_range()
                .filter(|(_, length)| *length != 0)
                .ok_or_else(|| {
                    Error::Invalid(format!("ELF section {name:?} has no stored bytes"))
                })?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= self.bytes.len() as u64)
                .ok_or_else(|| Error::Invalid("section range outside ELF".into()))?;
            ranges.push(offset as usize..end as usize);
        }
        Ok(ranges)
    }
}

/// Read PT_INTERP through the same object reader for ELF32 and ELF64.
#[cfg(feature = "builder")]
fn interpreter<'data, E: FileHeader>(
    file: &ElfFile<'data, E>,
) -> Result<Option<&'data [u8]>, Error> {
    for segment in file.elf_program_headers() {
        if let Some(path) = segment.interpreter(file.endian(), file.data())? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

/// Use object to validate class, byte order, version and declared header size.
pub(crate) fn header_length(bytes: &[u8]) -> Result<usize, Error> {
    if let Ok(header) = FileHeader64::<Endianness>::parse(bytes) {
        return checked_header_length(header);
    }
    let header = FileHeader32::<Endianness>::parse(bytes)
        .map_err(|_| Error::Invalid("invalid reconstructed ELF header".into()))?;
    checked_header_length(header)
}

/// Reject noncanonical header extensions rather than masking only a partial header.
fn checked_header_length<H: FileHeader>(header: &H) -> Result<usize, Error> {
    let endian = header
        .endian()
        .map_err(|_| Error::Invalid("invalid ELF byte order".into()))?;
    if usize::from(header.e_ehsize(endian)) != size_of::<H>() {
        return Err(Error::Invalid(
            "noncanonical ELF header size is unsupported".into(),
        ));
    }
    Ok(size_of::<H>())
}
