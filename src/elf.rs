//! ELF validation and file-backed section selection using the object parser.

use std::mem::size_of;
#[cfg(feature = "builder")]
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::Read,
    ops::Range,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[cfg(feature = "builder")]
use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ReadCache, ReadRef,
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
        let file = open_bounded(path, limit)?;
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(Error::Invalid("ELF exceeds input budget".into()));
        }
        header_length(&bytes)?;
        let elf = object::File::parse(bytes.as_slice())?;
        validate_executable(&elf, path)?;
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

/// Open a bounded regular ELF input, including when a pathname names a FIFO.
#[cfg(feature = "builder")]
fn open_bounded(path: &Path, max_bytes: u64) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(Error::Invalid(format!(
            "{} is not a regular file within the input budget",
            path.display()
        )));
    }
    Ok(file)
}

/// Check admission rules shared by packing and diagnostics.
#[cfg(feature = "builder")]
fn validate_executable<'data, R: ReadRef<'data>>(
    elf: &object::File<'data, R>,
    path: &Path,
) -> Result<(), Error> {
    if elf.format() != BinaryFormat::Elf
        || !matches!(elf.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
    {
        return Err(Error::Invalid(format!(
            "{} is not an executable ELF",
            path.display()
        )));
    }
    if elf.architecture() == Architecture::X86_64 && elf.entry() == 0 {
        return Err(Error::Invalid(format!(
            "{} has no executable entry point",
            path.display()
        )));
    }
    Ok(())
}

/// ELF diagnostics read only metadata and retain no payload body.
#[cfg(feature = "builder")]
pub(crate) struct ElfMetadata {
    pub(crate) architecture: Architecture,
    pub(crate) little_endian: bool,
    pub(crate) interpreter: Option<Vec<u8>>,
    pub(crate) codecs: Option<crate::capabilities::LauncherCodecs>,
}

#[cfg(feature = "builder")]
impl ElfMetadata {
    /// Load program headers and optional launcher capabilities through bounded cached reads.
    pub(crate) fn read(path: &Path, max_bytes: u64, launcher: bool) -> Result<Self, Error> {
        let cache = ReadCache::new(open_bounded(path, max_bytes.min(MAX_PAYLOAD))?);
        let remaining = Cell::new(16 * 1024 * 1024);
        let data = MetadataReader(&cache, &remaining);
        let header = data
            .len()
            .and_then(|len| data.read_bytes_at(0, len.min(64)))
            .map_err(|_| Error::Invalid("could not read ELF header".into()))?;
        header_length(header)?;
        let elf = object::File::parse(data)?;
        validate_executable(&elf, path)?;
        let interpreter = match &elf {
            object::File::Elf32(file) => interpreter(file)?,
            object::File::Elf64(file) => interpreter(file)?,
            _ => None,
        };
        Ok(Self {
            architecture: elf.architecture(),
            little_endian: elf.is_little_endian(),
            interpreter: interpreter.map(<[u8]>::to_vec),
            codecs: launcher
                .then(|| crate::capabilities::launcher_codecs(&elf))
                .transpose()?,
        })
    }

    /// Compare input and launcher execution architecture.
    pub(crate) fn matches(&self, launcher: &Self) -> bool {
        self.architecture == launcher.architecture && self.little_endian == launcher.little_endian
    }
}

/// Cap metadata read requests before the underlying cache allocates a buffer.
#[cfg(feature = "builder")]
#[derive(Clone, Copy)]
struct MetadataReader<'a>(&'a ReadCache<File>, &'a Cell<u64>);

#[cfg(feature = "builder")]
impl<'a> ReadRef<'a> for MetadataReader<'a> {
    fn len(self) -> Result<u64, ()> {
        self.0.len()
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        self.1.set(self.1.get().checked_sub(size).ok_or(())?);
        self.0.read_bytes_at(offset, size)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        if range.end > self.len()? {
            return Err(());
        }
        let limit = range.end.checked_sub(range.start).ok_or(())?.min(4096);
        self.1.set(self.1.get().checked_sub(limit).ok_or(())?);
        self.0
            .read_bytes_at_until(range.start..range.start + limit, delimiter)
    }
}

/// Read PT_INTERP through the same object reader for ELF32 and ELF64.
#[cfg(feature = "builder")]
fn interpreter<'data, E: FileHeader, R: ReadRef<'data>>(
    file: &ElfFile<'data, E, R>,
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
