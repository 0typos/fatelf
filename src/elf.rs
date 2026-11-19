//! ELF validation and file-backed section selection using the object parser.

use std::mem::size_of;
#[cfg(feature = "builder")]
use std::{
    cell::Cell,
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::Read,
    ops::Range,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::Path,
};

#[cfg(feature = "builder")]
use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSection, ReadCache, ReadRef, elf,
    read::elf::{Dyn, ElfFile, ProgramHeader},
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
    pub(crate) loader_path_warning: Option<String>,
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
            loader_path_warning: loader_path_warning(&elf)?,
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
        let bytes = self
            .0
            .read_bytes_at_until(range.start..range.start + limit, delimiter)?;
        // ReadCache may return a string cached for a wider range at this offset.
        if bytes.len() as u64 >= limit {
            return Err(());
        }
        Ok(bytes)
    }
}

/// Inspect loader path tags through program headers so section names are optional.
#[cfg(feature = "builder")]
pub(crate) fn loader_path_warning<'data, R: ReadRef<'data>>(
    file: &object::File<'data, R>,
) -> Result<Option<String>, Error> {
    match file {
        object::File::Elf32(file) => dynamic_paths(file),
        object::File::Elf64(file) => dynamic_paths(file),
        _ => Ok(None),
    }
}

/// Identify the first path that can change meaning when the executable moves.
#[cfg(feature = "builder")]
fn dynamic_paths<'data, E: FileHeader, R: ReadRef<'data>>(
    file: &ElfFile<'data, E, R>,
) -> Result<Option<String>, Error> {
    let endian = file.endian();
    let headers = file.elf_program_headers();
    let Some(segment) = headers
        .iter()
        .find(|header| header.p_type(endian) == elf::PT_DYNAMIC)
    else {
        return Ok(None);
    };
    let dynamic = segment.dynamic(endian, file.data())?.unwrap_or_default();
    let terminator = dynamic
        .iter()
        .position(|entry| entry.tag32(endian) == Some(elf::DT_NULL))
        .ok_or_else(|| Error::Invalid("ELF dynamic segment has no DT_NULL terminator".into()))?;
    let entries = dynamic[..terminator].iter();
    let has_runpath = entries
        .clone()
        .any(|entry| entry.tag32(endian) == Some(elf::DT_RUNPATH));
    let paths = entries.clone().filter(|entry| match entry.tag32(endian) {
        Some(elf::DT_NEEDED | elf::DT_RUNPATH) => true,
        Some(elf::DT_RPATH) => !has_runpath,
        _ => false,
    });
    if paths.clone().next().is_none() {
        return Ok(None);
    }
    let value = |tag| -> Result<u64, Error> {
        entries
            .clone()
            .find(|entry| entry.tag32(endian) == Some(tag))
            .map(|entry| entry.d_val(endian).into())
            .ok_or_else(|| Error::Invalid("ELF dynamic string table is missing".into()))
    };
    let address = value(elf::DT_STRTAB)?;
    let size = value(elf::DT_STRSZ)?;
    let base = headers
        .iter()
        .filter(|header| header.p_type(endian) == elf::PT_LOAD)
        .find_map(|header| {
            let delta = address.checked_sub(header.p_vaddr(endian).into())?;
            let (offset, length) = header.file_range(endian);
            (delta.checked_add(size)? <= length).then_some(())?;
            offset.checked_add(delta)
        })
        .ok_or_else(|| {
            Error::Invalid("ELF dynamic string table is outside file-backed segments".into())
        })?;
    let end = base
        .checked_add(size)
        .ok_or_else(|| Error::Invalid("ELF dynamic string table range overflow".into()))?;
    if !file.data().len().is_ok_and(|length| end <= length) {
        return Err(Error::Invalid(
            "ELF dynamic string table is outside the file".into(),
        ));
    }
    for entry in paths {
        let offset = base
            .checked_add(entry.d_val(endian).into())
            .filter(|&offset| offset < end)
            .ok_or_else(|| Error::Invalid("ELF loader path is outside its string table".into()))?;
        let bytes = file
            .data()
            .read_bytes_at_until(offset..end.min(offset.saturating_add(4096)), 0)
            .map_err(|_| Error::Invalid("could not read bounded ELF loader path".into()))?;
        let path = String::from_utf8_lossy(bytes);
        let origin = path.contains("${ORIGIN}")
            || path.match_indices("$ORIGIN").any(|(start, token)| {
                path.as_bytes()
                    .get(start + token.len())
                    .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
            });
        let (tag, relative) = match entry.tag32(endian) {
            Some(elf::DT_NEEDED) => (
                "DT_NEEDED",
                bytes.contains(&b'/') && !bytes.starts_with(b"/"),
            ),
            Some(elf::DT_RUNPATH) => (
                "DT_RUNPATH",
                !path.is_empty() && path.split(':').any(|part| !part.starts_with('/')),
            ),
            _ => (
                "DT_RPATH",
                !path.is_empty() && path.split(':').any(|part| !part.starts_with('/')),
            ),
        };
        let display = OsStr::from_bytes(bytes);
        if origin {
            return Ok(Some(format!(
                "{tag} {display:?} uses $ORIGIN; reconstructed payloads do not retain their original executable directory"
            )));
        }
        if relative {
            return Ok(Some(format!(
                "{tag} {display:?} contains a relative search path; startup can depend on the working directory"
            )));
        }
    }
    Ok(None)
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

#[cfg(all(test, feature = "builder"))]
mod tests {
    use std::{fs, io::Write};

    use object::{Endian, elf, pod};

    use super::*;

    /// Build an ELF header using the field types of the object reader.
    fn header64(machine: u16, endian: Endianness) -> FileHeader64<Endianness> {
        let mut header = *pod::from_bytes::<FileHeader64<Endianness>>(&[0; 64])
            .unwrap()
            .0;
        header.e_ident.magic = elf::ELFMAG;
        header.e_ident.class = elf::ELFCLASS64;
        header.e_ident.data = if endian.is_little_endian() {
            elf::ELFDATA2LSB
        } else {
            elf::ELFDATA2MSB
        };
        header.e_ident.version = elf::EV_CURRENT;
        header.e_version.set(endian, u32::from(elf::EV_CURRENT));
        header.e_ehsize.set(endian, 64);
        header.e_type.set(endian, elf::ET_EXEC);
        header.e_machine.set(endian, machine);
        header.e_entry.set(endian, 1);
        header
    }

    #[test]
    fn executable_requires_matching_machine_and_byte_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        let little = Endianness::Little;
        fs::write(&path, pod::bytes_of(&header64(elf::EM_X86_64, little))).unwrap();
        let launcher = Elf::read(&path).unwrap();
        let launcher_metadata = ElfMetadata::read(&path, 64, false).unwrap();
        for (machine, endian, expected) in [
            (elf::EM_X86_64, little, true),
            (elf::EM_AARCH64, little, false),
            (elf::EM_X86_64, Endianness::Big, false),
        ] {
            fs::write(&path, pod::bytes_of(&header64(machine, endian))).unwrap();
            let elf = Elf::read(&path).unwrap();
            let metadata = ElfMetadata::read(&path, 64, false).unwrap();
            assert_eq!(elf.matches(&launcher), expected, "{machine}/{endian:?}");
            assert_eq!(
                metadata.matches(&launcher_metadata),
                expected,
                "{machine}/{endian:?}"
            );
        }
    }

    #[test]
    fn input_bound_includes_the_limit_and_checks_bytes_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        let header = header64(elf::EM_X86_64, Endianness::Little);
        let mut bytes = pod::bytes_of(&header).to_vec();
        bytes.extend_from_slice(b"tail");
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            Elf::read_bounded(&path, bytes.len() as u64)
                .ok()
                .unwrap()
                .bytes,
            bytes
        );
        assert!(Elf::read_bounded(&path, bytes.len() as u64 - 1).is_err());

        // Procfs reports a zero file size even though the read returns data.
        let error = Elf::read_bounded(Path::new("/proc/self/cmdline"), 1)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "ELF exceeds input budget");
        let error = Elf::read(directory.path()).err().unwrap();
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn relocatable_elf_is_rejected_even_with_a_nonzero_entry_point() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relocatable");
        let mut header = header64(elf::EM_X86_64, Endianness::Little);
        header.e_type.set(Endianness::Little, elf::ET_REL);
        fs::write(&path, pod::bytes_of(&header)).unwrap();
        assert!(Elf::read(&path).is_err());
    }

    #[test]
    fn doctor_reads_metadata_that_exceeds_one_mib() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("large-section-table");
        let endian = Endianness::Little;
        let mut header = header64(elf::EM_X86_64, endian);
        let sections = 20_000_u16;
        header.e_shoff.set(endian, 64);
        header.e_shentsize.set(endian, 64);
        header.e_shnum.set(endian, sections);
        header.e_shstrndx.set(endian, 1);
        let mut file = File::create(&path).unwrap();
        file.write_all(pod::bytes_of(&header)).unwrap();
        file.write_all(&[0; 64]).unwrap();
        let strings_offset = 64 + u64::from(sections) * 64;
        let mut names = *pod::from_bytes::<elf::SectionHeader64<Endianness>>(&[0; 64])
            .unwrap()
            .0;
        names.sh_type.set(endian, elf::SHT_STRTAB);
        names.sh_offset.set(endian, strings_offset);
        names.sh_size.set(endian, 1);
        file.write_all(pod::bytes_of(&names)).unwrap();
        let length = strings_offset + 1;
        file.set_len(length).unwrap();
        let metadata = ElfMetadata::read(&path, length, false).unwrap();
        assert_eq!(metadata.architecture, Architecture::X86_64);
    }

    #[test]
    fn doctor_reads_the_elf32_interpreter_segment() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("elf32");
        let endian = Endianness::Little;
        let mut header = *pod::from_bytes::<FileHeader32<Endianness>>(&[0; 52])
            .unwrap()
            .0;
        header.e_ident.magic = elf::ELFMAG;
        header.e_ident.class = elf::ELFCLASS32;
        header.e_ident.data = elf::ELFDATA2LSB;
        header.e_ident.version = elf::EV_CURRENT;
        header.e_version.set(endian, u32::from(elf::EV_CURRENT));
        header.e_ehsize.set(endian, 52);
        header.e_type.set(endian, elf::ET_EXEC);
        header.e_machine.set(endian, elf::EM_386);
        header.e_phoff.set(endian, 52);
        header.e_phnum.set(endian, 1);
        header.e_phentsize.set(endian, 32);
        let mut segment = *pod::from_bytes::<elf::ProgramHeader32<Endianness>>(&[0; 32])
            .unwrap()
            .0;
        let interpreter = b"/test/ld.so\0";
        segment.p_type.set(endian, elf::PT_INTERP);
        segment.p_offset.set(endian, 84);
        segment.p_filesz.set(endian, interpreter.len() as u32);
        let bytes = [pod::bytes_of(&header), pod::bytes_of(&segment), interpreter].concat();
        fs::write(&path, &bytes).unwrap();
        let metadata = ElfMetadata::read(&path, bytes.len() as u64, false)
            .ok()
            .unwrap();
        assert_eq!(
            metadata.interpreter.as_deref(),
            Some(b"/test/ld.so".as_slice())
        );
    }

    #[test]
    fn metadata_string_reads_accept_eof_and_reject_out_of_file_ranges() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"prefix\0suffix\0").unwrap();
        let cache = ReadCache::new(file);
        let budget = Cell::new(128);
        let input = MetadataReader(&cache, &budget);
        assert_eq!(
            input.read_bytes_at_until(7..14, 0),
            Ok(b"suffix".as_slice())
        );
        assert_eq!(input.read_bytes_at_until(0..7, 0), Ok(b"prefix".as_slice()));
        assert!(input.read_bytes_at_until(0..6, 0).is_err());
        assert!(input.read_bytes_at_until(7..15, 0).is_err());
    }
}
