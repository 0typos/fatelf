//! Versioned metadata, bounded object decoding, and exact reconstruction.

use crate::{
    codec::{self, Encoding, Encryption, StoredCodec},
    elf,
    error::Error,
};
use blake3::{Hash, Hasher};
use bnb::bin;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "builder", feature = "encryption"))]
use std::path::Path;
#[cfg(feature = "encryption")]
use std::{collections::HashMap, env};
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom, Write},
};
#[cfg(feature = "builder")]
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
};
#[cfg(feature = "encryption")]
use zeroize::Zeroizing;

/// Version two has a different object model and deliberately rejects v1 readers.
pub(crate) const MAGIC: &[u8; 8] = b"FATELF02";
/// RSL footer: magic, three u64 values, exact-manifest BLAKE3 digest.
pub(crate) const FOOTER_LEN: u64 = 64;
/// Hard allocation ceiling, independently of configurable build limits.
pub(crate) const MAX_MANIFEST: u64 = 16 * 1024 * 1024;
/// Hard ceiling for an original executable.
pub(crate) const MAX_PAYLOAD: u64 = 1024 * 1024 * 1024;
/// Largest decoded object; encrypted storage may add one 16-byte tag.
pub(crate) const MAX_CHUNK: u64 = 1024 * 1024;
/// Hard descriptor and reference ceiling.
pub(crate) const MAX_REFS: usize = 1_000_000;
/// Aggregate logical and stored hard ceiling.
pub(crate) const MAX_LOGICAL: u64 = 2 * MAX_PAYLOAD;

/// Fixed little-endian locator; manifest placement is recorded inside its JSON.
#[bin(little, no_builder)]
pub(crate) struct Footer {
    pub(crate) magic: [u8; 8],
    pub(crate) launcher_length: u64,
    pub(crate) manifest_start: u64,
    pub(crate) manifest_length: u64,
    pub(crate) manifest_hash: [u8; 32],
}

/// Storage used to reconstruct the selected executable.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "builder", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub(crate) enum Backend {
    Memfd,
    File,
}

/// Front follows the outer ELF; the fixed locator always remains at the end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "builder", derive(clap::ValueEnum))]
#[serde(rename_all = "lowercase")]
pub(crate) enum Position {
    Front,
    #[default]
    End,
}

/// Validated build/runtime budgets cannot raise implementation hard ceilings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Budgets {
    pub(crate) max_payloads: usize,
    pub(crate) max_payload_bytes: u64,
    pub(crate) max_logical_bytes: u64,
    pub(crate) max_object_bytes: u64,
    pub(crate) max_objects: usize,
    pub(crate) max_references: usize,
    pub(crate) max_stored_bytes: u64,
    pub(crate) max_spool_bytes: u64,
    pub(crate) max_manifest_bytes: u64,
    pub(crate) max_config_bytes: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            max_payloads: 64,
            max_payload_bytes: 256 * 1024 * 1024,
            max_logical_bytes: 512 * 1024 * 1024,
            max_object_bytes: MAX_CHUNK,
            max_objects: 262_144,
            max_references: 262_144,
            max_stored_bytes: 512 * 1024 * 1024,
            max_spool_bytes: 512 * 1024 * 1024,
            max_manifest_bytes: 4 * 1024 * 1024,
            max_config_bytes: 1024 * 1024,
        }
    }
}

impl Budgets {
    /// Validate every configurable ceiling, including limits used only by the writer.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let counts = [
            (self.max_payloads, 64),
            (self.max_objects, MAX_REFS),
            (self.max_references, MAX_REFS),
        ];
        let bytes = [
            (self.max_payload_bytes, MAX_PAYLOAD),
            (self.max_logical_bytes, MAX_LOGICAL),
            (self.max_object_bytes, MAX_CHUNK),
            (self.max_stored_bytes, MAX_LOGICAL),
            (self.max_spool_bytes, MAX_LOGICAL),
            (self.max_manifest_bytes, MAX_MANIFEST),
            (self.max_config_bytes, 1024 * 1024),
        ];
        if counts
            .iter()
            .any(|&(value, hard)| value == 0 || value > hard)
            || bytes
                .iter()
                .any(|&(value, hard)| value == 0 || value > hard)
        {
            return Err(Error::Invalid(
                "budget is zero or exceeds a hard ceiling".into(),
            ));
        }
        Ok(())
    }
}

/// Runtime references contain environment names, never key bytes or build paths.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeKey {
    pub(crate) name: String,
    pub(crate) env: String,
}

/// Unique encoded object location is relative to the stored pool.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Chunk {
    pub(crate) offset: u64,
    pub(crate) length: u64,
    pub(crate) decoded_length: u64,
    pub(crate) codec: StoredCodec,
    pub(crate) encoding: Encoding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) encryption: Option<Encryption>,
}

/// Original executable described by its ordered object references.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Payload {
    pub(crate) name: String,
    pub(crate) length: u64,
    pub(crate) header_length: u64,
    pub(crate) hash: String,
    pub(crate) chunks: Vec<usize>,
}

/// Manifest is hashed exactly as serialized; that digest is encrypted objects' AAD.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) version: u32,
    pub(crate) select_env: String,
    pub(crate) default: String,
    pub(crate) backend: Backend,
    pub(crate) manifest_position: Position,
    pub(crate) budgets: Budgets,
    pub(crate) keys: Vec<RuntimeKey>,
    pub(crate) chunks: Vec<Chunk>,
    pub(crate) payloads: Vec<Payload>,
}

impl Manifest {
    /// Validate all bounds, transforms, references, headers and pool coverage before use.
    pub(crate) fn validate(&self, pool_length: u64) -> Result<(), Error> {
        self.budgets.validate()?;
        let limits = &self.budgets;
        if self.version != 2
            || self.payloads.is_empty()
            || self.payloads.len() > limits.max_payloads
        {
            return Err(Error::Invalid(
                "unsupported version or payload count".into(),
            ));
        }
        validate_env(&self.select_env)?;
        let mut key_names = HashSet::new();
        let mut key_envs = HashSet::new();
        if self.keys.len() > 64 {
            return Err(Error::Invalid("too many key references".into()));
        }
        for key in &self.keys {
            validate_name(&key.name)?;
            validate_env(&key.env)?;
            if key.env == self.select_env
                || !key_names.insert(&key.name)
                || !key_envs.insert(&key.env)
            {
                return Err(Error::Invalid(
                    "duplicate key or reserved selector environment".into(),
                ));
            }
        }
        if self.chunks.is_empty()
            || self.chunks.len() > limits.max_objects
            || pool_length > limits.max_stored_bytes
        {
            return Err(Error::Invalid(
                "object count or stored pool exceeds budget".into(),
            ));
        }
        let mut intervals = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            let tag = if let Some(encryption) = &chunk.encryption {
                if !key_names.contains(&encryption.key) {
                    return Err(Error::Invalid("unknown encryption key".into()));
                }
                codec::TAG_LENGTH as u64
            } else {
                0
            };
            let inner_length = chunk.length.checked_sub(tag);
            if chunk.decoded_length == 0
                || chunk.decoded_length > limits.max_object_bytes
                || inner_length.is_none_or(|length| length == 0 || length > limits.max_object_bytes)
                || chunk
                    .offset
                    .checked_add(chunk.length)
                    .is_none_or(|end| end > pool_length)
            {
                return Err(Error::Invalid(
                    "object outside pool or exceeds budget".into(),
                ));
            }
            match chunk.codec {
                StoredCodec::Raw if inner_length != Some(chunk.decoded_length) => {
                    return Err(Error::Invalid("raw object length mismatch".into()));
                }
                StoredCodec::Lz4Block
                    if inner_length.is_none_or(|length| length >= chunk.decoded_length) =>
                {
                    return Err(Error::Invalid(
                        "LZ4 object must be smaller than decoded bytes".into(),
                    ));
                }
                _ => (),
            }
            if chunk.codec == StoredCodec::Lz4Block && !cfg!(feature = "compression")
                || chunk.encryption.is_some() && !cfg!(feature = "encryption")
            {
                return Err(Error::Invalid(
                    "launcher lacks required decoder capability".into(),
                ));
            }
            intervals.push((chunk.offset, chunk.length));
        }
        intervals.sort_unstable();
        let mut next = 0;
        for (offset, length) in intervals {
            if offset != next {
                return Err(Error::Invalid("object pool has gaps or overlaps".into()));
            }
            next += length; // The individual end was already checked against pool length.
        }
        if next != pool_length {
            return Err(Error::Invalid(
                "object pool contains untracked bytes".into(),
            ));
        }
        let mut names = HashSet::new();
        let mut refs = 0_usize;
        let mut logical = 0_u64;
        let mut used = vec![false; self.chunks.len()];
        for payload in &self.payloads {
            validate_name(&payload.name)?;
            if !names.insert(&payload.name) {
                return Err(Error::Invalid("duplicate payload name".into()));
            }
            if payload.length == 0
                || payload.length > limits.max_payload_bytes
                || ![52, 64].contains(&payload.header_length)
            {
                return Err(Error::Invalid("invalid payload or header length".into()));
            }
            Hash::from_hex(&payload.hash)
                .map_err(|_| Error::Invalid("invalid payload hash".into()))?;
            refs = refs
                .checked_add(payload.chunks.len())
                .filter(|&v| v <= limits.max_references)
                .ok_or_else(|| Error::Invalid("too many payload references".into()))?;
            let mut length = 0_u64;
            for (ordinal, &index) in payload.chunks.iter().enumerate() {
                let chunk = self
                    .chunks
                    .get(index)
                    .ok_or_else(|| Error::Invalid("invalid object reference".into()))?;
                let expected = if ordinal == 0 {
                    Encoding::ElfHeaderXorA5
                } else {
                    Encoding::Identity
                };
                if chunk.encoding != expected
                    || ordinal == 0 && chunk.decoded_length != payload.header_length
                {
                    return Err(Error::Invalid(
                        "payload must begin with a complete masked header object".into(),
                    ));
                }
                used[index] = true;
                length = length
                    .checked_add(chunk.decoded_length)
                    .filter(|&v| v <= limits.max_payload_bytes)
                    .ok_or_else(|| Error::Invalid("payload expansion exceeds budget".into()))?;
            }
            if length != payload.length {
                return Err(Error::Invalid("payload length differs from objects".into()));
            }
            logical = logical
                .checked_add(length)
                .filter(|&v| v <= limits.max_logical_bytes)
                .ok_or_else(|| Error::Invalid("logical bytes exceed budget".into()))?;
        }
        if used.iter().any(|used| !used) || !names.contains(&self.default) {
            return Err(Error::Invalid(
                "unreferenced object or unknown default payload".into(),
            ));
        }
        Ok(())
    }
}

/// Validated random-access source; buffers are bounded by one encoded/decoded object.
pub(crate) struct Container<R> {
    source: R,
    #[cfg(feature = "builder")]
    pub(crate) launcher_length: u64,
    #[cfg(feature = "builder")]
    pub(crate) manifest_length: u64,
    pub(crate) pool_start: u64,
    #[cfg(feature = "builder")]
    pub(crate) pool_length: u64,
    #[cfg(feature = "encryption")]
    manifest_hash: [u8; 32],
    pub(crate) manifest: Manifest,
}

#[cfg(feature = "builder")]
impl Container<File> {
    /// Open a regular container file without waiting for writers on a FIFO.
    pub(crate) fn open_path(path: &Path) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::Invalid(format!(
                "{} is not a regular container file",
                path.display()
            )));
        }
        Self::open(file)
    }
}

impl<R: Read + Seek> Container<R> {
    /// Read the locator and bounded JSON, then derive the selected physical layout.
    pub(crate) fn open(mut source: R) -> Result<Self, Error> {
        let length = source.seek(SeekFrom::End(0))?;
        let footer_start = length
            .checked_sub(FOOTER_LEN)
            .ok_or_else(|| Error::Invalid("footer missing".into()))?;
        source.seek(SeekFrom::Start(footer_start))?;
        let mut footer_bytes = [0_u8; FOOTER_LEN as usize];
        source.read_exact(&mut footer_bytes)?;
        let footer = Footer::decode_exact(&footer_bytes)?;
        if &footer.magic != MAGIC {
            return Err(Error::Invalid(
                "not a fatelf v2 container (v1 is unsupported)".into(),
            ));
        }
        let manifest_end = footer.manifest_start.checked_add(footer.manifest_length);
        if footer.launcher_length == 0
            || footer.launcher_length > MAX_PAYLOAD
            || footer.manifest_start < footer.launcher_length
            || footer.manifest_length == 0
            || footer.manifest_length > MAX_MANIFEST
            || manifest_end.is_none_or(|end| end > footer_start)
        {
            return Err(Error::Invalid(
                "invalid footer offsets or manifest size".into(),
            ));
        }
        source.seek(SeekFrom::Start(footer.manifest_start))?;
        let mut bytes = vec![0_u8; footer.manifest_length as usize];
        source.read_exact(&mut bytes)?;
        if blake3::hash(&bytes).as_bytes() != &footer.manifest_hash {
            return Err(Error::Invalid("manifest integrity check failed".into()));
        }
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        let end = manifest_end.expect("invariant: checked manifest end");
        let (pool_start, pool_end) = match manifest.manifest_position {
            Position::Front if footer.manifest_start == footer.launcher_length => {
                (end, footer_start)
            }
            Position::End if end == footer_start => (footer.launcher_length, footer.manifest_start),
            _ => {
                return Err(Error::Invalid(
                    "manifest position contradicts locator".into(),
                ));
            }
        };
        if footer.manifest_length > manifest.budgets.max_manifest_bytes {
            return Err(Error::Invalid("manifest exceeds configured budget".into()));
        }
        let pool_length = pool_end
            .checked_sub(pool_start)
            .ok_or_else(|| Error::Invalid("invalid pool boundaries".into()))?;
        manifest.validate(pool_length)?;
        Ok(Self {
            source,
            #[cfg(feature = "builder")]
            launcher_length: footer.launcher_length,
            #[cfg(feature = "builder")]
            manifest_length: footer.manifest_length,
            pool_start,
            #[cfg(feature = "builder")]
            pool_length,
            #[cfg(feature = "encryption")]
            manifest_hash: footer.manifest_hash,
            manifest,
        })
    }

    /// Unknown explicit selections fail instead of silently using the default.
    pub(crate) fn payload_index(&self, name: &str) -> Result<usize, Error> {
        self.manifest
            .payloads
            .iter()
            .position(|p| p.name == name)
            .ok_or_else(|| Error::Invalid(format!("unknown payload {name:?}")))
    }

    /// Authenticate each encrypted object before decoding, then verify the original digest.
    pub(crate) fn reconstruct(
        &mut self,
        index: usize,
        writer: &mut impl Write,
    ) -> Result<(), Error> {
        let payload = self
            .manifest
            .payloads
            .get(index)
            .ok_or_else(|| Error::Invalid("invalid payload index".into()))?;
        #[cfg(feature = "encryption")]
        let keys = self.unlock_keys(payload)?;
        let mut hasher = Hasher::new();
        for (ordinal, &id) in payload.chunks.iter().enumerate() {
            let chunk = &self.manifest.chunks[id];
            self.source
                .seek(SeekFrom::Start(self.pool_start + chunk.offset))?;
            let mut bytes = vec![0_u8; chunk.length as usize];
            self.source.read_exact(&mut bytes)?;
            if let Some(encryption) = &chunk.encryption {
                #[cfg(feature = "encryption")]
                codec::decrypt(
                    &mut bytes,
                    &keys[&encryption.key],
                    &encryption.nonce,
                    &self.manifest_hash,
                    id,
                )?;
                #[cfg(not(feature = "encryption"))]
                {
                    let _ = encryption;
                    return Err(Error::Invalid("encryption feature is unavailable".into()));
                }
            }
            let decoded = codec::decode(
                bytes,
                chunk.decoded_length as usize,
                chunk.codec,
                chunk.encoding,
            )?;
            if ordinal == 0 && elf::header_length(&decoded)? as u64 != payload.header_length {
                return Err(Error::Invalid(
                    "reconstructed ELF header size mismatch".into(),
                ));
            }
            hasher.update(&decoded);
            writer.write_all(&decoded)?;
        }
        let expected = Hash::from_hex(&payload.hash)
            .map_err(|_| Error::Invalid("invalid payload hash".into()))?;
        if hasher.finalize() != expected {
            return Err(Error::Invalid(format!(
                "payload {:?} integrity check failed",
                payload.name
            )));
        }
        writer.flush()?;
        Ok(())
    }

    /// Load only keys referenced by the selected payload and erase them when decoding ends.
    #[cfg(feature = "encryption")]
    fn unlock_keys(
        &self,
        payload: &Payload,
    ) -> Result<HashMap<String, Zeroizing<[u8; 32]>>, Error> {
        let mut keys = HashMap::new();
        for &id in &payload.chunks {
            let Some(encryption) = &self.manifest.chunks[id].encryption else {
                continue;
            };
            if keys.contains_key(&encryption.key) {
                continue;
            }
            let reference = self
                .manifest
                .keys
                .iter()
                .find(|key| key.name == encryption.key)
                .expect("invariant: validated object key reference");
            let path = env::var_os(&reference.env).ok_or_else(|| {
                Error::Invalid(format!(
                    "required key file environment {} is missing",
                    reference.env
                ))
            })?;
            keys.insert(reference.name.clone(), codec::read_key(Path::new(&path))?);
        }
        Ok(keys)
    }
}

/// Validate portable environment variable names before storing selection policy.
pub(crate) fn validate_env(name: &str) -> Result<(), Error> {
    let first = name.as_bytes().first().copied();
    if name.len() > 128
        || first.is_none_or(|b| !(b.is_ascii_alphabetic() || b == b'_'))
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(Error::Invalid(
            "invalid selection environment variable".into(),
        ));
    }
    Ok(())
}

/// Validate unique, nonempty labels used on the CLI and in the selector value.
pub(crate) fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(Error::Invalid(format!("invalid payload name {name:?}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Backend, Budgets, Chunk, Container, FOOTER_LEN, Footer, MAGIC, Manifest, Payload, Position,
        RuntimeKey,
    };
    use crate::codec::{Encoding, StoredCodec};
    use std::io::Cursor;

    /// Minimal ELF64 header plus a body; original bytes are an independent decoder oracle.
    fn original() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes.extend_from_slice(b"hello");
        bytes
    }

    /// Two names share a complete masked header and an identity body object.
    fn manifest(position: Position) -> Manifest {
        let original = original();
        Manifest {
            version: 2,
            select_env: "CHOICE".into(),
            default: "a".into(),
            backend: Backend::Memfd,
            manifest_position: position,
            budgets: Budgets::default(),
            keys: vec![],
            chunks: vec![
                Chunk {
                    offset: 0,
                    length: 64,
                    decoded_length: 64,
                    codec: StoredCodec::Raw,
                    encoding: Encoding::ElfHeaderXorA5,
                    encryption: None,
                },
                Chunk {
                    offset: 64,
                    length: 5,
                    decoded_length: 5,
                    codec: StoredCodec::Raw,
                    encoding: Encoding::Identity,
                    encryption: None,
                },
            ],
            payloads: ["a", "b"]
                .into_iter()
                .map(|name| Payload {
                    name: name.into(),
                    length: original.len() as u64,
                    header_length: 64,
                    hash: blake3::hash(&original).to_hex().to_string(),
                    chunks: vec![0, 1],
                })
                .collect(),
        }
    }

    /// Assemble locator offsets directly, independently of the RSL encoding implementation.
    fn image(manifest: &Manifest) -> Vec<u8> {
        let metadata = serde_json::to_vec(manifest).unwrap();
        let original = original();
        let mut pool = original[..64]
            .iter()
            .map(|byte| byte ^ 0xa5)
            .collect::<Vec<_>>();
        pool.extend_from_slice(&original[64..]);
        let mut bytes = b"stub".to_vec();
        let start = match manifest.manifest_position {
            Position::Front => {
                bytes.extend_from_slice(&metadata);
                bytes.extend_from_slice(&pool);
                4
            }
            Position::End => {
                bytes.extend_from_slice(&pool);
                let start = bytes.len();
                bytes.extend_from_slice(&metadata);
                start
            }
        };
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&4_u64.to_le_bytes());
        bytes.extend_from_slice(&(start as u64).to_le_bytes());
        bytes.extend_from_slice(&(metadata.len() as u64).to_le_bytes());
        bytes.extend_from_slice(blake3::hash(&metadata).as_bytes());
        bytes
    }

    #[test]
    fn rsl_footer_matches_little_endian_wire_layout() {
        let footer = Footer {
            magic: *MAGIC,
            launcher_length: 0x0102030405060708,
            manifest_start: 0x1112131415161718,
            manifest_length: 0x2122232425262728,
            manifest_hash: [0x5a; 32],
        };
        let mut expected = b"FATELF02\x08\x07\x06\x05\x04\x03\x02\x01\x18\x17\x16\x15\x14\x13\x12\x11\x28\x27\x26\x25\x24\x23\x22\x21".to_vec();
        expected.extend_from_slice(&[0x5a; 32]);
        assert_eq!(footer.to_bytes().unwrap(), expected);
        assert_eq!(expected.len() as u64, FOOTER_LEN);
    }

    #[test]
    fn both_positions_reconstruct_shared_objects_byte_exactly() {
        for position in [Position::Front, Position::End] {
            let mut container = Container::open(Cursor::new(image(&manifest(position)))).unwrap();
            for name in ["a", "b"] {
                let mut recovered = Vec::new();
                container
                    .reconstruct(container.payload_index(name).unwrap(), &mut recovered)
                    .unwrap();
                assert_eq!(recovered, original(), "{position:?}: original bytes");
            }
            assert!(container.payload_index("missing").is_err());
        }
    }

    #[test]
    fn locator_rejects_overflow_oversize_and_trailing_data() {
        for position in [Position::Front, Position::End] {
            let bytes = image(&manifest(position));
            let footer_start = bytes.len() - FOOTER_LEN as usize;
            for (offset, value) in [
                (8, u64::MAX),
                (16, u64::MAX),
                (24, super::MAX_MANIFEST + 1),
                (24, 0),
            ] {
                let mut invalid = bytes.clone();
                invalid[footer_start + offset..footer_start + offset + 8]
                    .copy_from_slice(&value.to_le_bytes());
                assert!(
                    Container::open(Cursor::new(invalid)).is_err(),
                    "{position:?}: footer offset {offset}"
                );
            }
            let mut trailing = bytes;
            trailing.push(0);
            assert!(Container::open(Cursor::new(trailing)).is_err());
        }
    }

    #[test]
    fn metadata_rejects_bad_refs_partial_headers_and_untracked_objects() {
        for mutate in [
            |m: &mut Manifest| m.payloads[0].chunks = vec![2],
            |m: &mut Manifest| m.payloads[0].header_length = 1,
            |m: &mut Manifest| m.chunks[0].encoding = Encoding::Identity,
            |m: &mut Manifest| m.chunks[1].encoding = Encoding::ElfHeaderXorA5,
            |m: &mut Manifest| m.payloads[0].length = 1,
            |m: &mut Manifest| m.chunks[0].offset = u64::MAX,
            |m: &mut Manifest| m.payloads[1].name = "a".into(),
            |m: &mut Manifest| m.default = "missing".into(),
            |m: &mut Manifest| m.chunks[1].offset = 63,
            |m: &mut Manifest| m.budgets.max_payload_bytes = 68,
            |m: &mut Manifest| {
                m.keys.push(RuntimeKey {
                    name: "unlock".into(),
                    env: "CHOICE".into(),
                })
            },
        ] {
            let mut invalid = manifest(Position::End);
            mutate(&mut invalid);
            assert!(Container::open(Cursor::new(image(&invalid))).is_err());
        }
    }

    #[test]
    fn masked_header_is_independently_validated_after_reversal() {
        let mut bytes = image(&manifest(Position::End));
        bytes[4 + 4] ^= 1; // Change decoded ELF class without changing metadata.
        let mut container = Container::open(Cursor::new(bytes)).unwrap();
        let mut output = Vec::new();
        assert!(container.reconstruct(0, &mut output).is_err());
        assert!(
            output.is_empty(),
            "invalid header must fail before writing bytes"
        );
    }

    #[test]
    fn corrupted_body_and_manifest_are_detected() {
        let mut bytes = image(&manifest(Position::End));
        bytes[4 + 64] ^= 1;
        let mut container = Container::open(Cursor::new(bytes)).unwrap();
        assert!(container.reconstruct(0, &mut Vec::new()).is_err());
        let mut bytes = image(&manifest(Position::End));
        bytes[4 + 69] ^= 1;
        assert!(Container::open(Cursor::new(bytes)).is_err());
    }
}
