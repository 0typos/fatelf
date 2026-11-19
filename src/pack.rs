//! Configurable packing with a disk-backed chunk pool and atomic output creation.

use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{File, Permissions},
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    slice,
    str::FromStr,
};

use blake3::Hash;
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::{
    capabilities::{self, LauncherCodecs},
    codec::{self, Compression, Encoding, Encryption, StoredCodec},
    container::{
        Backend, Budgets, Chunk, Container, FOOTER_LEN, Footer, MAGIC, MAX_CHUNK, Manifest,
        Payload, Position, RuntimeKey, validate_env, validate_name,
    },
    elf::Elf,
    error::Error,
};

/// A named input executable and its optional transform overrides.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Input {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) compression: Option<Compression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) shuffle: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) encryption: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) regions: Vec<Region>,
}

impl Input {
    /// Construct an input with inherited transform policy.
    pub(crate) fn new(name: String, path: PathBuf) -> Self {
        Self {
            name,
            path,
            compression: None,
            shuffle: None,
            encryption: None,
            regions: Vec::new(),
        }
    }
}

impl FromStr for Input {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, path) = value
            .split_once('=')
            .ok_or_else(|| "expected name=path".to_owned())?;
        validate_name(name).map_err(|e| e.to_string())?;
        if path.is_empty() {
            return Err("input path is empty".into());
        }
        Ok(Self::new(name.into(), path.into()))
    }
}

/// A section or byte-range rule that overrides its payload's transform policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Region {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) compression: Option<Compression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) shuffle: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) encryption: Option<String>,
}

/// External encryption material used during packing and referenced at runtime.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyConfig {
    pub(crate) name: String,
    pub(crate) key_file: PathBuf,
    pub(crate) env: String,
}

/// A half-open byte range applied independently to every input ELF.
#[derive(Clone, Debug)]
pub(crate) struct ByteRange(pub(crate) Range<usize>);

impl FromStr for ByteRange {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (start, end) = value
            .split_once(':')
            .ok_or_else(|| "expected START:END (end exclusive)".to_owned())?;
        let start = parse_offset(start)?;
        let end = parse_offset(end)?;
        if start >= end {
            return Err("range must be nonempty and increasing".into());
        }
        Ok(Self(start..end))
    }
}

/// Parse decimal or hexadecimal offsets without silently truncating them.
fn parse_offset(value: &str) -> Result<usize, String> {
    let result = match value.strip_prefix("0x") {
        Some(hex) => usize::from_str_radix(hex, 16),
        None => value.parse(),
    };
    result.map_err(|_| format!("invalid byte offset {value:?}"))
}

/// Physical storage order, independent of deduplication and execution backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Order {
    Ordered,
    Shuffled,
}

/// Build options shared by direct CLI packing and validated TOML builds.
#[derive(Args, Debug)]
pub(crate) struct PackOptions {
    /// One or more named executable ELFs: name=path.
    #[arg(required = true, num_args = 1..=64)]
    pub(crate) inputs: Vec<Input>,
    /// New output path; existing paths are never overwritten.
    #[arg(short, long)]
    pub(crate) output: PathBuf,
    /// Launcher ELF (defaults to fatelf-launcher beside this tool).
    #[arg(long)]
    pub(crate) launcher: Option<PathBuf>,
    /// Build identity labels, configured through TOML.
    #[arg(skip)]
    pub(crate) launcher_name: Option<String>,
    #[arg(skip)]
    pub(crate) launcher_version: Option<String>,
    /// Environment variable selecting a payload by name.
    #[arg(long, default_value = "FATELF_VARIANT")]
    pub(crate) select_env: String,
    /// Payload used when the variable is absent (defaults to the first input).
    #[arg(long)]
    pub(crate) default: Option<String>,
    /// Reconstruction storage; both backends replace the launcher process.
    #[arg(long = "exec", value_enum, default_value = "memfd")]
    pub(crate) backend: Backend,
    /// Store objects in encounter order or shuffle contiguous eligible runs.
    #[arg(long, value_enum, default_value = "ordered")]
    pub(crate) order: Order,
    /// Shuffle only these file-backed ELF sections; each section must exist in every payload.
    #[arg(long, conflicts_with = "ranges", requires = "order")]
    pub(crate) section: Vec<String>,
    /// Shuffle only START:END byte ranges; end exclusive, validated against every payload.
    #[arg(long = "range", conflicts_with = "section", requires = "order")]
    pub(crate) ranges: Vec<ByteRange>,
    /// Restrict global shuffle eligibility to these payload names; repeat as needed.
    #[arg(long = "shuffle-payload", requires = "order")]
    pub(crate) shuffle_payloads: Vec<String>,
    /// Reproducible shuffle seed; this is not a cryptographic key.
    #[arg(long, default_value_t = 0)]
    pub(crate) seed: u64,
    /// Share exactly equal bytes only under compatible transform policies.
    #[arg(long)]
    pub(crate) dedup: bool,
    /// Chunk size, from 256 bytes through 1 MiB; policy boundaries also split chunks.
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(256..=1_048_576))]
    pub(crate) chunk_size: u32,
    /// Compress objects only when the encoded form is smaller.
    #[arg(long, value_enum, default_value = "none")]
    pub(crate) compression: Compression,
    /// Mask payload bodies with public XOR (0xA5), without a key.
    #[arg(long)]
    pub(crate) xor: bool,
    /// Repeating public mask loaded from TOML.
    #[arg(skip)]
    pub(crate) xor_mask: Option<Vec<u8>>,
    /// Place the readable manifest after the launcher or after the stored pool.
    #[arg(long, value_enum, default_value = "end")]
    pub(crate) manifest_position: Position,
    /// Global encryption key ID, configured through TOML.
    #[arg(skip)]
    pub(crate) encryption: Option<String>,
    /// External key references, configured through TOML.
    #[arg(skip)]
    pub(crate) keys: Vec<KeyConfig>,
    /// Bounded resource policy, configured through TOML.
    #[arg(skip)]
    pub(crate) budgets: Budgets,
}

/// Resolved transform choices governing one original byte interval.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Policy {
    compression: Compression,
    shuffle: bool,
    encryption: Option<String>,
}

impl Policy {
    /// Apply encryption overrides, including the explicit unencrypted value `none`.
    fn encryption(value: Option<&str>, inherited: &Option<String>) -> Option<String> {
        match value {
            Some("none") => None,
            Some(key) => Some(key.into()),
            None => inherited.clone(),
        }
    }
}

/// A validated region selector paired with its effective inherited transform policy.
struct ResolvedRegion {
    range: Range<usize>,
    policy: Policy,
    shuffle: Option<bool>,
}

impl PackOptions {
    /// Validate shared CLI/config semantics without reading or writing input files.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.budgets.validate()?;
        for (field, value) in [
            ("launcher_name", self.launcher_name.as_deref()),
            ("launcher_version", self.launcher_version.as_deref()),
        ] {
            if let Some(value) = value {
                validate_name(value).map_err(|_| {
                    Error::Invalid(format!(
                        "{field} must contain 1 to 64 ASCII letters, digits, dots, underscores or hyphens"
                    ))
                })?;
            }
        }
        if let Some(mask) = &self.xor_mask {
            codec::validate_xor_mask(mask)?;
            if self.xor {
                return Err(Error::Invalid("choose either xor or xor_mask".into()));
            }
        }
        validate_env(&self.select_env)?;
        if self.inputs.is_empty()
            || self.inputs.len() > self.budgets.max_payloads
            || !(256..=MAX_CHUNK).contains(&u64::from(self.chunk_size))
            || u64::from(self.chunk_size) > self.budgets.max_object_bytes
        {
            return Err(Error::Invalid(
                "invalid input count or chunk size for configured budgets".into(),
            ));
        }
        if self.order != Order::Shuffled
            && (!self.section.is_empty()
                || !self.ranges.is_empty()
                || !self.shuffle_payloads.is_empty())
        {
            return Err(Error::Invalid(
                "shuffle scopes and payload selection require --order shuffled".into(),
            ));
        }
        if !self.section.is_empty() && !self.ranges.is_empty() {
            return Err(Error::Invalid(
                "sections and ranges are mutually exclusive".into(),
            ));
        }
        if self.section.len() > 1024 || self.ranges.len() > 1024 {
            return Err(Error::Invalid(
                "at most 1024 global scope entries are supported".into(),
            ));
        }
        if self.output.as_os_str().is_empty()
            || self
                .launcher
                .as_ref()
                .is_some_and(|p| p.as_os_str().is_empty())
        {
            return Err(Error::Invalid(
                "output and launcher paths must not be empty".into(),
            ));
        }
        if self.keys.len() > 64 {
            return Err(Error::Invalid(
                "at most 64 encryption keys are supported".into(),
            ));
        }
        let mut keys = HashSet::new();
        let mut envs = HashSet::new();
        for key in &self.keys {
            validate_name(&key.name)?;
            validate_env(&key.env)?;
            if key.name == "none"
                || !keys.insert(key.name.as_str())
                || !envs.insert(key.env.as_str())
                || key.env == self.select_env
                || key.key_file.as_os_str().is_empty()
            {
                return Err(Error::Invalid(
                    "invalid, duplicated or selector-conflicting key reference".into(),
                ));
            }
        }
        self.validate_encryption(self.encryption.as_deref(), &keys)?;
        let mut names = HashSet::new();
        for input in &self.inputs {
            validate_name(&input.name)?;
            if input.path.as_os_str().is_empty() {
                return Err(Error::Invalid(format!(
                    "payload {:?} has no input path",
                    input.name
                )));
            }
            if !names.insert(&input.name) {
                return Err(Error::Invalid("duplicate input name".into()));
            }
            if input.shuffle == Some(true) && self.order != Order::Shuffled {
                return Err(Error::Invalid(
                    "payload shuffle requires shuffled order".into(),
                ));
            }
            self.validate_encryption(input.encryption.as_deref(), &keys)?;
            if input.regions.len() > 1024 {
                return Err(Error::Invalid(
                    "at most 1024 region rules per payload are supported".into(),
                ));
            }
            for region in &input.regions {
                if region.section.is_some() == region.range.is_some()
                    || region.section.as_ref().is_some_and(|v| v.is_empty())
                {
                    return Err(Error::Invalid(
                        "each region requires exactly one nonempty section or range".into(),
                    ));
                }
                if let Some(range) = &region.range {
                    range.parse::<ByteRange>().map_err(Error::Invalid)?;
                }
                if region.shuffle == Some(true) && self.order != Order::Shuffled {
                    return Err(Error::Invalid(
                        "region shuffle requires shuffled order".into(),
                    ));
                }
                self.validate_encryption(region.encryption.as_deref(), &keys)?;
            }
        }
        if self
            .default
            .as_ref()
            .is_some_and(|name| !names.contains(name))
            || self
                .shuffle_payloads
                .iter()
                .any(|name| !names.contains(name))
        {
            return Err(Error::Invalid(
                "default or shuffle payload does not exist".into(),
            ));
        }
        Ok(())
    }

    /// Require configured key IDs without loading the corresponding material yet.
    fn validate_encryption(&self, value: Option<&str>, keys: &HashSet<&str>) -> Result<(), Error> {
        if let Some(key) = value
            && key != "none"
            && !keys.contains(key)
        {
            return Err(Error::Invalid(format!(
                "encryption key {key:?} is not configured"
            )));
        }
        Ok(())
    }

    /// Resolve the launcher from the explicit option or the packer's directory.
    pub(crate) fn launcher_path(&self) -> Result<PathBuf, Error> {
        match &self.launcher {
            Some(path) => Ok(path.clone()),
            None => Ok(env::current_exe()?.with_file_name("fatelf-launcher")),
        }
    }

    /// Generate exact size and layout diagnostics using the same validated build plan.
    pub(crate) fn plan(&self) -> Result<serde_json::Value, Error> {
        let prepared = self.prepare()?;
        let logical: u64 = prepared.manifest.payloads.iter().map(|p| p.length).sum();
        Ok(serde_json::json!({
            "version": 2, "manifest_position": self.manifest_position,
            "launcher_bytes": prepared.launcher.len(), "logical_bytes": logical,
            "stored_bytes": prepared.pool_length, "manifest_bytes": prepared.manifest_bytes.len(),
            "footer_bytes": FOOTER_LEN, "output_bytes": prepared.output_length,
            "unique_objects": prepared.manifest.chunks.len(),
            "payloads": prepared.manifest.payloads.iter().map(|p| serde_json::json!({
                "name":p.name, "length":p.length, "header_length":p.header_length,
                "object_references":p.chunks.len(),
                "encrypted_objects":p.chunks.iter().filter(|&&id| prepared.manifest.chunks[id].encryption.is_some()).count()
            })).collect::<Vec<_>>()
        }))
    }

    /// Write a planned container atomically, authenticating encrypted objects to its manifest.
    pub(crate) fn pack(&self) -> Result<(), Error> {
        let mut prepared = self.prepare()?;
        let mut output = new_output(&self.output)?;
        output.write_all(&prepared.launcher)?;
        if self.manifest_position == Position::Front {
            output.write_all(&prepared.manifest_bytes)?;
        }
        prepared.pool.write_to(
            &mut output,
            &prepared.manifest,
            &prepared.footer.manifest_hash,
            &prepared.keys,
        )?;
        if self.manifest_position == Position::End {
            output.write_all(&prepared.manifest_bytes)?;
        }
        output.write_all(&prepared.footer.to_bytes()?)?;
        finish_output(output, &self.output)
    }

    /// Read inputs and finalize all object metadata before publishing output or encrypting bytes.
    fn prepare(&self) -> Result<Prepared<'_>, Error> {
        self.validate()?;
        let launcher_path = self.launcher_path()?;
        let mut launcher = Elf::read(&launcher_path)?;
        let launcher_codecs =
            capabilities::launcher_codecs(&object::File::parse(launcher.bytes.as_slice())?)?;
        if self.launcher_name.is_some() || self.launcher_version.is_some() {
            capabilities::set_launcher_identity(
                &mut launcher.bytes,
                self.launcher_name.as_deref(),
                self.launcher_version.as_deref(),
            )?;
        }
        let mut pool = Pool::new(
            self.budgets.clone(),
            self.xor_mask.as_deref().unwrap_or_default(),
        )?;
        let mut payloads: Vec<Payload> = Vec::new();
        let body_encoding = if self.xor_mask.is_some() {
            Encoding::XorMask
        } else if self.xor {
            Encoding::XorA5
        } else {
            Encoding::Identity
        };
        let mut logical = 0_u64;
        let mut references = 0_usize;
        for input in &self.inputs {
            let elf = Elf::read_bounded(&input.path, self.budgets.max_payload_bytes)?;
            if !elf.matches(&launcher) {
                return Err(Error::Invalid(format!(
                    "{} is incompatible with the launcher architecture",
                    input.path.display()
                )));
            }
            logical = logical
                .checked_add(elf.bytes.len() as u64)
                .filter(|v| *v <= self.budgets.max_logical_bytes)
                .ok_or_else(|| {
                    Error::Invalid("total input bytes exceed configured budget".into())
                })?;
            let header_length = elf.header_length()?;
            if header_length as u64 > self.budgets.max_object_bytes {
                return Err(Error::Invalid("ELF header exceeds object budget".into()));
            }
            let policies = self.policies(input, &elf, header_length)?;
            let mut chunks = Vec::new();
            for (range, policy) in policies {
                if range.start == 0 {
                    if chunks.len() >= self.budgets.max_references.saturating_sub(references) {
                        return Err(Error::Invalid("too many payload object references".into()));
                    }
                    chunks.push(pool.insert(
                        &elf.bytes[..header_length],
                        Encoding::ElfHeaderXorA5,
                        &policy,
                        self.dedup,
                        None,
                    )?);
                }
                let start = range.start.max(header_length);
                if start < range.end {
                    for bytes in elf.bytes[start..range.end].chunks(self.chunk_size as usize) {
                        if chunks.len() >= self.budgets.max_references.saturating_sub(references) {
                            return Err(Error::Invalid(
                                "too many payload object references".into(),
                            ));
                        }
                        let base = payloads
                            .first()
                            .and_then(|payload| payload.chunks.get(chunks.len()))
                            .copied();
                        chunks.push(pool.insert(
                            bytes,
                            body_encoding,
                            &policy,
                            self.dedup,
                            base,
                        )?);
                    }
                }
            }
            references = references
                .checked_add(chunks.len())
                .filter(|v| *v <= self.budgets.max_references)
                .ok_or_else(|| Error::Invalid("too many payload object references".into()))?;
            payloads.push(Payload {
                name: input.name.clone(),
                length: elf.bytes.len() as u64,
                header_length: header_length as u64,
                hash: blake3::hash(&elf.bytes).to_hex().to_string(),
                chunks,
            });
        }
        let (chunks, pool_length) = pool.layout(self.order, self.seed)?;
        let mask_required = chunks.iter().any(|c| c.encoding == Encoding::XorMask);
        launcher_codecs.validate(LauncherCodecs {
            compression: chunks.iter().any(|c| c.codec == StoredCodec::Lz4Block),
            encryption: chunks.iter().any(|c| c.encryption.is_some()),
            zstandard: chunks.iter().any(|c| c.codec.uses_zstd()),
        })?;
        let used: HashSet<&str> = chunks
            .iter()
            .filter_map(|c| c.encryption.as_ref().map(|e| e.key.as_str()))
            .collect();
        let mut keys = HashMap::new();
        let mut runtime_keys = Vec::new();
        for key in &self.keys {
            if used.contains(key.name.as_str()) {
                keys.insert(key.name.clone(), codec::read_key(&key.key_file)?);
            }
            runtime_keys.push(RuntimeKey {
                name: key.name.clone(),
                env: key.env.clone(),
            });
        }
        let manifest = Manifest {
            version: 2,
            select_env: self.select_env.clone(),
            default: self
                .default
                .clone()
                .unwrap_or_else(|| self.inputs[0].name.clone()),
            backend: self.backend,
            manifest_position: self.manifest_position,
            budgets: self.budgets.clone(),
            keys: runtime_keys,
            xor_mask: self.xor_mask.clone().filter(|_| mask_required),
            chunks,
            payloads,
        };
        manifest.validate(pool_length)?;
        let mut manifest_bytes = BoundedManifest::new(self.budgets.max_manifest_bytes as usize);
        serde_json::to_writer(&mut manifest_bytes, &manifest)?;
        let manifest_bytes = manifest_bytes.bytes;
        let launcher_length = launcher.bytes.len() as u64;
        let manifest_start = match self.manifest_position {
            Position::Front => launcher_length,
            Position::End => launcher_length + pool_length,
        };
        let output_length = launcher_length
            .checked_add(pool_length)
            .and_then(|v| v.checked_add(manifest_bytes.len() as u64))
            .and_then(|v| v.checked_add(FOOTER_LEN))
            .ok_or_else(|| Error::Invalid("output length overflow".into()))?;
        let footer = Footer {
            magic: *MAGIC,
            launcher_length,
            manifest_start,
            manifest_length: manifest_bytes.len() as u64,
            manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
        };
        Ok(Prepared {
            launcher: launcher.bytes,
            pool,
            pool_length,
            output_length,
            manifest,
            manifest_bytes,
            footer,
            keys,
        })
    }

    /// Resolve scopes and region rules into disjoint intervals with explicit conflict checks.
    fn policies(
        &self,
        input: &Input,
        elf: &Elf,
        header_length: usize,
    ) -> Result<Vec<(Range<usize>, Policy)>, Error> {
        let global_shuffle = self.order == Order::Shuffled
            && (self.shuffle_payloads.is_empty() || self.shuffle_payloads.contains(&input.name));
        let base = Policy {
            compression: input.compression.unwrap_or(self.compression),
            shuffle: input.shuffle.unwrap_or(global_shuffle),
            encryption: Policy::encryption(
                input.encryption.as_deref(),
                &Policy::encryption(self.encryption.as_deref(), &None),
            ),
        };
        let scopes = self.selected_ranges(elf)?;
        let mut regions = Vec::new();
        let mut boundaries = vec![0, header_length, elf.bytes.len()];
        for scope in &scopes {
            Self::check_header_boundary(scope, header_length)?;
            boundaries.extend([scope.start, scope.end]);
        }
        for rule in &input.regions {
            let range = if let Some(section) = &rule.section {
                elf.section_ranges(slice::from_ref(section))?.remove(0)
            } else {
                rule.range
                    .as_ref()
                    .expect("invariant: selectors validated")
                    .parse::<ByteRange>()
                    .map_err(Error::Invalid)?
                    .0
            };
            if range.end > elf.bytes.len() {
                return Err(Error::Invalid("region exceeds input ELF".into()));
            }
            Self::check_header_boundary(&range, header_length)?;
            boundaries.extend([range.start, range.end]);
            regions.push(ResolvedRegion {
                range,
                policy: Policy {
                    compression: rule.compression.unwrap_or(base.compression),
                    shuffle: rule.shuffle.unwrap_or(base.shuffle),
                    encryption: Policy::encryption(rule.encryption.as_deref(), &base.encryption),
                },
                shuffle: rule.shuffle,
            });
        }
        boundaries.sort_unstable();
        boundaries.dedup();
        let mut resolved: Vec<(Range<usize>, Policy)> = Vec::new();
        for ends in boundaries.windows(2) {
            let range = ends[0]..ends[1];
            let mut policy = base.clone();
            if !scopes.is_empty()
                && !scopes
                    .iter()
                    .any(|r| r.start <= range.start && r.end >= range.end)
            {
                policy.shuffle = false;
            }
            let mut effective = None;
            for region in regions
                .iter()
                .filter(|r| r.range.start <= range.start && r.range.end >= range.end)
            {
                let mut rule_policy = region.policy.clone();
                rule_policy.shuffle = region.shuffle.unwrap_or(policy.shuffle);
                if effective
                    .as_ref()
                    .is_some_and(|previous| previous != &rule_policy)
                {
                    return Err(Error::Invalid(
                        "overlapping region rules have conflicting effective policies".into(),
                    ));
                }
                effective = Some(rule_policy);
            }
            if let Some(rule) = effective {
                policy = rule;
            }
            if let Some((previous, previous_policy)) = resolved.last_mut()
                && previous.end == range.start
                && *previous_policy == policy
                && range.start != header_length
            {
                previous.end = range.end;
            } else {
                resolved.push((range, policy));
            }
        }
        Ok(resolved)
    }

    /// Keep the complete ELF header in one mandatory masked object.
    fn check_header_boundary(range: &Range<usize>, header_length: usize) -> Result<(), Error> {
        if (range.start > 0 && range.start < header_length) || (range.end < header_length) {
            return Err(Error::Invalid(
                "region boundary splits the mandatory ELF header".into(),
            ));
        }
        Ok(())
    }

    /// Resolve and merge the legacy global shuffle scope independently for each ELF.
    fn selected_ranges(&self, elf: &Elf) -> Result<Vec<Range<usize>>, Error> {
        let mut ranges = if !self.section.is_empty() {
            elf.section_ranges(&self.section)?
        } else {
            self.ranges.iter().map(|r| r.0.clone()).collect()
        };
        if ranges.iter().any(|r| r.end > elf.bytes.len()) {
            return Err(Error::Invalid("selected range exceeds input ELF".into()));
        }
        ranges.sort_unstable_by_key(|r| r.start);
        let mut merged: Vec<Range<usize>> = Vec::new();
        for range in ranges {
            if let Some(previous) = merged.last_mut().filter(|p| range.start <= p.end) {
                previous.end = previous.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        Ok(merged)
    }
}

/// A manifest serializer target that rejects oversized writes before growing its buffer.
struct BoundedManifest {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedManifest {
    /// Start with modest capacity, reserving no more than the configured byte ceiling.
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
            limit,
        }
    }
}

impl Write for BoundedManifest {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.limit)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest exceeds configured budget",
                )
            })?;
        if length > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(length)
                .min(self.limit);
            self.bytes.reserve_exact(capacity - self.bytes.len());
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Fully bounded packing state whose manifest is finalized before output publication.
struct Prepared<'a> {
    launcher: Vec<u8>,
    pool: Pool<'a>,
    pool_length: u64,
    output_length: u64,
    manifest: Manifest,
    manifest_bytes: Vec<u8>,
    footer: Footer,
    keys: HashMap<String, Zeroizing<[u8; 32]>>,
}

/// Stored object before encryption, retaining its spool location and transform context.
struct Object {
    spool_offset: u64,
    stored_length: u64,
    decoded_length: u64,
    codec: StoredCodec,
    encoding: Encoding,
    policy: Policy,
}

/// Hash lookup context; all original bytes are still compared before sharing.
#[derive(Hash, PartialEq, Eq)]
struct CandidateKey {
    hash: Hash,
    encoding: Encoding,
    compression: Compression,
    shuffle: bool,
    encryption: Option<String>,
}

/// Encoded-only disk-backed object store, avoiding a simultaneous raw and encoded spool.
struct Pool<'a> {
    xor_mask: &'a [u8],
    file: File,
    objects: Vec<Object>,
    candidates: HashMap<CandidateKey, Vec<usize>>,
    order: Vec<usize>,
    budgets: Budgets,
}

impl<'a> Pool<'a> {
    /// Create temporary backing storage with the build's enforced spool budgets.
    fn new(budgets: Budgets, xor_mask: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            xor_mask,
            file: tempfile::tempfile().map_err(|error| {
                Error::from(error).context("creating the build spool in TMPDIR".into())
            })?,
            objects: Vec::new(),
            candidates: HashMap::new(),
            order: Vec::new(),
            budgets,
        })
    }

    /// Encode an original object once, sharing only byte-identical compatible candidates.
    fn insert(
        &mut self,
        bytes: &[u8],
        encoding: Encoding,
        policy: &Policy,
        dedup: bool,
        base: Option<usize>,
    ) -> Result<usize, Error> {
        if bytes.is_empty() || bytes.len() as u64 > self.budgets.max_object_bytes {
            return Err(Error::Invalid(
                "decoded object exceeds configured budget".into(),
            ));
        }
        let key = dedup.then(|| CandidateKey {
            hash: blake3::hash(bytes),
            encoding,
            compression: policy.compression,
            shuffle: policy.shuffle,
            encryption: policy.encryption.clone(),
        });
        if let Some(candidates) = key.as_ref().and_then(|key| self.candidates.get(key)) {
            for &id in candidates {
                let object = &self.objects[id];
                if object.decoded_length != bytes.len() as u64 {
                    continue;
                }
                if Self::decode_spooled(&mut self.file, &self.objects, id, self.xor_mask)? == bytes
                {
                    return Ok(id);
                }
            }
        }
        if self.objects.len() >= self.budgets.max_objects {
            return Err(Error::Invalid("too many unique objects".into()));
        }
        let (mut encoded, mut stored_codec) =
            codec::prepare(bytes, policy.compression, encoding, self.xor_mask)?;
        if policy.compression == Compression::ZstdDelta
            && let Some(base) = base
            && self.objects[base].policy.encryption.is_none()
            && self.objects[base].decoded_length <= bytes.len() as u64
        {
            let decoded_base =
                Self::decode_spooled(&mut self.file, &self.objects, base, self.xor_mask)?;
            let delta = codec::prepare_delta(bytes, &decoded_base, encoding, self.xor_mask)?;
            // Reserve room for the longer codec field and base index in the manifest.
            if delta.len().saturating_add(32) < encoded.len() {
                encoded = delta;
                stored_codec = StoredCodec::ZstdDelta { base };
            }
        }
        let spool_offset = self.file.seek(SeekFrom::End(0))?;
        spool_offset
            .checked_add(encoded.len() as u64)
            .filter(|v| *v <= self.budgets.max_spool_bytes)
            .ok_or_else(|| Error::Invalid("encoded spool exceeds configured budget".into()))?;
        self.file.write_all(&encoded)?;
        let id = self.objects.len();
        self.objects.push(Object {
            spool_offset,
            stored_length: encoded.len() as u64,
            decoded_length: bytes.len() as u64,
            codec: stored_codec,
            encoding,
            policy: policy.clone(),
        });
        if let Some(key) = key {
            self.candidates.entry(key).or_default().push(id);
        }
        Ok(id)
    }

    /// Read one stored object before encryption is applied.
    fn read_spooled(file: &mut File, object: &Object) -> Result<Vec<u8>, Error> {
        file.seek(SeekFrom::Start(object.spool_offset))?;
        let mut encoded = vec![0; object.stored_length as usize];
        file.read_exact(&mut encoded)?;
        Ok(encoded)
    }

    /// Decode spool candidates for exact deduplication, including one-hop deltas.
    fn decode_spooled(
        file: &mut File,
        objects: &[Object],
        id: usize,
        mask: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let object = &objects[id];
        let encoded = Self::read_spooled(file, object)?;
        let length = object.decoded_length as usize;
        if let StoredCodec::ZstdDelta { base } = object.codec {
            let base = &objects[base];
            let prefix = codec::decode(
                Self::read_spooled(file, base)?,
                base.decoded_length as usize,
                base.codec,
                base.encoding,
                mask,
            )?;
            codec::decode_delta(&encoded, length, &prefix, object.encoding, mask)
        } else {
            codec::decode(encoded, length, object.codec, object.encoding, mask)
        }
    }

    /// Assign physical offsets, shuffling eligible contiguous runs between fixed anchors.
    fn layout(&mut self, order: Order, seed: u64) -> Result<(Vec<Chunk>, u64), Error> {
        self.order = (0..self.objects.len()).collect();
        if order == Order::Shuffled {
            let mut rng = Shuffle(seed);
            let mut start = 0;
            while start < self.order.len() {
                if !self.objects[start].policy.shuffle {
                    start += 1;
                    continue;
                }
                let mut end = start + 1;
                while end < self.order.len() && self.objects[end].policy.shuffle {
                    end += 1;
                }
                for position in (start + 1..end).rev() {
                    let chosen = start + (rng.next() % ((position - start + 1) as u64)) as usize;
                    self.order.swap(position, chosen);
                }
                start = end;
            }
        }
        let mut chunks: Vec<Chunk> = self
            .objects
            .iter()
            .map(|o| Chunk {
                offset: 0,
                length: o.stored_length + if o.policy.encryption.is_some() { 16 } else { 0 },
                decoded_length: o.decoded_length,
                codec: o.codec,
                encoding: o.encoding,
                encryption: None,
            })
            .collect();
        let mut offset = 0_u64;
        for &id in &self.order {
            let object = &self.objects[id];
            let chunk = &mut chunks[id];
            chunk.offset = offset;
            if let Some(key) = &object.policy.encryption {
                chunk.encryption = Some(Encryption {
                    key: key.clone(),
                    nonce: codec::random_nonce()?,
                });
            }
            offset = offset
                .checked_add(chunk.length)
                .filter(|v| *v <= self.budgets.max_stored_bytes)
                .ok_or_else(|| Error::Invalid("stored pool exceeds configured budget".into()))?;
        }
        Ok((chunks, offset))
    }

    /// Emit each encoded object, encrypting it against the already-finalized manifest hash.
    fn write_to(
        &mut self,
        output: &mut impl Write,
        manifest: &Manifest,
        manifest_hash: &[u8; 32],
        keys: &HashMap<String, Zeroizing<[u8; 32]>>,
    ) -> Result<(), Error> {
        for &id in &self.order {
            let object = &self.objects[id];
            self.file.seek(SeekFrom::Start(object.spool_offset))?;
            let mut encoded = vec![0; object.stored_length as usize];
            self.file.read_exact(&mut encoded)?;
            if let Some(encryption) = &manifest.chunks[id].encryption {
                let key = keys
                    .get(&encryption.key)
                    .expect("invariant: used keys loaded during preparation");
                codec::encrypt(&mut encoded, key, &encryption.nonce, manifest_hash, id)?;
            }
            if encoded.len() as u64 != manifest.chunks[id].length {
                return Err(Error::Invalid(
                    "encoded object length disagrees with the plan".into(),
                ));
            }
            output.write_all(&encoded)?;
        }
        Ok(())
    }
}

/// Deterministic SplitMix64 state for storage permutations, never cryptographic use.
struct Shuffle(u64);

impl Shuffle {
    /// Produce a reproducible integer for a Fisher–Yates permutation.
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }
}

/// Check the output name and resolve its staging directory without creating a file.
pub(crate) fn output_parent(path: &Path) -> Result<&Path, Error> {
    let name = path
        .as_os_str()
        .as_bytes()
        .rsplit(|&byte| byte == b'/')
        .next();
    if matches!(name, None | Some(b"" | b"." | b"..")) {
        return Err(Error::Invalid(format!("output {path:?} must name a file")));
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(Error::Invalid(format!(
                "output {} already exists",
                path.display()
            )));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")))
}

/// Create output scratch storage in the destination directory for atomic publication.
pub(crate) fn new_output(path: &Path) -> Result<NamedTempFile, Error> {
    NamedTempFile::new_in(output_parent(path)?)
        .map_err(|error| Error::from(error).context(format!("staging output {}", path.display())))
}

/// Finish an executable output without replacing any existing destination inode.
pub(crate) fn finish_output(output: NamedTempFile, path: &Path) -> Result<(), Error> {
    output
        .as_file()
        .set_permissions(Permissions::from_mode(0o755))?;
    output.as_file().sync_all()?;
    output.persist_noclobber(path).map_err(|e| e.error)?;
    Ok(())
}

/// Reconstruct one variant to a new file, publishing only after digest verification.
pub(crate) fn extract(input: &Path, name: &str, output: &Path) -> Result<(), Error> {
    let mut container = Container::open_path(input)?;
    let index = container.payload_index(name)?;
    let mut scratch = new_output(output)?;
    container.reconstruct(index, &mut scratch)?;
    finish_output(scratch, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn destination_created_after_staging_is_not_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bundle");
        let mut output = new_output(&path).unwrap();
        output.write_all(b"staged bundle").unwrap();
        fs::write(&path, b"another writer").unwrap();
        assert!(finish_output(output, &path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"another writer");
    }

    #[test]
    fn input_specs_and_ranges_preserve_paths_and_exact_boundaries() {
        let input: Input = "a=path=with=equals".parse().unwrap();
        assert_eq!(input.name, "a");
        assert_eq!(input.path, Path::new("path=with=equals"));
        for bad in ["missing-separator", "a=", "bad name=path"] {
            assert!(bad.parse::<Input>().is_err(), "{bad:?}");
        }

        let range: ByteRange = "0x100:257".parse().unwrap();
        assert_eq!(range.0, 256..257);
        for bad in ["0", "0x:1", "256:256", "257:256", "1:2:3"] {
            assert!(bad.parse::<ByteRange>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn bounded_manifest_accepts_the_limit_without_partial_overflow() {
        let limit = 96 * 1024;
        let first = vec![1; 64 * 1024];
        let remaining = vec![2; limit - first.len()];
        let mut manifest = BoundedManifest::new(limit);
        manifest.write_all(&first).unwrap();
        assert!(manifest.bytes.capacity() < limit);
        manifest.write_all(&remaining).unwrap();
        assert!(manifest.bytes.capacity() <= limit);
        manifest.flush().unwrap();

        assert_eq!(manifest.write(&[]).unwrap(), 0);
        let error = manifest.write(&[3]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(manifest.bytes.len(), limit);
        assert_eq!(&manifest.bytes[..first.len()], first);
        assert_eq!(&manifest.bytes[first.len()..], remaining);
    }

    fn pack_options() -> PackOptions {
        crate::config::BuildConfig::parse(
            "version = 2\noutput = 'combined'\n[[payloads]]\nname = 'a'\npath = 'one'\n",
        )
        .unwrap()
        .options(Path::new("."))
        .unwrap()
    }

    #[test]
    fn pack_validation_enforces_independent_options_and_exact_limits() {
        let mut options = pack_options();
        options.chunk_size = 256;
        options.budgets.max_payloads = 1;
        options.budgets.max_object_bytes = 256;
        options.validate().unwrap();
        for size in [255, 257] {
            options.chunk_size = size;
            assert!(options.validate().is_err(), "accepted chunk size {size}");
        }
        options.budgets.max_object_bytes = MAX_CHUNK;
        options.chunk_size = MAX_CHUNK as u32;
        options.validate().unwrap();
        options.chunk_size += 1;
        assert!(options.validate().is_err());

        type Change = fn(&mut PackOptions);
        let invalid: &[(&str, Change)] = &[
            ("empty inputs", |o| o.inputs.clear()),
            ("exceeded payload count", |o| {
                o.budgets.max_payloads = 1;
                o.inputs.push(Input::new("b".into(), "two".into()));
            }),
            ("sections require shuffled order", |o| {
                o.section.push(".text".into())
            }),
            ("ranges require shuffled order", |o| {
                o.ranges.push(ByteRange(256..512))
            }),
            ("payload scope requires shuffled order", |o| {
                o.shuffle_payloads.push("a".into())
            }),
            ("scopes must be mutually exclusive", |o| {
                o.order = Order::Shuffled;
                o.section.push(".text".into());
                o.ranges.push(ByteRange(256..512));
            }),
            ("empty output", |o| o.output.clear()),
            ("empty launcher", |o| o.launcher = Some(PathBuf::new())),
            ("empty payload path", |o| o.inputs[0].path.clear()),
            ("explicit payload shuffle requires shuffled order", |o| {
                o.inputs[0].shuffle = Some(true)
            }),
            ("unknown shuffle payload", |o| {
                o.order = Order::Shuffled;
                o.shuffle_payloads.push("missing".into());
            }),
            ("missing default payload", |o| {
                o.default = Some("missing".into())
            }),
            ("missing global key", |o| {
                o.encryption = Some("missing".into())
            }),
        ];
        for (description, change) in invalid {
            let mut options = pack_options();
            change(&mut options);
            assert!(options.validate().is_err(), "{description}");
        }
    }

    #[test]
    fn list_limits_and_region_selectors_are_validated_before_packing() {
        let mut options = pack_options();
        options.order = Order::Shuffled;
        options.section = vec![".text".into(); 1024];
        options.validate().unwrap();
        options.section.push(".data".into());
        assert!(options.validate().is_err());
        options.section.clear();
        options.ranges = vec![ByteRange(256..512); 1024];
        options.validate().unwrap();
        options.ranges.push(ByteRange(512..768));
        assert!(options.validate().is_err());
        options.ranges.clear();
        let range = Region {
            section: None,
            range: Some("256:512".into()),
            compression: None,
            shuffle: Some(true),
            encryption: None,
        };
        options.inputs[0].regions = vec![range.clone(); 1024];
        options.validate().unwrap();
        options.inputs[0].regions.push(range.clone());
        assert!(options.validate().is_err());
        options.order = Order::Ordered;
        options.inputs[0].regions = vec![range];
        assert!(
            options.validate().is_err(),
            "region shuffle requires shuffled order"
        );
        let region = &mut options.inputs[0].regions[0];
        region.shuffle = None;
        region.section = Some(".text".into());
        assert!(
            options.validate().is_err(),
            "each rule must define exactly one selector"
        );
        let region = &mut options.inputs[0].regions[0];
        region.range = None;
        region.section = Some(String::new());
        assert!(
            options.validate().is_err(),
            "an empty section is not a selector"
        );
    }

    #[test]
    fn key_validation_accepts_exactly_64_references_and_reserves_none() {
        let mut options = pack_options();
        options.keys = (0..64)
            .map(|index| KeyConfig {
                name: format!("key{index}"),
                key_file: "unused".into(),
                env: format!("UNLOCK_{index}"),
            })
            .collect();
        options.encryption = Some("key0".into());
        options.validate().unwrap();
        options.keys.push(KeyConfig {
            name: "extra".into(),
            key_file: "unused".into(),
            env: "EXTRA_UNLOCK".into(),
        });
        assert!(options.validate().is_err());
        options.keys.pop();

        options.keys[1].name = options.keys[0].name.clone();
        assert!(options.validate().is_err());
        options.keys[1].name = "key1".into();
        options.keys[1].env = options.keys[0].env.clone();
        assert!(options.validate().is_err());
        options.keys[1].env = "UNLOCK_1".into();

        options.keys[0].name = "none".into();
        options.encryption = None;
        assert!(options.validate().is_err());
        options.keys.remove(0);
        options.encryption = Some("none".into());
        options.validate().unwrap();
    }

    #[test]
    fn scope_ranges_merge_and_keep_the_complete_elf_header_intact() {
        for range in [0..64, 0..65, 64..65, 65..66] {
            assert!(
                PackOptions::check_header_boundary(&range, 64).is_ok(),
                "{range:?}"
            );
        }
        for range in [0..63, 1..64, 63..65] {
            assert!(
                PackOptions::check_header_boundary(&range, 64).is_err(),
                "{range:?}"
            );
        }
        let elf = Elf {
            bytes: vec![0; 192],
            architecture: object::Architecture::X86_64,
            little_endian: true,
        };
        let mut options = pack_options();
        options.order = Order::Shuffled;
        options.ranges = [64..128, 160..192, 80..96, 128..144]
            .into_iter()
            .map(ByteRange)
            .collect();
        assert_eq!(options.selected_ranges(&elf).unwrap(), [64..144, 160..192]);
        options.ranges.push(ByteRange(192..193));
        assert!(options.selected_ranges(&elf).is_err());
    }

    #[test]
    fn resolved_policies_preserve_header_and_merge_adjacent_equal_regions() {
        let elf = Elf {
            bytes: vec![0; 192],
            architecture: object::Architecture::X86_64,
            little_endian: true,
        };
        let options = pack_options();
        let mut input = options.inputs[0].clone();
        input.regions = [
            ("64:80", Compression::None),
            ("80:96", Compression::None),
            ("96:160", Compression::Lz4),
            ("160:192", Compression::None),
        ]
        .into_iter()
        .map(|(range, compression)| Region {
            section: None,
            range: Some(range.into()),
            compression: Some(compression),
            shuffle: None,
            encryption: None,
        })
        .collect();
        let rules = options
            .policies(&input, &elf, 64)
            .unwrap()
            .into_iter()
            .map(|(range, policy)| (range, policy.compression))
            .collect::<Vec<_>>();
        assert_eq!(
            rules,
            [
                (0..64, Compression::None),
                (64..96, Compression::None),
                (96..160, Compression::Lz4),
                (160..192, Compression::None),
            ]
        );
        input.regions[3].range = Some("160:193".into());
        assert!(options.policies(&input, &elf, 64).is_err());
    }

    #[test]
    fn spool_enforces_object_and_disk_budgets_at_the_boundary() {
        let mut pool = Pool::new(
            Budgets {
                max_object_bytes: 4,
                max_objects: 3,
                max_spool_bytes: 5,
                ..Budgets::default()
            },
            &[],
        )
        .unwrap();
        let policy = Policy {
            compression: Compression::None,
            shuffle: false,
            encryption: None,
        };
        for bytes in [&[][..], &[0; 5]] {
            assert!(
                pool.insert(bytes, Encoding::Identity, &policy, true, None)
                    .is_err()
            );
        }
        let full = pool
            .insert(b"abcd", Encoding::Identity, &policy, true, None)
            .unwrap();
        assert_eq!(
            pool.insert(b"abcd", Encoding::Identity, &policy, true, None)
                .unwrap(),
            full
        );
        pool.insert(b"e", Encoding::Identity, &policy, true, None)
            .unwrap();
        let error = pool
            .insert(b"f", Encoding::Identity, &policy, true, None)
            .unwrap_err();
        assert_eq!(error.to_string(), "encoded spool exceeds configured budget");
    }

    #[test]
    fn seeded_layout_shuffles_runs_independently_between_anchors() {
        let mut pool = Pool::new(Budgets::default(), &[]).unwrap();
        for (index, shuffle) in [true, false, true, true, true, true, false, true, true]
            .into_iter()
            .enumerate()
        {
            let policy = Policy {
                compression: Compression::None,
                shuffle,
                encryption: None,
            };
            pool.insert(&[index as u8], Encoding::Identity, &policy, false, None)
                .unwrap();
        }
        let (chunks, length) = pool.layout(Order::Shuffled, 0).unwrap();
        assert_eq!(length, 9);
        let offsets = chunks.iter().map(|chunk| chunk.offset).collect::<Vec<_>>();
        // At seed zero the length-four run swaps its first and third objects.
        assert_eq!(offsets, [0, 1, 4, 3, 2, 5, 6, 8, 7]);
    }

    #[test]
    fn splitmix_reference_sequence_is_stable() {
        let mut rng = Shuffle(0);
        assert_eq!(rng.next(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(rng.next(), 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(rng.next(), 0x06c4_5d18_8009_454f);
    }

    #[test]
    fn output_resolution_checks_the_destination_without_creating_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("out");
        assert_eq!(output_parent(&output).unwrap(), directory.path());
        assert!(!output.exists());
        fs::write(&output, b"keep").unwrap();
        assert!(output_parent(&output).is_err());
        assert!(output_parent(&output.join("child")).is_err());

        let relative = PathBuf::from(directory.path().file_name().unwrap());
        directory.close().unwrap();
        assert_eq!(output_parent(&relative).unwrap(), Path::new("."));
        for invalid in ["", ".", "..", "missing/"] {
            assert!(output_parent(Path::new(invalid)).is_err(), "{invalid:?}");
        }
    }
}
