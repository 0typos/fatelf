//! Strict TOML build settings shared by handwritten configurations and the TUI.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::{
    fs::{
        FlockOperation, XattrFlags, fchown, fgetxattr, fgetxattr_query, flock, fremovexattr,
        fsetxattr,
    },
    io::Errno,
    process::{Gid, Uid},
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{
    codec::Compression,
    container::{Backend, Budgets, Position},
    error::Error,
    pack::{ByteRange, Input, KeyConfig, Order, PackOptions},
};

/// Maximum configuration text size, enforced before parsing and after encoding.
pub(crate) const MAX_CONFIG: usize = 1024 * 1024;

/// User-facing layout selection; new strategies must be implemented before admission.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Layout {
    Overlay,
}

/// Independent schema for a reproducible build; payload order determines the fallback.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BuildConfig {
    pub(crate) version: u32,
    pub(crate) output: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) launcher: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) launcher_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) launcher_version: Option<String>,
    pub(crate) payloads: Vec<Input>,
    #[serde(default)]
    pub(crate) selection: Selection,
    #[serde(default)]
    pub(crate) storage: Storage,
    #[serde(default)]
    pub(crate) execution: Execution,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) keys: Vec<KeyConfig>,
    #[serde(default)]
    pub(crate) budgets: Budgets,
}

/// Runtime selector name and optional fallback label configured during the build.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Selection {
    pub(crate) env: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) default: Option<String>,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            env: "FATELF_VARIANT".into(),
            default: None,
        }
    }
}

/// Physical storage settings, independent of selection and execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Storage {
    pub(crate) layout: Layout,
    pub(crate) order: Order,
    pub(crate) dedup: bool,
    pub(crate) chunk_size: u32,
    pub(crate) seed: u64,
    pub(crate) sections: Vec<String>,
    pub(crate) ranges: Vec<String>,
    pub(crate) manifest_position: Position,
    pub(crate) compression: Compression,
    #[serde(skip_serializing_if = "is_false")]
    pub(crate) xor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) xor_mask: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) encryption: Option<String>,
}

/// Omit disabled XOR from saved configs so older builders can read them.
fn is_false(value: &bool) -> bool {
    !value
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            layout: Layout::Overlay,
            order: Order::Ordered,
            dedup: false,
            chunk_size: 4096,
            seed: 0,
            sections: Vec::new(),
            ranges: Vec::new(),
            manifest_position: Position::End,
            compression: Compression::None,
            xor: false,
            xor_mask: None,
            encryption: None,
        }
    }
}

/// Reconstruction backend used by the resulting launcher.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Execution {
    pub(crate) backend: Backend,
}

impl Default for Execution {
    fn default() -> Self {
        Self {
            backend: Backend::Memfd,
        }
    }
}

impl BuildConfig {
    /// Create the unsaved TUI draft; input paths must be filled before saving.
    pub(crate) fn draft() -> Self {
        Self {
            version: 2,
            output: "combined".into(),
            launcher: None,
            launcher_name: None,
            launcher_version: None,
            payloads: ["a", "b"]
                .into_iter()
                .map(|name| Input::new(name.into(), PathBuf::new()))
                .collect(),
            selection: Selection::default(),
            storage: Storage::default(),
            execution: Execution::default(),
            keys: Vec::new(),
            budgets: Budgets::default(),
        }
    }

    /// Decode bounded TOML with strict fields and shared semantic validation.
    pub(crate) fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_CONFIG {
            return Err(Error::Invalid("configuration exceeds 1 MiB limit".into()));
        }
        let config: Self = toml::from_str(text)?;
        config.options(Path::new("."))?;
        if text.len() as u64 > config.budgets.max_config_bytes {
            return Err(Error::Invalid(
                "configuration exceeds configured budget".into(),
            ));
        }
        Ok(config)
    }

    /// Translate a config into the same validated options used by `fatelf pack`.
    pub(crate) fn options(&self, base: &Path) -> Result<PackOptions, Error> {
        if self.version != 2 {
            return Err(Error::Invalid(format!(
                "unsupported configuration version {}",
                self.version
            )));
        }
        // Validate empty paths before joining them onto a nonempty base directory.
        if self.output.as_os_str().is_empty()
            || self
                .launcher
                .as_ref()
                .is_some_and(|p| p.as_os_str().is_empty())
            || self.payloads.iter().any(|p| p.path.as_os_str().is_empty())
            || self
                .keys
                .iter()
                .any(|key| key.key_file.as_os_str().is_empty())
        {
            return Err(Error::Invalid(
                "output, launcher, payload and key paths must not be empty".into(),
            ));
        }
        let options = PackOptions {
            inputs: self
                .payloads
                .iter()
                .map(|p| {
                    let mut input = p.clone();
                    input.path = resolve(base, &p.path);
                    input
                })
                .collect(),
            output: resolve(base, &self.output),
            launcher: self.launcher.as_ref().map(|path| resolve(base, path)),
            launcher_name: self.launcher_name.clone(),
            launcher_version: self.launcher_version.clone(),
            select_env: self.selection.env.clone(),
            default: self.selection.default.clone(),
            backend: self.execution.backend,
            order: self.storage.order,
            section: self.storage.sections.clone(),
            ranges: self
                .storage
                .ranges
                .iter()
                .map(|r| r.parse::<ByteRange>().map_err(Error::Invalid))
                .collect::<Result<_, _>>()?,
            seed: self.storage.seed,
            dedup: self.storage.dedup,
            chunk_size: self.storage.chunk_size,
            shuffle_payloads: Vec::new(),
            compression: self.storage.compression,
            xor: self.storage.xor,
            xor_mask: self.storage.xor_mask.clone(),
            manifest_position: self.storage.manifest_position,
            encryption: self.storage.encryption.clone(),
            keys: self
                .keys
                .iter()
                .map(|key| KeyConfig {
                    name: key.name.clone(),
                    key_file: resolve(base, &key.key_file),
                    env: key.env.clone(),
                })
                .collect(),
            budgets: self.budgets.clone(),
        };
        options.validate()?;
        Ok(options)
    }

    /// Serialize validated settings to reviewable, bounded TOML.
    pub(crate) fn encode(&self) -> Result<String, Error> {
        self.options(Path::new("."))?;
        let text = toml::to_string_pretty(self)?;
        if text.len() > MAX_CONFIG || text.len() as u64 > self.budgets.max_config_bytes {
            return Err(Error::Invalid(
                "configuration exceeds configured budget".into(),
            ));
        }
        Ok(text)
    }

    /// Preserve referenced files on Save As by absolutizing paths from the old base.
    pub(crate) fn rebase(&mut self, old_base: &Path) {
        self.output = resolve(old_base, &self.output);
        self.launcher = self.launcher.as_ref().map(|p| resolve(old_base, p));
        for payload in &mut self.payloads {
            payload.path = resolve(old_base, &payload.path);
        }
        for key in &mut self.keys {
            key.key_file = resolve(old_base, &key.key_file);
        }
    }
}

/// A config loaded from its canonical path, which defines relative-path resolution.
pub(crate) struct Document {
    pub(crate) config: BuildConfig,
    pub(crate) path: PathBuf,
    fingerprint: blake3::Hash,
}

impl Document {
    /// Read only a bounded regular file and resolve symlinked configs consistently.
    pub(crate) fn load(path: &Path) -> Result<Self, Error> {
        let path = fs::canonicalize(path)?;
        let (bytes, _) = read_config(&path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| Error::Invalid("configuration must be UTF-8".into()))?;
        Ok(Self {
            config: BuildConfig::parse(text)?,
            fingerprint: blake3::hash(&bytes),
            path,
        })
    }

    /// Build using the config directory, independently of the invoking working directory.
    pub(crate) fn build(&self) -> Result<(), Error> {
        self.config.options(self.base())?.pack()
    }

    /// Return the directory of an already canonicalized configuration file.
    pub(crate) fn base(&self) -> &Path {
        self.path
            .parent()
            .expect("invariant: canonical config has a parent")
    }
}

/// Read a bounded configuration snapshot without following a replacement symlink.
fn read_config(path: &Path) -> Result<(Vec<u8>, File), Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG as u64 {
        return Err(Error::Invalid(
            "configuration must be a regular file of at most 1 MiB".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_CONFIG as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_CONFIG {
        return Err(Error::Invalid("configuration exceeds 1 MiB".into()));
    }
    Ok((bytes, file))
}

/// Resolve relative path fields using their document's directory.
fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

/// Normalize a prospective config path without requiring that the file exists.
pub(crate) fn destination(path: &Path) -> Result<PathBuf, Error> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Invalid("configuration output must name a file".into()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(fs::canonicalize(parent)?.join(name))
}

/// Atomically save TOML; only the explicitly loaded original may be overwritten.
pub(crate) fn save(
    config: &BuildConfig,
    path: &Path,
    original: Option<&Document>,
) -> Result<(), Error> {
    let text = config.encode()?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Invalid("configuration output has no parent directory".into()))?;
    let mut scratch = NamedTempFile::new_in(parent)?;
    scratch.write_all(text.as_bytes())?;
    if let Some(original) = original.filter(|document| document.path == path) {
        // The directory inode survives atomic replacement of the config.
        let directory = fs::File::open(parent)?;
        flock(&directory, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == Errno::WOULDBLOCK {
                Error::Invalid("another configuration save is in progress; retry".into())
            } else {
                error.into()
            }
        })?;
        let (current, source) = read_config(path)?;
        if blake3::hash(&current) != original.fingerprint {
            return Err(Error::Invalid(format!(
                "configuration {} changed since it was loaded; reload or save to a new path",
                path.display()
            )));
        }
        preserve_access(&source, scratch.as_file())?;
        scratch.as_file().sync_all()?;
        scratch.persist(path).map_err(|e| e.error)?;
    } else {
        scratch.as_file().sync_all()?;
        scratch.persist_noclobber(path).map_err(|e| e.error)?;
    }
    Ok(())
}

/// Preserve access controls before replacing an existing configuration inode.
fn preserve_access(source: &File, staged: &File) -> Result<(), Error> {
    let original = source.metadata()?;
    let new = staged.metadata()?;
    let uid = (original.uid() != new.uid()).then(|| Uid::from_raw(original.uid()));
    let gid = (original.gid() != new.gid()).then(|| Gid::from_raw(original.gid()));
    if uid.is_some() || gid.is_some() {
        fchown(staged, uid, gid)?;
    }

    const ACCESS_ACL: &str = "system.posix_acl_access";
    match fgetxattr_query(source, ACCESS_ACL) {
        Ok(size) => {
            let mut acl = vec![0; size];
            let read = fgetxattr(source, ACCESS_ACL, acl.as_mut_slice())?;
            fsetxattr(staged, ACCESS_ACL, &acl[..read], XattrFlags::empty())?;
        }
        Err(Errno::NODATA | Errno::NOTSUP) => {
            // A new inode can inherit an ACL from its directory even if the old
            // file had none. Remove it before chmod opens the group mask.
            match fremovexattr(staged, ACCESS_ACL) {
                Ok(()) | Err(Errno::NODATA | Errno::NOTSUP) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    staged.set_permissions(fs::Permissions::from_mode(original.mode() & 0o666))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    /// Valid settings with relative references exercise relocation without reading ELFs.
    fn settings() -> BuildConfig {
        BuildConfig::parse(
            "version = 2\noutput = 'combined'\nlauncher = 'launcher'\n\
             [[payloads]]\nname = 'a'\npath = 'one'\n\
             [[payloads]]\nname = 'b'\npath = 'two'\n",
        )
        .unwrap()
    }

    #[test]
    fn config_roundtrip_preserves_paths_scope_and_full_unsigned_seed() {
        let mut config = settings();
        config.payloads[0].path = "one with spaces and \"quotes\"".into();
        config.storage.order = Order::Shuffled;
        config.storage.sections = vec![".text,extra".into(), ".quote\"".into()];
        config.storage.seed = u64::MAX;
        let encoded = config.encode().unwrap();
        assert_eq!(
            BuildConfig::parse(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        assert!(encoded.contains("18446744073709551615"));
    }

    #[test]
    fn new_editor_drafts_require_payload_paths_and_resolve_relative_destinations() {
        let draft = BuildConfig::draft();
        assert_eq!(draft.output, Path::new("combined"));
        assert_eq!(
            draft
                .payloads
                .iter()
                .map(|input| input.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(
            draft
                .payloads
                .iter()
                .all(|input| input.path.as_os_str().is_empty())
        );
        assert!(draft.encode().is_err());
        assert_eq!(
            destination(Path::new("bundle.toml")).unwrap(),
            fs::canonicalize(".").unwrap().join("bundle.toml")
        );
    }

    #[test]
    fn key_files_rebase_and_validate_without_embedding_material() {
        let mut config = settings();
        config.keys.push(KeyConfig {
            name: "second".into(),
            key_file: "unlock.key".into(),
            env: "UNLOCK_FILE".into(),
        });
        config.payloads[1].encryption = Some("second".into());
        let before = config.options(Path::new("/old/config")).unwrap();
        config.rebase(Path::new("/old/config"));
        let after = config.options(Path::new("/new/config")).unwrap();
        assert_eq!(before.keys[0].key_file, after.keys[0].key_file);
        assert_eq!(after.keys[0].key_file, Path::new("/old/config/unlock.key"));
        let encoded = config.encode().unwrap();
        assert!(encoded.contains("key_file"));
        config.keys[0].env = config.selection.env.clone();
        assert!(
            config.encode().is_err(),
            "unlock paths must never reuse the selection variable"
        );
    }

    #[test]
    fn save_only_replaces_the_explicitly_loaded_document() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.toml");
        let mut config = settings();
        save(&config, &path, None).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::read(&path).unwrap();
        config.selection.env = "APP_MODE".into();
        assert!(save(&config, &path, None).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let document = Document::load(&path).unwrap();
        save(&config, &path, Some(&document)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), config.encode().unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let link = directory.path().join("link.toml");
        symlink(&path, &link).unwrap();
        assert!(save(&config, &link, Some(&document)).is_err());
        let revised = fs::read(&path).unwrap();
        assert!(save(&settings(), &path, Some(&document)).is_err());
        assert_eq!(fs::read(&path).unwrap(), revised);
    }

    #[test]
    fn a_concurrent_save_keeps_the_original_and_can_be_retried() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("bundle.toml");
        let mut config = settings();
        save(&config, &path, None).unwrap();
        let document = Document::load(&path).unwrap();
        let open_directory = fs::File::open(directory.path()).unwrap();
        flock(&open_directory, FlockOperation::LockExclusive).unwrap();
        config.selection.env = "APP_MODE".into();

        let error = save(&config, &path, Some(&document)).unwrap_err();
        assert!(error.to_string().contains("save is in progress"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            document.config.encode().unwrap()
        );

        drop(open_directory);
        save(&config, &path, Some(&document)).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), config.encode().unwrap());
    }

    #[test]
    fn save_as_preserves_all_references_from_a_symlinked_document() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source");
        let target = directory.path().join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        let path = source.join("bundle.toml");
        save(&settings(), &path, None).unwrap();
        let link = target.join("link.toml");
        symlink(&path, &link).unwrap();
        let document = Document::load(&link).unwrap();
        let before = document.config.options(document.base()).unwrap();
        let mut moved = document.config;
        moved.rebase(&source);
        let destination = target.join("saved.toml");
        save(&moved, &destination, None).unwrap();
        let saved = Document::load(&destination).unwrap();
        let after = saved.config.options(saved.base()).unwrap();
        assert_eq!(before.output, after.output);
        assert_eq!(before.launcher, after.launcher);
        assert_eq!(
            before.inputs.iter().map(|p| &p.path).collect::<Vec<_>>(),
            after.inputs.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn config_snapshot_rejects_links_and_accepts_exactly_one_mib() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let mut text = settings().encode().unwrap();
        text.push('\n');
        text.push('#');
        text.extend(std::iter::repeat_n(' ', MAX_CONFIG - text.len()));
        fs::write(&path, &text).unwrap();
        assert_eq!(read_config(&path).unwrap().0, text.as_bytes());
        assert!(Document::load(&path).is_ok());
        let link = directory.path().join("link.toml");
        symlink(&path, &link).unwrap();
        assert!(read_config(&link).is_err());
        assert!(Document::load(&link).is_ok());
        let error = read_config(directory.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configuration must be a regular file")
        );
        text.push(' ');
        fs::write(&path, &text).unwrap();
        let error = read_config(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configuration must be a regular file")
        );
        assert!(BuildConfig::parse(&text).is_err());
        fs::write(&path, [0xff]).unwrap();
        let error = Document::load(&path).err().unwrap();
        assert_eq!(error.to_string(), "configuration must be UTF-8");
    }

    #[test]
    fn config_encoder_accepts_exactly_one_mib() {
        let mut config = settings();
        let length = config.encode().unwrap().len();
        config
            .output
            .as_mut_os_string()
            .push("x".repeat(MAX_CONFIG - length));
        let text = config.encode().unwrap();
        assert_eq!(text.len(), MAX_CONFIG);
        config.output.as_mut_os_string().push("x");
        assert!(config.encode().is_err());
    }

    #[test]
    fn save_preserves_an_owner_or_group_that_differs_from_the_staged_file() {
        let root = rustix::process::geteuid().is_root();
        let groups = rustix::process::getgroups().unwrap();
        for change_owner in [false, true] {
            let source = tempfile::tempfile().unwrap();
            let staged = tempfile::tempfile().unwrap();
            let original_staged = staged.metadata().unwrap();
            let (owner, group) = if change_owner {
                (root.then(|| Uid::from_raw(1)), None)
            } else {
                let current = original_staged.gid();
                let group = if root {
                    Some(Gid::from_raw(if current == 1 { 2 } else { 1 }))
                } else {
                    groups
                        .iter()
                        .copied()
                        .find(|candidate| candidate.as_raw() != current)
                };
                (None, group)
            };
            if owner.is_none() && group.is_none() {
                continue;
            }
            match fchown(&source, owner, group) {
                Ok(()) => {}
                // A restricted test runner may lack CAP_CHOWN or only map one ID.
                Err(Errno::PERM | Errno::INVAL) => continue,
                Err(error) => panic!("could not set fixture ownership: {error}"),
            }
            let expected = source.metadata().unwrap();
            assert_ne!(
                (original_staged.uid(), original_staged.gid()),
                (expected.uid(), expected.gid()),
            );
            preserve_access(&source, &staged).unwrap();
            let saved = staged.metadata().unwrap();
            assert_eq!((saved.uid(), saved.gid()), (expected.uid(), expected.gid()));
        }
    }

    #[test]
    fn encoded_and_decoded_configs_share_the_configured_byte_limit() {
        let mut config = settings();
        config.budgets.max_config_bytes = 4096;
        config.budgets.max_config_bytes = config.encode().unwrap().len() as u64;
        config.budgets.max_config_bytes = config.encode().unwrap().len() as u64;
        let mut text = config.encode().unwrap();
        assert_eq!(text.len() as u64, config.budgets.max_config_bytes);
        assert!(BuildConfig::parse(&text).is_ok());
        text.push(' ');
        assert!(BuildConfig::parse(&text).is_err());

        config.budgets.max_config_bytes = 16;
        assert!(config.encode().is_err());
    }
}
