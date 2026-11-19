//! Verify and atomically exchange two bundles in a trusted deployment directory.

use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    os::fd::AsRawFd,
    os::unix::{fs::MetadataExt, process::CommandExt},
    path::Path,
    process::Command,
    str,
};

use rustix::fs::{
    Access, AtFlags, FlockOperation, Mode, OFlags, RenameFlags, StatVfsMountFlags, accessat, flock,
    fstatvfs, openat, renameat_with,
};

use crate::{
    capabilities::LauncherCodecs, config, container::Container, doctor, elf::ElfMetadata,
    error::Error,
};

/// Promote a verified staged bundle, or restore the previous bundle by exchanging it back.
pub(crate) fn exchange(live: &Path, staged: &Path, checks: Option<&Path>) -> Result<(), Error> {
    let live_arg = live;
    let live = config::destination(live)?;
    let staged = config::destination(staged)?;
    let directory = live.parent().expect("invariant: normalized live parent");
    if staged.parent() != Some(directory) || live == staged {
        return Err(Error::Invalid(
            "live and staged bundles must be distinct files in the same directory".into(),
        ));
    }
    let directory_path = directory;
    let directory = File::open(directory_path)?;
    let directory_metadata = directory.metadata()?;
    let live_name = live
        .file_name()
        .expect("invariant: normalized live basename");
    let staged_name = staged
        .file_name()
        .expect("invariant: normalized staged basename");
    flock(&directory, FlockOperation::NonBlockingLockExclusive)
        .map_err(|e| Error::from(e).context("locking deployment directory".into()))?;
    let live_file = executable_file(&directory, Path::new(live_name))?;
    let staged_file = executable_file(&directory, Path::new(staged_name))?;
    let live_metadata = live_file.metadata()?;
    let staged_metadata = staged_file.metadata()?;
    if identity(&live_metadata) == identity(&staged_metadata) {
        return Err(Error::Invalid(
            "live and staged refer to the same file".into(),
        ));
    }

    let mut bundle = Container::open(staged_file.try_clone()?)?;
    let launcher = ElfMetadata::read_file(staged_file.try_clone()?, &staged, true)?;
    launcher
        .codecs
        .as_ref()
        .expect("invariant: launcher read includes codecs")
        .validate(LauncherCodecs::required(&bundle.manifest.chunks))?;
    doctor::interpreter(&launcher)?;
    if fstatvfs(&staged_file)?
        .f_flag
        .contains(StatVfsMountFlags::NOEXEC)
    {
        return Err(Error::Invalid("staged bundle is on a noexec mount".into()));
    }
    accessat(&directory, staged_name, Access::EXEC_OK, AtFlags::empty())?;
    bundle.verify()?;
    if let Some(checks) = checks {
        smoke_all(live_arg, &bundle, checks)?;
    }
    live_file.sync_all()?;
    staged_file.sync_all()?;
    unchanged(&directory, Path::new(live_name), &live_metadata)?;
    unchanged(&directory, Path::new(staged_name), &staged_metadata)?;
    if identity(&fs::metadata(directory_path)?) != identity(&directory_metadata) {
        return Err(Error::Invalid(
            "deployment directory changed during checks".into(),
        ));
    }
    renameat_with(
        &directory,
        live_name,
        &directory,
        staged_name,
        RenameFlags::EXCHANGE,
    )
    .map_err(|error| Error::from(error).context("atomically exchanging bundle files".into()))?;
    directory.sync_all().map_err(|error| {
        Error::from(error).context("bundle paths exchanged, but directory sync failed".into())
    })
}

/// Open a regular executable without following a link or blocking on a FIFO.
fn executable_file(directory: &File, path: &Path) -> Result<File, Error> {
    let file = File::from(openat(
        directory,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(Error::Invalid(format!(
            "{path:?} must be an executable regular file"
        )));
    }
    Ok(file)
}

/// Identify an opened file even when it has multiple directory entries.
fn identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

/// Catch replacement or in-place changes during verification and smoke tests.
fn unchanged(directory: &File, path: &Path, before: &Metadata) -> Result<(), Error> {
    let after = executable_file(directory, path)?.metadata()?;
    if identity(&after) != identity(before)
        || after.len() != before.len()
        || (after.mtime(), after.mtime_nsec()) != (before.mtime(), before.mtime_nsec())
        || (after.ctime(), after.ctime_nsec()) != (before.ctime(), before.ctime_nsec())
    {
        return Err(Error::Invalid(format!(
            "{path:?} changed during deployment"
        )));
    }
    Ok(())
}

/// Run one explicitly configured, successful smoke invocation per variant.
fn smoke_all(live: &Path, bundle: &Container<File>, checks: &Path) -> Result<(), Error> {
    let (bytes, _) = config::read_config(checks)?;
    let text =
        str::from_utf8(&bytes).map_err(|_| Error::Invalid("smoke checks must be UTF-8".into()))?;
    let arguments: BTreeMap<String, Vec<String>> = toml::from_str(text)?;
    let manifest = &bundle.manifest;
    if arguments.len() != manifest.payloads.len()
        || manifest
            .payloads
            .iter()
            .any(|payload| !arguments.contains_key(&payload.name))
    {
        return Err(Error::Invalid(
            "smoke checks must cover every bundle variant exactly once".into(),
        ));
    }
    for payload in &manifest.payloads {
        let status = bundle_command(bundle, live, &payload.name)
            .args(&arguments[&payload.name])
            .status()
            .map_err(|error| {
                Error::from(error).context(format!("smoke launching {:?}", payload.name))
            })?;
        if !status.success() {
            return Err(Error::Invalid(format!(
                "smoke check {:?} returned {status}",
                payload.name
            )));
        }
    }
    Ok(())
}

/// Execute the inode whose selector was parsed, preserving the requested argv[0].
pub(crate) fn bundle_command(bundle: &Container<File>, argv0: &Path, variant: &str) -> Command {
    let mut command = Command::new(format!(
        "/proc/self/fd/{}",
        bundle.source_file().as_raw_fd()
    ));
    command
        .arg0(argv0)
        .env(&bundle.manifest.select_env, variant);
    command
}
