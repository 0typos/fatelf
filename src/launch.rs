//! Reconstruct the selected ELF into an executable descriptor and replace this process.

use std::{
    env,
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    ptr,
};

use rustix::{
    fs::{MemfdFlags, Mode, SealFlags, fchmod, fcntl_add_seals, memfd_create},
    io::Errno,
};
use tempfile::{Builder, NamedTempFile};

use crate::{
    container::{Backend, Container},
    error::Error,
};

/// Choose from the build-defined environment variable, then execute after verification.
pub(crate) fn run() -> Result<(), Error> {
    let mut container = Container::open(File::open("/proc/self/exe")?)?;
    let name = env::var_os(&container.manifest.select_env);
    let name = match name.as_deref() {
        Some(value) => value
            .to_str()
            .ok_or_else(|| Error::Invalid("payload selector is not valid UTF-8".into()))?,
        None => &container.manifest.default,
    };
    let index = container.payload_index(name)?;
    let private_environment: Vec<String> = container
        .manifest
        .keys
        .iter()
        .map(|key| key.env.clone())
        .collect();
    let backend = container.manifest.backend;
    let label = container.manifest.payloads[index].name.clone();
    let executable = match backend {
        Backend::Memfd => memory_executable(&mut container, index),
        Backend::File => file_executable(&mut container, index),
    }
    .map_err(|error| error.context(format!("preparing payload {label:?} with {backend:?}")))?;
    // Do not carry the container descriptor or its metadata into the payload.
    drop(container);
    execute(executable, &private_environment)
        .map_err(|error| error.context(format!("executing payload {label:?} with {backend:?}")))
}

/// Reconstruct and seal a memfd, requesting executable permission on modern kernels.
fn memory_executable(container: &mut Container<File>, index: usize) -> Result<File, Error> {
    let mut file = executable_memfd()?;
    container.reconstruct(index, &mut file)?;
    fchmod(&file, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )?;
    Ok(file)
}

/// Create the same executable descriptor used by launch and the optional host probe.
pub(crate) fn executable_memfd() -> Result<File, Error> {
    let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    let fd = match memfd_create(c"fatelf", flags | MemfdFlags::EXEC) {
        Err(Errno::INVAL) => memfd_create(c"fatelf", flags)?, // MFD_EXEC is unavailable before Linux 6.3.
        result => result?,
    };
    Ok(File::from(fd))
}

/// Unlink the scratch file before decoding, then close its writer before execution.
fn file_executable(container: &mut Container<File>, index: usize) -> Result<File, Error> {
    let directory = Builder::new().prefix("fatelf-").tempdir()?;
    let (mut writer, path) = NamedTempFile::new_in(directory.path())?.into_parts();
    fchmod(&writer, Mode::RUSR | Mode::XUSR)?;
    let executable = File::open(&path)?;
    path.close()?;
    directory.close()?;
    container.reconstruct(index, &mut writer)?;
    drop(writer);
    Ok(executable)
}

/// Replace the launcher while preserving raw argv, environment, PID, and inherited FDs.
fn execute(executable: File, private_environment: &[String]) -> Result<(), Error> {
    let args: Vec<CString> = env::args_os()
        .map(|arg| cstring(&arg))
        .collect::<Result<_, _>>()?;
    let environment: Vec<CString> = env::vars_os()
        .filter(|(key, _)| {
            !private_environment
                .iter()
                .any(|private| key == OsStr::new(private))
        })
        .map(|(key, value)| {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            CString::new(bytes).map_err(|_| Error::Invalid("environment contains NUL".into()))
        })
        .collect::<Result<_, _>>()?;
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|s| s.as_ptr()).collect();
    let mut envp: Vec<*const libc::c_char> = environment.iter().map(|s| s.as_ptr()).collect();
    argv.push(ptr::null());
    envp.push(ptr::null());
    // Rust startup ignores SIGPIPE. Native executables conventionally start with
    // its default disposition; restore that before handing off to any payload.
    // SAFETY: SIGPIPE is valid and SIG_DFL is the platform's predefined handler.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: both arrays end in NULL; every other pointer addresses a CString
    // kept alive through this call. The fd is open, the path is NUL-terminated,
    // and AT_EMPTY_PATH is valid. execveat only reads these arrays and strings.
    // libc::syscall supplies execveat across GNU and musl targets alike.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            executable.as_raw_fd(),
            c"".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    Err(io::Error::last_os_error().into())
}

/// Preserve arbitrary Unix argument bytes while constructing syscall strings.
fn cstring(value: &OsStr) -> Result<CString, Error> {
    CString::new(value.as_bytes()).map_err(|_| Error::Invalid("argument contains NUL".into()))
}
