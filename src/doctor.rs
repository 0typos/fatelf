//! Non-executing checks of a build configuration against the current host.

use std::{
    env, fs,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

use rustix::{
    fs::{Access, Mode, StatVfsMountFlags, access, fchmod, statvfs},
    io::Errno,
};
use serde::Serialize;

use crate::{
    config::Document,
    container::{Backend, MAX_PAYLOAD},
    elf::ElfMetadata,
    error::Error,
    launch::executable_memfd,
    pack::output_parent,
};

/// Versioned operator diagnostics, with human-readable detail in either output mode.
#[derive(Serialize)]
struct Check {
    code: &'static str,
    status: Status,
    subject: String,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Ok,
    Error,
    Warning,
    Skipped,
}

/// Validate config and inspect the host without building a bundle or running a payload.
pub(crate) fn run(config: &Path, json: bool, probe: bool, strict: bool) -> Result<(), Error> {
    let mut checks = Vec::new();
    match Document::load(config).and_then(|document| document.config.options(document.base())) {
        Ok(options) => {
            let launcher_path = options.launcher_path()?;
            let launcher = ElfMetadata::read(&launcher_path, MAX_PAYLOAD, true);
            checks.push(check(
                "launcher",
                launcher_path.display().to_string(),
                launcher.as_ref().map(|elf| {
                    let codecs = elf
                        .codecs
                        .as_ref()
                        .expect("invariant: launcher read includes codecs");
                    format!(
                        "{:?}; current launcher revision; compression={}; encryption={}; zstandard={}",
                        elf.architecture, codecs.compression, codecs.encryption, codecs.zstandard
                    )
                }),
            ));
            if let Ok(elf) = &launcher {
                checks.push(check(
                    "launcher_interpreter",
                    launcher_path.display().to_string(),
                    interpreter(elf),
                ));
                checks.push(loader_paths(
                    "launcher_loader_paths",
                    launcher_path.display().to_string(),
                    elf,
                ));
            }
            for input in &options.inputs {
                let elf = ElfMetadata::read(&input.path, options.budgets.max_payload_bytes, false);
                let architecture = elf.as_ref().map_err(ToString::to_string).and_then(|elf| {
                    if let Ok(launcher) = &launcher
                        && !elf.matches(launcher)
                    {
                        return Err(format!(
                            "architecture {:?} differs from launcher {:?}",
                            elf.architecture, launcher.architecture
                        ));
                    }
                    Ok(format!("{:?} ELF", elf.architecture))
                });
                checks.push(check("payload_elf", input.name.clone(), architecture));
                if let Ok(elf) = &elf {
                    checks.push(check("interpreter", input.name.clone(), interpreter(elf)));
                    checks.push(loader_paths(
                        "payload_loader_paths",
                        input.name.clone(),
                        elf,
                    ));
                }
            }

            let tmp = env::temp_dir();
            checks.push(check(
                "temporary_storage",
                tmp.display().to_string(),
                storage(&tmp, matches!(options.backend, Backend::File)),
            ));
            let output = &options.output;
            let destination = output_parent(output).and_then(|parent| storage(parent, false));
            checks.push(check("output", output.display().to_string(), destination));

            if matches!(options.backend, Backend::Memfd) {
                let subject = "memfd".into();
                checks.push(if probe {
                    check(
                        "memfd_probe",
                        subject,
                        executable_memfd().and_then(|file| {
                            fchmod(&file, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
                            Ok("empty executable descriptor created".into())
                        }),
                    )
                } else {
                    Check {
                        code: "memfd_probe",
                        status: Status::Skipped,
                        subject,
                        detail: "use --probe to try allocating an empty executable descriptor"
                            .into(),
                    }
                });
            }
        }
        Err(error) => checks.push(check("config", config.display().to_string(), Err(error))),
    }
    let ok = checks.iter().all(|entry| {
        !matches!(entry.status, Status::Error)
            && !(strict && matches!(entry.status, Status::Warning))
    });
    let mut stdout = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(
            &mut stdout,
            &serde_json::json!({ "schema_version": 2, "ok": ok, "checks": checks }),
        )?;
        writeln!(stdout)?;
    } else {
        for entry in &checks {
            let status = match entry.status {
                Status::Ok => "ok",
                Status::Error => "error",
                Status::Warning => "warning",
                Status::Skipped => "skipped",
            };
            writeln!(
                stdout,
                "{status} {} {:?} {:?}",
                entry.code, entry.subject, entry.detail
            )?;
        }
    }
    if !ok {
        return Err(Error::Invalid("one or more doctor checks failed".into()));
    }
    Ok(())
}

/// Preserve each check's result alongside its stable machine-readable code.
fn check(code: &'static str, subject: String, result: Result<String, impl ToString>) -> Check {
    let (status, detail) = match result {
        Ok(detail) => (Status::Ok, detail),
        Err(error) => (Status::Error, error.to_string()),
    };
    Check {
        code,
        status,
        subject,
        detail,
    }
}

/// Report path-dependent startup without running the loader or payload.
fn loader_paths(code: &'static str, subject: String, elf: &ElfMetadata) -> Check {
    let (status, detail) = match &elf.loader_path_warning {
        Some(warning) => (Status::Warning, warning.clone()),
        None => (
            Status::Ok,
            "no location-dependent paths found in ELF loader tags".into(),
        ),
    };
    Check {
        code,
        status,
        subject,
        detail,
    }
}

/// Check the path named by PT_INTERP without running a dependency lister.
fn interpreter(elf: &ElfMetadata) -> Result<String, Error> {
    let Some(bytes) = elf.interpreter.as_deref() else {
        return Ok("no PT_INTERP segment".into());
    };
    let path = Path::new(std::ffi::OsStr::from_bytes(bytes));
    if !fs::metadata(path).is_ok_and(|metadata| metadata.is_file()) {
        return Err(Error::Invalid(format!(
            "interpreter {path:?} is missing or not a regular file"
        )));
    }
    access(path, Access::EXEC_OK).map_err(|error| {
        Error::Invalid(format!("interpreter {path:?} is not executable: {error}"))
    })?;
    Ok(format!("interpreter {path:?} is executable"))
}

/// Report available bytes and relevant mount restrictions without creating a scratch file.
fn storage(path: &Path, executable: bool) -> Result<String, Error> {
    if !fs::metadata(path)?.is_dir() {
        return Err(Error::Invalid(format!("{path:?} is not a directory")));
    }
    let stats = statvfs(path)?;
    if executable && stats.f_flag.contains(StatVfsMountFlags::NOEXEC) {
        return Err(Error::Invalid(
            "file backend cannot execute on a noexec mount".into(),
        ));
    }
    if stats.f_flag.contains(StatVfsMountFlags::RDONLY) {
        return Err(Errno::ROFS.into());
    }
    access(path, Access::WRITE_OK | Access::EXEC_OK)?;
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    if available == 0 {
        return Err(Error::Invalid("filesystem has no available bytes".into()));
    }
    if stats.f_flag.contains(StatVfsMountFlags::NOEXEC) {
        Ok(format!(
            "{available} bytes available; noexec mount cannot run local bundles"
        ))
    } else {
        Ok(format!("{available} bytes available"))
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    use super::{ElfMetadata, StatVfsMountFlags, fs, interpreter, statvfs, storage};

    #[test]
    fn interpreter_check_requires_a_regular_executable_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("loader");
        let mut elf = ElfMetadata {
            architecture: object::Architecture::X86_64,
            little_endian: true,
            interpreter: None,
            loader_path_warning: None,
            codecs: None,
        };
        assert_eq!(interpreter(&elf).unwrap(), "no PT_INTERP segment");
        for candidate in [PathBuf::from(directory.path()), path.clone()] {
            elf.interpreter = Some(candidate.into_os_string().into_encoded_bytes());
            let error = interpreter(&elf).unwrap_err();
            assert!(error.to_string().contains("missing or not a regular file"));
        }
        fs::write(&path, b"fixture").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = interpreter(&elf).unwrap_err();
        assert!(error.to_string().contains("is not executable"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        if statvfs(&path)
            .unwrap()
            .f_flag
            .contains(StatVfsMountFlags::NOEXEC)
        {
            return;
        }
        assert!(interpreter(&elf).unwrap().ends_with(" is executable"));
    }

    #[test]
    fn storage_check_requires_a_writable_directory_and_reports_available_space() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path();
        let file = path.join("file");
        fs::write(&file, []).unwrap();
        assert!(
            storage(&file, false)
                .unwrap_err()
                .to_string()
                .contains("not a directory")
        );
        assert!(storage(path, false).unwrap().contains("bytes available"));
        let noexec = statvfs(path)
            .unwrap()
            .f_flag
            .contains(StatVfsMountFlags::NOEXEC);
        assert_eq!(storage(path, true).is_err(), noexec);
        let original = fs::metadata(path).unwrap().permissions();
        fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
        let result = storage(path, false);
        fs::set_permissions(path, original).unwrap();
        if !rustix::process::geteuid().is_root() {
            assert!(result.is_err());
        }
    }
}
