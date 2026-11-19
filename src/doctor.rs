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
    capabilities::launcher_codecs, config::Document, container::Backend, elf::Elf, error::Error,
    launch::executable_memfd, pack::output_parent,
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
    Skipped,
}

/// Validate config and inspect the host without building a bundle or running a payload.
pub(crate) fn run(config: &Path, json: bool, probe: bool) -> Result<(), Error> {
    let mut checks = Vec::new();
    match Document::load(config).and_then(|document| document.config.options(document.base())) {
        Ok(options) => {
            let launcher_path = options.launcher_path()?;
            let launcher = Elf::read(&launcher_path).and_then(|elf| {
                let codecs = launcher_codecs(&elf.bytes)?;
                Ok((elf, codecs))
            });
            checks.push(check(
                "launcher",
                launcher_path.display().to_string(),
                launcher.as_ref().map(|(elf, codecs)| {
                    format!(
                        "{:?}; v2; compression={}; encryption={}",
                        elf.architecture,
                        codecs & 1 != 0,
                        codecs & 2 != 0
                    )
                }),
            ));
            if let Ok((elf, _)) = &launcher {
                checks.push(check(
                    "launcher_interpreter",
                    launcher_path.display().to_string(),
                    interpreter(elf),
                ));
            }
            for input in &options.inputs {
                let elf = Elf::read_bounded(&input.path, options.budgets.max_payload_bytes);
                let architecture = elf.as_ref().map_err(ToString::to_string).and_then(|elf| {
                    if let Ok((launcher, _)) = &launcher
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
    let ok = checks
        .iter()
        .all(|entry| !matches!(entry.status, Status::Error));
    let mut stdout = io::stdout().lock();
    if json {
        serde_json::to_writer_pretty(
            &mut stdout,
            &serde_json::json!({ "schema_version": 1, "ok": ok, "checks": checks }),
        )?;
        writeln!(stdout)?;
    } else {
        for entry in &checks {
            let status = match entry.status {
                Status::Ok => "ok",
                Status::Error => "error",
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

/// Check the path named by PT_INTERP without running a dependency lister.
fn interpreter(elf: &Elf) -> Result<String, Error> {
    let Some(bytes) = elf.interpreter()? else {
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
    Ok(format!("{available} bytes available"))
}
