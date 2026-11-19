//! Acceptance tests use independent executable outputs and original file bytes as oracles.

use std::{
    ffi::OsString,
    fs,
    io::{BufRead, BufReader},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
};

use object::{Object, ObjectSection};
use rustix::process::{Pid, Signal, kill_process};
use serde_json::Value;
use tempfile::{TempDir, tempdir};

/// Shared immutable fixture executables, compiled once for all acceptance tests.
struct Fixtures {
    _directory: TempDir,
    a: PathBuf,
    b: PathBuf,
}

/// Compile two independent Linux ELF executables using the pinned toolchain.
fn fixtures() -> &'static Fixtures {
    static FIXTURES: OnceLock<Fixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let directory = tempdir().unwrap();
        let a = directory.path().join("one");
        let b = directory.path().join("two");
        for (path, variant) in [(&a, "variant_a"), (&b, "variant_b")] {
            let output = Command::new("rustc")
                .args([
                    "--edition=2024",
                    "--cfg",
                    variant,
                    "-C",
                    "opt-level=s",
                    "-C",
                    "strip=symbols",
                ])
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/payload.rs"))
                .arg("-o")
                .arg(path)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "rustc fixture: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Fixtures {
            _directory: directory,
            a,
            b,
        }
    })
}

/// Run the actual CLI; no internal packing functions are duplicated by the tests.
fn tool(args: &[OsString]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fatelf"))
        .args(args)
        .output()
        .unwrap()
}

/// Pack a two-payload container with explicit launcher and optional build settings.
fn pack(output: &Path, options: &[&str], same: bool) -> Output {
    let fixture = fixtures();
    let second = if same { &fixture.a } else { &fixture.b };
    let mut args: Vec<OsString> = vec![
        "pack".into(),
        format!("a={}", fixture.a.display()).into(),
        format!("b={}", second.display()).into(),
        "--launcher".into(),
        env!("CARGO_BIN_EXE_fatelf-launcher").into(),
        "-o".into(),
        output.as_os_str().into(),
    ];
    args.extend(options.iter().map(OsString::from));
    tool(&args)
}

/// Make command failures report diagnostics without a second execution.
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Retrieve documented inspection statistics for storage assertions.
fn inspect(path: &Path) -> Value {
    let output = tool(&["inspect".into(), path.as_os_str().into()]);
    success(&output);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn zstandard_modes_round_trip_both_executables_and_share_related_blocks() {
    let directory = tempdir().unwrap();
    let mut sizes = Vec::new();
    let duplicate = format!("duplicate={}", fixtures().b.display());
    for (compression, backend) in [("zstd", "memfd"), ("zstd-delta", "file")] {
        let binary = directory.path().join(compression);
        success(&pack(
            &binary,
            &[
                "--compression",
                compression,
                "--chunk-size",
                "65536",
                "--exec",
                backend,
                "--dedup",
                &duplicate,
            ],
            false,
        ));
        let report = inspect(&binary);
        assert!(report["zstd_objects"].as_u64().unwrap() > 0);
        assert_eq!(
            report["delta_objects"].as_u64().unwrap() > 0,
            compression == "zstd-delta"
        );
        success(&tool(&["verify".into(), binary.as_os_str().into()]));
        for (variant, source) in [("a", &fixtures().a), ("b", &fixtures().b)] {
            let output = directory.path().join(format!("{compression}-{variant}"));
            success(&tool(&[
                "extract".into(),
                binary.as_os_str().into(),
                "--variant".into(),
                variant.into(),
                "-o".into(),
                output.as_os_str().into(),
            ]));
            assert_eq!(fs::read(output).unwrap(), fs::read(source).unwrap());
            let launched = Command::new(&binary)
                .args(["exit", "37"])
                .env("FATELF_VARIANT", variant)
                .output()
                .unwrap();
            assert_eq!(launched.status.code(), Some(37));
        }
        sizes.push(fs::metadata(binary).unwrap().len());
        if compression == "zstd-delta" {
            let binary = directory.path().join(compression);
            let (mut bytes, start, _, mut manifest) = metadata(&binary);
            assert_eq!(
                manifest["payloads"][1]["chunks"],
                manifest["payloads"][2]["chunks"]
            );
            let chunks = manifest["chunks"].as_array_mut().unwrap();
            let (id, chunk) = chunks
                .iter_mut()
                .enumerate()
                .find(|(_, chunk)| chunk["codec"]["zstd-delta"].is_object())
                .unwrap();
            chunk["codec"]["zstd-delta"]["base"] = id.into();
            let manifest = serde_json::to_vec(&manifest).unwrap();
            let mut footer = bytes.split_off(bytes.len() - 64);
            footer[24..32].copy_from_slice(&(manifest.len() as u64).to_le_bytes());
            footer[32..].copy_from_slice(blake3::hash(&manifest).as_bytes());
            bytes.truncate(start);
            bytes.extend(manifest);
            bytes.extend(footer);
            let corrupt = directory.path().join("cyclic-delta");
            fs::write(&corrupt, bytes).unwrap();
            let rejected = tool(&["verify".into(), corrupt.into_os_string()]);
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains("invalid Zstandard delta base object")
            );
        }
    }
    assert!(sizes[1] < sizes[0]);
}

#[test]
fn selection_preserves_raw_arguments_environment_and_exit_status() {
    for backend in ["memfd", "file"] {
        let directory = tempdir().unwrap();
        let binary = directory.path().join("combined");
        success(&pack(
            &binary,
            &[
                "--exec",
                backend,
                "--select-env",
                "CUSTOM_CHOICE",
                "--default",
                "b",
            ],
            false,
        ));
        let argument = OsString::from_vec(b"raw\xffargument".to_vec());
        let variable = OsString::from_vec(b"raw\xfeenvironment".to_vec());
        let output = Command::new(&binary)
            .arg("context-with-selector-check")
            .arg(&argument)
            .env("CUSTOM_CHOICE", "a")
            .env("FATELF_PROBE", &variable)
            .output()
            .unwrap();
        success(&output);
        let mut expected = b"a\0".to_vec();
        expected.extend_from_slice(binary.as_os_str().as_bytes());
        expected.extend_from_slice(
            b"\0context-with-selector-check\0raw\xffargument\0raw\xfeenvironment",
        );
        assert_eq!(
            output.stdout, expected,
            "{backend}: raw Unix argv/env must survive"
        );
        let default = Command::new(&binary)
            .arg("context")
            .env_remove("CUSTOM_CHOICE")
            .output()
            .unwrap();
        success(&default);
        assert!(
            default.stdout.starts_with(b"b\0"),
            "{backend}: absent selector must use configured default"
        );
        let exited = Command::new(&binary)
            .args(["exit", "37"])
            .env_remove("CUSTOM_CHOICE")
            .output()
            .unwrap();
        assert_eq!(
            exited.status.code(),
            Some(37),
            "{backend}: payload exit code must survive"
        );
        for selector in [
            OsString::from("missing"),
            OsString::from(""),
            OsString::from_vec(vec![0xff]),
        ] {
            let invalid = Command::new(&binary)
                .env("CUSTOM_CHOICE", selector)
                .output()
                .unwrap();
            assert!(
                !invalid.status.success(),
                "{backend}: invalid selector must fail closed"
            );
            assert!(invalid.stdout.is_empty());
        }
    }
}

#[test]
fn both_backends_preserve_pid_signals_and_cleanup_files_before_exec() {
    for backend in ["memfd", "file"] {
        let directory = tempdir().unwrap();
        let runtime = directory.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        let binary = directory.path().join("combined");
        success(&pack(&binary, &["--exec", backend], false));
        let mut child = Command::new(&binary)
            .arg("wait")
            .env("FATELF_VARIANT", "a")
            .env("TMPDIR", &runtime)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        assert_eq!(
            line.trim().parse::<u32>().unwrap(),
            child.id(),
            "{backend}: launcher must exec rather than spawn"
        );
        assert_eq!(
            fs::read_dir(&runtime).unwrap().count(),
            0,
            "{backend}: no runtime files after exec"
        );
        kill_process(Pid::from_raw(child.id() as i32).unwrap(), Signal::TERM).unwrap();
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.signal(),
            Some(15),
            "{backend}: SIGTERM must reach payload"
        );
    }
}

#[test]
fn all_storage_modes_extract_each_original_byte_for_byte() {
    let fixture = fixtures();
    let modes: &[&[&str]] = &[
        &[],
        &["--manifest-position", "front"],
        &["--compression", "lz4"],
        &[
            "--compression",
            "lz4",
            "--manifest-position",
            "front",
            "--order",
            "shuffled",
            "--shuffle-payload",
            "b",
        ],
        &["--dedup"],
        &["--order", "shuffled", "--seed", "42"],
        &[
            "--order",
            "shuffled",
            "--dedup",
            "--section",
            ".text",
            "--section",
            ".rodata",
        ],
        &[
            "--order",
            "shuffled",
            "--dedup",
            "--range",
            "4096:12288",
            "--range",
            "8192:16384",
        ],
    ];
    for mode in modes {
        let directory = tempdir().unwrap();
        let binary = directory.path().join("combined");
        success(&pack(&binary, mode, false));
        for (name, original) in [("a", &fixture.a), ("b", &fixture.b)] {
            let recovered = directory.path().join(name);
            let output = tool(&[
                "extract".into(),
                binary.as_os_str().into(),
                "--variant".into(),
                name.into(),
                "-o".into(),
                recovered.as_os_str().into(),
            ]);
            success(&output);
            assert_eq!(
                fs::read(&recovered).unwrap(),
                fs::read(original).unwrap(),
                "mode {mode:?}, payload {name}"
            );
            let execution = Command::new(&binary)
                .args(["exit", "19"])
                .env("FATELF_VARIANT", name)
                .output()
                .unwrap();
            assert_eq!(
                execution.status.code(),
                Some(19),
                "mode {mode:?}, payload {name}: {}",
                String::from_utf8_lossy(&execution.stderr)
            );
        }
    }
}

#[test]
fn dedup_shares_exact_bytes_and_reduces_physical_storage() {
    let directory = tempdir().unwrap();
    let plain = directory.path().join("plain");
    let shared = directory.path().join("shared");
    success(&pack(&plain, &[], true));
    success(&pack(&shared, &["--dedup"], true));
    let original = fs::metadata(&fixtures().a).unwrap().len();
    let plain_info = inspect(&plain);
    let shared_info = inspect(&shared);
    assert_eq!(plain_info["stored_bytes"].as_u64(), Some(2 * original));
    assert_eq!(shared_info["logical_bytes"].as_u64(), Some(2 * original));
    assert!(shared_info["stored_bytes"].as_u64().unwrap() <= original);
}

#[test]
fn partial_shuffle_preserves_anchors_and_is_reproducible() {
    let directory = tempdir().unwrap();
    let shuffled = directory.path().join("shuffled");
    let duplicate = directory.path().join("duplicate");
    let options = &[
        "--order",
        "shuffled",
        "--chunk-size",
        "256",
        "--range",
        "4096:20480",
        "--seed",
        "42",
    ];
    success(&pack(&shuffled, options, false));
    success(&pack(&duplicate, options, false));
    let bytes = fs::read(&shuffled).unwrap();
    assert_eq!(
        bytes,
        fs::read(&duplicate).unwrap(),
        "same seed and inputs must reproduce whole container"
    );
    let launcher_length = fs::metadata(env!("CARGO_BIN_EXE_fatelf-launcher"))
        .unwrap()
        .len() as usize;
    let a = fs::read(&fixtures().a).unwrap();
    let b = fs::read(&fixtures().b).unwrap();
    let mut original = [a.as_slice(), b.as_slice()].concat();
    // Complete ELF64 headers are always masked, including outside shuffle scopes.
    for start in [0, a.len()] {
        for byte in &mut original[start..start + 64] {
            *byte ^= 0xa5;
        }
    }
    let stored = &bytes[launcher_length..launcher_length + original.len()];
    for (start, end) in [
        (0, 4096),
        (20480, a.len() + 4096),
        (a.len() + 20480, original.len()),
    ] {
        assert!(
            stored[start..end] == original[start..end],
            "unselected slots must stay unchanged"
        );
    }
    assert_ne!(
        &stored[4096..20480],
        &original[4096..20480],
        "selected chunks must actually move for this seed"
    );
}

#[test]
fn corrupt_selected_bytes_fail_before_execution_or_output_publication() {
    let directory = tempdir().unwrap();
    let binary = directory.path().join("corrupt");
    success(&pack(&binary, &[], false));
    let verify = || tool(&["verify".into(), binary.as_os_str().into()]);
    success(&verify());
    let mut bytes = fs::read(&binary).unwrap();
    let pool_start = fs::metadata(env!("CARGO_BIN_EXE_fatelf-launcher"))
        .unwrap()
        .len() as usize;
    bytes[pool_start + 64] ^= 1;
    fs::write(&binary, bytes).unwrap();
    let verification = verify();
    assert!(!verification.status.success());
    assert!(String::from_utf8_lossy(&verification.stderr).contains("integrity check failed"));
    let attempted = Command::new(&binary)
        .env("FATELF_VARIANT", "a")
        .output()
        .unwrap();
    assert!(!attempted.status.success());
    assert!(String::from_utf8_lossy(&attempted.stderr).contains("integrity check failed"));
    let recovered = directory.path().join("recovered");
    let attempted = tool(&[
        "extract".into(),
        binary.as_os_str().into(),
        "--variant".into(),
        "a".into(),
        "-o".into(),
        recovered.as_os_str().into(),
    ]);
    assert!(!attempted.status.success());
    assert!(
        !recovered.exists(),
        "unverified bytes must not be published"
    );
    let unaffected = Command::new(&binary)
        .args(["exit", "23"])
        .env("FATELF_VARIANT", "b")
        .output()
        .unwrap();
    assert_eq!(unaffected.status.code(), Some(23));
}

#[test]
fn existing_outputs_inputs_and_launcher_are_never_overwritten() {
    let directory = tempdir().unwrap();
    let existing = directory.path().join("existing");
    fs::write(&existing, b"keep this").unwrap();
    let payload = directory.path().join("input");
    let launcher = directory.path().join("launcher");
    fs::copy(&fixtures().a, &payload).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_fatelf-launcher"), &launcher).unwrap();
    for path in [&existing, &payload, &launcher] {
        let before = fs::read(path).unwrap();
        let attempted = tool(&[
            "pack".into(),
            format!("a={}", payload.display()).into(),
            "--launcher".into(),
            launcher.as_os_str().into(),
            "-o".into(),
            path.as_os_str().into(),
        ]);
        assert!(!attempted.status.success());
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn invalid_launcher_descriptor_is_rejected_without_creating_output() {
    let directory = tempdir().unwrap();
    let launcher = directory.path().join("launcher");
    let payload = directory.path().join("payload");
    let output = directory.path().join("combined");
    let original = fs::read(env!("CARGO_BIN_EXE_fatelf-launcher")).unwrap();
    let elf = object::File::parse(original.as_slice()).unwrap();
    let (offset, _) = elf
        .section_by_name(".fatelf")
        .unwrap()
        .file_range()
        .unwrap();
    let offset = usize::try_from(offset).unwrap();
    fs::copy(&fixtures().a, &payload).unwrap();
    for (description, index, byte) in [
        ("invalid magic", 0, b'X'),
        ("unknown codec", 8, 0x80),
        ("nonzero reserved byte", 9, 1),
    ] {
        let mut bytes = original.clone();
        bytes[offset + index] = byte;
        fs::write(&launcher, bytes).unwrap();
        let attempted = tool(&[
            "pack".into(),
            format!("sample={}", payload.display()).into(),
            "--launcher".into(),
            launcher.as_os_str().into(),
            "-o".into(),
            output.as_os_str().into(),
        ]);
        assert!(!attempted.status.success(), "{description}");
        assert!(
            String::from_utf8_lossy(&attempted.stderr)
                .contains("invalid launcher capability descriptor"),
            "{description}: {}",
            String::from_utf8_lossy(&attempted.stderr),
        );
        assert!(!output.exists(), "{description}");
    }
}

#[test]
fn duplicate_launcher_descriptor_is_rejected() {
    let directory = tempdir().unwrap();
    let launcher = directory.path().join("launcher");
    let output = directory.path().join("combined");
    let mut bytes = fs::read(env!("CARGO_BIN_EXE_fatelf-launcher")).unwrap();
    let elf = object::File::parse(bytes.as_slice()).unwrap();
    let capabilities = elf.section_by_name(".fatelf").unwrap();
    let names = elf.section_by_name(".shstrtab").unwrap();
    assert!(names.index().0 > capabilities.index().0);
    let (offset, _) = names.file_range().unwrap();
    let name_offset = names
        .data()
        .unwrap()
        .windows(10)
        .position(|name| name == b".shstrtab\0")
        .unwrap();
    let name_offset = usize::try_from(offset).unwrap() + name_offset;
    bytes[name_offset..name_offset + 8].copy_from_slice(b".fatelf\0");
    fs::write(&launcher, bytes).unwrap();

    let attempted = tool(&[
        "pack".into(),
        format!("sample={}", fixtures().a.display()).into(),
        "--launcher".into(),
        launcher.into_os_string(),
        "-o".into(),
        output.as_os_str().into(),
    ]);
    assert!(!attempted.status.success());
    assert!(
        String::from_utf8_lossy(&attempted.stderr)
            .contains("invalid launcher capability descriptor")
    );
    assert!(!output.exists());
}

#[test]
fn build_respects_each_declared_launcher_codec() {
    let directory = tempdir().unwrap();
    let launcher = directory.path().join("launcher");
    let payload = directory.path().join("payload");
    let config = directory.path().join("bundle.toml");
    let key = directory.path().join("key");
    fs::write(&key, [13; 32]).unwrap();
    fs::copy(&fixtures().a, &payload).unwrap();
    let input = fs::OpenOptions::new().write(true).open(&payload).unwrap();
    input
        .set_len(input.metadata().unwrap().len() + 65536)
        .unwrap();

    let original = fs::read(env!("CARGO_BIN_EXE_fatelf-launcher")).unwrap();
    let elf = object::File::parse(original.as_slice()).unwrap();
    let (offset, _) = elf
        .section_by_name(".fatelf")
        .unwrap()
        .file_range()
        .unwrap();
    let mask_offset = usize::try_from(offset).unwrap() + 8;
    for (name, mask, compression, encryption, supported) in [
        ("core-with-lz4", 0, "lz4", "none", false),
        ("core-with-encryption", 0, "none", "key", false),
        ("lz4-only", 1, "lz4", "none", true),
        ("encryption-only", 2, "none", "key", true),
    ] {
        let mut bytes = original.clone();
        bytes[mask_offset] = mask;
        fs::write(&launcher, bytes).unwrap();
        let output = directory.path().join(name);
        let settings = serde_json::json!({
            "version": 2, "output": output, "launcher": launcher,
            "storage": {"compression": compression},
            "keys": [{"name": "key", "key_file": key, "env": "FATELF_TEST_KEY"}],
            "payloads": [{"name": "sample", "path": payload, "encryption": encryption}],
        });
        fs::write(&config, toml::to_string_pretty(&settings).unwrap()).unwrap();
        let attempted = tool(&["build".into(), "--config".into(), config.as_os_str().into()]);
        if supported {
            success(&attempted);
        } else {
            assert!(!attempted.status.success(), "{name}");
            assert!(
                String::from_utf8_lossy(&attempted.stderr)
                    .contains("launcher does not support the selected codecs"),
                "{name}"
            );
        }
        assert_eq!(output.exists(), supported, "{name}");
    }
}

#[test]
fn invalid_selection_policy_or_scope_never_creates_output() {
    let options: &[&[&str]] = &[
        &["--select-env", "BAD=NAME"],
        &["--default", "missing"],
        &["--order", "shuffled", "--section", ".missing"],
        &["--order", "shuffled", "--section", ".bss"],
        &["--order", "shuffled", "--range", "0:1073741824"],
        &["--range", "0:256"],
    ];
    for mode in options {
        let directory = tempdir().unwrap();
        let binary = directory.path().join("combined");
        let attempted = pack(&binary, mode, false);
        assert!(!attempted.status.success(), "invalid options {mode:?}");
        assert!(!binary.exists());
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            0,
            "temporary pack files must be cleaned up"
        );
    }
}

#[test]
fn native_payload_keeps_default_sigpipe_behavior() {
    let original = Path::new("/usr/bin/yes");
    let broken_pipe_status = |binary: &Path| {
        let mut child = Command::new(binary)
            .env("FATELF_VARIANT", "a")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        drop(child.stdout.take());
        child.wait().unwrap()
    };
    assert_eq!(broken_pipe_status(original).signal(), Some(13));
    for backend in ["memfd", "file"] {
        let directory = tempdir().unwrap();
        let binary = directory.path().join("combined");
        let packed = tool(&[
            "pack".into(),
            "a=/usr/bin/yes".into(),
            "b=/usr/bin/yes".into(),
            "--launcher".into(),
            env!("CARGO_BIN_EXE_fatelf-launcher").into(),
            "--exec".into(),
            backend.into(),
            "-o".into(),
            binary.as_os_str().into(),
        ]);
        success(&packed);
        assert_eq!(
            broken_pipe_status(&binary).signal(),
            Some(13),
            "{backend}: Rust launcher must not make native payload ignore SIGPIPE"
        );
    }
}

/// Independently read the fixed v2 footer; test code does not use the production parser.
fn metadata(binary: &Path) -> (Vec<u8>, usize, usize, Value) {
    let bytes = fs::read(binary).unwrap();
    let footer = bytes.len() - 64;
    assert_eq!(&bytes[footer..footer + 8], b"FATELF02");
    let start = u64::from_le_bytes(bytes[footer + 16..footer + 24].try_into().unwrap()) as usize;
    let length = u64::from_le_bytes(bytes[footer + 24..footer + 32].try_into().unwrap()) as usize;
    let value = serde_json::from_slice(&bytes[start..start + length]).unwrap();
    (bytes, start, length, value)
}

#[test]
fn encrypted_second_payload_is_selective_and_key_environment_is_private() {
    for (position, backend) in [("front", "memfd"), ("end", "file")] {
        let directory = tempdir().unwrap();
        let binary = directory.path().join("combined");
        let key = directory.path().join("key");
        fs::write(&key, [7_u8; 32]).unwrap();
        let config = serde_json::json!({
            "version":2,"output":binary,"launcher":env!("CARGO_BIN_EXE_fatelf-launcher"),
            "payloads":[{"name":"a","path":fixtures().a,"shuffle":false},
                {"name":"b","path":fixtures().b,"shuffle":true,"encryption":"ps","compression":"lz4"}],
            "keys":[{"name":"ps","key_file":key,"env":"PS_KEY_FILE"}],
            "storage":{"order":"shuffled","manifest_position":position,"dedup":true,"seed":42,"xor":position == "front"},
            "execution":{"backend":backend}
        });
        let path = directory.path().join("bundle.toml");
        fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
        let plan = tool(&["plan".into(), "--config".into(), path.as_os_str().into()]);
        success(&plan);
        assert!(!binary.exists(), "plan must not publish an executable");
        success(&tool(&[
            "build".into(),
            "--config".into(),
            path.as_os_str().into(),
        ]));
        let mut verify = Command::new(env!("CARGO_BIN_EXE_fatelf"));
        verify.arg("verify").arg(&binary).env_remove("PS_KEY_FILE");
        let missing_key = verify.output().unwrap();
        assert!(!missing_key.status.success());
        assert!(String::from_utf8_lossy(&missing_key.stderr).contains("PS_KEY_FILE"));
        success(&verify.env("PS_KEY_FILE", &key).output().unwrap());
        let a = Command::new(&binary)
            .arg("key-environment")
            .env("FATELF_VARIANT", "a")
            .env("PS_KEY_FILE", "unused-invalid-file")
            .output()
            .unwrap();
        success(&a);
        assert_eq!(
            a.stdout, b"false\n",
            "even unselected key references stay private"
        );
        for supplied in [None, Some(directory.path().join("missing"))] {
            let mut command = Command::new(&binary);
            command
                .arg("key-environment")
                .env("FATELF_VARIANT", "b")
                .env_remove("PS_KEY_FILE");
            if let Some(path) = supplied {
                command.env("PS_KEY_FILE", path);
            }
            let attempted = command.output().unwrap();
            assert!(!attempted.status.success());
            assert!(
                attempted.stdout.is_empty(),
                "key errors must prevent payload execution"
            );
        }
        let b = Command::new(&binary)
            .arg("key-environment")
            .env("FATELF_VARIANT", "b")
            .env("PS_KEY_FILE", &key)
            .output()
            .unwrap();
        success(&b);
        assert_eq!(b.stdout, b"false\n");
        let recovered = directory.path().join("recovered");
        let extracted = Command::new(env!("CARGO_BIN_EXE_fatelf"))
            .args(["extract"])
            .arg(&binary)
            .args(["--variant", "b", "-o"])
            .arg(&recovered)
            .env("PS_KEY_FILE", &key)
            .output()
            .unwrap();
        success(&extracted);
        assert_eq!(
            fs::read(recovered).unwrap(),
            fs::read(&fixtures().b).unwrap()
        );
        // Wrong key must neither run nor publish recovered bytes.
        fs::write(&key, [8_u8; 32]).unwrap();
        let denied = Command::new(&binary)
            .arg("exit")
            .arg("9")
            .env("FATELF_VARIANT", "b")
            .env("PS_KEY_FILE", &key)
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("authentication failed"));
        let unpublished = directory.path().join("unpublished");
        let denied = Command::new(env!("CARGO_BIN_EXE_fatelf"))
            .arg("extract")
            .arg(&binary)
            .args(["--variant", "b", "-o"])
            .arg(&unpublished)
            .env("PS_KEY_FILE", &key)
            .output()
            .unwrap();
        assert!(!denied.status.success());
        assert!(!unpublished.exists());
        fs::write(&key, [7_u8; 32]).unwrap();
        // Change a policy field and repair the public hash. AEAD must still reject it.
        let (mut bytes, start, length, _) = metadata(&binary);
        let mut manifest = String::from_utf8(bytes[start..start + length].to_vec()).unwrap();
        assert!(manifest.contains("\"default\":\"a\""));
        manifest = manifest.replacen("\"default\":\"a\"", "\"default\":\"b\"", 1);
        bytes[start..start + length].copy_from_slice(manifest.as_bytes());
        let footer = bytes.len() - 64;
        bytes[footer + 32..].copy_from_slice(blake3::hash(manifest.as_bytes()).as_bytes());
        fs::write(&binary, bytes).unwrap();
        let denied = Command::new(&binary)
            .arg("key-environment")
            .env_remove("FATELF_VARIANT")
            .env("PS_KEY_FILE", &key)
            .output()
            .unwrap();
        assert!(
            !denied.status.success(),
            "manifest repair cannot forge encrypted-object AAD"
        );
        assert!(String::from_utf8_lossy(&denied.stderr).contains("authentication failed"));
    }
}

#[test]
fn only_payload_headers_are_masked_and_only_selected_payload_is_shuffled() {
    let directory = tempdir().unwrap();
    let binary = directory.path().join("combined");
    success(&pack(
        &binary,
        &[
            "--order",
            "shuffled",
            "--shuffle-payload",
            "b",
            "--seed",
            "42",
        ],
        false,
    ));
    let (bytes, _, _, manifest) = metadata(&binary);
    let pool = fs::metadata(env!("CARGO_BIN_EXE_fatelf-launcher"))
        .unwrap()
        .len() as usize;
    assert_eq!(&bytes[..4], b"\x7fELF");
    for payload in manifest["payloads"].as_array().unwrap() {
        let id = payload["chunks"][0].as_u64().unwrap() as usize;
        let chunk = &manifest["chunks"][id];
        let start = pool + chunk["offset"].as_u64().unwrap() as usize;
        assert_ne!(
            &bytes[start..start + 4],
            b"\x7fELF",
            "stored payload header must be obscured"
        );
        assert_eq!(chunk["encoding"], "elf-header-xor-a5");
    }
    let a = fs::read(&fixtures().a).unwrap();
    assert_eq!(
        &bytes[pool + 64..pool + a.len()],
        &a[64..],
        "first payload body stays plain and ordered"
    );
    let b = fs::read(&fixtures().b).unwrap();
    let mut b_first = 0;
    for id in manifest["payloads"][1]["chunks"].as_array().unwrap() {
        let chunk = &manifest["chunks"][id.as_u64().unwrap() as usize];
        if chunk["encoding"] == "identity" {
            b_first = chunk["offset"].as_u64().unwrap() as usize;
            break;
        }
    }
    assert_ne!(
        b_first,
        a.len() + 64,
        "second payload must actually move for this seed"
    );
    assert_eq!(
        inspect(&binary)["logical_bytes"].as_u64(),
        Some((a.len() + b.len()) as u64)
    );
}

#[test]
fn payload_xor_masks_stored_bytes_and_round_trips_without_a_key() {
    let directory = tempdir().unwrap();
    let binary = directory.path().join("xor");
    success(&pack(&binary, &["--xor"], false));
    let (bytes, _, _, manifest) = metadata(&binary);
    let pool = fs::metadata(env!("CARGO_BIN_EXE_fatelf-launcher"))
        .unwrap()
        .len() as usize;
    let original = fs::read(&fixtures().a).unwrap();
    let masked: Vec<_> = original.iter().map(|byte| byte ^ 0xa5).collect();
    assert_eq!(&bytes[pool..pool + original.len()], masked);
    assert_eq!(manifest["chunks"][0]["encoding"], "elf-header-xor-a5");
    assert_eq!(manifest["chunks"][1]["encoding"], "xor-a5");
    for backend in ["memfd", "file"] {
        if backend == "file" {
            let settings = serde_json::json!({
                "version": 2, "output": binary, "execution": {"backend": "file"},
                "storage": {"xor": true, "compression": "lz4", "manifest_position": "front"},
                "payloads": [{"name": "a", "path": fixtures().a}],
            });
            let config = directory.path().join("xor.toml");
            fs::remove_file(&binary).unwrap();
            fs::write(&config, toml::to_string(&settings).unwrap()).unwrap();
            success(&tool(&[
                "build".into(),
                "--config".into(),
                config.into_os_string(),
            ]));
            let (_, _, _, manifest) = metadata(&binary);
            assert_eq!(manifest["chunks"][1]["encoding"], "xor-a5");
        }
        success(
            &Command::new(&binary)
                .args(["exit", "0"])
                .env_remove("FATELF_VARIANT")
                .output()
                .unwrap(),
        );
        let extracted = directory.path().join(backend);
        success(&tool(&[
            "extract".into(),
            binary.as_os_str().into(),
            "--variant".into(),
            "a".into(),
            "-o".into(),
            extracted.as_os_str().into(),
        ]));
        assert_eq!(fs::read(extracted).unwrap(), original);
    }
}

#[test]
fn plain_pack_rejects_a_previous_launcher_revision() {
    let directory = tempdir().unwrap();
    let launcher = directory.path().join("launcher");
    let bundle = directory.path().join("bundle");
    let mut bytes = fs::read(env!("CARGO_BIN_EXE_fatelf-launcher")).unwrap();
    let elf = object::File::parse(bytes.as_slice()).unwrap();
    let (offset, _) = elf
        .section_by_name(".fatelf")
        .unwrap()
        .file_range()
        .unwrap();
    bytes[offset as usize + 7] = b'2';
    fs::write(&launcher, bytes).unwrap();
    let output = tool(&[
        "pack".into(),
        format!("a={}", fixtures().a.display()).into(),
        "--launcher".into(),
        launcher.as_os_str().into(),
        "-o".into(),
        bundle.as_os_str().into(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("launcher compatibility revision"));
    assert!(!bundle.exists());

    let config = directory.path().join("bundle.toml");
    let settings = serde_json::json!({
        "version": 2, "output": bundle, "launcher": launcher,
        "payloads": [{"name": "a", "path": fixtures().a}]
    });
    fs::write(&config, toml::to_string(&settings).unwrap()).unwrap();
    for command in ["doctor", "plan"] {
        let output = tool(&[command.into(), "--config".into(), config.as_os_str().into()]);
        assert!(!output.status.success(), "{command}");
        assert!(
            [&output.stdout, &output.stderr]
                .iter()
                .any(|stream| String::from_utf8_lossy(stream).contains("FATCAP03")),
            "{command} should name the required revision"
        );
        assert!(!bundle.exists());
    }
}

#[test]
fn smoke_runs_the_requested_variant_with_its_arguments_and_status() {
    let directory = tempdir().unwrap();
    let bundle = directory.path().join("bundle");
    success(&pack(
        &bundle,
        &["--select-env", "FATELF_TEST_CHOICE", "--default", "a"],
        false,
    ));
    let output = tool(&[
        "smoke".into(),
        bundle.as_os_str().into(),
        "--variant".into(),
        "b".into(),
        "--".into(),
        "context".into(),
        OsString::from_vec(b"arg\xff".to_vec()),
    ]);
    success(&output);
    let mut expected = b"b\0".to_vec();
    expected.extend_from_slice(bundle.as_os_str().as_bytes());
    expected.extend_from_slice(b"\0context\0arg\xff\0");
    assert!(output.stdout.starts_with(&expected));
    let output = tool(&[
        "smoke".into(),
        bundle.as_os_str().into(),
        "--variant".into(),
        "b".into(),
        "--".into(),
        "exit".into(),
        "27".into(),
    ]);
    assert_eq!(output.status.code(), Some(27));
    assert!(output.stderr.is_empty());
    for expected in ["27", "0"] {
        let output = tool(&[
            "smoke".into(),
            bundle.as_os_str().into(),
            "--variant".into(),
            "b".into(),
            "--expect-exit".into(),
            expected.into(),
            "--".into(),
            "exit".into(),
            "27".into(),
        ]);
        assert_eq!(output.status.success(), expected == "27");
    }
    let output = tool(&[
        "smoke".into(),
        bundle.as_os_str().into(),
        "--variant".into(),
        "missing".into(),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown payload"));
}

#[test]
fn promotion_requires_all_smokes_and_rollback_restores_the_previous_inode() {
    use std::os::unix::fs::MetadataExt;

    let directory = tempdir().unwrap();
    let live = directory.path().join("live");
    let staged = directory.path().join("staged");
    let checks = directory.path().join("smoke.toml");
    success(&pack(&live, &["--default", "a"], false));
    success(&pack(&staged, &["--default", "b"], false));
    let inode = |path| fs::metadata(path).unwrap().ino();
    let original = [inode(&live), inode(&staged)];
    let promote = || {
        tool(&[
            "promote".into(),
            staged.as_os_str().into(),
            "--live".into(),
            live.as_os_str().into(),
            "--checks".into(),
            checks.as_os_str().into(),
        ])
    };
    for (checks_text, error) in [
        ("a = ['exit', '0']\n", "cover every bundle variant"),
        (
            "a = ['exit', '0']\nb = ['exit', '17']\n",
            "returned exit status: 17",
        ),
    ] {
        fs::write(&checks, checks_text).unwrap();
        let rejected = promote();
        assert!(!rejected.status.success());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains(error));
        assert_eq!([inode(&live), inode(&staged)], original);
    }
    fs::write(&checks, "a = ['exit', '0']\nb = ['exit', '0']\n").unwrap();
    success(&promote());
    assert_eq!([inode(&live), inode(&staged)], [original[1], original[0]]);
    assert_eq!(inspect(&live)["default"], "b");
    success(&tool(&[
        "rollback".into(),
        staged.as_os_str().into(),
        "--live".into(),
        live.as_os_str().into(),
    ]));
    assert_eq!([inode(&live), inode(&staged)], original);
    assert_eq!(inspect(&live)["default"], "a");
    let mut damaged = fs::read(&staged).unwrap();
    damaged[0] = 0;
    fs::write(&staged, damaged).unwrap();
    let rejected = tool(&[
        "rollback".into(),
        staged.as_os_str().into(),
        "--live".into(),
        live.as_os_str().into(),
    ]);
    assert!(
        !rejected.status.success(),
        "rollback admitted a damaged launcher"
    );
    assert_eq!([inode(&live), inode(&staged)], original);
}
