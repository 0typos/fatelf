//! Config-driven builds prove path alignment and equivalence to the direct CLI.

use std::{
    ffi::OsString,
    fs,
    path::Path,
    process::{Command, Output},
};

use object::{Object, ObjectSection};
use serde_json::{Value, json};
use tempfile::tempdir;

/// Invoke the real packer, optionally from an unrelated current directory.
fn tool(args: &[OsString], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fatelf"))
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap()
}

/// Produce a complete valid configuration as serializable data for targeted mutations.
fn settings(output: &str) -> Value {
    json!({
        "version": 2, "output": output,
        "launcher": env!("CARGO_BIN_EXE_fatelf-launcher"),
        "payloads": [{"name": "a", "path": "/usr/bin/true"}, {"name": "b", "path": "/usr/bin/false"}],
        "selection": {"env": "APP_MODE", "default": "b"},
        "storage": {"layout": "overlay", "order": "shuffled", "dedup": true, "chunk_size": 256, "seed": 42,
            "ranges": ["4096:8192"]},
        "execution": {"backend": "file"}
    })
}

/// Report a subprocess failure with its original diagnostics.
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn toml_build_matches_direct_pack_and_aligns_relative_paths_to_config() {
    let directory = tempdir().unwrap();
    let configs = directory.path().join("configs");
    let elsewhere = directory.path().join("elsewhere");
    fs::create_dir(&configs).unwrap();
    fs::create_dir(&elsewhere).unwrap();
    fs::copy("/usr/bin/true", configs.join("one")).unwrap();
    fs::copy("/usr/bin/false", configs.join("two")).unwrap();
    let mut config = settings("combined");
    config["payloads"] =
        json!([{"name":"a","path":"one"}, {"name":"b","path":"two"}, {"name":"c","path":"one"}]);
    let path = configs.join("bundle.toml");
    fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
    success(&tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        &elsewhere,
    ));
    let combined = configs.join("combined");
    assert!(
        combined.exists(),
        "relative output belongs beside the config"
    );
    assert!(!elsewhere.join("combined").exists());
    let direct = directory.path().join("direct");
    success(&tool(
        &[
            "pack".into(),
            format!("a={}", configs.join("one").display()).into(),
            format!("b={}", configs.join("two").display()).into(),
            format!("c={}", configs.join("one").display()).into(),
            "-o".into(),
            direct.as_os_str().into(),
            "--launcher".into(),
            env!("CARGO_BIN_EXE_fatelf-launcher").into(),
            "--select-env".into(),
            "APP_MODE".into(),
            "--default".into(),
            "b".into(),
            "--exec".into(),
            "file".into(),
            "--order".into(),
            "shuffled".into(),
            "--dedup".into(),
            "--chunk-size".into(),
            "256".into(),
            "--seed".into(),
            "42".into(),
            "--range".into(),
            "4096:8192".into(),
        ],
        &elsewhere,
    ));
    assert_eq!(
        fs::read(&combined).unwrap(),
        fs::read(&direct).unwrap(),
        "config and CLI must share packing semantics"
    );
    for (name, code) in [("a", 0), ("b", 1), ("c", 0)] {
        let executed = Command::new(&combined)
            .env("APP_MODE", name)
            .output()
            .unwrap();
        assert_eq!(
            executed.status.code(),
            Some(code),
            "payload {name}: {}",
            String::from_utf8_lossy(&executed.stderr)
        );
    }
}

#[test]
fn builds_embed_distinct_launcher_identities_without_changing_capabilities() {
    let directory = tempdir().unwrap();
    let config_path = directory.path().join("bundle.toml");
    let launcher_path = env!("CARGO_BIN_EXE_fatelf-launcher");
    let launcher_bytes = fs::read(launcher_path).unwrap();
    let launcher = object::File::parse(launcher_bytes.as_slice()).unwrap();
    let descriptor = launcher.section_by_name(".fatelf").unwrap().data().unwrap();
    for name in ["staging", "production"] {
        let version = format!("{name}-{}", "v".repeat(63 - name.len()));
        let mut config = settings(name);
        config["launcher_name"] = json!(name);
        config["launcher_version"] = json!(version);
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        success(&tool(
            &[
                "build".into(),
                "--config".into(),
                config_path.as_os_str().into(),
            ],
            directory.path(),
        ));
        let bundle_path = directory.path().join(name);
        let bytes = fs::read(&bundle_path).unwrap();
        let bundle = object::File::parse(bytes.as_slice()).unwrap();
        let identity = bundle
            .section_by_name(".fatelf.identity")
            .unwrap()
            .data()
            .unwrap();
        assert_eq!(identity.len(), 138);
        assert_eq!(&identity[..8], b"FATID01\0");
        assert_eq!(&identity[8..8 + name.len()], name.as_bytes());
        assert!(identity[8 + name.len()..73].iter().all(|&byte| byte == 0));
        assert_eq!(&identity[73..137], version.as_bytes());
        assert_eq!(identity[137], 0);
        assert_eq!(
            bundle.section_by_name(".fatelf").unwrap().data().unwrap(),
            descriptor
        );
        success(
            &Command::new(bundle_path)
                .env("APP_MODE", "a")
                .output()
                .unwrap(),
        );
    }
    assert_eq!(fs::read(launcher_path).unwrap(), launcher_bytes);
}

#[test]
fn invalid_or_unknown_config_fields_fail_before_output_creation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    let mutations: &[(&str, &str, Value)] = &[
        ("", "version", json!(1)),
        ("", "unknown", json!(true)),
        ("", "launcher_name", json!("a b")),
        ("", "launcher_version", json!("v".repeat(65))),
        ("storage", "layout", json!("scattered")),
        ("storage", "unknown", json!(1)),
        ("selection", "unknown", json!("bad")),
        ("selection", "env", json!("BAD=NAME")),
        ("selection", "default", json!("missing")),
        ("execution", "unknown", json!(true)),
        ("execution", "backend", json!("other")),
        ("storage", "chunk_size", json!(0)),
        ("storage", "seed", json!(-1)),
        ("storage", "sections", json!([".text"])),
        ("storage", "order", json!("ordered")),
        ("storage", "ranges", json!(["10:2"])),
        ("", "output", json!("")),
        ("", "payloads", json!([])),
        (
            "",
            "payloads",
            json!([{"name":"a","path":""},{"name":"b","path":"/usr/bin/false"}]),
        ),
        (
            "",
            "payloads",
            json!([{"name":"a","path":"/usr/bin/true"},{"name":"a","path":"/usr/bin/false"}]),
        ),
        (
            "",
            "payloads",
            json!([{"name":"a","path":"/usr/bin/true","unknown":1},{"name":"b","path":"/usr/bin/false"}]),
        ),
    ];
    for (table, key, value) in mutations {
        let mut config = settings("combined");
        if table.is_empty() {
            config[*key] = value.clone();
        } else {
            config[*table][*key] = value.clone();
        }
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let attempted = tool(
            &["build".into(), "--config".into(), path.as_os_str().into()],
            directory.path(),
        );
        assert!(
            !attempted.status.success(),
            "accepted invalid {table}.{key}={value}"
        );
        assert!(!directory.path().join("combined").exists());
    }
}

#[test]
fn config_size_and_terminal_requirements_fail_cleanly() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("large.toml");
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    let attempted = tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        directory.path(),
    );
    assert!(!attempted.status.success());
    assert!(String::from_utf8_lossy(&attempted.stderr).contains("1 MiB"));
    let config = directory.path().join("bundle.toml");
    let attempted = tool(
        &[
            "configure".into(),
            "--output".into(),
            config.as_os_str().into(),
        ],
        directory.path(),
    );
    assert!(!attempted.status.success());
    assert!(String::from_utf8_lossy(&attempted.stderr).contains("interactive terminal"));
    assert!(!config.exists());
}

#[test]
fn config_read_checks_actual_bytes_even_when_procfs_reports_zero() {
    const PADDING_LEN: usize = 120_000;
    const PADDING_KEYS: usize = 9;
    // SAFETY: sysconf takes a fixed selector and does not use caller memory.
    let argument_limit = unsafe { libc::sysconf(libc::_SC_ARG_MAX) };
    if argument_limit < (PADDING_LEN * PADDING_KEYS + 4096) as libc::c_long {
        return;
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_fatelf"));
    command
        .args(["build", "--config", "/proc/self/environ"])
        .env_clear();
    let padding = "x".repeat(PADDING_LEN);
    for index in 0..PADDING_KEYS {
        command.env(format!("FATELF_TEST_PADDING_{index}"), &padding);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("configuration exceeds 1 MiB"),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn xor_mask_generator_and_config_reject_out_of_range_lengths() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    for length in [0, 33] {
        let generated = tool(
            &["xor-mask".into(), length.to_string().into()],
            directory.path(),
        );
        assert!(!generated.status.success(), "{length}");
        assert!(generated.stdout.is_empty());
        let mut config = settings("combined");
        config["storage"]["xor_mask"] = json!(vec![1; length]);
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let build = tool(
            &["build".into(), "--config".into(), path.as_os_str().into()],
            directory.path(),
        );
        assert!(!build.status.success(), "{length}");
        assert!(
            String::from_utf8_lossy(&build.stderr).contains("xor_mask must contain 1 to 32 bytes")
        );
        assert!(!directory.path().join("combined").exists());
    }
}

#[test]
fn single_payload_front_manifest_plan_predicts_exact_output_size() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    let mut config = settings("combined");
    config["payloads"] = json!([{"name":"b","path":"/usr/bin/false"}]);
    config["storage"]["manifest_position"] = json!("front");
    config["storage"]["compression"] = json!("lz4");
    let generated = tool(&["xor-mask".into(), "32".into()], directory.path());
    success(&generated);
    let setting: toml::Table =
        toml::from_str(std::str::from_utf8(&generated.stdout).unwrap()).unwrap();
    let mask = setting["xor_mask"].as_array().unwrap();
    assert_eq!(mask.len(), 32);
    config["storage"]["xor_mask"] = serde_json::to_value(mask).unwrap();
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let planned = tool(
        &["plan".into(), "--config".into(), path.as_os_str().into()],
        directory.path(),
    );
    success(&planned);
    let plan: Value = serde_json::from_slice(&planned.stdout).unwrap();
    assert!(
        !directory.path().join("combined").exists(),
        "planning must not publish an output"
    );
    success(&tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        directory.path(),
    ));
    let combined = directory.path().join("combined");
    assert_eq!(
        fs::metadata(&combined).unwrap().len(),
        plan["output_bytes"].as_u64().unwrap()
    );
    let executed = Command::new(&combined)
        .env_remove("APP_MODE")
        .output()
        .unwrap();
    assert_eq!(
        executed.status.code(),
        Some(1),
        "one payload must execute through a front manifest"
    );
    assert!(executed.stderr.is_empty());
    let bytes = fs::read(&combined).unwrap();
    let launcher_length = fs::metadata(env!("CARGO_BIN_EXE_fatelf-launcher"))
        .unwrap()
        .len() as usize;
    assert_eq!(
        bytes[launcher_length], b'{',
        "front metadata follows the launcher ELF"
    );
}

#[test]
fn encrypted_second_payload_uses_relative_external_key_without_gating_first() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let configs = directory.path().join("configs");
    let elsewhere = directory.path().join("elsewhere");
    fs::create_dir(&configs).unwrap();
    fs::create_dir(&elsewhere).unwrap();
    let key = configs.join("unlock.key");
    fs::write(&key, [0x3b; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let wrong = configs.join("wrong.key");
    fs::write(&wrong, [0x3c; 32]).unwrap();
    fs::set_permissions(&wrong, fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = settings("combined");
    config["keys"] =
        json!([{"name":"second","key_file":"unlock.key","env":"FATELF_TEST_KEY_FILE"}]);
    config["payloads"][0]["shuffle"] = json!(false);
    config["payloads"][1]["shuffle"] = json!(true);
    config["payloads"][1]["encryption"] = json!("second");
    config["payloads"][1]["compression"] = json!("lz4");
    config["storage"]["manifest_position"] = json!("front");
    let path = configs.join("bundle.toml");
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let planned = tool(
        &["plan".into(), "--config".into(), path.as_os_str().into()],
        &elsewhere,
    );
    success(&planned);
    let plan: Value = serde_json::from_slice(&planned.stdout).unwrap();
    success(&tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        &elsewhere,
    ));
    let combined = configs.join("combined");
    assert_eq!(
        fs::metadata(&combined).unwrap().len(),
        plan["output_bytes"].as_u64().unwrap(),
        "fresh encryption nonces must retain the planned size"
    );
    let first = Command::new(&combined)
        .env("APP_MODE", "a")
        .env_remove("FATELF_TEST_KEY_FILE")
        .output()
        .unwrap();
    success(&first);
    let missing = Command::new(&combined)
        .env("APP_MODE", "b")
        .env_remove("FATELF_TEST_KEY_FILE")
        .output()
        .unwrap();
    assert!(
        !missing.status.success(),
        "the encrypted variant requires its external key"
    );
    let wrong_key = Command::new(&combined)
        .env("APP_MODE", "b")
        .env("FATELF_TEST_KEY_FILE", &wrong)
        .output()
        .unwrap();
    assert!(!wrong_key.status.success());
    assert!(String::from_utf8_lossy(&wrong_key.stderr).contains("authentication"));
    let second = Command::new(&combined)
        .env("APP_MODE", "b")
        .env("FATELF_TEST_KEY_FILE", &key)
        .output()
        .unwrap();
    assert_eq!(
        second.status.code(),
        Some(1),
        "decrypted false preserves its native exit status"
    );
    assert!(second.stderr.is_empty());
    let extracted = configs.join("extracted");
    let recovered = Command::new(env!("CARGO_BIN_EXE_fatelf"))
        .args([
            "extract",
            combined.to_str().unwrap(),
            "--variant",
            "b",
            "-o",
            extracted.to_str().unwrap(),
        ])
        .env("FATELF_TEST_KEY_FILE", &key)
        .output()
        .unwrap();
    success(&recovered);
    assert_eq!(
        fs::read(extracted).unwrap(),
        fs::read("/usr/bin/false").unwrap(),
        "external-key reconstruction must be byte-exact"
    );
    let inspected = tool(&["inspect".into(), combined.as_os_str().into()], &elsewhere);
    success(&inspected);
    let inspect_text = String::from_utf8(inspected.stdout).unwrap();
    assert!(
        !inspect_text.contains("unlock.key"),
        "the manifest must not contain build key paths"
    );
}

#[test]
fn region_conflicts_and_header_splits_fail_before_output_publication() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    for (name, regions) in [
        (
            "split-header",
            json!([{"range":"16:32","compression":"lz4"}]),
        ),
        (
            "conflict",
            json!([{"range":"4096:8192","compression":"none"},{"range":"6144:10240","compression":"lz4"}]),
        ),
    ] {
        let mut config = settings(name);
        config["payloads"][0]["regions"] = regions;
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let rejected = tool(
            &["build".into(), "--config".into(), path.as_os_str().into()],
            directory.path(),
        );
        assert!(!rejected.status.success(), "accepted {name}");
        assert!(!directory.path().join(name).exists());
    }
    let mut config = settings("compatible-overlap");
    config["storage"]["compression"] = json!("lz4");
    config["payloads"][0]["regions"] = json!([
        {"range":"4096:8192"},
        {"range":"6144:10240","compression":"lz4"}
    ]);
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    success(&tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        directory.path(),
    ));
}

#[test]
fn configured_resource_budgets_reject_builds_without_publishing_output() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("budgets.toml");
    for (budget, limit) in [
        ("max_payloads", 1),
        ("max_payload_bytes", 16),
        ("max_logical_bytes", 16),
        ("max_objects", 1),
        ("max_references", 1),
        ("max_stored_bytes", 16),
        ("max_spool_bytes", 16),
        ("max_manifest_bytes", 16),
        ("max_config_bytes", 16),
    ] {
        let mut config = settings("combined");
        config["budgets"] = json!({budget:limit});
        fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
        let rejected = tool(
            &["build".into(), "--config".into(), path.as_os_str().into()],
            directory.path(),
        );
        assert!(!rejected.status.success(), "accepted exceeded {budget}");
        assert!(
            !directory.path().join("combined").exists(),
            "failed {budget} build published output"
        );
    }
}

#[test]
fn unused_key_references_do_not_read_their_build_files() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    let mut config = settings("combined");
    config["keys"] =
        json!([{"name":"unused","key_file":"does-not-exist.key","env":"UNUSED_UNLOCK_FILE"}]);
    fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    success(&tool(
        &["build".into(), "--config".into(), path.as_os_str().into()],
        directory.path(),
    ));
    let first = Command::new(directory.path().join("combined"))
        .env("APP_MODE", "a")
        .env("UNUSED_UNLOCK_FILE", "/missing/runtime.key")
        .output()
        .unwrap();
    success(&first);
}

#[test]
fn doctor_reports_missing_interpreter_without_building() {
    let directory = tempdir().unwrap();
    let path = directory.path();
    let source = path.join("sample.c");
    let payload = path.join("payload");
    let config_path = path.join("bundle.toml");
    fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    let linker = path.join("missing-interpreter");
    let compilation = Command::new("cc")
        .arg(&source)
        .arg(format!("-Wl,--dynamic-linker,{}", linker.display()))
        .arg("-o")
        .arg(&payload)
        .output()
        .unwrap();
    success(&compilation);

    let mut config = settings("combined");
    config["payloads"] =
        json!([{"name": "a", "path": "payload"}, {"name": "b", "path": "/usr/bin/false"}]);
    config["execution"]["backend"] = json!("memfd");
    fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let report = Command::new(env!("CARGO_BIN_EXE_fatelf"))
        .args(["doctor", "--json", "--config"])
        .arg(&config_path)
        .env("TMPDIR", path)
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["ok"], false);
    let checks = report["checks"].as_array().unwrap();
    assert!(checks.iter().any(|check| {
        check["code"] == "interpreter"
            && check["subject"] == "a"
            && check["status"] == "error"
            && check["detail"]
                .as_str()
                .unwrap()
                .contains("missing-interpreter")
    }));
    assert!(checks.iter().any(|check| {
        check["code"] == "interpreter" && check["subject"] == "b" && check["status"] == "ok"
    }));
    assert!(
        checks
            .iter()
            .any(|check| { check["code"] == "memfd_probe" && check["status"] == "skipped" })
    );
    assert!(!path.join("combined").exists());
}

#[test]
fn doctor_warns_about_origin_and_relative_loader_paths_before_building() {
    let directory = tempdir().unwrap();
    let dir = directory.path();
    let source = dir.join("app.c");
    let config_path = dir.join("bundle.toml");
    fs::write(&source, "int main(void) { return 0; }").unwrap();
    for (runpath, message) in [
        ("${ORIGIN}/lib", "uses $ORIGIN"),
        ("relative/lib", "relative search path"),
        ("/usr/lib", ""),
    ] {
        let payload = dir.join("app");
        success(
            &Command::new("cc")
                .arg(&source)
                .arg(format!("-Wl,-rpath,{runpath}"))
                .arg("-o")
                .arg(&payload)
                .output()
                .unwrap(),
        );
        let mut config = settings("combined");
        config["payloads"] =
            json!([{"name":"a","path":payload},{"name":"b","path":"/usr/bin/true"}]);
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        for strict in [false, true] {
            let mut args = vec![
                "doctor".into(),
                "--json".into(),
                "--config".into(),
                config_path.as_os_str().into(),
            ];
            if strict {
                args.push("--strict".into());
            }
            let report = tool(&args, dir);
            let ok = !strict || message.is_empty();
            assert_eq!(
                report.status.success(),
                ok,
                "{runpath}: {}",
                String::from_utf8_lossy(&report.stderr)
            );
            let report: Value = serde_json::from_slice(&report.stdout).unwrap();
            assert_eq!(report["ok"], ok);
            let entry = report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["code"] == "payload_loader_paths" && entry["subject"] == "a")
                .unwrap();
            assert_eq!(
                entry["status"],
                if message.is_empty() { "ok" } else { "warning" },
                "{runpath}"
            );
            assert!(
                entry["detail"].as_str().unwrap().contains(message),
                "{runpath}: {entry}"
            );
            assert!(!dir.join("combined").exists());
        }
    }
}

#[test]
fn doctor_probes_memfd_without_building_and_reports_the_result() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    let mut config = settings("combined");
    config["execution"]["backend"] = json!("memfd");
    fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();
    for json in [false, true] {
        let mut args = vec![
            "doctor".into(),
            "--probe".into(),
            "--config".into(),
            path.as_os_str().into(),
        ];
        if json {
            args.push("--json".into());
        }
        let output = tool(&args, directory.path());
        success(&output);
        if json {
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["ok"], true);
            assert!(
                report["checks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|check| { check["code"] == "memfd_probe" && check["status"] == "ok" })
            );
        } else {
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.starts_with("ok memfd_probe "))
            );
        }
    }
    assert!(!directory.path().join("combined").exists());
}

#[test]
fn doctor_probe_sets_executable_permissions_under_a_restrictive_policy() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bundle.toml");
    let mut config = settings("combined");
    config["execution"]["backend"] = json!("memfd");
    fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

    let source = directory.path().join("probe-policy.c");
    let wrapper = directory.path().join("probe-policy");
    fs::write(
        &source,
        r#"
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const unsigned int mode = offsetof(struct seccomp_data, args[1])
        + (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? 4 : 0);
    const unsigned int allowed_mode = argv[1][0] == 'd' ? ~0U : 0700;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fchmod, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, mode),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, allowed_mode, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { sizeof filter / sizeof filter[0], filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)
        || prctl(PR_SET_SECCOMP, (unsigned long)SECCOMP_MODE_FILTER,
                 (unsigned long)&program, 0UL, 0UL)) {
        perror("installing the probe test policy");
        return 77;
    }
    execv(argv[2], argv + 2);
    perror("executing fatelf");
    return 127;
}
"#,
    )
    .unwrap();
    success(
        &Command::new("cc")
            .arg(&source)
            .arg("-o")
            .arg(&wrapper)
            .output()
            .unwrap(),
    );
    for (policy, expected) in [("allow-0700", "ok"), ("deny", "error")] {
        let output = Command::new(&wrapper)
            .arg(policy)
            .arg(env!("CARGO_BIN_EXE_fatelf"))
            .args(["doctor", "--json", "--probe", "--config"])
            .arg(&path)
            .output()
            .unwrap();
        if output.status.code() == Some(77) {
            return;
        }
        assert_eq!(output.status.success(), expected == "ok");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| { check["code"] == "memfd_probe" && check["status"] == expected })
        );
    }
}

#[test]
fn doctor_returns_json_for_an_invalid_configuration() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bad.toml");
    fs::write(&path, "version = 1").unwrap();
    let output = tool(
        &[
            "doctor".into(),
            "--json".into(),
            "--config".into(),
            path.into_os_string(),
        ],
        directory.path(),
    );
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["checks"][0]["code"], "config");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn doctor_and_build_reject_a_shared_library_without_an_entry_point() {
    let directory = tempdir().unwrap();
    let path = directory.path();
    let source = path.join("library.c");
    fs::write(&source, "int exported(void) { return 0; }\n").unwrap();
    success(
        &Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(path.join("library.so"))
            .arg(source)
            .output()
            .unwrap(),
    );
    let mut config = settings("combined");
    config["payloads"] = json!([{"name": "library", "path": "library.so"}]);
    config["selection"]["default"] = json!("library");
    fs::write(
        path.join("bundle.toml"),
        toml::to_string_pretty(&config).unwrap(),
    )
    .unwrap();
    for command in ["doctor", "build"] {
        let output = tool(
            &[command.into(), "--config".into(), "bundle.toml".into()],
            path,
        );
        assert!(
            !output.status.success(),
            "{command} admitted a shared library"
        );
        let diagnostics = [output.stdout, output.stderr].concat();
        assert!(String::from_utf8_lossy(&diagnostics).contains("no executable entry point"));
    }
    assert!(!path.join("combined").exists());
}

#[path = "support/pty.rs"]
mod test_pty;

#[test]
fn editor_restores_terminal_after_cancel_save_build_and_sigterm() {
    use std::{
        io::Write,
        os::unix::process::ExitStatusExt,
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };

    use rustix::process::{Pid, Signal, kill_process};

    let position = |transcript: &[u8], sequence: &[u8]| {
        transcript
            .windows(sequence.len())
            .position(|bytes| bytes == sequence)
    };
    let enter = b"\x1b[?1049h";
    let leave = b"\x1b[?1049l";
    let hide = b"\x1b[?25l";
    let show = b"\x1b[?25h";
    for (input, saves, builds, missing_tty) in [
        (Some(&b"\x03"[..]), false, false, None),
        (Some(&b"\x1b[15~"[..]), true, false, None),
        (Some(&b"\x1b[17~"[..]), true, true, None),
        (None, false, false, None),
        (None, false, false, Some("stdin")),
        (None, false, false, Some("stdout")),
    ] {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.toml");
        let destination = directory.path().join("saved.toml");
        fs::write(
            &source,
            toml::to_string_pretty(&settings("combined")).unwrap(),
        )
        .unwrap();
        let mut pty = test_pty::Pty::open();
        let original = pty.settings();
        let mut command = Command::new(env!("CARGO_BIN_EXE_fatelf"));
        command
            .args(["configure", "--config"])
            .arg(&source)
            .arg("--output")
            .arg(&destination)
            .stderr(Stdio::piped());
        pty.attach(&mut command, missing_tty != Some("stdin"));
        match missing_tty {
            Some("stdin") => {
                command.stdin(Stdio::null());
            }
            Some("stdout") => {
                command.stdout(Stdio::null());
            }
            _ => {}
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut transcript = Vec::new();
        let mut sent = false;
        while child.try_wait().unwrap().is_none() {
            pty.drain(&mut transcript);
            if missing_tty.is_none()
                && !sent
                && pty.is_raw()
                && position(&transcript, enter).is_some()
                && position(&transcript, hide).is_some()
            {
                if let Some(input) = input {
                    pty.master.write_all(input).unwrap();
                } else {
                    kill_process(Pid::from_raw(child.id() as i32).unwrap(), Signal::TERM).unwrap();
                }
                sent = true;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                let result = child.wait_with_output().unwrap();
                panic!(
                    "editor timed out for {input:?}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        let result = child.wait_with_output().unwrap();
        pty.drain(&mut transcript);
        pty.assert_restored(&original);
        if missing_tty.is_some() {
            assert_eq!(result.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&result.stderr)
                    .contains("requires an interactive terminal")
            );
            assert!(!destination.exists());
            continue;
        }
        assert!(sent, "{input:?}: editor must finish terminal setup");
        for (setup, restore) in [(enter.as_slice(), leave.as_slice()), (hide, show)] {
            let setup_index = position(&transcript, setup).unwrap();
            assert!(
                position(&transcript[setup_index + setup.len()..], restore).is_some(),
                "{input:?}: missing terminal restoration sequence {restore:?}"
            );
        }
        if input.is_some() {
            success(&result);
        } else {
            assert_eq!(result.status.signal(), Some(libc::SIGTERM));
        }
        assert_eq!(destination.exists(), saves, "{input:?}");
        assert_eq!(
            directory.path().join("combined").exists(),
            builds,
            "{input:?}"
        );
    }
}
