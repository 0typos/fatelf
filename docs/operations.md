# Operate and troubleshoot Fatelf

| Command | When to use it |
|---|---|
| `fatelf doctor --config bundle.toml --probe` | Diagnose inputs, interpreter paths, output placement, and temporary storage on this host. The optional memfd probe allocates an empty descriptor. |
| `fatelf plan --config bundle.toml` | Check build policies and get exact output sizes before publishing. It reads used build keys and uses the same temporary spool as a build. |
| `fatelf inspect ./combined` | List payloads, selection policy, and storage statistics from an existing bundle. |
| `fatelf verify ./combined` | Reconstruct every payload without execution and validate its digest. Supply all required runtime key files. |

| Symptom | Check and action |
|---|---|
| Launch reports “No such file or directory” | Use `doctor` on the deployment host with the original inputs, or inspect the original ELF's interpreter. Confirm the payload's dynamic loader and libraries exist on that host. |
| Memfd preparation reports “Operation not permitted” | Run `fatelf doctor --config bundle.toml --probe` in the same environment to check allocation policy. If executable files are allowed, set `execution.backend = "file"` in TOML or add `--exec file` to your `fatelf pack` command. Use a new output path. |
| File launch reports “Permission denied” | Check whether `TMPDIR` points to a `noexec` mount. Use an executable filesystem for the scratch file, or rebuild for `memfd` when host policy permits it. The bundle itself also needs to be on an executable mount. |
| Verification reports a missing key | Set the configured environment variable to a path to the 32-byte key file. Launch needs only the selected payload's keys. Full verification needs every referenced key. |
| Build reports “No space left on device” | Check free space in `TMPDIR` and at the destination. The spool and output can coexist. `plan` also needs spool space. |
| Build refuses an existing destination | Choose a new output path. Compare or verify the replacement before swapping it into service. |

## Execution boundaries

- Fatelf is validated on x86-64 Linux. Both backends need `/proc/self/exe` and
  [`execveat(AT_EMPTY_PATH)`](https://man7.org/linux/man-pages/man2/execveat.2.html),
  available since Linux 3.19. See the [release procedure](release/README.md) for the supported scope.
  `memfd` requires executable memfds to be allowed by kernel/container policy;
  `file` requires executable filesystem storage (`noexec` mounts fail).
- Static executables and dynamically linked executables, including PIE, can be
  packed. The host must support the chosen ELF's ABI/ISA and have its interpreter,
  shared libraries, and external resources. Those dependencies are not bundled.
  ELF relocatable objects, non-ELF files, and zero-entry x86-64 ELFs are
  rejected when packing. An `ET_DYN` file with an entry point still needs
  a compatible host and loader.
- Raw Unix argument bytes and environment values, working directory, PID,
  inherited descriptors, and exit/signal termination semantics are retained.
  `argv[0]` remains the invocation of the combined binary. Test the intended
  bundle name when wrapping tools that dispatch on it. For example, Git treats
  a basename starting with `git-` as a request for that subcommand. SIGPIPE is
  reset to its default disposition to undo Rust startup's ignored SIGPIPE;
  deliberately inherited ignored SIGPIPE is consequently not retained.
  Rust startup also reopens closed standard descriptors (0, 1, and 2) on
  `/dev/null`; deliberately closed standard descriptors are not retained.
- `/proc/self/exe` refers to the reconstructed, anonymous/unlinked executable.
  Programs using their executable pathname, `$ORIGIN`-relative libraries, or
  resources beside the original executable may require adaptation. Neither
  backend is a custom ELF loader.
- Original permissions, setuid/setgid bits, capabilities, xattrs, and signatures
  are not propagated. Containers and extracted files are published with mode
  0755. Do not install the selector launcher as a privileged executable.

## Diagnose a configured build

```sh
fatelf doctor --config bundle.toml
fatelf doctor --config bundle.toml --json --probe
```

`doctor` checks the config, launcher descriptor, payload compatibility with
the launcher, ELF interpreter paths, temporary storage, and output destination
on the current host. The ELF metadata read budget is 16 MiB per input.
An output directory may be writable on a `noexec` mount. In that case the
output check describes the restriction while allowing staging there.
`doctor` creates no bundle, reads no key files, and runs no
payload. `--probe` also creates and closes an empty executable memfd if the
config selects that backend. The probe does not attempt `execveat`.

Exit status 0 means the checks found no failures. Status 1 means a check or
reporting operation failed. CLI usage errors exit 2. JSON reports use
`schema_version: 1`, an `ok` boolean, and a `checks` array. Each check has a
stable `code`, a `status` of `ok`, `error`, or `skipped`, a `subject`, and
human-readable `detail`. Check codes are `config`, `launcher`,
`launcher_interpreter`, `payload_elf`, `interpreter`, `temporary_storage`,
`output`, and `memfd_probe`. Host conditions may change after the report. Relative interpreter paths resolve from
the working directory of the invoking process. Use `plan` for exact storage sizes
and to check whether the chosen codecs fit the supplied launcher. Use
`verify` for a completed bundle.

## Verify a bundle

`fatelf verify ./combined` reconstructs every payload into a discard stream
and checks its digest without executing it or writing extracted files. Supply
every required runtime key file through the configured environment variables.
Successful verification exits silently. Verification work scales with the
logical bytes across all payloads, including aliases of deduplicated objects. `fatelf inspect` reports metadata
without reading payload data.

## Security boundaries

Header XOR and shuffling are reversible obfuscation. They remove deliberately
verbatim source headers, not every incidental ELF magic sequence; the launcher
may contain parser constants. The readable JSON and `FATELF02` footer identify
the container. Compression, entropy, and header masking do not make it invisible.

External-key AEAD protects encrypted stored bytes from a container holder lacking
the key and detects ciphertext/manifest changes when encrypted objects decode.
The outer launcher and readable routing policy are **not authenticated**. An
attacker who can replace the executable can change code, route to plaintext
payloads, or strip encryption policy and replace objects. A public manifest hash
is not a publisher signature. Capability descriptors declare supported decoders
and do not authenticate supplied launcher code. Keep launcher/container inputs
trusted. [Release-package signatures](release/README.md#verify-before-extraction)
authenticate distributed Fatelf tools. Confirm provenance separately for bundles
built and distributed by someone else.

Selected plaintext becomes available to the launcher and kernel at execution;
memfd is not a confidentiality boundary against privileged debuggers or permitted
`/proc` access. The file backend writes decoded bytes to an already unlinked file.
Unencrypted encoded packing spools and swap can also retain plaintext.
Use storage/host protections appropriate to that threat model. No remote checks,
network probes, secret environment delivery, or general action orchestration run.
