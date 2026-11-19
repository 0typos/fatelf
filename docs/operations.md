# Operate and troubleshoot Fatelf

| Command | When to use it |
|---|---|
| `fatelf doctor --config bundle.toml --strict --probe` | Check launcher revision, location-dependent ELF loader paths, interpreter paths, and host storage. The optional memfd probe allocates an empty descriptor. |
| `fatelf plan --config bundle.toml` | Check build policies and get exact output sizes before publishing. It reads used build keys and uses the same temporary spool as a build. |
| `fatelf inspect ./combined` | List payloads, selection policy, and storage statistics from an existing bundle. |
| `fatelf verify ./combined` | Reconstruct every payload without execution and validate its digest. Supply all required runtime key files. |
| `fatelf smoke ./combined --variant example -- --version` | Execute the named variant of a trusted bundle with application-specific test arguments and return its exit status. |

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
- The launcher consumes the configured selector and excludes it and the
  configured key-source variables from the payload environment.
- Raw Unix argument bytes and other environment values, working directory, PID,
  inherited descriptors, and exit/signal termination semantics are retained.
  `argv[0]` remains the invocation of the combined binary. Test the intended
  bundle name when wrapping tools that dispatch on it. For example, Git treats
  a basename starting with `git-` as a request for that subcommand. SIGPIPE is
  reset to its default disposition to undo Rust startup's ignored SIGPIPE;
  deliberately inherited ignored SIGPIPE is consequently not retained.
  Rust startup also reopens closed standard descriptors (0, 1, and 2) on
  `/dev/null`; deliberately closed standard descriptors are not retained.
- Some multicall executables select or validate the utility using their
  executable name or path. Ubuntu's uutils `ls` is one example. Use a
  standalone executable if the multicall payload rejects the bundle.
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
fatelf doctor --config bundle.toml --json --strict --probe
```

`doctor` checks the configuration, current launcher compatibility revision,
payload architecture, ELF interpreter paths, temporary storage, and output
destination on this host. It reports a warning for `$ORIGIN` or relative
loader paths in `DT_NEEDED`, `DT_RUNPATH`, and the fallback `DT_RPATH`.
It reports the first risk for each executable. Those paths may
resolve differently from a reconstructed payload. This check uses program
headers, covers binaries without section names, and runs neither the loader
nor the payload. The metadata read budget is 16 MiB per input. See the
[ELF dynamic section](https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section)
and [Linux loader rules](https://man7.org/linux/man-pages/man8/ld.so.8.html#DESCRIPTION).

Use `--strict` to make warnings fail the gate. Exit status 0 means no failures,
status 1 means a check or reporting operation failed, and CLI usage errors exit
2. JSON reports use `schema_version: 2` and statuses `ok`, `warning`, `error`,
and `skipped`. The new check codes are `launcher_loader_paths` and
`payload_loader_paths`. An output directory may still be writable on a
`noexec` mount. The optional memfd probe allocates and closes an empty descriptor.

Build with the launcher from the same installation. `doctor`, `plan`,
`pack`, and `build` reject a stale launcher. `plan` additionally checks
whether the chosen optional codecs fit that launcher's build profile.

After building, run `verify` to check reconstructed bytes, then run `smoke`
for each trusted variant from its intended deployment path, working directory,
and environment. Supply any runtime keys and use arguments with a known exit
status for that application, such as `--version` where supported. Smoke
executes the actual bundle with its configured selector. Metadata inspection
cannot validate transitive dependencies, runtime-loaded libraries, or adjacent
application resources.

## Verify a bundle

`fatelf verify ./combined` reconstructs every payload into a discard stream
and checks its digest without executing it or writing extracted files. Supply
every required runtime key file through the configured environment variables.
Successful verification exits silently. Verification work scales with the
logical bytes across all payloads, including aliases of deduplicated objects. `fatelf inspect` reports metadata
without reading payload data.

## Security boundaries

Header XOR, optional payload XOR, and shuffling are reversible obfuscation.
The launcher may still contain ELF parser constants and incidental magic sequences.
The readable JSON and `FATELF02` footer identify
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
