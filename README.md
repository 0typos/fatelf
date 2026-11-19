<p align="center">
  <img src="assets/brand/fatelf-banner.png" width="860" alt="Fatelf wordmark beside an elf carrying three colorful file cards">
</p>

<h1 align="center">Many programs. One executable.</h1>

<p align="center">
  <a href="https://github.com/0typos/fatelf/releases"><img alt="Release: beta" src="assets/brand/badge-release.svg"></a>
  <a href="docs/operations.md#execution-boundaries"><img alt="Platform: Linux x86-64" src="assets/brand/badge-platform.svg"></a>
  <a href="LICENSE"><img alt="License: MIT" src="assets/brand/badge-license.svg"></a>
</p>

Fatelf packs several Linux ELF executables into one runnable file. Ship a
single artifact containing, for example, a service and its diagnostic tool,
or two builds of the same command. An environment variable selects the payload,
and the launcher verifies its reconstructed bytes before running it with the
arguments you supplied.

**Beta.** Fatelf supports container and TOML schema v2. Use the packer and
launcher from the same release when building bundles. See the
[changelog](CHANGELOG.md) and [compatibility policy](docs/release/README.md).

**Supported target:** x86-64 Linux. Payloads must be compatible with the host
architecture and ABI. Dynamic payloads use the host's interpreter and shared
libraries. Programs that rely on their executable path or nearby resources
need testing in the target environment. See
[execution boundaries](docs/operations.md#execution-boundaries).

## Install

From a source checkout, install the
[release build prerequisites](docs/development.md#build-from-source) and run:

```sh
just release
install -Dm755 -t "$HOME/.local/bin" \
  target/x86_64-unknown-linux-musl/release/fatelf \
  target/x86_64-unknown-linux-musl/release/fatelf-launcher
export PATH="$HOME/.local/bin:$PATH"
fatelf --version
```

Keep the two binaries together so `fatelf` can find its matching launcher.
If `~/.local/bin` is new to your `PATH`, add the export to your shell startup
file to make it available in new terminals.

## Quickstart

On a host with `/usr/bin/bash` and `/usr/bin/ps`, run:

```sh
bundle_dir=$(mktemp -d "$PWD/fatelf-quickstart.XXXXXX")
fatelf pack bash=/usr/bin/bash ps=/usr/bin/ps -o "$bundle_dir/combined"
env -u FATELF_VARIANT "$bundle_dir/combined" -c 'printf "%s\n" "hello from the default payload"'
FATELF_VARIANT=ps "$bundle_dir/combined" -p 1 -o pid,comm
FATELF_VARIANT=bash FATELF_MESSAGE='passed through' "$bundle_dir/combined" -c '
  test "${FATELF_VARIANT+x}" != x &&
  test "$FATELF_MESSAGE" = "passed through" &&
  printf "FATELF_MESSAGE=%s; selector is unset\n" "$FATELF_MESSAGE"
'
fatelf verify "$bundle_dir/combined"
```

The first launch runs Bash by default. The second selects `ps` and prints
PID 1. The third checks that Bash receives `FATELF_MESSAGE` and that the
launcher removes `FATELF_VARIANT` before handing off. Verification checks every
payload without executing it and exits silently on success. This example
uses executable memfds. If host policy blocks them, rerun `pack` with
`--exec file` and a new output path, then check the
[host storage requirements](docs/operations.md#execution-boundaries).

## Save a build for reuse

Use a TOML file when you need to rebuild the same bundle, review its settings,
or use different labels and policies per environment. Put this in `bundle.toml`.

```toml
version = 2
output = "combined"

[selection]
env = "FATELF_APP"
default = "bash"

[[payloads]]
name = "bash"
path = "/usr/bin/bash"

[[payloads]]
name = "ps"
path = "/usr/bin/ps"
```

```sh
fatelf plan --config bundle.toml
fatelf doctor --config bundle.toml --strict --probe
fatelf build --config bundle.toml
fatelf verify ./combined
fatelf smoke ./combined --variant ps -- -p 1 -o pid,comm
```

`plan` checks build settings and reports output size. Run `doctor` where
the input files are available to check host requirements. Run `smoke`
against each trusted variant on the deployment host to exercise the real
program, its libraries, and the selected execution backend.

## Configure storage and execution

- Use LZ4 for fast packing, Zstandard for a smaller bundle, or Zstandard
  deltas for closely related builds. Each mode can use exact-byte deduplication.
- Apply external-key encryption to selected payloads or byte ranges. XOR
  masking is reversible and provides no confidentiality. See the
  [security boundaries](docs/operations.md#security-boundaries).
- Use `inspect` for bundle metadata and `extract` to recover original payload bytes.
- Edit common build settings with `configure`. TOML also exposes launcher
  labels, byte-range policies, and resource budgets.

## Documentation

- [Walkthrough](docs/tutorial.md) covers static builds, selective shuffling, encryption, and exact extraction.
- [Configuration](docs/configuration.md) covers TOML, the interactive editor, policy inheritance, and limits.
- [Operations](docs/operations.md) covers diagnostics, verification, runtime requirements, and security boundaries.
- [Container format v2](docs/format-v2.md) documents the layout, manifest, and reconstruction rules.
- [Development](docs/development.md) covers build prerequisites, checks, and launcher profiles.
- [Release procedure](docs/release/README.md) covers release testing, packaging, and signing.
- [Security policy](SECURITY.md) covers vulnerability reporting.
- [Binary analysis](docs/binary-analysis.md) records size and startup measurements and how to reproduce the walkthroughs.
