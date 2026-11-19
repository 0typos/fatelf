<p align="center">
  <img src="assets/brand/fatelf-mark-v6.png" width="168" alt="fatelf: a large fantasy elf bursting out of cyan, yellow, and magenta gear over an EXTRA LARGE FORMAT shirt">
</p>

<h1 align="center">fatelf</h1>

<p align="center">
  <strong>Many programs. One executable.</strong>
</p>

Fatelf bundles several Linux ELF executables into one file. An environment
variable selects which program runs. On launch, Fatelf reconstructs the original
bytes, verifies them, and replaces itself with the selected program.

**Beta.** Fatelf supports container and TOML schema v2. Use the packer and
launcher from the same release when building bundles. See the
[changelog](CHANGELOG.md) and [compatibility policy](docs/release/README.md).

The supported target is **x86-64 Linux**. Dynamic payloads use the host's
interpreter, shared libraries, and resources. Test the bundle in the environment
where it will run. See [execution boundaries](docs/operations.md#execution-boundaries).

## Build from source

Install Rust through rustup and a C toolchain with a linker. The checked-in
toolchain file selects Rust 1.99.0. From the repository root, build the packer and
its adjacent launcher:

```sh
cargo build --locked --bins
```

## Pack, run, and verify

On a host with `/usr/bin/bash` and `/usr/bin/ps`, run:

```sh
bundle_dir=$(mktemp -d "$PWD/target/fatelf-quickstart.XXXXXX")
target/debug/fatelf pack bash=/usr/bin/bash ps=/usr/bin/ps -o "$bundle_dir/combined"
FATELF_VARIANT=bash "$bundle_dir/combined" -c 'printf "%s\n" "hello from Fatelf"'
FATELF_VARIANT=ps "$bundle_dir/combined" -p 1 -o pid,comm
target/debug/fatelf verify "$bundle_dir/combined"
```

The first launch prints a message. The second prints the process at
PID 1. Verification exits silently on success. This example uses executable
memfds. If host policy blocks them, see [troubleshooting](docs/operations.md).

## Documentation

- [Walkthrough](docs/tutorial.md) covers static builds, selective shuffling, encryption, and exact extraction.
- [Configuration](docs/configuration.md) covers TOML, the interactive editor, policy inheritance, and limits.
- [Operations](docs/operations.md) covers diagnostics, verification, runtime requirements, and security boundaries.
- [Container format v2](docs/format-v2.md) documents the layout, manifest, and reconstruction rules.
- [Development](docs/development.md) covers build prerequisites, checks, and launcher profiles.
- [Release procedure](docs/release/README.md) covers release testing, packaging, and signing.
- [Security policy](SECURITY.md) covers vulnerability reporting.
- [Binary analysis](docs/binary-analysis.md) records size and startup measurements and how to reproduce the walkthroughs.
