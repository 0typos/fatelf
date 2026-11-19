# Build and development tooling

## Build from source

On Linux, install Rust through rustup and a C toolchain with a linker. The
checked-in toolchain file selects Rust 1.99.0 and the x86-64 musl target.

```sh
cargo build --locked --bins
./target/debug/fatelf --help
```

Use `just` for the development recipes. Install `cargo-deny` and populate its
local advisory database with `cargo deny fetch db` before the first gate run.
The fuzz recipes need nightly Rust and `cargo-fuzz` and start from checked-in
v2 seeds. The static release recipe needs Zig, `cargo-zigbuild`, and
`cargo-auditable`. Install the Cargo helpers
with `cargo install --locked <package>`. The documented static target is
`x86_64-unknown-linux-musl`.

## Development and smaller launchers

```sh
just ci
just fuzz
just fuzz-config
just release # Static musl packer + size-optimized launcher supporting both codecs.
just launcher '' # Core launcher without optional compression/encryption decoders.
just launcher compression
just launcher encryption
```

`just launcher` writes `target/x86_64-unknown-linux-musl/launcher/fatelf-launcher`;
copy it before building another profile and supply `--launcher` explicitly. The
packer rejects launchers without v2/required decoder capability descriptors.
`just release` copies its matching full launcher beside the release packer.
The `launcher` Cargo profile uses `opt-level="s"`, full LTO, one codegen unit,
and aborting panics; the runtime omits packer/TUI/TOML/error-reporting dependencies.
On x86_64, `just launcher` also enables `compact-hash`: BLAKE3 uses Rust SIMD
intrinsics without its native assembly/AVX-512 implementations. Hashes and the
v2 format remain identical. This reduces code size but can slow large-payload
verification; [measured sizes and startup tradeoffs](binary-analysis.md#launcher-optimization-pass)
are recorded separately. Other target recipes retain native hashing until measured.
To keep native hashing on x86_64, use the same Cargo command without `compact-hash`:

```sh
bash docs/release/zigbuild --locked --profile launcher --no-default-features \
  --features compression,encryption --target x86_64-unknown-linux-musl --bin fatelf-launcher
```

This direct build writes under `target/fatelf-distribution/`.

The default `builder` feature enables the packer and both codecs;
`--no-default-features` exposes the runtime entrypoint and runtime error variants.
`compact-hash` is additive; explicitly enabling it with `builder` changes hashing
there too because Cargo unifies dependency features. Normal builder defaults stay native.
The beta supports the documented CLI and file formats. The Rust library
entry points and Cargo feature split are internal implementation details.

Tests use independent native stdout, original bytes, exit/PID/signal behavior,
malformed objects, key failures, policy tampering, and resource limits as oracles.
Fuzzing repairs public manifest hashes to reach semantic validation, exercises
codecs directly, and avoids environment-driven key file access. The standard gate
uses cached cargo-deny advisory data; refresh advisories explicitly before release.

The first source release targets x86-64 Linux with a compatible host userspace.
Run `just release-check` from a fresh checkout on an x86-64 Linux runner
before cutting a release. It runs the standard gate and both fuzz smokes,
builds the static tools, and verifies packing, launching, and extraction on
both backends. The smoke needs Bash, `ps`, binutils (`readelf`), GNU grep, and
GNU coreutils. Validate other architectures on their target hosts
before claiming support. Follow the [release procedure](release/README.md)
for signing and verifying binary packages.
