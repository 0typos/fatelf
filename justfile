set shell := ["bash", "-euo", "pipefail", "-c"]

default: ci

# Run a real dynamically linked ls/ps packaging walkthrough.
demo:
    just release
    bash docs/tutorial/demos/record --play memfd

# Save local asciinema casts and GIFs for both walkthroughs.
record-demo backend="all":
    just release
    bash docs/tutorial/demos/record {{quote(backend)}}

fmt:
    cargo fmt --all --check

lint:
    cargo clippy --locked --all-targets --all-features -- -D warnings

test:
    cargo test --locked --all-targets --all-features

# Standard gate. Uses the locally cached advisory database; refresh explicitly.
ci: fmt lint test
    cargo deny --offline --locked --config .config/deny.toml check

# Parser/decoder smoke, kept separate from the standard gate.
fuzz target="x86_64-unknown-linux-gnu":
    mkdir -p fuzz/corpus/container
    cargo +nightly fuzz run container --target {{target}} fuzz/corpus/container fuzz/seeds/container -- -max_total_time=60 -max_len=65536

# Build configuration parser smoke, independent of the binary container target.
fuzz-config target="x86_64-unknown-linux-gnu":
    mkdir -p fuzz/corpus/config
    cargo +nightly fuzz run config --target {{target}} fuzz/corpus/config fuzz/seeds/config -- -max_total_time=60 -max_len=65536

# Static, auditable artifacts; unsigned, with no publication side effects.
release target="x86_64-unknown-linux-musl":
    bash docs/release/zigbuild --locked --release --target {{target}} --bin fatelf
    just launcher compression,encryption,zstandard {{target}}
    mkdir -p target/{{target}}/release
    cp target/fatelf-distribution/{{target}}/release/fatelf target/{{target}}/release/fatelf
    cp target/{{target}}/launcher/fatelf-launcher target/{{target}}/release/fatelf-launcher

# Host-neutral release gate for an x86-64 Linux runner.
release-check: ci fuzz fuzz-config release
    bash tests/release-smoke target/x86_64-unknown-linux-musl/release
    bash tests/release-profiles

# Resource and mount checks using the existing x86-64 static release pair.
release-operations:
    bash tests/release-operations target/x86_64-unknown-linux-musl/release

# Exercise signed packaging and consumer verification with a disposable key.
release-distribution-check:
    bash tests/release-distribution target/x86_64-unknown-linux-musl/release

# Small runtime only; select the required optional decoders.
launcher features="compression,encryption,zstandard" target="x86_64-unknown-linux-musl":
    bash docs/release/zigbuild --locked --profile launcher --no-default-features --features '{{features}}{{if target =~ "^x86_64-" { ",compact-hash" } else { "" }}}' --target {{target}} --bin fatelf-launcher
    mkdir -p target/{{target}}/launcher
    cp target/fatelf-distribution/{{target}}/launcher/fatelf-launcher target/{{target}}/launcher/fatelf-launcher
