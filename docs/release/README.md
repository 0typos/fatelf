# Fatelf release procedure

Run `just release-check` in a fresh source checkout with the prerequisites
in the [development guide](../development.md#build-from-source). Before cutting a release,
refresh the advisory cache with `cargo deny fetch db`. The gate must pass
with the lockfiles that will ship.

The first supported target is x86-64 Linux. Record the runner image or OS,
host kernel, toolchain versions, both backend results, and the commit used
to build each artifact. Record unfuzzed or untested environments separately.
The x86-64 gate exercises ordinary Linux userspace with procfs and compatible
shared libraries. Document separately any container restrictions validated
with a real runner. Validate another architecture on native hardware before
adding it to the support matrix. Static builds remap the checkout, Cargo-cache, and toolchain paths.
The smoke test checks the binaries for matching private paths. Export an
existing compiler wrapper as `RUSTC_WRAPPER` if the runner needs it chained
during release builds.

Run `just release-operations` after the standard gate on a Linux runner that
permits unprivileged user and mount namespaces and has util-linux
(`unshare` and `mount`). It exercises parallel launches
on both backends, interrupted output staging, a `noexec` temporary mount, and
spool exhaustion. A runner that denies user namespaces cannot provide the
mount-policy evidence. If a build is killed while staging its output, its final
destination remains absent, but a partial temporary file can remain beside it.
Inspect that directory before retrying after an interrupted build.

## Compatibility and rollback

Keep v2 readers compatible with v2 bundles emitted by earlier supported
releases. Test the checked-in v2 fixture and representative encrypted and
compressed bundles as part of format changes. Breaking wire changes need a
new format version and migration guidance. The config schema is independently
versioned in the TOML file.

Ship the packer and launcher together. New builds require the packer's
current launcher compatibility revision. Update that revision when the packer
can generate bundles that the previous launcher revision cannot run.

Before promoting a deployment, run `doctor --probe` and `smoke` as the
deployment user in the target environment. Smoke-test each deployed variant
with a harmless invocation that checks the application's expected behavior.
Build and verify the next bundle at a separate path. Keep the prior bundle,
source configuration and access to its runtime keys until the new bundle has
passed the deployment checks. To roll back, restore the prior bundle and
runtime configuration together and rerun its smoke checks.

## Prepare binary artifacts

Run `just release-check` first, then use a reviewed notice file for the exact
locked binary dependencies and the full fingerprint of the release signing key.
Packaging needs GNU tar, gzip, and GnuPG.

```sh
bash docs/release/package NOTICE_FILE RELEASE_SIGNING_FINGERPRINT
```

The command rechecks the matched static binaries, then stages a tarball, its
SHA-256 digest, and a detached signature of `SHA256SUMS` under `target/dist/`.
Choose and distribute the release signing key through an authenticated channel.
Keep the package, checksum, and signature together.

## Verify before extraction

Obtain the release keyring through the project's authenticated channel. Keep
the three downloaded release files in a private directory. From the source
checkout, verify the signature and checksum before unpacking the archive.

```sh
downloads=/path/to/private-download-directory
archive="$downloads/fatelf-VERSION-x86_64-unknown-linux-musl.tar.gz"
bash docs/release/verify-package /absolute/path/fatelf-release.gpg "$archive" &&
    tar -xzf "$archive" -C "$downloads"
```

Run `just release-distribution-check` on the release runner to exercise this
workflow with a disposable key. It needs GnuPG and GNU coreutils. A version
archive with an altered name or contents must be rejected.

The checksum comparison binds the chosen archive filename and its contents to
the signed record. Fatelf bundle verification checks reconstructed payloads. Package signatures
cover the distributed bytes, including the launcher.
