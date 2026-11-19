# Changelog

## 0.2.0-beta.3

- Cap complete bundle size with `max_output_bytes` and report plan headroom.
- Diagnose host compatibility and verify payloads from a finished bundle.
- Assert smoke exit statuses, promote a verified bundle after all variant
  smoke checks pass, and roll back by atomically exchanging bundle paths.

## 0.2.0-beta.2

- Add `zstd` for independent object compression and `zstd-delta` for sharing
  bytes with a related first payload. Both modes retain raw fallback.
- Ship a Zstandard-capable launcher and keep the smaller launcher feature
  profiles available. Existing v2 bundles remain readable.
- Report Zstandard and delta object counts in `fatelf inspect`.

## 0.2.0-beta.1

- Package and select Linux ELF payloads in a single executable. The memfd and
  file backends reconstruct and verify the selected payload before launch.
- Build from strict v2 TOML or the terminal editor. Configure compression,
  encryption, XOR masking, byte-range policies, and resource budgets.
- Check builds with `plan`, diagnose host constraints with `doctor`, and
  use `smoke` to run selected payloads before promoting a bundle.
- Inspect or extract a bundle and verify reconstructed payload bytes. Add
  optional launcher name and version labels per deployment environment.
- Release builds target x86-64 Linux and ship a matched packer and launcher.
