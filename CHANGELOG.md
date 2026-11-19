# Changelog

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
