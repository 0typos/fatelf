# fatelf

- Linux-only Rust CLI and launcher; Rust 1.99.0, edition 2024.
- `just ci` is the standard gate. `just fuzz` runs the container parser/decoder smoke; `just fuzz-config` exercises TOML config parsing. Run the affected target for input handling changes. `just release` produces unsigned static musl binaries.
- `cargo deny` in the gate uses cached advisory data; explicitly refresh before a release.
- One crate, private container model. ELF parsing uses `object`; no custom relocation or ELF loader.
- Binary layout codecs use RSL `bitsandbytes` 0.7.1, imported as `bnb`; JSON carries the bounded manifest.
- The v2 on-disk format and limits are documented in README.md; v1 readers/configs are intentionally unsupported. Changes to that format require a version decision.
- TOML is the build source of truth; the TUI saves it, restores the terminal, then executes the real `build --config` command. Prefer absolute paths; relative references use the canonical config directory. Only implemented layouts/policies are accepted.
- No forge CI configuration until the repository's destination is declared.
