# Fuzz seeds

`container/v2` is a synthetic end-manifest container with a one-byte launcher
stub, a masked ELF64 header and a five-byte body. It exercises metadata
validation, object decoding and digest verification. This fixture has no runnable
launcher or payload. `config/v2.toml` reaches semantic validation with a minimal
valid build configuration.

LibFuzzer writes evolved inputs to the ignored `fuzz/corpus/` directories.
