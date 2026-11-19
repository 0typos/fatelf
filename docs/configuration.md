# Configuration

TOML is the build source of truth. Relative output, launcher, payload, and
build-time key paths resolve from the canonical config directory, even when
the config is opened through a symlink. Absolute paths are also accepted. An omitted launcher uses `fatelf-launcher` beside the packer.

```sh
fatelf configure --output /full/path/bundle.toml
fatelf configure --config /full/path/bundle.toml
fatelf plan --config /full/path/bundle.toml
fatelf build --config /full/path/bundle.toml
```

The TUI exposes common settings, compression/manifest placement, payload shuffle
and key IDs, with per-field help. Tab moves; Enter edits; Left/Right cycle choices;
F2 adds a payload, F3 removes one, F5 saves, F6 saves and runs the real build
command after restoring the terminal. Escape/Ctrl-C cancels. Detailed regions,
key sources and budgets are edited in TOML and preserved by the TUI; their
creation is not yet a guided wizard. Save As resolves referenced paths before
moving the config. Structured saves replace comments and formatting. An in-place save checks
that the loaded file still has the same contents just before replacement.
Fatelf preserves ownership, read/write mode, and the POSIX access ACL of an
in-place config and serializes saves with an advisory directory lock and reports
contention so you can retry. Coordinate edits with other tools yourself.
For a separate copy, run `configure --config OLD --output NEW`.

This protects only `ps`, keeps `ls` independent of its key, and places the readable
manifest at the front. Replace `/full/path` with your paths; a key file contains
exactly **32 random raw bytes**, created with mode 0600.

```toml
version = 2
output = "/full/path/combined"
launcher = "/full/path/fatelf-launcher"

[selection]
env = "FATELF_APP"
default = "ls"

[storage]
layout = "overlay"
manifest_position = "front" # Or "end"; locator footer always remains at the end.
order = "shuffled"
seed = 42
dedup = true
chunk_size = 4096
compression = "none"

[[keys]]
name = "ps-key"
key_file = "/full/path/ps.key" # Build input; this path is not stored in the container.
env = "PS_KEY_FILE"          # Runtime variable contains a key FILE path.

[[payloads]]
name = "ls"
path = "/usr/bin/ls"
shuffle = false

[[payloads]]
name = "ps"
path = "/usr/bin/ps"
shuffle = true
compression = "lz4"
encryption = "ps-key"

[execution]
backend = "memfd" # Or "file".
```

```sh
FATELF_APP=ls /full/path/combined -1
PS_KEY_FILE=/full/path/ps.key FATELF_APP=ps /full/path/combined -p 1 -o pid,comm
PS_KEY_FILE=/full/path/ps.key fatelf extract /full/path/combined --variant ps -o /full/path/recovered-ps
```

Only selected-payload keys are read. Missing, malformed or wrong keys prevent
launch/extraction. Every configured key-source variable is excluded from the
payload environment, including unused keys. Key bytes are zeroized after use;
build-time paths and key bytes are never embedded. Keys arrive from files only
in this release; inherited key descriptors/providers and secret delivery are later.

## Policies and supported choices

| Knob | Implemented choices |
|---|---|
| Layout | `overlay`, with `front` or `end` manifest placement |
| Chunking | Fixed size, 256 bytes–1 MiB; default 4096 |
| Source encoding | Mandatory full-header `elf-header-xor-a5`; body `identity`, `xor-a5`, or `xor-mask` |
| Compression | `none`, raw LZ4 blocks with automatic raw fallback |
| Encryption | External-key XChaCha20-Poly1305, fresh OS nonce per unique object |
| Placement | `ordered`, seeded `shuffled`; global, payload, section/range scope |
| Deduplication | Opt-in, exact byte equality within compatible policies |
| Execution | `memfd`, private, unlinked `file`, both replace the process |
| Selection | Configurable environment name, exact label, configured default |

Use `fatelf pack --xor` or set `xor = true` under `[storage]` to XOR-mask
every payload body with the fixed public byte `0xA5`. This requires an updated
launcher. XOR itself needs no key and provides no confidentiality or authentication.
The option defaults to false and can be combined with compression or encryption.

For a repeating mask, run `fatelf xor-mask 16` and copy the printed
`xor_mask = [...]` line into `[storage]` instead of setting `xor = true`.
The generator accepts **1–32 bytes** and draws a new public mask from the OS
on each invocation. Save the generated line once so `plan` and repeated
builds use the same mask. This setting requires a launcher that supports
variable payload XOR. The mask is stored in the bundle.

Compression/encryption/shuffle inherit global → payload → region settings.
`storage.encryption` supplies an optional default key ID; `encryption = "none"`
disables inherited encryption. Regions select **one** `section` or half-open
`range`, using original source offsets, and can override compression, encryption,
or shuffle:

```toml
[[payloads.regions]]
section = ".text" # Or range = "0x1000:0x5000".
compression = "lz4"
shuffle = true
# encryption = "ps-key"
```

Attach region tables immediately after their intended payload. Conflicting
effective policies on overlapping bytes are rejected; identical overlaps merge.
No region boundary may split the complete mandatory header. `shuffle = true`
requires shuffled storage order. Global `storage.sections`/`ranges` (CLI
`--section`/`--range`) are validated against every payload, including unselected ones. At most 1024 scopes
and 1024 region rules per payload are accepted.

Deduplication compares original bytes after BLAKE3 candidate lookup. Sharing
requires matching header encoding, requested compression, key identity and
shuffle eligibility. Plain and encrypted objects do not share storage. Eligible
contiguous runs are permuted between fixed anchors; variable object sizes keep
each run's total length unchanged. Anchors stay at their offsets for the same
objects/policies, not across changes to compression or sharing.

`plan` prepares the same validated object/placement plan and reports sizes without
publishing the executable or running payloads/checks. It reads inputs/used keys
and uses temporary encoded spool storage. Encrypted plans use fresh nonces too;
fixed-width nonce metadata keeps size accounting stable. The runtime decodes one
object at a time. Deterministic unencrypted builds require identical inputs,
launcher, config and encoder version. Reproducible encryption is not implemented;
shuffle seeds never control encryption nonces.

## Resource limits

`[budgets]` accepts integer byte counts/counts with conservative defaults below
hard ceilings. Zero and excessive values fail; configured limits cannot remove
hard bounds.

| Setting | Default | Hard ceiling |
|---|---|---|
| `max_payloads` | 64 | 64 |
| `max_payload_bytes` | 256 MiB | 1 GiB |
| `max_logical_bytes` | 512 MiB | 2 GiB |
| `max_object_bytes` | 1 MiB | 1 MiB |
| `max_objects` / `max_references` | 262,144 each | 1,000,000 each |
| `max_stored_bytes` / `max_spool_bytes` | 512 MiB each | 2 GiB each |
| `max_manifest_bytes` | 4 MiB | 16 MiB |
| `max_config_bytes` | 1 MiB | 1 MiB |

Packing reads one bounded original ELF at a time and spools encoded unique objects
once; it retains no parallel raw spool. Encrypted storage adds 16 bytes per object
and counts toward stored budgets. Reconstruction holds at most one stored object
(1 MiB + tag) and one decoded object (1 MiB). Compression output scratch is capped
at 2 MiB beyond the source buffer. Manifest writes are bounded before growth;
parsers enforce hard size caps before applying lower manifest/config budgets.
Launcher input has a separate 1 GiB ceiling. Temporary output length is bounded
by launcher + stored pool + manifest + footer. Build/extract publication is
atomic and refuses existing paths. Small chunks increase manifest size. If a
large payload hits the manifest budget first, try a larger chunk size before
raising that budget. Larger chunks also reduce per-object launch overhead but
may reduce deduplication across similar inputs. Measure both bundle size and
startup time with the intended workload.
