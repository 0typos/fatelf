# Terminal walkthroughs

Local recordings execute real `/usr/bin/ls` and `/usr/bin/ps` builds, compare
native stdout, and recover both original ELFs byte-for-byte. Each cast has an
`agg` GIF. Nothing is uploaded.

| Recording | Manifest and payload policy | Backend |
|---|---|---|
| [01-ls-ps-memfd.cast](01-ls-ps-memfd.cast) | End manifest; only `ps` shuffled; both headers masked | `memfd` |
| [02-ls-ps-toml-file.cast](02-ls-ps-toml-file.cast) | Front manifest; plain `ls` body; `ps` shuffled, LZ4 compressed and externally keyed | `file` |

```bash
asciinema play docs/tutorial/demos/01-ls-ps-memfd.cast
asciinema play docs/tutorial/demos/02-ls-ps-toml-file.cast
```

From the repository root:

```bash
just demo          # Build the static release tools and run the memfd walkthrough.
just record-demo   # Build release tools, record both workflows, and render GIFs.
just record-demo file  # Build release tools and refresh only the TOML/file recording.
bash docs/tutorial/demos/record memfd          # Reuse release tools and refresh one pair.
bash docs/tutorial/demos/record --no-gif file  # Refresh only the cast.
bash docs/tutorial/demos/record --render file  # Refresh only the GIF from its cast.
DEMO_PAUSE=0 bash docs/tutorial/demos/record --play file  # Check the workflow without recording.
```

Recording requires installed `asciinema`; rendering requires `agg`. The commands
use Bash, Python 3, `file`, GNU `stat` and standalone GNU `ls`, procps `ps`, and static release
packer/launcher files in `target/x86_64-unknown-linux-musl/release/`. Building
those files uses the repository's release tooling. Payload execution requires a
compatible Linux host with its original shared libraries and `/proc`.

Both workflows print the release version, actual input/output sizes, and container inspection. The
TOML workflow additionally shows a build plan, verifies that `ls` needs no `ps`
key, checks the expected missing-key rejection, then supplies `PS_KEY_FILE` and
executes `ps`. A fresh 32-byte OS-random key is created with mode 0600; its bytes
never appear in a recording, TOML or environment variable. Recorded metadata
contains only the key path reference.

No dependencies are installed by the recorder. Workflow failures propagate even
if `asciinema` returns success. The recorder replaces a workflow's cast and GIF
only after the workflow and rendering succeed. Each build uses a fresh directory under `target/`; its generated
config, combined executable, private key and recovered payloads remain there
for local inspection.

The terminal defaults to 110x34 at 14 px; override `COLS` and `ROWS` as needed.
Commands execute with a short reading pause. Set `DEMO_PAUSE` in seconds to
adjust the pace. Process output is
restricted to PID 1. Absolute paths and that process's name can still appear;
review local casts before sharing. See the [walkthrough](../../tutorial.md).
