# Fatelf on x86-64 Linux

From the verified, unpacked release directory, install both binaries together:

```sh
install -Dm755 -t "$HOME/.local/bin" fatelf fatelf-launcher
export PATH="$HOME/.local/bin:$PATH"
fatelf --version
```

Add the export to your shell startup file if that directory is new to your
`PATH`. On a host with `/usr/bin/bash` and `/usr/bin/ps`, run:

```sh
fatelf pack bash=/usr/bin/bash ps=/usr/bin/ps -o ./combined
env -u FATELF_VARIANT ./combined -c 'printf "%s\n" "hello from the default payload"'
FATELF_VARIANT=ps ./combined -p 1 -o pid,comm
FATELF_VARIANT=bash FATELF_MESSAGE='passed through' ./combined -c '
  test "${FATELF_VARIANT+x}" != x &&
  test "$FATELF_MESSAGE" = "passed through" &&
  printf "FATELF_MESSAGE=%s; selector is unset\n" "$FATELF_MESSAGE"
'
fatelf verify ./combined
```

A bundle uses the host interpreter, libraries, and resources of each payload.
The default backend requires executable memfds. To use temporary files on
an executable filesystem, add `--exec file` to `pack` and choose a new output.
`fatelf --help` lists configuration, diagnostics, inspection, and extraction
commands. License and dependency notices are included in this directory.
