# Fatelf on x86-64 Linux

Keep `fatelf` and `fatelf-launcher` together. Run this example from the
unpacked directory on a host with `/usr/bin/ls` and `/usr/bin/ps`.

```sh
./fatelf pack ls=/usr/bin/ls ps=/usr/bin/ps -o ./combined
FATELF_VARIANT=ls ./combined -1
FATELF_VARIANT=ps ./combined -p 1 -o pid,comm
./fatelf verify ./combined
```

A bundle uses the host interpreter, libraries, and resources of each payload.
The default backend requires executable memfds. To use temporary files on
an executable filesystem, add `--exec file` to `pack` and choose a new output.
`./fatelf --help` lists configuration, diagnostics, inspection, and extraction
commands. License and dependency notices are included in this directory.
