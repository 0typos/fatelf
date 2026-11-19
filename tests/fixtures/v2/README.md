# Frozen v2 reader fixture

`encrypted` was written by Fatelf at `af77f68` from the original bytes recovered
from `fuzz/seeds/container/v2`. The build encrypted payload `sample` with a public
all-zero 32-byte test key exposed via `FATELF_COMPAT_KEY`. The launcher was
replaced by a one-byte stub and the two affected footer offsets adjusted.
The fixture is for extraction only. Release smoke checks the recovered bytes
against the SHA-256 measured directly from the baseline plaintext.
