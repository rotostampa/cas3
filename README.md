# cas3 – Content‑Addressable Storage CLI

`cas3` stores files by their SHA‑256 hash. It supports HTTP/HTTPS and local `file://` URLs, keeping blobs under `~/.cas3/data/`.

## Build

```bash
cargo build --release
```

The binary is created at `target/release/cas3`.

## Usage

```bash
# Store a remote file
cas3 save https://example.com/file.txt
# → Stores the file under ~/.cas3/data/<sha>.  Prints the SHA‑256 hash.

# Store a local file
cas3 save file:///Users/me/documents/report.pdf
# → Same as above.

# Fetch a stored file
cas3 fetch <sha256>
# → Prints: file:///home/user/.cas3/data/<sha>.  Exits with 0 if found, 1 otherwise.
```

Run `cas3 --help` for a list of options. The binary is located at `target/release/cas3`.

Enjoy a simple, hash‑based storage layer!