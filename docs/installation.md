# Installation

For the happy path (`cargo install nyx-scanner`, release binary on PATH), see the README. This page covers platform-specific notes and upgrade paths.

## Supported platforms

Release binaries are published for:

| Platform | Archive |
|---|---|
| Linux x86_64 | `nyx-x86_64-unknown-linux-gnu.zip` |
| macOS Intel | `nyx-x86_64-apple-darwin.zip` |
| macOS Apple Silicon | `nyx-aarch64-apple-darwin.zip` |
| Windows x86_64 | `nyx-x86_64-pc-windows-msvc.zip` |

Build from source works on any stable Rust 1.88+ target (edition 2024).

## Verify the download

Each release attaches a `SHA256SUMS` file. When the maintainer signs the release, a detached `SHA256SUMS.asc` is published alongside it.

```bash
# Verify the checksum file's signature (skip if .asc isn't present)
gpg --verify SHA256SUMS.asc SHA256SUMS

# Then check your archive against it
sha256sum -c SHA256SUMS --ignore-missing
```

If `sha256sum` is missing on macOS, `shasum -a 256 -c SHA256SUMS --ignore-missing` is equivalent.

## Windows

```powershell
Expand-Archive -Path nyx-x86_64-pc-windows-msvc.zip -DestinationPath .
Move-Item -Path .\nyx.exe -Destination "C:\Program Files\Nyx\"
# Add C:\Program Files\Nyx to PATH in System Properties → Environment Variables
nyx --version
```

## Build from source

```bash
git clone https://github.com/elicpeter/nyx.git
cd nyx
cargo build --release
# Binary at target/release/nyx
```

The frontend is built and embedded into the binary during `cargo build`, so there's no separate step for `nyx serve`. Node is only required if you're working on the frontend itself; see `CONTRIBUTING.md`.

Optional features:

| Flag | Adds |
|---|---|
| `--features smt` | Bundles Z3 for stronger path-constraint solving. MIT-licensed; distributors should include Z3's license in their attribution |
| `--features smt-system-z3` | Links against a system-installed Z3 instead of bundling |

## Upgrading

Nyx stores its scanner version in the project's index database. When the binary's version differs from the stored version, the index is wiped on the next scan and rebuilt against the new engine. You'll see one info-level log line:

```
engine version changed (<old> → <new>), rebuilding index
```

No flag needed. If you see this on *every* scan, the metadata row isn't being persisted; file an issue.

## Corrupt database recovery

If the SQLite file itself is damaged (killed scan, full disk), delete it and let the next scan rebuild from scratch:

```bash
rm "$(nyx config path)"/<project>.sqlite*
```

Only the named project's rows are affected.
