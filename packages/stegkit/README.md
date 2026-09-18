# StegKit

StegKit is an educational, multi-format steganography CLI. It hides one
authenticated payload in PNG/BMP pixels, WAV/FLAC samples, QR module damage,
zero-width Unicode, PDF structures, or Git history.

> Use it only on files and repositories you own or are authorized to modify.
> Steganography conceals the existence of data; encryption protects its
> contents. Neither makes an unsafe communication channel safe.

## Install

Python 3.10+ is required.

```console
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest
```

`soundfile` uses libsndfile. Most wheels bundle it; Linux distributions may
require their `libsndfile` package.

## Quick start

All encoders encrypt by default with AES-256-GCM. Omit `--key` to enter the
passphrase without putting it in shell history. Use `--no-encrypt` only for
demonstrations.

```console
stegkit encode image cover.png secret.png --secret "meet at noon"
stegkit decode secret.png

stegkit encode audio cover.wav secret.flac --data-file archive.zip
stegkit decode secret.flac --output archive.zip

stegkit encode text cover.txt message.txt --secret "invisible"
stegkit decode message.txt

stegkit encode pdf report.pdf report-steg.pdf --technique invisible --secret "note"
stegkit decode report-steg.pdf

stegkit encode qr out.png --public https://example.org --qr-version 20 --secret "note"
stegkit decode out.png
```

Git commands create commits and therefore intentionally require an explicit
repository path:

```console
stegkit encode git . --technique whitespace --secret "release phrase"
stegkit decode . --type git --technique whitespace
```

Timestamp mode creates one empty commit per hidden bit and is conspicuous:

```console
stegkit encode git . --technique timestamps --secret "x"
stegkit decode . --type git --technique timestamps --count 424
```

Compare carriers and account for encryption/framing overhead:

```console
stegkit capacity photo.png recording.wav cover.txt --secret "payload"
stegkit batch encoded cover.png cover.wav cover.txt --data-file payload.bin
```

## How the formats work

### Images

Each payload bit replaces the least significant bit of one RGB channel.
Changing a channel by at most one level is normally imperceptible. PNG and BMP
are supported because JPEG/WebP lossy transforms destroy those bits. Capacity
is approximately `width × height × 3 / 8`, minus framing.

Detection: compare LSB histograms, inspect color-channel correlations, or use
sample-pair/chi-square analysis. Resizing, color correction, and lossy
re-encoding destroy the payload.

### Audio

Integer PCM samples carry one bit each. A 44.1 kHz stereo stream therefore has
88,200 carrier bits (about 10.7 KiB) per second, before framing. The writer
preserves the PCM subtype and changes samples by at most one integer unit.
WAV and lossless FLAC preserve the result.

Detection: inspect bit-plane statistics, noise floors, and sample-pair
correlations. MP3/AAC conversion, resampling, normalization, or editing may
destroy it. “Plays identically” means perceptually identical; the PCM checksum
is necessarily different.

### QR

Level-H QR symbols contain Reed–Solomon redundancy. StegKit generates the
public symbol, flips a conservative subset of non-function modules, and then
uses OpenCV to confirm the public value still scans. Extraction scans that
value, regenerates the pristine reference, and reads module differences.
This demonstrates error-correction exploitation; it does **not** rewrite
Reed–Solomon parity codewords directly.

Capacity and reliability vary with symbol version, camera, print quality, and
public data. Any QR “repair,” regeneration, screenshot scaling, or added damage
can remove the secret. Module-difference comparison makes this carrier easy to
detect when the public value is known.

### Zero-width text

U+200B encodes zero, U+200C encodes one, and U+200D terminates the stream.
Characters are interleaved between visible cover characters. Capacity is about
one byte per eight visible characters.

Detection is trivial: search for Unicode category `Cf` or specifically these
code points. Slack, Discord, editors, normalization, sanitizers, and copy/paste
may preserve, strip, or reorder them; test the actual channel.

### PDF

Three modes are available:

- `metadata`: a custom document-information field.
- `invisible`: a hidden, zero-area annotation on the first page.
- `whitespace`: spaces/tabs encoded in a valid trailing PDF comment.

They preserve page appearance but are not equally robust. Metadata scrubbers,
PDF optimization, printing, and “Save As” can remove all three. Detection tools
should inspect metadata, annotations, content streams, bytes after `%%EOF`,
unusual whitespace, attachments, and text whose render mode/color hides it.

### Git

Whitespace mode places spaces and tabs after a marker in an otherwise ordinary
empty commit message. Timestamp mode records one bit in each author/committer
Unix timestamp parity. Both are decoded from repository history.

Detection: show whitespace (`git show --check`, editor visualization), inspect
regular timestamp parity/patterns, author identity changes, and bursts of empty
commits. Rebasing, squashing, hooks, hosting sanitizers, and mail patches can
destroy carriers. Author-name variations are discussed as a possible channel
but intentionally not automated because they impersonate identity and are
highly visible in signed/audited histories.

## Payload and cryptography

Every handler uses the same binary frame:

1. zlib-compress the input;
2. derive a 256-bit key from the passphrase using scrypt and a random salt;
3. encrypt/authenticate with AES-GCM and a random nonce;
4. prepend a magic/version/length header.

The header is visible so decoders can find the payload length. The secret,
including its integrity tag, is encrypted. Reusing a cover leaks which carrier
positions changed, so always start with a fresh original. StegKit does not store
filenames or MIME types; use `--output` when extracting binary data.

## Ethics, use cases, and limits

Steganography has been used for watermarking, tamper-evident provenance,
anti-counterfeiting, censorship resistance, espionage, malware command
channels, and confidential source communication. The same dual-use property
makes operational context essential. A hidden channel may put sources at risk:
file metadata, cloud logs, message forwarding, device seizure, traffic
analysis, or a known tool signature can reveal it even when the secret remains
encrypted.

This project is a teaching implementation, not an anonymity system. Its
deterministic starting positions and `STGK` framing favor interoperability and
testing over resistance to steganalysis. For defensive analysis, compare files
against originals, enumerate metadata and Unicode controls, inspect low bit
planes, regenerate QR symbols, and audit version-control history.
