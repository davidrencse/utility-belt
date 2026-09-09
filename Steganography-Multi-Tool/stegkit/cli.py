"""Unified command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import audio, gitsteg, image, pdf, qr, text
from .core import frame_size
from .errors import StegKitError

IMAGE = {".png", ".bmp"}
AUDIO = {".wav", ".flac"}


def _secret(args) -> bytes:
    if getattr(args, "data_file", None):
        return Path(args.data_file).read_bytes()
    if getattr(args, "secret", None) is not None:
        return args.secret.encode("utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    raise StegKitError("provide --secret, --data-file, or pipe bytes on stdin")


def _password(args, encoding: bool) -> str | None:
    value = getattr(args, "key", None)
    if value is not None:
        return value
    if getattr(args, "no_encrypt", False):
        return None
    if encoding:
        return getpass.getpass("Encryption passphrase: ")
    return getpass.getpass("Passphrase (empty for unencrypted): ") or None


def _write(data: bytes, output: str | None) -> None:
    if output:
        Path(output).write_bytes(data)
    else:
        try:
            print(data.decode("utf-8"))
        except UnicodeDecodeError:
            sys.stdout.buffer.write(data)


def detect(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in IMAGE:
        return "image"
    if suffix in AUDIO:
        return "audio"
    if suffix == ".pdf":
        return "pdf"
    if suffix in {".txt", ".md"}:
        return "text"
    if path.is_dir() and (path / ".git").exists():
        return "git"
    raise StegKitError(f"cannot detect carrier type for {path}")


def command_encode(args) -> None:
    payload, key = _secret(args), _password(args, True)
    kind = args.type
    if kind == "image":
        image.encode(args.input, args.output, payload, key)
    elif kind == "audio":
        audio.encode(args.input, args.output, payload, key)
    elif kind == "text":
        cover = Path(args.input).read_text(encoding="utf-8")
        Path(args.output).write_text(text.encode(cover, payload, key), encoding="utf-8")
    elif kind == "pdf":
        pdf.encode(args.input, args.output, payload, key, args.technique)
    elif kind == "qr":
        qr.encode(args.public, args.output, payload, key, args.qr_version)
    elif kind == "git":
        if args.technique == "timestamps":
            hashes = gitsteg.encode_timestamps(args.input, payload, key, args.message)
            print(json.dumps(hashes))
        else:
            print(gitsteg.encode_whitespace(args.input, payload, key, args.message))
    print(f"encoded {len(payload)} payload bytes", file=sys.stderr)


def command_decode(args) -> None:
    path = Path(args.input)
    kind = args.type or detect(path)
    key = _password(args, False)
    if kind == "image":
        data = image.decode(path, key)
    elif kind == "audio":
        data = audio.decode(path, key)
    elif kind == "text":
        data = text.decode(path.read_text(encoding="utf-8"), key)
    elif kind == "pdf":
        data = pdf.decode(path, key, args.technique)
    elif kind == "qr":
        public, data = qr.decode(path, key)
        print(f"public QR payload: {public}", file=sys.stderr)
    elif kind == "git":
        if args.technique == "timestamps":
            data = gitsteg.decode_timestamps(path, key, args.count)
        else:
            data = gitsteg.decode_whitespace(path, key, args.revision)
    _write(data, args.output)


def _capacity(path: Path, kind: str, args) -> int:
    if kind == "image":
        return image.capacity(path)
    if kind == "audio":
        return audio.capacity(path)
    if kind == "text":
        return text.capacity(path.read_text(encoding="utf-8"))
    if kind == "pdf":
        return pdf.capacity(path, args.technique)
    if kind == "qr":
        return qr.capacity(args.public, args.qr_version)
    if kind == "git":
        return 512 if args.technique == "timestamps" else 16 * 1024 * 1024
    raise StegKitError(f"unsupported carrier type: {kind}")


def command_capacity(args) -> None:
    requested = None
    if args.secret is not None or args.data_file:
        requested = frame_size(_secret(args), encrypted=not args.no_encrypt)
    rows = []
    for item in args.inputs:
        path = Path(item)
        kind = args.type or detect(path)
        amount = _capacity(path, kind, args)
        rows.append({
            "input": str(path),
            "type": kind,
            "payload_capacity_bytes": amount,
            "fits": requested is None or amount >= requested,
        })
    if args.public and not args.inputs:
        amount = qr.capacity(args.public, args.qr_version)
        rows.append({"input": "<generated QR>", "type": "qr",
                     "payload_capacity_bytes": amount,
                     "fits": requested is None or amount >= requested})
    rows.sort(key=lambda row: row["payload_capacity_bytes"], reverse=True)
    result = {"carriers": rows}
    if requested is not None:
        result["framed_payload_bytes"] = requested
        result["recommendation"] = next(
            (row["input"] for row in reversed(rows) if row["fits"]), None
        )
    print(json.dumps(result, indent=2))


def command_batch(args) -> None:
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    payload, key = _secret(args), _password(args, True)
    results = []
    for name in args.inputs:
        source = Path(name)
        try:
            kind = detect(source)
            target = out / f"{source.stem}.steg{source.suffix}"
            if kind == "image":
                image.encode(source, target, payload, key)
            elif kind == "audio":
                audio.encode(source, target, payload, key)
            elif kind == "text":
                target.write_text(text.encode(source.read_text(encoding="utf-8"), payload, key),
                                  encoding="utf-8")
            elif kind == "pdf":
                pdf.encode(source, target, payload, key, args.technique)
            else:
                raise StegKitError("batch supports image, audio, text, and PDF files")
            results.append({"input": name, "output": str(target), "ok": True})
        except Exception as exc:
            results.append({"input": name, "ok": False, "error": str(exc)})
    print(json.dumps(results, indent=2))
    if any(not row["ok"] for row in results):
        raise StegKitError("one or more batch items failed")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="stegkit", description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="hide a payload")
    enc.add_argument("type", choices=["image", "audio", "qr", "pdf", "text", "git"])
    enc.add_argument("input", nargs="?", help="carrier file or repository")
    enc.add_argument("output", nargs="?", help="output carrier")
    enc.add_argument("--secret")
    enc.add_argument("--data-file")
    enc.add_argument("--key", help="passphrase (prefer interactive prompt for privacy)")
    enc.add_argument("--no-encrypt", action="store_true")
    enc.add_argument("--public", help="public QR text/URL")
    enc.add_argument("--qr-version", type=int, choices=range(1, 41))
    enc.add_argument("--technique", default="metadata",
                     choices=["metadata", "whitespace", "invisible", "timestamps"])
    enc.add_argument("--message", default="maintenance")
    enc.set_defaults(func=command_encode)

    dec = sub.add_parser("decode", help="extract a payload (type is auto-detected)")
    dec.add_argument("input")
    dec.add_argument("--type", choices=["image", "audio", "qr", "pdf", "text", "git"])
    dec.add_argument("--output")
    dec.add_argument("--key")
    dec.add_argument("--technique", default="auto",
                     choices=["auto", "metadata", "whitespace", "invisible", "timestamps"])
    dec.add_argument("--revision", default="HEAD")
    dec.add_argument("--count", type=int)
    dec.set_defaults(func=command_decode)

    cap = sub.add_parser("capacity", help="compare carriers and recommend the smallest fit")
    cap.add_argument("inputs", nargs="*")
    cap.add_argument("--type", choices=["image", "audio", "qr", "pdf", "text", "git"])
    cap.add_argument("--secret")
    cap.add_argument("--data-file")
    cap.add_argument("--no-encrypt", action="store_true")
    cap.add_argument("--public")
    cap.add_argument("--qr-version", type=int, choices=range(1, 41))
    cap.add_argument("--technique", default="metadata")
    cap.set_defaults(func=command_capacity)

    batch = sub.add_parser("batch", help="encode one payload into multiple carriers")
    batch.add_argument("output_dir")
    batch.add_argument("inputs", nargs="+")
    batch.add_argument("--secret")
    batch.add_argument("--data-file")
    batch.add_argument("--key")
    batch.add_argument("--no-encrypt", action="store_true")
    batch.add_argument("--technique", default="metadata",
                       choices=["metadata", "whitespace", "invisible"])
    batch.set_defaults(func=command_batch)
    return root


def main(argv=None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "encode":
            if args.type == "qr" and (not args.public or not args.output):
                raise StegKitError("QR encode requires --public and an output path")
            if args.type != "qr" and not args.input:
                raise StegKitError("encode requires an input carrier/repository")
            if args.type not in {"git"} and not args.output:
                raise StegKitError("encode requires an output path")
        args.func(args)
        return 0
    except (StegKitError, OSError, ValueError) as exc:
        print(f"stegkit: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

