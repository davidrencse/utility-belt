"""PDF carriers.

The whitespace mode appends a standards-safe comment after %%EOF. Metadata mode
stores the frame in a custom document-information field. Invisible mode stores
it in a non-rendering annotation. All modes preserve the displayed pages.
"""

from __future__ import annotations

import base64
from pathlib import Path

from .core import pack, unpack
from .errors import DecodeError, StegKitError

COMMENT_PREFIX = b"\n%STEGKIT-WS:"
INVISIBLE_PREFIX = "STEGKIT-INVISIBLE:"
META_KEY = "/StegKitPayload"


def _pypdf():
    try:
        import pypdf
    except ImportError as exc:
        raise StegKitError("PDF metadata/invisible support requires: pip install pypdf") from exc
    return pypdf


def capacity(path, technique: str = "metadata") -> int:
    # Incremental metadata/comment carriers are not page-area constrained.
    size = Path(path).stat().st_size
    return max(0, min(16 * 1024 * 1024, size * 4))


def encode(source, output, data: bytes, password=None, technique="metadata") -> None:
    frame = pack(data, password)
    if technique == "whitespace":
        bits = "".join(f"{byte:08b}" for byte in frame)
        encoded = "".join(" " if bit == "0" else "\t" for bit in bits).encode()
        Path(output).write_bytes(Path(source).read_bytes() + COMMENT_PREFIX + encoded + b"\n")
        return
    pypdf = _pypdf()
    reader = pypdf.PdfReader(str(source))
    writer = pypdf.PdfWriter()
    writer.clone_document_from_reader(reader)
    value = base64.b64encode(frame).decode("ascii")
    metadata = dict(reader.metadata or {})
    if technique == "metadata":
        metadata[META_KEY] = value
    elif technique == "invisible":
        # A zero-area, hidden annotation is a genuine non-rendering PDF layer.
        if not writer.pages:
            raise StegKitError("PDF has no pages for an invisible annotation")
        from pypdf.generic import (
            ArrayObject, DictionaryObject, NameObject, NumberObject, TextStringObject
        )
        annotation = DictionaryObject({
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Text"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
            NameObject("/F"): NumberObject(35),  # invisible + hidden + no-view
            NameObject("/Contents"): TextStringObject(INVISIBLE_PREFIX + value),
        })
        ref = writer._add_object(annotation)
        page = writer.pages[0]
        annots = page.get("/Annots", ArrayObject())
        annots.append(ref)
        page[NameObject("/Annots")] = annots
    else:
        raise StegKitError("PDF technique must be metadata, whitespace, or invisible")
    writer.add_metadata(metadata)
    with Path(output).open("wb") as stream:
        writer.write(stream)


def decode(path, password=None, technique="auto") -> bytes:
    raw = Path(path).read_bytes()
    if technique in {"auto", "whitespace"} and COMMENT_PREFIX in raw:
        encoded = raw.rsplit(COMMENT_PREFIX, 1)[1].splitlines()[0]
        bits = "".join("0" if byte == 32 else "1" for byte in encoded if byte in (9, 32))
        frame = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8))
        return unpack(frame, password)
    if technique == "whitespace":
        raise DecodeError("no whitespace PDF payload found")
    pypdf = _pypdf()
    reader = pypdf.PdfReader(str(path))
    if technique in {"auto", "metadata"}:
        value = (reader.metadata or {}).get(META_KEY)
        if value:
            return unpack(base64.b64decode(value), password)
    if technique in {"auto", "invisible"}:
        for page in reader.pages:
            for ref in page.get("/Annots", []):
                contents = ref.get_object().get("/Contents", "")
                if str(contents).startswith(INVISIBLE_PREFIX):
                    return unpack(
                        base64.b64decode(str(contents)[len(INVISIBLE_PREFIX):]), password
                    )
    raise DecodeError("no supported StegKit PDF payload found")

