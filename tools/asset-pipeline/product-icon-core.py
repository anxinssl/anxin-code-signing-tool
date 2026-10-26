"""Deterministic ICO encoding and decoding for the CodeSigner product icon."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from hashlib import sha256
from importlib import import_module
from io import BytesIO
from pathlib import Path
from typing import Final

from PIL import Image

_icon_validation = import_module("tools.asset-pipeline.product-icon-validation")
PNG_SIGNATURE = _icon_validation.PNG_SIGNATURE
IconPipelineError = _icon_validation.IconPipelineError
load_rgba_png = _icon_validation.load_rgba_png

ICON_SIZES: Final[tuple[int, ...]] = (16, 24, 32, 48, 64, 128, 256)
SMALL_SIZES: Final[tuple[int, ...]] = (16, 24, 32, 48)


@dataclass(frozen=True, slots=True)
class IcoEntry:
    """One decoded ICO directory entry."""

    size: int
    payload_offset: int
    payload_length: int
    payload_sha256: str


def build_ico(alpha_path: Path, ico_path: Path) -> tuple[IcoEntry, ...]:
    """Write a deterministic PNG-frame ICO from the alpha master."""
    source = load_rgba_png(alpha_path)
    payloads: list[bytes] = []
    for size in ICON_SIZES:
        frame = source.resize((size, size), Image.Resampling.LANCZOS)
        buffer = BytesIO()
        frame.save(buffer, format="PNG", optimize=False, compress_level=9)
        payloads.append(buffer.getvalue())
    offset = 6 + 16 * len(payloads)
    directory = bytearray(struct.pack("<HHH", 0, 1, len(payloads)))
    for size, payload in zip(ICON_SIZES, payloads, strict=True):
        encoded_size = 0 if size == 256 else size
        directory.extend(
            struct.pack(
                "<BBBBHHII",
                encoded_size,
                encoded_size,
                0,
                0,
                1,
                32,
                len(payload),
                offset,
            )
        )
        offset += len(payload)
    ico_path.parent.mkdir(parents=True, exist_ok=True)
    _ = ico_path.write_bytes(bytes(directory) + b"".join(payloads))
    return read_ico_entries(ico_path)


def read_ico_entries(path: Path) -> tuple[IcoEntry, ...]:
    """Parse and validate the exact ICO directory and frame encodings."""
    data = path.read_bytes()
    if len(data) < 6:
        raise IconPipelineError("ICO header is truncated.")
    reserved = int.from_bytes(data[0:2], "little")
    image_type = int.from_bytes(data[2:4], "little")
    count = int.from_bytes(data[4:6], "little")
    if (reserved, image_type, count) != (0, 1, len(ICON_SIZES)):
        message = f"ICO header inventory is invalid: {(reserved, image_type, count)}."
        raise IconPipelineError(message)
    entries: list[IcoEntry] = []
    for index in range(count):
        entry_offset = 6 + index * 16
        width = data[entry_offset]
        height = data[entry_offset + 1]
        planes = int.from_bytes(data[entry_offset + 4 : entry_offset + 6], "little")
        bits = int.from_bytes(data[entry_offset + 6 : entry_offset + 8], "little")
        length = int.from_bytes(data[entry_offset + 8 : entry_offset + 12], "little")
        offset = int.from_bytes(data[entry_offset + 12 : entry_offset + 16], "little")
        size = 256 if width == 0 else width
        decoded_height = 256 if height == 0 else height
        valid_entry = (
            size == decoded_height
            and planes == 1
            and bits == 32
            and offset + length <= len(data)
        )
        if not valid_entry:
            raise IconPipelineError(f"ICO directory entry {index} is invalid.")
        payload = data[offset : offset + length]
        if not payload.startswith(PNG_SIGNATURE):
            raise IconPipelineError(f"ICO frame {size} is not PNG encoded.")
        with Image.open(BytesIO(payload)) as frame:
            _ = frame.load()
            if frame.size != (size, size) or frame.mode != "RGBA":
                message = f"ICO frame {size} does not decode as {size}x{size} RGBA."
                raise IconPipelineError(message)
        entries.append(IcoEntry(size, offset, length, sha256(payload).hexdigest()))
    if tuple(entry.size for entry in entries) != ICON_SIZES:
        raise IconPipelineError(
            "ICO does not contain the exact required size inventory."
        )
    return tuple(entries)


def decode_frame(path: Path, entry: IcoEntry) -> Image.Image:
    """Decode one validated ICO PNG payload as RGBA."""
    data = path.read_bytes()
    payload = data[entry.payload_offset : entry.payload_offset + entry.payload_length]
    with Image.open(BytesIO(payload)) as opened:
        return opened.convert("RGBA")
