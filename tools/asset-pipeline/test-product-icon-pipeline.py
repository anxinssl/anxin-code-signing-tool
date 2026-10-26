#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pillow==12.3.0",
#     "pytest==9.1.1",
#     "typing-extensions==4.16.0",
# ]
# ///

# --- How to run ---
# 1. Install uv: https://docs.astral.sh/uv/getting-started/installation/
# 2. Run: uv run tools/asset-pipeline/test-product-icon-pipeline.py
# 3. Or run in the repository environment:
#      .venv/Scripts/python.exe -m pytest tools/asset-pipeline/test-product-icon-pipeline.py
# ------------------

"""Regression tests for deterministic product icon validation and packaging."""

from __future__ import annotations

# ruff: noqa: S101
from hashlib import sha256
from importlib import import_module
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

_icon_core = import_module("tools.asset-pipeline.product-icon-core")
_icon_validation = import_module("tools.asset-pipeline.product-icon-validation")
ICON_SIZES = _icon_core.ICON_SIZES
build_ico = _icon_core.build_ico
read_ico_entries = _icon_core.read_ico_entries
IconPipelineError = _icon_validation.IconPipelineError
validate_alpha_master = _icon_validation.validate_alpha_master
validate_chroma_source = _icon_validation.validate_chroma_source


def _write_valid_fixture(path: Path) -> None:
    image = Image.new("RGBA", (1024, 1024), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rectangle((240, 180, 784, 844), fill=(20, 100, 210, 255))
    draw.line((350, 540, 470, 660, 700, 400), fill=(255, 255, 255, 255), width=90)
    image.save(path, format="PNG")


def _write_valid_rgb_chroma_fixture(path: Path) -> None:
    image = Image.new("RGB", (1024, 1024), (0, 255, 0))
    draw = ImageDraw.Draw(image)
    draw.rectangle((240, 180, 784, 844), fill=(20, 100, 210))
    draw.line((350, 540, 470, 660, 700, 400), fill=(255, 255, 255), width=90)
    image.save(path, format="PNG")


def test_validator_rejects_opaque_chroma_corner(tmp_path: Path) -> None:
    """Reject a master whose chroma corner remains opaque."""
    # Given: a nominal transparent master with an opaque chroma-key corner.
    fixture = tmp_path / "opaque-corner.png"
    _write_valid_fixture(fixture)
    with Image.open(fixture) as opened:
        image = opened.convert("RGBA")
    image.putpixel((0, 0), (0, 255, 0, 255))
    image.save(fixture, format="PNG")

    # When / Then: alpha validation rejects the fixture at the boundary.
    with pytest.raises(IconPipelineError, match="corner"):
        _ = validate_alpha_master(fixture)


def test_chroma_validator_accepts_opaque_rgb_png(tmp_path: Path) -> None:
    """Accept an opaque RGB source before chroma removal adds alpha."""
    # Given: a generated-style RGB PNG with an exact chroma border.
    fixture = tmp_path / "rgb-chroma-source.png"
    _write_valid_rgb_chroma_fixture(fixture)

    # When: the raw generated source is validated.
    metrics = validate_chroma_source(fixture)

    # Then: its opaque chroma border and subject are measured successfully.
    assert metrics.exact_key_border_pixels == metrics.border_pixels


def test_ico_build_is_deterministic_and_has_exact_inventory(tmp_path: Path) -> None:
    """Write stable ICO bytes with every required frame exactly once."""
    # Given: a valid 1024 px transparent source with blue and white contrast.
    source = tmp_path / "source.png"
    first = tmp_path / "first.ico"
    second = tmp_path / "second.ico"
    _write_valid_fixture(source)

    # When: the ICO is built twice from the same bytes.
    _ = build_ico(source, first)
    _ = build_ico(source, second)

    # Then: the byte stream is stable and contains every required size once.
    assert sha256(first.read_bytes()).digest() == sha256(second.read_bytes()).digest()
    assert tuple(entry.size for entry in read_ico_entries(first)) == ICON_SIZES
