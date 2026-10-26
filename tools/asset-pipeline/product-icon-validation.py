"""Chroma and alpha validation for the CodeSigner product icon."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from PIL import Image
from typing_extensions import override

PNG_SIGNATURE: Final[bytes] = b"\x89PNG\r\n\x1a\n"
CHROMA_KEY: Final[tuple[int, int, int]] = (0, 255, 0)
MASTER_SIZE: Final[int] = 1024


class IconPipelineError(Exception):
    """Report an invalid source or packaged icon."""

    message: str

    def __init__(self, message: str) -> None:
        """Store the validation message for CLI rejection receipts."""
        super().__init__(message)
        self.message = message

    @override
    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True, slots=True)
class AlphaMetrics:
    """Measured alpha, palette, and placement properties."""

    width: int
    height: int
    coverage: float
    partial_alpha_pixels: int
    blue_pixels: int
    white_pixels: int
    green_fringe_pixels: int
    corner_alpha_max: int
    bounding_box: tuple[int, int, int, int]


@dataclass(frozen=True, slots=True)
class ChromaMetrics:
    """Measured chroma source properties."""

    width: int
    height: int
    exact_key_border_pixels: int
    border_pixels: int
    subject_coverage: float
    blue_pixels: int
    white_pixels: int


def file_hash(path: Path) -> str:
    """Return the SHA-256 digest for a file."""
    return sha256(path.read_bytes()).hexdigest()


def load_png(path: Path) -> Image.Image:
    """Decode a PNG after checking its binary signature and format."""
    if path.read_bytes()[: len(PNG_SIGNATURE)] != PNG_SIGNATURE:
        raise IconPipelineError(f"PNG signature is invalid: {path}")
    with Image.open(path) as opened:
        _ = opened.load()
        if opened.format != "PNG":
            raise IconPipelineError(f"Image decoder did not identify PNG: {path}")
        return opened.copy()


def load_rgba_png(path: Path) -> Image.Image:
    """Decode a PNG that stores an explicit RGBA alpha channel."""
    image = load_png(path)
    if image.mode != "RGBA":
        message = f"PNG must have a stored RGBA alpha channel: {path}"
        raise IconPipelineError(message)
    return image


def measure_alpha(image: Image.Image) -> AlphaMetrics:
    """Measure visibility, palette contrast, corners, and chroma spill."""
    width, height = image.size
    alpha = image.getchannel("A")
    histogram = alpha.histogram()
    visible_pixels = sum(histogram[1:])
    bounding_box = alpha.getbbox()
    if bounding_box is None:
        raise IconPipelineError("Alpha master has no visible subject.")
    corner = max(1, min(width, height) // 64)
    corner_boxes = (
        (0, 0, corner, corner),
        (width - corner, 0, width, corner),
        (0, height - corner, corner, height),
        (width - corner, height - corner, width, height),
    )
    corner_alpha_max = max(max(alpha.crop(box).tobytes()) for box in corner_boxes)
    blue_pixels = 0
    white_pixels = 0
    green_fringe_pixels = 0
    rgba = image.tobytes()
    for offset in range(0, len(rgba), 4):
        red, green, blue, opacity = rgba[offset : offset + 4]
        if opacity == 0:
            continue
        if blue >= 90 and blue >= red + 25 and blue >= green + 8:
            blue_pixels += 1
        channel_minimum = min(red, green, blue)
        channel_range = max(red, green, blue) - channel_minimum
        if channel_minimum >= 205 and channel_range <= 42:
            white_pixels += 1
        if green > max(red, blue) + 18:
            green_fringe_pixels += 1
    return AlphaMetrics(
        width=width,
        height=height,
        coverage=visible_pixels / (width * height),
        partial_alpha_pixels=sum(histogram[1:255]),
        blue_pixels=blue_pixels,
        white_pixels=white_pixels,
        green_fringe_pixels=green_fringe_pixels,
        corner_alpha_max=corner_alpha_max,
        bounding_box=bounding_box,
    )


def validate_alpha_master(path: Path) -> AlphaMetrics:
    """Validate the sealed transparent 1024 px product master."""
    image = load_rgba_png(path)
    metrics = measure_alpha(image)
    if image.size != (MASTER_SIZE, MASTER_SIZE):
        raise IconPipelineError(f"Alpha master must be 1024x1024, got {image.size}.")
    if metrics.corner_alpha_max != 0:
        raise IconPipelineError("Alpha master corner pixels must be fully transparent.")
    if not 0.12 <= metrics.coverage <= 0.68:
        message = f"Subject coverage is implausible: {metrics.coverage:.4f}."
        raise IconPipelineError(message)
    if metrics.blue_pixels < 20_000 or metrics.white_pixels < 4_000:
        raise IconPipelineError("Alpha master lacks the required blue/white contrast.")
    if metrics.green_fringe_pixels > 256:
        message = f"Obvious green fringe remains: {metrics.green_fringe_pixels} pixels."
        raise IconPipelineError(message)
    left, top, right, bottom = metrics.bounding_box
    if min(left, top, MASTER_SIZE - right, MASTER_SIZE - bottom) < 32:
        raise IconPipelineError("Visible subject is too close to the canvas edge.")
    return metrics


def validate_chroma_source(path: Path) -> ChromaMetrics:
    """Validate the generated master and its exact opaque chroma border."""
    image = load_png(path)
    if image.mode not in {"RGB", "RGBA"}:
        raise IconPipelineError("Generated source must store RGB color channels.")
    image = image.convert("RGBA")
    if image.size != (MASTER_SIZE, MASTER_SIZE):
        message = f"Generated source must be 1024x1024, got {image.size}."
        raise IconPipelineError(message)
    band = 12
    border = b"".join(
        (
            image.crop((0, 0, MASTER_SIZE, band)).tobytes(),
            image.crop((0, MASTER_SIZE - band, MASTER_SIZE, MASTER_SIZE)).tobytes(),
            image.crop((0, band, band, MASTER_SIZE - band)).tobytes(),
            image.crop(
                (MASTER_SIZE - band, band, MASTER_SIZE, MASTER_SIZE - band)
            ).tobytes(),
        )
    )
    exact_key = 0
    for offset in range(0, len(border), 4):
        red, green, blue, opacity = border[offset : offset + 4]
        if (red, green, blue) == CHROMA_KEY and opacity == 255:
            exact_key += 1
    subject_pixels = 0
    blue_pixels = 0
    white_pixels = 0
    rgba = image.tobytes()
    for offset in range(0, len(rgba), 4):
        red, green, blue, _ = rgba[offset : offset + 4]
        if (red, green, blue) == CHROMA_KEY:
            continue
        subject_pixels += 1
        if blue >= 90 and blue >= red + 25 and blue >= green + 8:
            blue_pixels += 1
        channel_minimum = min(red, green, blue)
        channel_range = max(red, green, blue) - channel_minimum
        if channel_minimum >= 205 and channel_range <= 42:
            white_pixels += 1
    border_pixels = len(border) // 4
    metrics = ChromaMetrics(
        width=MASTER_SIZE,
        height=MASTER_SIZE,
        exact_key_border_pixels=exact_key,
        border_pixels=border_pixels,
        subject_coverage=subject_pixels / (MASTER_SIZE * MASTER_SIZE),
        blue_pixels=blue_pixels,
        white_pixels=white_pixels,
    )
    if exact_key != border_pixels:
        raise IconPipelineError(
            "Generated source border is not perfectly flat opaque #00ff00."
        )
    if not 0.12 <= metrics.subject_coverage <= 0.68:
        message = (
            "Generated subject coverage is implausible: "
            f"{metrics.subject_coverage:.4f}."
        )
        raise IconPipelineError(message)
    if blue_pixels < 20_000 or white_pixels < 4_000:
        raise IconPipelineError(
            "Generated source lacks the required blue/white contrast."
        )
    return metrics
