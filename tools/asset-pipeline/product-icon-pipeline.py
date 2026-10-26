#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pillow==12.3.0",
#     "typer==0.27.0",
#     "typing-extensions==4.16.0",
# ]
# ///

# --- How to run ---
# 1. Install uv: https://docs.astral.sh/uv/getting-started/installation/
# 2. Run: uv run -m tools.asset-pipeline.product-icon-pipeline --help
# 3. Or run in the repository environment:
#      .venv/Scripts/python.exe -m tools.asset-pipeline.product-icon-pipeline --help
# ------------------

"""CLI and visual evidence writer for the CodeSigner product icon pipeline."""

from __future__ import annotations

import json
import platform
from dataclasses import asdict, dataclass
from importlib import import_module
from pathlib import Path

import typer
from PIL import Image, ImageDraw
from PIL import __version__ as pillow_version

_icon_core = import_module("tools.asset-pipeline.product-icon-core")
_icon_validation = import_module("tools.asset-pipeline.product-icon-validation")
SMALL_SIZES = _icon_core.SMALL_SIZES
build_ico = _icon_core.build_ico
decode_frame = _icon_core.decode_frame
read_ico_entries = _icon_core.read_ico_entries
AlphaMetrics = _icon_validation.AlphaMetrics
ChromaMetrics = _icon_validation.ChromaMetrics
IconPipelineError = _icon_validation.IconPipelineError
file_hash = _icon_validation.file_hash
measure_alpha = _icon_validation.measure_alpha
validate_alpha_master = _icon_validation.validate_alpha_master
validate_chroma_source = _icon_validation.validate_chroma_source

app = typer.Typer(add_completion=False, no_args_is_help=True)


@dataclass(frozen=True, slots=True)
class FrameReceipt:
    """Validation and hash receipt for one decoded ICO frame."""

    size: int
    png_sha256: str
    coverage: float
    blue_pixels: int
    white_pixels: int
    corner_alpha_max: int


def _write_metrics(path: Path, metrics: AlphaMetrics | ChromaMetrics) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(
        json.dumps(asdict(metrics), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_rejection(
    path: Path,
    error: IconPipelineError,
    input_path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": "rejected",
        "exit_code": 2,
        "input": str(input_path),
        "input_sha256": file_hash(input_path),
        "message": str(error),
    }
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _render_receipts(ico_path: Path, evidence_dir: Path) -> list[FrameReceipt]:
    entries = read_ico_entries(ico_path)
    sheet = Image.new("RGB", (640, 880), (238, 240, 244))
    draw = ImageDraw.Draw(sheet)
    receipts: list[FrameReceipt] = []
    for row, entry in enumerate(entries):
        frame = decode_frame(ico_path, entry)
        metrics = measure_alpha(frame)
        if metrics.corner_alpha_max != 0 or not 0.10 <= metrics.coverage <= 0.72:
            raise IconPipelineError(
                f"ICO frame {entry.size} fails alpha/coverage checks."
            )
        if entry.size in SMALL_SIZES and (
            metrics.blue_pixels == 0 or metrics.white_pixels == 0
        ):
            raise IconPipelineError(
                f"ICO frame {entry.size} loses the shield/check contrast."
            )
        frame_path = evidence_dir / f"ico-rendered-{entry.size}.png"
        frame.save(frame_path, format="PNG", optimize=False, compress_level=9)
        receipts.append(
            FrameReceipt(
                entry.size,
                file_hash(frame_path),
                metrics.coverage,
                metrics.blue_pixels,
                metrics.white_pixels,
                metrics.corner_alpha_max,
            )
        )
        y = row * 124 + 18
        draw.text((18, y + 42), f"{entry.size} px", fill=(20, 24, 32))
        native_panel = Image.new("RGBA", (80, 80), (255, 255, 255, 255))
        native_panel.alpha_composite(
            frame, ((80 - entry.size) // 2, (80 - entry.size) // 2)
        )
        sheet.paste(native_panel.convert("RGB"), (92, y))
        zoom = frame.resize((entry.size * 3, entry.size * 3), Image.Resampling.NEAREST)
        dark_panel = Image.new("RGBA", (420, 104), (28, 32, 40, 255))
        dark_panel.alpha_composite(zoom, (18, (104 - zoom.height) // 2))
        sheet.paste(dark_panel.convert("RGB"), (194, y - 12))
    sheet.save(
        evidence_dir / "icon-small-sizes-inspection.png",
        format="PNG",
        optimize=False,
        compress_level=9,
    )
    return receipts


@app.command("validate-source")
def validate_source_command(source: Path, receipt: Path) -> None:
    """Validate the generated chroma master and write a JSON receipt."""
    try:
        metrics = validate_chroma_source(source)
    except IconPipelineError as error:
        _write_rejection(receipt, error, source)
        raise typer.Exit(2) from error
    _write_metrics(receipt, metrics)
    typer.echo(json.dumps(asdict(metrics), sort_keys=True))


@app.command("validate-png")
def validate_png_command(alpha: Path, receipt: Path) -> None:
    """Validate the transparent alpha master and write a JSON receipt."""
    try:
        metrics = validate_alpha_master(alpha)
    except IconPipelineError as error:
        _write_rejection(receipt, error, alpha)
        raise typer.Exit(2) from error
    _write_metrics(receipt, metrics)
    typer.echo(json.dumps(asdict(metrics), sort_keys=True))


@app.command("build")
def build_command(alpha: Path, ico: Path, evidence_dir: Path) -> None:
    """Build the ICO, validate its frames, and write visual/hash receipts."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    metrics = validate_alpha_master(alpha)
    entries = build_ico(alpha, ico)
    frames = _render_receipts(ico, evidence_dir)
    receipt = {
        "alpha_master": str(alpha),
        "alpha_master_sha256": file_hash(alpha),
        "alpha_metrics": asdict(metrics),
        "ico": str(ico),
        "ico_sha256": file_hash(ico),
        "inventory": [entry.size for entry in entries],
        "frames": [asdict(frame) for frame in frames],
        "python": platform.python_version(),
        "pillow": pillow_version,
        "command": (
            ".venv/Scripts/python.exe -m tools.asset-pipeline.product-icon-pipeline build "
            f"{alpha} {ico} {evidence_dir}"
        ),
    }
    receipt_path = evidence_dir / "pipeline-receipt.json"
    _ = receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    typer.echo(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    app()
