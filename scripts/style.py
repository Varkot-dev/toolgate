"""Shared look for every figure in this repo. Import it, call apply(), then save()."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
RESULTS = ROOT / "results"

INK = "#0b0b0b"  # primary text
MUTED = "#52514e"  # secondary text, neutral edges
ALLOW = "#008300"  # accepted / allowed
DENY = "#d03b3a"  # rejected / denied
ACCENT = "#2a78d6"  # the one highlight color
PANEL = "#f1f0ec"  # node and card background
RULE = "#d6d4cc"  # panel borders, grid lines
SURFACE = "#fcfcfb"  # figure background

FONT = "DejaVu Sans"  # ships with matplotlib, so every machine renders the same
MONO = "DejaVu Sans Mono"
DPI = 100
SIZE = (16, 9)  # inches: 1600 x 900 px at DPI


def apply() -> None:
    """Set the rcParams all figures share, including the ones for reproducible files."""
    plt.rcParams.update(
        {
            "font.family": FONT,
            "font.size": 13,
            "text.color": INK,
            "axes.edgecolor": RULE,
            "axes.labelcolor": MUTED,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "figure.dpi": DPI,
            "savefig.dpi": DPI,
            "svg.hashsalt": "toolgate",
        }
    )


def save(fig: Figure, stem: str) -> tuple[Path, Path]:
    """Write assets/<stem>.png and assets/<stem>.svg with no timestamps in the metadata."""
    ASSETS.mkdir(exist_ok=True)
    png, svg = ASSETS / f"{stem}.png", ASSETS / f"{stem}.svg"
    fig.savefig(png, metadata={"Software": None})
    fig.savefig(svg, metadata={"Date": None, "Creator": None})
    return png, svg
