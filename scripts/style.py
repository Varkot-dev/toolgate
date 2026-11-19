"""Shared paths for the figure and results scripts.

Figures are HTML pages under scripts/design/, rendered by
scripts/design/render.py; this module only says where things live.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
RESULTS = ROOT / "results"
