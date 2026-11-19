"""Turn a figure template (HTML + system.css) into PNG files.

A template is an HTML file in this directory. It links system.css, marks
icons as {{icon:NAME}} (inlined here from icons/, Lucide, ISC license) and
reads its data from window.DATA, which this module injects. The page is
captured by render.cjs with headless Chromium, driven by Node.js Playwright
(Node 18 or later on PATH; see `node_path` for where the package is looked
for). Fonts come from fonts/ (OFL), never from the system, so output does not
depend on what the machine has installed.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

DESIGN = Path(__file__).resolve().parent
ROOT = DESIGN.parent.parent
# The build environment's preinstalled copy; used only if nothing else is found.
FALLBACK_NODE_MODULES = Path("/opt/node-tools/node_modules")
WIDTH = 800  # CSS px: the README display width every figure is designed at


@dataclass
class Shot:
    """One capture: the page posed at time `t` (None for a still page)."""

    path: str
    t: float | None = None
    scale: float = 2
    square: bool = False  # square stage corners, for formats without alpha (GIF)


def node_path() -> str:
    """The node_modules directory that holds the Node.js `playwright` package.

    In order: $TOOLGATE_NODE_PATH, $NODE_PATH, node_modules/ in the repo (as
    made by `npm i -D playwright`), then the preinstalled FALLBACK_NODE_MODULES.
    An environment variable is used only if the package is actually in it.
    """
    candidates = [os.environ.get("TOOLGATE_NODE_PATH"), os.environ.get("NODE_PATH")]
    candidates += [str(ROOT / "node_modules"), str(FALLBACK_NODE_MODULES)]
    for directory in filter(None, candidates):
        if (Path(directory) / "playwright").is_dir():
            return directory
    raise SystemExit(
        "Node.js Playwright not found: run `npm i -D playwright` and "
        "`npx playwright install chromium` in the repo root, or set TOOLGATE_NODE_PATH "
        "to the node_modules directory that contains it"
    )


def icon(name: str) -> str:
    """A Lucide icon as inline SVG that inherits size and color from CSS."""
    svg = (DESIGN / "icons" / f"{name}.svg").read_text()
    svg = re.sub(r"<!--.*?-->\s*", "", svg, flags=re.S)
    tag_end = svg.index(">") + 1  # strip size and class from the root <svg> tag only
    svg = re.sub(r'\s(class|width|height)="[^"]*"', "", svg[:tag_end]) + svg[tag_end:]
    return " ".join(svg.split()).replace("> <", "><")


def build_page(template: str, data: dict[str, Any]) -> str:
    html = (DESIGN / template).read_text()
    html = re.sub(r"\{\{icon:([a-z0-9-]+)\}\}", lambda m: icon(m.group(1)), html)
    base = f'<base href="{DESIGN.as_uri()}/">'
    payload = json.dumps(data, sort_keys=True).replace("</", "<\\/")
    return html.replace("<!--BASE-->", base).replace("/*DATA*/", f"window.DATA = {payload};")


def render(template: str, data: dict[str, Any], shots: list[Shot]) -> None:
    """Build the page from `template` and `data`, then write every shot."""
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "page.html"
        page.write_text(build_page(template, data))
        job = Path(tmp) / "job.json"
        job.write_text(
            json.dumps({"html": str(page), "width": WIDTH, "shots": [asdict(s) for s in shots]})
        )
        env = {**os.environ, "NODE_PATH": node_path()}
        done = subprocess.run(
            ["node", str(DESIGN / "render.cjs"), str(job)],
            env=env,
            capture_output=True,
            text=True,
        )
        if done.returncode != 0:
            raise SystemExit(f"render failed for {template}:\n{done.stderr}")
