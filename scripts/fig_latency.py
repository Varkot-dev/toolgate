"""Latency figure for M6: what the gateway adds to one tool call.

Reads results/m6_latency.json (written by scripts/bench_latency.py; this
script never runs the benchmark) and writes

    assets/latency.png    2x, drawn from scripts/design/latency.html

Top: the added latency of an allowed call in the main configuration
(MemoryStore, audit fsync on), median and p99, for a reused token (warm:
verify hits its cache) and a new token every call (cold: the signature is
checked). Below: the median of each pipeline step timed on its own.

The page is drawn as inline SVG from coordinates computed here, on the shared
design system in scripts/design/, and captured with headless Chromium (see
scripts/design/render.py). The numbers change from run to run of the
benchmark, as measurements do; the same JSON always gives the same PNG bytes.

Run from the repo root: .venv/bin/python scripts/fig_latency.py
"""

from __future__ import annotations

import json
from typing import Any

import style
from design.render import Shot, render

DATA = style.RESULTS / "m6_latency.json"

# (key in "stages", row label, bar color). In the order a call goes through
# them; a call verifies once, with a reused token or a new one.
STEPS = (
    ("call_build", "build call, hash args", "var(--muted)"),
    ("verify_warm", "verify, reused token", "var(--muted)"),
    ("verify_cold", "verify, new token", "var(--wire)"),
    ("grant_decide", "grant decide", "var(--muted)"),
    ("policy_decide", "policy decide", "var(--muted)"),
    ("authorize", "authorize + charge", "var(--muted)"),
    ("audit_append_fsync", "audit append + fsync", "var(--accent)"),
    ("recheck", "recheck expiry, revocation", "var(--muted)"),
    ("tool_run", "run tool, check output", "var(--muted)"),
)

WIDTH = 682  # chart width in CSS px: the stage's 720 px content minus card padding
LABEL_W = 216
ROW_H = 30
BAR_H = 14


def fmt_us(value: float) -> str:
    """Microseconds as a reader wants them: 1.40 ms, 448 µs, 8.2 µs."""
    if value >= 1000:
        return f"{value / 1000:.2f} ms"
    if value >= 100:
        return f"{value:.0f} µs"
    return f"{value:.1f} µs"


def big(value: float) -> str:
    """A tile number with a smaller unit."""
    number, unit = fmt_us(value).split(" ")
    return f"{number}<small>{unit}</small>"


def text(x: float, y: float, body: str, cls: str = "") -> str:
    c = f' class="{cls}"' if cls else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" dominant-baseline="central"{c}>{body}</text>'


def steps_chart(stages: dict[str, Any]) -> str:
    rows = [(label, stages[key]["p50_us"], color, key) for key, label, color in STEPS]
    top = max(v for _, v, _, _ in rows)
    room = WIDTH - LABEL_W - 236  # space after the longest bar for its value and note
    parts = []
    for i, (label, value, color, key) in enumerate(rows):
        y = i * ROW_H
        mid = y + BAR_H / 2
        w = max(2.0, room * value / top)  # a step never vanishes, however fast
        strong = key == "audit_append_fsync"
        parts.append(text(0, mid, label, "strong" if strong else ""))
        parts.append(
            f'<rect x="{LABEL_W}" y="{y}" width="{w:.1f}" height="{BAR_H}" '
            f'rx="{min(2.0, w / 2):g}" fill="{color}"/>'
        )
        note = ""
        if key == "audit_append_fsync":
            off = stages["audit_append_no_fsync"]["p50_us"]
            note = f'<tspan class="quiet" dx="8">{fmt_us(off)} without fsync</tspan>'
        elif key == "verify_cold":
            note = '<tspan class="quiet" dx="8">new token only</tspan>'
        parts.append(text(LABEL_W + w + 8, mid, fmt_us(value) + note, "strong" if strong else ""))
    height = (len(rows) - 1) * ROW_H + BAR_H
    body = "".join(parts)
    return (
        f'<svg class="chart" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}">{body}</svg>'
    )


def view(data: dict[str, Any]) -> dict[str, Any]:
    pipeline = data["pipeline"]
    warm = pipeline["memory_fsync_on_warm"]["added"]
    cold = pipeline["memory_fsync_on_cold"]["added"]
    assert warm["n"] == cold["n"]
    title = (
        "Under a millisecond for a typical call"
        if warm["p50_us"] < 1000
        else f"About {fmt_us(warm['p50_us'])} for a typical call"
    )
    return {
        "title": title,
        "tiles": [
            {
                "tone": "accent",
                "icon": "timer",
                "label": "reused token, median",
                "value": big(warm["p50_us"]),
                "sub": f"p99 {fmt_us(warm['p99_us'])}",
            },
            {
                "tone": "",
                "icon": "timer",
                "label": "new token every call, median",
                "value": big(cold["p50_us"]),
                "sub": f"p99 {fmt_us(cold['p99_us'])}",
            },
        ],
        "note": f"Added per allowed call, {warm['n']:,} calls each. "
        "One shared cloud machine: indicative.",
        "charts": [
            {
                "icon": "clock",
                "name": "Where the time goes",
                "meta": "median of each step, timed alone",
                "svg": steps_chart(data["stages"]),
            }
        ],
    }


def main() -> None:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "latency.png"
    render("latency.html", view(data), [Shot(str(png), scale=2)])
    print(png.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
