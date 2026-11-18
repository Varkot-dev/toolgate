"""Completeness gap figure for M0b: never unsafe, and less often too strict.

Reads results/m0b_completeness.json (written by scripts/m0b_completeness.py)
and writes

    assets/completeness_gap.png    2x, drawn from scripts/design/completeness_gap.html

Top: three counts over the exhaustive universe of constraint pairs (unsafe
pairs accepted, safe pairs accepted, safe pairs still rejected). Below: the
safe pairs the checker rejects, before and after rule A, on a bar whose full
length is every safe pair. Every number drawn is read from the JSON; the
script only checks that the file is consistent with itself.

The page is drawn as inline SVG from coordinates computed here, on the shared
design system in scripts/design/, and captured with headless Chromium (see
scripts/design/render.py). Same JSON in, same PNG bytes out.

Run from the repo root: .venv/bin/python scripts/fig_completeness_gap.py
"""

from __future__ import annotations

import json
import re
from html import escape
from typing import Any

import style
from design.render import Shot, render

WIDTH = 682  # chart width in CSS px: the stage's 720 px content minus card padding
LABEL_W = 132  # left column for row labels
BAR_H = 20
ROW_H = 40


def n(value: int) -> str:
    return f"{value:,}"


def rule_html(rule: str) -> str:
    """'A: a star-free child glob is checked like eq (implemented in src/)' -> the middle,
    with operator names set as code."""
    text = re.sub(r"\s*\(.*\)$", "", re.sub(r"^[A-Z]:\s*", "", rule))
    return re.sub(r"\b(eq|in|max|glob|any)$", r'<span class="mono">\1</span>', escape(text))


def gap_chart(before: int, now: int, safe: int) -> str:
    """Two bars on one scale whose full length (the track) is every safe pair."""
    x0 = LABEL_W
    room = WIDTH - x0
    rows = [
        ("before the rule", before, "var(--wire)", "muted"),
        ("with the rule", now, "var(--accent)", "strong"),
    ]
    top = 4
    parts = []
    for i, (label, value, fill, cls) in enumerate(rows):
        y = top + i * ROW_H
        w = room * value / safe
        mid = y + BAR_H / 2
        parts.append(
            f'<text x="0" y="{mid:.1f}" dominant-baseline="central" class="{cls}">{label}</text>'
        )
        parts.append(
            f'<rect class="track" x="{x0}" y="{y}" width="{room}" height="{BAR_H}" rx="5"/>'
        )
        parts.append(
            f'<rect x="{x0}" y="{y}" width="{w:.1f}" height="{BAR_H}" rx="5" fill="{fill}"/>'
        )
        parts.append(
            f'<text x="{x0 + w + 10:.1f}" y="{mid:.1f}" dominant-baseline="central" '
            f'class="{cls}">{n(value)}</text>'
        )
    height = top + ROW_H + BAR_H
    body = "".join(parts)
    return (
        f'<svg class="chart" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}">{body}</svg>'
    )


def view(data: dict[str, Any]) -> dict[str, Any]:
    section = data["exhaustive_constraints"]
    totals = section["outcomes"]
    effect = section["rule_a"]
    before = section["previous_rule_set"]["outcomes"]

    # The figure must not disagree with the file it was drawn from.
    unsafe_accepted = data["accepted_unsafe_total"]
    assert unsafe_accepted == totals["accepted_unsafe_BUG"] == 0, "security bug: do not draw"
    assert effect["gap_before"] == before["rejected_safe_gap"]
    assert effect["gap_now"] == totals["rejected_safe_gap"]
    assert effect["unsafe_pairs_newly_accepted"] == 0
    safe = totals["truly_safe"]
    assert safe == totals["accepted_safe"] + totals["rejected_safe_gap"]
    assert safe == before["truly_safe"]
    assert totals["inconclusive_accepted"] + totals["inconclusive_rejected"] == 0
    unsafe = totals["rejected_unsafe"] + unsafe_accepted

    return {
        "title": "Never unsafe, and less often too strict",
        "tiles": [
            {
                "tone": "ok",
                "icon": "shield-check",
                "label": "unsafe pairs accepted",
                "value": n(unsafe_accepted),
                "sub": f"of {n(unsafe)} unsafe",
            },
            {
                "tone": "okmark",
                "icon": "check",
                "label": "safe pairs accepted",
                "value": n(totals["accepted_safe"]),
                "sub": f"of {n(safe)} safe",
            },
            {
                "tone": "quiet",
                "icon": "x",
                "label": "safe pairs rejected",
                "value": n(totals["rejected_safe_gap"]),
                "sub": "the gap that remains",
            },
        ],
        "charts": [
            {
                "icon": "trending-down",
                "name": "One added rule closed most of the gap",
                "meta": f"bar length: all {n(safe)} safe pairs",
                "svg": gap_chart(effect["gap_before"], effect["gap_now"], safe),
                "aside": [
                    f"Added rule: {rule_html(effect['rule'])}",
                    f"{n(totals['pairs'])} pairs, solver-checked",
                ],
            }
        ],
    }


def main() -> None:
    source = style.RESULTS / "m0b_completeness.json"
    data = json.loads(source.read_text())
    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "completeness_gap.png"
    render("completeness_gap.html", view(data), [Shot(str(png), scale=2)])
    print(png.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
