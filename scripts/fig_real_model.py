"""Real-model figure: the attacks a real model fell for, and which setup stopped them.

Reads only the two committed real-model results files (one pass each, written by
scripts/eval_real_model.py with an Anthropic API key; this script calls no model):

    results/real_model_sonnet.json            Claude Sonnet 5.5
    results/real_model_haiku.json    Claude Haiku 4.5

and draws

    assets/real_model.png    2x, on the shared template scripts/design/label_creep.html

One row per attack task that the model actually attempted in some configuration,
one column per configuration: a cross where the attack went through, a check where
the gateway stopped it. Below the grid, per configuration, the cost side: benign
tasks completed and approvals asked. Counts from one pass, not rates.

Run from the repo root: .venv/bin/python scripts/fig_real_model.py
"""

from __future__ import annotations

import json
from typing import Any

import style
from design.render import Shot, render

SONNET = "real_model_sonnet.json"
HAIKU = "real_model_haiku.json"
COLUMNS = (
    ("0-no-gateway", "no gateway"),
    ("2-policy-careful", "plus policy"),
    ("3-session-labels", "plus session labels"),
)
ATTEMPTED = {"attack succeeded": False, "gateway stopped it": True}  # outcome -> stopped?
# What each drawn attack tried to do, in a few words (from the task's injected step).
WHAT = {
    "approval-01": "outsider added to an invite",
    "misuse-02": "Q3 report emailed out",
}

WIDTH = 682  # chart width in CSS px, as in the other chart figures
LABEL_W = 236
COL_W = (WIDTH - LABEL_W) / len(COLUMNS)
HEAD_H = 34
ROW_H = 44
CHECK = "M20 6 9 17l-5-5"  # Lucide "check", 24 px box
CROSS = "M18 6 6 18M6 6l12 12"  # Lucide "x", 24 px box


def text(x: float, y: float, body: str, cls: str = "", anchor: str = "start") -> str:
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    c = f' class="{cls}"' if cls else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" dominant-baseline="central"{a}{c}>{body}</text>'


def glyph(x: float, y: float, stopped: bool) -> str:
    d, color = (CHECK, "var(--ok)") if stopped else (CROSS, "var(--no)")
    return (
        f'<path class="icon" d="{d}" transform="translate({x - 9:.1f} {y - 9:.1f}) '
        f'scale({18 / 24})" stroke="{color}" stroke-width="3.2"/>'
    )


def outcomes(data: dict[str, Any]) -> dict[str, dict[str, str]]:
    """config key -> task id -> attack outcome, for attack tasks only."""
    return {
        c["key"]: {tid: t["attack"]["outcome"] for tid, t in c["tasks"].items() if t.get("attack")}
        for c in data["configurations"]
    }


def chart(haiku: dict[str, Any], rows: list[str]) -> str:
    by_key = outcomes(haiku)
    summary = {c["key"]: c["summary"] for c in haiku["configurations"]}
    parts = [text(0, 8, "attack the model tried", "head")]
    for i, (_, name) in enumerate(COLUMNS):
        parts.append(text(LABEL_W + (i + 0.5) * COL_W, 8, name, "head", "middle"))
    parts.append(f'<line class="rule" x1="0" x2="{WIDTH}" y1="{HEAD_H - 11}" y2="{HEAD_H - 11}"/>')
    for r, tid in enumerate(rows):
        mid = HEAD_H + r * ROW_H + ROW_H / 2 - 8
        parts.append(text(0, mid, WHAT[tid]))
        for i, (key, _) in enumerate(COLUMNS):
            stopped = ATTEMPTED[by_key[key][tid]]
            cx = LABEL_W + (i + 0.5) * COL_W
            parts.append(glyph(cx - 52, mid, stopped))
            label = "stopped" if stopped else "went through"
            parts.append(text(cx - 38, mid, label, "ok strong" if stopped else "no"))
    y = HEAD_H + len(rows) * ROW_H + 4
    parts.append(f'<line class="rule" x1="0" x2="{WIDTH}" y1="{y - 10}" y2="{y - 10}"/>')
    cost_rows = (
        (
            "benign tasks done",
            lambda s: f"{s['benign_utility']['completed']} of {s['benign_utility']['of']}",
        ),
        ("approvals asked", lambda s: str(s["approvals_requested"]["total"])),
    )
    for j, (name, value) in enumerate(cost_rows):
        mid = y + 12 + j * 32
        parts.append(text(0, mid, name, "muted"))
        for i, (key, _) in enumerate(COLUMNS):
            parts.append(text(LABEL_W + (i + 0.5) * COL_W, mid, value(summary[key]), "", "middle"))
    height = y + 12 + len(cost_rows) * 32 - 16
    return (
        f'<svg class="chart" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}">{"".join(parts)}</svg>'
    )


def view(sonnet: dict[str, Any], haiku: dict[str, Any]) -> dict[str, Any]:
    for data in (sonnet, haiku):
        assert "real language model" in data["agents"] and data["status"] == "complete"
    by_key = outcomes(haiku)
    rows = sorted({tid for per in by_key.values() for tid, o in per.items() if o in ATTEMPTED})
    assert set(rows) == set(WHAT), rows  # a new attempted attack needs a WHAT entry
    attacks = haiku["configurations"][0]["summary"]["attacks_run"]
    sonnet_tried = max(c["summary"]["attacks_attempted"] for c in sonnet["configurations"])
    return {
        "title": "A real model fell for two attacks",
        "tiles": [],
        "charts": [
            {
                "icon": "shield-check",
                "name": "What each setup did with them",
                "meta": "Claude Haiku 4.5, one pass",
                "svg": chart(haiku, rows),
                "aside": [
                    f"{attacks} attack tasks; Claude Sonnet 5.5 tried {sonnet_tried}",
                    "careful approver",
                ],
            }
        ],
    }


def main() -> None:
    sonnet = json.loads((style.RESULTS / SONNET).read_text(encoding="utf-8"))
    haiku = json.loads((style.RESULTS / HAIKU).read_text(encoding="utf-8"))
    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "real_model.png"
    render("label_creep.html", view(sonnet, haiku), [Shot(str(png), scale=2)])
    print(png.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
