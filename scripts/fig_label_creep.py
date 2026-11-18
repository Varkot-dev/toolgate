"""Label creep figure for M4b: what provenance stops, and what it asks a person.

Runs toolgate.sandbox.runner.label_creep() (scripted agents, not a language
model), writes results/m4b_label_creep.json, then draws from that JSON (and
results/m5_scripted.json, which it is checked against) only:

    assets/label_creep.png    2x, drawn from scripts/design/label_creep.html

One row per configuration, careful approver: attacks that still succeeded
(of 18) on the left, approvals the honest agent asked for (mean per task, 26
tasks) on the right. Two panels with their own scales on shared rows, never
one dual axis.

The page is drawn as inline SVG from coordinates computed here, on the shared
design system in scripts/design/, and captured with headless Chromium (see
scripts/design/render.py). Deterministic: running it twice writes the same
bytes.

Run from the repo root: .venv/bin/python scripts/fig_label_creep.py
"""

from __future__ import annotations

import json
from typing import Any

import style
from design.render import Shot, render
from toolgate.sandbox.runner import label_creep

# The configurations drawn, in order, with their row labels. Careful approver
# throughout; the rubber-stamp variants and 1c stay in the JSON.
ROWS = (
    ("0-no-gateway", "no gateway"),
    ("1-grant-only", "grant only"),
    ("2-policy-careful", "plus policy"),
    ("3-session-labels", "plus session labels"),
    ("4-value-labels", "plus value labels"),
    ("5-plan-execute", "plan-then-execute"),
)

WIDTH = 682  # chart width in CSS px: the stage's 720 px content minus card padding
LABEL_W = 176
A_X, A_ROOM = 184, 180  # attacks panel: left edge and longest bar
B_X, B_ROOM = 448, 180  # approvals panel
HEAD_H = 34
ROW_H = 40
BAR_H = 18
CHECK = "M20 6 9 17l-5-5"  # Lucide "check", 24 px box


def text(x: float, y: float, body: str, cls: str = "", anchor: str = "start") -> str:
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    c = f' class="{cls}"' if cls else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" dominant-baseline="central"{a}{c}>{body}</text>'


def bar(x: float, y: float, w: float, fill: str) -> str:
    return f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{BAR_H}" rx="4" fill="{fill}"/>'


def chart(rows: list[dict[str, Any]], attacks: int, top_approvals: float) -> str:
    parts = [
        text(A_X, 8, f'attacks that succeeded <tspan class="quiet">of {attacks}</tspan>', "head"),
        text(B_X, 8, 'approvals asked <tspan class="quiet">per task</tspan>', "head"),
        f'<line class="rule" x1="0" x2="{WIDTH}" y1="{HEAD_H - 11}" y2="{HEAD_H - 11}"/>',
    ]
    for i, row in enumerate(rows):
        y = HEAD_H + i * ROW_H
        mid = y + BAR_H / 2
        parts.append(text(0, mid, row["name"]))
        hits = row["attacks_succeeded"]
        # A row whose denominator differs from the header says so (value labels:
        # label creep blocked one injection before it was ever delivered).
        tried = row["attacks_attempted"]
        of = "" if tried == attacks else f' <tspan class="quiet">of {tried}</tspan>'
        if hits:
            w = A_ROOM * hits / attacks
            parts.append(bar(A_X, y, w, "var(--no)"))
            parts.append(text(A_X + w + 8, mid, f"{hits}{of}"))
        else:  # nothing got through: a check mark and a zero, not an empty row
            parts.append(
                f'<path class="icon" d="{CHECK}" transform="translate({A_X - 1} {mid - 8}) '
                f'scale({16 / 24})" stroke="var(--ok)" stroke-width="3.4"/>'
            )
            parts.append(text(A_X + 22, mid, f"0{of}", "ok strong"))
        asks = row["honest_approvals_mean_per_task"]
        if asks:
            w = B_ROOM * asks / top_approvals
            parts.append(bar(B_X, y, w, "var(--accent)"))
            parts.append(text(B_X + w + 8, mid, f"{asks:.2f}"))
        else:
            parts.append(text(B_X, mid, "none", "muted"))
    height = HEAD_H + len(rows) * ROW_H - ROW_H + BAR_H + 2
    body = "".join(parts)
    return (
        f'<svg class="chart" width="{WIDTH}" height="{height}" '
        f'viewBox="0 0 {WIDTH} {height}">{body}</svg>'
    )


def view(data: dict[str, Any], scripted: dict[str, Any]) -> dict[str, Any]:
    by_key = {r["configuration"]: r for r in data["protection_vs_approvals"]}
    m5 = {c["key"]: c["summary"] for c in scripted["configurations"]}
    rows = []
    for key, name in ROWS:
        r = by_key[key]
        # The two result files must agree on every number drawn.
        assert r["attacks_succeeded"] == m5[key]["attacks_succeeded"], key
        honest = m5[key]["approvals_requested"]["honest"]
        assert r["honest_approvals_total"] == honest["total"], key
        assert r["honest_approvals_mean_per_task"] == honest["mean_per_task"], key
        rows.append({**r, "name": name, "attacks_attempted": m5[key]["attacks_attempted"]})
    attacks = {r["attacks"] for r in rows}
    assert len(attacks) == 1
    tasks = len(scripted["tasks"])
    assert "scripted" in scripted["agents"]
    return {
        "title": "Provenance stops attacks, at the cost of questions",
        "tiles": [],
        "charts": [
            {
                "icon": "shield-check",
                "name": "What each setup stops, and what it asks",
                "meta": "scripted agents",
                "svg": chart(
                    rows,
                    attacks.pop(),
                    max(r["honest_approvals_mean_per_task"] for r in rows),
                ),
                "aside": [
                    f"Approvals: asked by an honest agent, mean over {tasks} tasks",
                    "careful approver",
                ],
            }
        ],
    }


def main() -> None:
    data = label_creep()
    out = style.RESULTS / "m4b_label_creep.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    data = json.loads(out.read_text(encoding="utf-8"))
    scripted = json.loads((style.RESULTS / "m5_scripted.json").read_text(encoding="utf-8"))

    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "label_creep.png"
    render("label_creep.html", view(data, scripted), [Shot(str(png), scale=2)])
    for path in (png, out):
        print(path.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
