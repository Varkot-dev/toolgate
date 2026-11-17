"""Completeness gap figure for M0b: what the checker rejects although it is safe.

Reads results/m0b_completeness.json (written by scripts/m0b_completeness.py)
and writes

    assets/completeness_gap.png
    assets/completeness_gap.svg

Left: parent operator by child operator, three counts per cell from the
exhaustive section. Right: the gap pairs by the reason the checker missed them,
then what rule A (implemented) closed and what candidate B would still close.
Both panels show the CURRENT checker.
Every number drawn is read from the JSON; nothing is computed here except sums
used to check that the file is consistent.

Run from the repo root: .venv/bin/python scripts/fig_completeness_gap.py
"""

from __future__ import annotations

import json
from typing import Any

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import Rectangle

import style

OPS = ("eq", "in", "max", "glob", "any")
# One color per outcome. The gap is the subject, so it gets the highlight color;
# the unsafe pairs that were correctly rejected are background and stay gray.
SERIES = (
    ("accepted_safe", "safe, accepted", style.ALLOW),
    ("rejected_safe_gap", "safe, but rejected (the gap)", style.ACCENT),
    ("rejected_unsafe", "unsafe, rejected", "#8c8b87"),
)
GAP = 2  # px of surface between touching marks

# Left panel geometry, in figure pixels.
GRID_X, GRID_Y = 170, 236
CELL_W, CELL_H = 136, 112
# Right panel geometry.
BARS_X, BARS_Y, BARS_W, ITEM_H = 905, 212, 500, 90


def n(value: int) -> str:
    return f"{value:,}"


def segments(ax: Axes, x: float, y: float, width: float, height: float, counts: list[int]) -> None:
    """One whole split into parts. A nonzero part is never drawn thinner than 4 px."""
    shown = [(c, color) for c, (_, _, color) in zip(counts, SERIES, strict=True) if c]
    room = width - GAP * (len(shown) - 1)
    total = sum(c for c, _ in shown)
    widths = [max(4.0, room * c / total) for c, _ in shown]
    widest = max(range(len(widths)), key=widths.__getitem__)
    widths[widest] -= sum(widths) - room  # the widest part pays for the minimum widths
    for w, (_, color) in zip(widths, shown, strict=True):
        ax.add_patch(Rectangle((x, y), w, height, facecolor=color, edgecolor="none"))
        x += w + GAP


def draw_grid(ax: Axes, cells: dict[tuple[str, str], dict[str, Any]]) -> None:
    ax.text(40, 160, "Every pair, by operator", fontsize=19, fontweight="bold", va="center")
    ax.text(
        GRID_X + 2.5 * CELL_W,
        GRID_Y - 58,
        "child constraint",
        fontsize=15,
        color=style.MUTED,
        ha="center",
        va="center",
    )
    ax.text(
        58,
        GRID_Y + 2.5 * CELL_H,
        "parent constraint",
        fontsize=15,
        color=style.MUTED,
        ha="center",
        va="center",
        rotation=90,
    )
    for i, op in enumerate(OPS):
        ax.text(
            GRID_X + (i + 0.5) * CELL_W,
            GRID_Y - 24,
            op,
            fontsize=17,
            family=style.MONO,
            fontweight="bold",
            ha="center",
            va="center",
        )
        ax.text(
            GRID_X - 18,
            GRID_Y + (i + 0.5) * CELL_H,
            op,
            fontsize=17,
            family=style.MONO,
            fontweight="bold",
            ha="right",
            va="center",
        )
    for k in range(len(OPS) + 1):  # hairlines between cells
        ax.plot(
            [GRID_X, GRID_X + 5 * CELL_W],
            [GRID_Y + k * CELL_H] * 2,
            color=style.RULE,
            linewidth=1,
            solid_capstyle="butt",
        )
        ax.plot(
            [GRID_X + k * CELL_W] * 2,
            [GRID_Y, GRID_Y + 5 * CELL_H],
            color=style.RULE,
            linewidth=1,
            solid_capstyle="butt",
        )

    pad = 14
    for r, parent in enumerate(OPS):
        for c, child in enumerate(OPS):
            cell = cells[parent, child]
            counts = [cell[key] for key, _, _ in SERIES]
            if not sum(counts):
                continue  # no pairs: the cell stays blank
            x, y = GRID_X + c * CELL_W, GRID_Y + r * CELL_H
            segments(ax, x + pad, y + 13, CELL_W - 2 * pad, 10, counts)
            for row, (count, (key, _, color)) in enumerate(zip(counts, SERIES, strict=True)):
                if not count:
                    continue  # zeros are left out so the nonzero counts stand out
                line = y + 46 + row * 25
                ax.add_patch(
                    Rectangle((x + pad, line - 6), 12, 12, facecolor=color, edgecolor="none")
                )
                ax.text(
                    x + CELL_W - pad,
                    line,
                    n(count),
                    fontsize=16,
                    fontweight="bold" if key == "rejected_safe_gap" else "normal",
                    ha="right",
                    va="center",
                )

    # Legend: always present, because three series share every cell.
    x, y = GRID_X, GRID_Y + 5 * CELL_H + 32
    for _, label, color in SERIES:
        ax.add_patch(Rectangle((x, y - 7), 14, 14, facecolor=color, edgecolor="none"))
        ax.text(x + 22, y, label, fontsize=15, va="center")
        x += 54 + 9.6 * len(label)


def draw_categories(ax: Axes, categories: list[dict[str, Any]], gap_total: int) -> None:
    ax.text(
        BARS_X,
        160,
        f"Why the {n(gap_total)} safe pairs were rejected",
        fontsize=19,
        fontweight="bold",
        va="center",
    )
    largest = max(c["count"] for c in categories)
    for i, cat in enumerate(categories):
        y = BARS_Y + i * ITEM_H
        example = cat["examples"][0]
        ax.text(BARS_X, y, cat["category"], fontsize=14.5, va="center")
        ax.text(
            BARS_X,
            y + 25,
            f"e.g. parent {example['parent']}   child {example['child']}",
            fontsize=13,
            family=style.MONO,
            color=style.MUTED,
            va="center",
        )
        width = BARS_W * cat["count"] / largest
        ax.add_patch(
            Rectangle((BARS_X, y + 42), width, 16, facecolor=style.ACCENT, edgecolor="none")
        )
        ax.text(
            BARS_X + width + 10,
            y + 50,
            n(cat["count"]),
            fontsize=16,
            fontweight="bold",
            va="center",
        )


def main() -> None:
    source = style.RESULTS / "m0b_completeness.json"
    data = json.loads(source.read_text())
    section = data["exhaustive_constraints"]
    totals = section["outcomes"]
    cells = {(c["parent"], c["child"]): c for c in section["by_parent_and_child_operator"]}
    categories = [c for c in section["gap_categories"] if c["count"]]

    # The figure must not disagree with the file it was drawn from.
    for key, _, _ in SERIES:
        assert sum(c[key] for c in cells.values()) == totals[key], key
    assert sum(c["count"] for c in categories) == totals["rejected_safe_gap"]
    unsafe_accepted = data["accepted_unsafe_total"]
    assert unsafe_accepted == totals["accepted_unsafe_BUG"] == 0, "security bug: do not draw"

    style.apply()
    fig = plt.figure(figsize=style.SIZE)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1600)
    ax.set_ylim(900, 0)
    ax.axis("off")

    ax.text(
        40,
        50,
        "Sound, not complete: what the checker rejects although it is safe",
        fontsize=26,
        fontweight="bold",
        va="center",
    )
    universe = section["universe"]
    ax.text(
        40,
        90,
        f"All {n(totals['pairs'])} ordered (parent, child) pairs of {universe['size']} "
        "single-argument constraints, each one decided exactly by the Z3 model of the rules.",
        fontsize=15,
        color=style.MUTED,
        va="center",
    )
    ax.text(
        40,
        116,
        f"safe and accepted: {n(totals['accepted_safe'])}      "
        f"safe but rejected: {n(totals['rejected_safe_gap'])}      "
        f"unsafe and rejected: {n(totals['rejected_unsafe'])}      "
        f"accepted but unsafe: {unsafe_accepted}",
        fontsize=15,
        fontweight="bold",
        va="center",
    )

    draw_grid(ax, cells)
    draw_categories(ax, categories, totals["rejected_safe_gap"])

    # What rule A closed (before -> after) and what candidate B would still close,
    # both as measured by the same script.
    effect = section["rule_a"]
    before = section["previous_rule_set"]["outcomes"]
    gap = totals["rejected_safe_gap"]
    assert effect["gap_before"] == before["rejected_safe_gap"]
    assert effect["gap_now"] == gap
    assert effect["gap_pairs_closed"] == effect["gap_before"] - gap
    assert effect["unsafe_pairs_newly_accepted"] == 0
    by_rules = {
        "+".join(label[0] for label in r["extensions"]): r
        for r in section["what_if_extensions"]["results"]
    }
    for r in by_rules.values():
        assert r["unsafe_pairs_it_would_accept"] == 0
    y = BARS_Y + len(categories) * ITEM_H + 4
    ax.plot([BARS_X, 1560], [y - 22, y - 22], color=style.RULE, linewidth=1)
    ax.text(
        BARS_X,
        y,
        "Implemented: a star-free child glob is checked like eq.",
        fontsize=14.5,
        fontweight="bold",
        va="center",
    )
    ax.text(
        BARS_X,
        y + 26,
        f"It closed {n(effect['gap_pairs_closed'])} pairs: the gap went from "
        f"{n(effect['gap_before'])} to {n(gap)}.",
        fontsize=14.5,
        va="center",
    )
    ax.text(
        BARS_X,
        y + 60,
        "Measured, not implemented: collapsing repeated stars",
        fontsize=14.5,
        fontweight="bold",
        va="center",
    )
    ax.text(
        BARS_X,
        y + 86,
        f"first would close {n(by_rules['B']['gap_pairs_closed'])} of the remaining {n(gap)}.",
        fontsize=14.5,
        va="center",
    )

    undecided = totals["inconclusive_accepted"] + totals["inconclusive_rejected"]
    ax.text(
        40,
        872,
        "Counts describe this small enumerated universe, not real workloads.   "
        f"Pairs the solver could not decide: {undecided}.   "
        f"Data: results/{source.name}",
        fontsize=13,
        color=style.MUTED,
        va="center",
    )

    png, svg = style.save(fig, "completeness_gap")
    for path in (png, svg):
        print(path.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
