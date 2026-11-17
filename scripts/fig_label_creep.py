"""Label creep figure for M4b: what provenance stops, what it asks a person, and why.

Runs toolgate.sandbox.runner.label_creep() (scripted agents, not a language
model), writes results/m4b_label_creep.json, then draws from that JSON only:

    assets/label_creep.png
    assets/label_creep.svg

Left: per configuration, attacks that still succeeded (of 18) and approvals
the honest agent asked for (mean per task, 26 tasks): two panels on one row
per configuration, never one dual axis. Right: the fraction of values labeled
untrusted at each step number of a task, for configurations 3, 4 and 5.

Deterministic: running it twice writes the same bytes.

Run from the repo root: .venv/bin/python scripts/fig_label_creep.py
"""

from __future__ import annotations

import json

import matplotlib.pyplot as plt

import style
from toolgate.sandbox.runner import label_creep

# Categorical slots in fixed order (validated: scripts of the dataviz method).
SERIES = (
    ("3-session-labels", "3 session labels", "#2a78d6"),
    ("4-value-labels", "4 value labels (handles)", "#eb6834"),
    ("5-plan-execute", "5 plan-then-execute", "#1baf7a"),
)
BASELINE = "#8c8b87"


def main() -> None:
    style.apply()
    data = label_creep()
    out = style.RESULTS / "m4b_label_creep.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    data = json.loads(out.read_text(encoding="utf-8"))

    fig = plt.figure(figsize=style.SIZE)
    fig.text(
        0.04,
        0.94,
        "Provenance in the sandbox: protection, approvals and label creep",
        fontsize=20,
        fontweight="bold",
    )
    fig.text(
        0.04,
        0.905,
        "Scripted agents, planner and extractor, not a language model. "
        "26 tasks, 18 of them attacks. Careful approver unless marked rubber stamp.",
        fontsize=12.5,
        color=style.MUTED,
    )
    rows = data["protection_vs_approvals"]
    names = [r["configuration"] for r in rows]
    y = list(range(len(rows)))[::-1]
    color = {key: c for key, _, c in SERIES}

    def bar_color(name: str) -> str:
        for key, c in color.items():
            if name.startswith(key):
                return c
        return BASELINE

    ax1 = fig.add_axes((0.17, 0.15, 0.17, 0.67))
    ax2 = fig.add_axes((0.36, 0.15, 0.13, 0.67))
    for ax, field, title, limit, fmt in (
        (ax1, "attacks_succeeded", "attacks that succeeded\n(of 18, fewer is better)", 18, "{:d}"),
        (
            ax2,
            "honest_approvals_mean_per_task",
            "approvals asked per task\n(honest agent)",
            1.3,
            "{:.2f}",
        ),
    ):
        values = [r[field] for r in rows]
        ax.barh(y, values, height=0.62, color=[bar_color(n) for n in names], edgecolor="none")
        for yy, v in zip(y, values, strict=True):
            ax.text(
                v + limit * 0.02, yy, fmt.format(v), va="center", fontsize=11.5, color=style.INK
            )
        ax.set_xlim(0, limit * 1.18)
        ax.set_ylim(-0.6, len(rows) - 0.4)
        ax.set_title(title, fontsize=13, color=style.INK, loc="left", pad=10)
        ax.set_xticks([])
        for side in ("top", "right", "bottom"):
            ax.spines[side].set_visible(False)
        ax.tick_params(axis="y", length=0)
    ax1.set_yticks(y, [n.replace("-rubber-stamp", " (rubber stamp)") for n in names], fontsize=11.5)
    ax2.set_yticks([])

    ax3 = fig.add_axes((0.58, 0.15, 0.38, 0.67))
    creep = data["configurations"]
    for key, label, c in SERIES:
        steps = [s for s in creep[key]["by_step"] if s["fraction_values_untrusted"] is not None]
        xs = [s["step"] for s in steps]
        ys = [s["fraction_values_untrusted"] for s in steps]
        ax3.plot(
            xs,
            ys,
            color=c,
            linewidth=2,
            marker="o",
            markersize=8,
            markeredgecolor=style.SURFACE,
            markeredgewidth=2,
            label=label,
        )
        ax3.text(
            xs[-1] + 0.12,
            ys[-1],
            label.split(" ", 1)[1],
            color=style.INK,
            fontsize=11.5,
            va="center",
        )
    tasks = [s["tasks"] for s in creep["3-session-labels"]["by_step"]]
    ax3.set_xticks(
        range(1, len(tasks) + 1),
        [f"{i + 1}\n{n} tasks" for i, n in enumerate(tasks)],
        fontsize=10.5,
    )
    ax3.set_xlim(0.7, len(tasks) + 1.9)
    ax3.set_ylim(0, 1.05)
    ax3.set_yticks([0, 0.25, 0.5, 0.75, 1.0], ["0%", "25%", "50%", "75%", "100%"])
    ax3.grid(axis="y", color=style.RULE, linewidth=0.8)
    ax3.set_axisbelow(True)
    for side in ("top", "right"):
        ax3.spines[side].set_visible(False)
    ax3.set_title(
        "values labeled untrusted, by step within a task\n(honest agent, all 26 tasks)",
        fontsize=13,
        loc="left",
        pad=10,
    )
    ax3.set_xlabel("step number (calls that reached a decision)", fontsize=11.5)
    ax3.legend(loc="lower right", frameon=False, fontsize=11)
    fig.text(
        0.04,
        0.025,
        "In 4 (both approvers) one attack (args-03) never reached the agent: label creep "
        "denied the fetch that carried it. Session mode counts every value after the first "
        "untrusted result as untrusted.",
        fontsize=11,
        color=style.MUTED,
    )
    style.save(fig, "label_creep")


if __name__ == "__main__":
    main()
