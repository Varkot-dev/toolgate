"""Latency figure for M6: what the gateway adds to one tool call.

Reads results/m6_latency.json (written by scripts/bench_latency.py; this
script never runs the benchmark) and draws:

    assets/latency.png
    assets/latency.svg

Left: histogram of the added latency of every timed allowed call in the main
configuration (MemoryStore, audit fsync on), log-scaled x axis, p50 and p99
marked. Right: the median of each pipeline component timed on its own, with
the bars that are a part of another bar or a reference drawn in gray.

The layout is fixed; the numbers change from run to run, as measurements do.

Run from the repo root: .venv/bin/python scripts/fig_latency.py
"""

from __future__ import annotations

import json
import math

import matplotlib.pyplot as plt

import style

DATA = style.RESULTS / "m6_latency.json"
REFERENCE = "#a3a29d"  # gray for bars that are a part of another bar, or a reference

# (key in "stages", label on the chart, drawn as a pipeline stage?)
STAGES = (
    ("call_build", "build Call, hash arguments", True),
    ("token_verify", "verify token (step b)", True),
    ("ed25519_signature_only", "of which: Ed25519 signature", False),
    ("grant_decide", "grant decide", True),
    ("policy_decide", "policy decide (17-rule example)", True),
    ("authorize", "verify again + charge budget (step d)", True),
    ("budget_charge", "of which: budget charge", False),
    ("audit_append_fsync", "audit append, fsync on", True),
    ("audit_append_no_fsync", "same append, fsync a no-op", False),
    ("re_verify", "verify a third time (step e)", True),
    ("tool_dispatch", "run no-op tool, check output", True),
)


def fmt_us(value: float) -> str:
    if value >= 1000:
        return f"{value / 1000:.2f} ms"
    if value >= 100:
        return f"{value:.0f} us"
    return f"{value:.1f} us"


def tick_label(value: float) -> str:
    return f"{value / 1000:g} ms" if value >= 1000 else f"{value:g} us"


def main() -> None:
    style.apply()
    data = json.loads(DATA.read_text(encoding="utf-8"))
    main_run = data["pipeline"]["memory_fsync_on"]
    no_fsync = data["pipeline"]["memory_fsync_off"]["added"]
    samples = [s for s in main_run["added_samples_us"] if s > 0]
    added = main_run["added"]
    host = data["machine"]

    fig = plt.figure(figsize=style.SIZE)
    fig.text(0.04, 0.93, "What the gateway adds to one tool call", fontsize=26, fontweight="bold")
    fig.text(
        0.04,
        0.885,
        f"In-process Gateway.handle_call for an allowed call to a no-op tool, minus calling "
        f"the tool directly. MemoryStore, audit fsync on, {added['n']:,} calls.",
        fontsize=15,
        color=style.MUTED,
    )

    # -- left: histogram ---------------------------------------------------
    ax = fig.add_axes((0.06, 0.2, 0.44, 0.57))
    low, high = min(samples) / 1.05, max(samples) * 1.05
    count = round(40 * math.log10(high / low))  # 40 bins per factor of ten
    bins = [low * (high / low) ** (i / count) for i in range(count + 1)]
    ax.hist(samples, bins=bins, color=style.ACCENT, edgecolor=style.SURFACE, linewidth=0.6)
    ax.set_xscale("log")
    ax.set_xlim(min(samples) / 1.5, max(samples) * 1.5)
    top = ax.get_ylim()[1]
    ax.set_ylim(0, top * 1.22)
    for value, name, align in ((added["p50_us"], "p50", "right"), (added["p99_us"], "p99", "left")):
        ax.axvline(value, color=style.INK, linewidth=1.5, linestyle=(0, (4, 3)))
        offset = 0.94 if align == "right" else 1.06
        ax.text(
            value * offset,
            top * 1.12,
            f"{name} {fmt_us(value)}",
            ha=align,
            va="center",
            fontsize=15,
            fontweight="bold",
            color=style.INK,
        )
    ax.set_xlabel("added latency per call (log scale)", fontsize=14)
    ax.set_ylabel("calls", fontsize=14)
    ticks = [t for t in (100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000)
             if ax.get_xlim()[0] <= t <= ax.get_xlim()[1]]  # fmt: skip
    ax.set_xticks(ticks, [tick_label(t) for t in ticks], fontsize=13)
    ax.xaxis.set_minor_formatter(plt.NullFormatter())
    ax.tick_params(axis="y", labelsize=13)
    ax.grid(axis="y", color=style.RULE, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.set_title(
        f"added latency, every call  (mean {fmt_us(added['mean_us'])}, "
        f"p99.9 {fmt_us(added['p99_9_us'])})",
        fontsize=16,
        loc="left",
        pad=12,
    )
    ax.text(
        0.0,
        -0.21,
        f"Same calls with the audit fsync replaced by a no-op: p50 {fmt_us(no_fsync['p50_us'])}, "
        f"p99 {fmt_us(no_fsync['p99_us'])}.",
        transform=ax.transAxes,
        fontsize=13,
        color=style.MUTED,
    )

    # -- right: stage medians -----------------------------------------------
    bx = fig.add_axes((0.72, 0.2, 0.23, 0.57))
    stages = data["stages"]
    rows = [(label, stages[key]["p50_us"], main) for key, label, main in STAGES if key in stages]
    y = list(range(len(rows)))[::-1]
    values = [v for _, v, _ in rows]
    limit = max(values)
    bx.barh(
        y,
        values,
        height=0.66,
        color=[style.ACCENT if main else REFERENCE for _, _, main in rows],
        edgecolor="none",
    )
    for yy, (_, value, _) in zip(y, rows, strict=True):
        bx.text(value + limit * 0.02, yy, fmt_us(value), va="center", fontsize=13)
    bx.set_yticks(y, [label for label, _, _ in rows], fontsize=13)
    bx.set_xlim(0, limit * 1.3)
    bx.set_ylim(-0.6, len(rows) - 0.4)
    bx.set_xticks([])
    bx.tick_params(axis="y", length=0)
    for side in ("top", "right", "bottom"):
        bx.spines[side].set_visible(False)
    bx.set_title("median of each component, timed alone", fontsize=16, loc="right", pad=12)
    bx.text(
        1.0,
        -0.1,
        "Timed one by one; they need not sum to the pipeline.\n"
        "Gray: part of the bar above, or a reference.",
        transform=bx.transAxes,
        ha="right",
        va="top",
        fontsize=13,
        color=style.MUTED,
    )

    fig.text(
        0.04,
        0.03,
        f"{host['cpu_model']}, {host['logical_cores']} cores, Python {host['python']}, "
        f"{host['temp_dir_filesystem']} temp dir. One shared cloud container, not isolated: "
        "indicative numbers. Data: results/m6_latency.json",
        fontsize=12.5,
        color=style.MUTED,
    )
    style.save(fig, "latency")


if __name__ == "__main__":
    main()
