"""Latency figure for M6: what the gateway adds to one tool call.

Reads results/m6_latency.json (written by scripts/bench_latency.py; this
script never runs the benchmark) and draws:

    assets/latency.png
    assets/latency.svg

Left: histograms of the added latency of every timed allowed call in the main
configuration (MemoryStore, audit fsync on), in two series: warm (one token
reused, so verify hits its cache) and cold (a new token every call, so the
signature is checked every call). Log-scaled x axis, p50 and p99 marked for
each. Right: the median of each component of the current pipeline timed on
its own, with the bars that are a part of another bar or a reference drawn in
gray.

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
WARM = style.ACCENT
COLD = style.MUTED

# (key in "stages", label on the chart, drawn as a pipeline stage?)
STAGES = (
    ("call_build", "build Call, hash arguments", True),
    ("verify_cold", "verify, new token (cold)", True),
    ("ed25519_signature_only", "of which: Ed25519 signature", False),
    ("verify_warm", "verify, reused token (warm)", True),
    ("grant_decide", "grant decide", True),
    ("policy_decide", "policy decide ({rules}-rule example)", True),
    ("authorize", "authorize: recheck + charge", True),
    ("budget_charge", "of which: budget charge", False),
    ("audit_append_fsync", "audit append, fsync on", True),
    ("audit_append_no_fsync", "same append, fsync a no-op", False),
    ("recheck", "recheck: expiry, revocation", True),
    ("tool_run", "run no-op tool, check output", True),
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
    pipeline = data["pipeline"]
    series = []  # (name, color, samples, summary)
    for mode, color in (("warm", WARM), ("cold", COLD)):
        run = pipeline[f"memory_fsync_on_{mode}"]
        series.append((mode, color, [x for x in run["added_samples_us"] if x > 0], run["added"]))
    off = {mode: pipeline[f"memory_fsync_off_{mode}"]["added"] for mode in ("warm", "cold")}
    host = data["machine"]
    n = series[0][3]["n"]

    fig = plt.figure(figsize=style.SIZE)
    fig.text(0.04, 0.93, "What the gateway adds to one tool call", fontsize=26, fontweight="bold")
    fig.text(
        0.04,
        0.885,
        "In-process Gateway.handle_call for an allowed call to a no-op tool, minus a direct "
        f"tool call. MemoryStore, audit fsync on, {n:,} calls each.",
        fontsize=15,
        color=style.MUTED,
    )

    # -- left: histograms ----------------------------------------------------
    ax = fig.add_axes((0.06, 0.2, 0.44, 0.6))
    every = [x for _, _, samples, _ in series for x in samples]
    low, high = min(every) / 1.05, max(every) * 1.05
    count = round(40 * math.log10(high / low))  # 40 bins per factor of ten
    bins = [low * (high / low) ** (i / count) for i in range(count + 1)]
    for _, color, samples, _ in series:
        ax.hist(samples, bins=bins, histtype="stepfilled", color=color, alpha=0.28, linewidth=0)
        ax.hist(samples, bins=bins, histtype="step", color=color, linewidth=1.8)
    ax.set_xscale("log")
    ax.set_xlim(min(every) / 1.5, max(every) * 1.5)
    top = ax.get_ylim()[1]
    ax.set_ylim(0, top * 1.4)
    # Each series' p50 and p99: a dashed line in its color, labeled at its
    # top, p50 to the left of its line and p99 to the right. Cold's lines
    # reach higher, so the two rows of labels never meet.
    for row, (_, color, _, summary) in enumerate(series):
        height = top * (1.04 + 0.1 * row)
        for name, align in (("p50", "right"), ("p99", "left")):
            value = summary[f"{name}_us"]
            ax.vlines(value, 0, height, color=color, linewidth=1.6, linestyle=(0, (4, 3)))
            ax.text(
                value,
                height,
                f"{name} {fmt_us(value)} " if align == "right" else f" {name} {fmt_us(value)}",
                ha=align,
                va="center",
                fontsize=14,
                fontweight="bold",
                color=color,
                zorder=5,
                bbox={"facecolor": style.SURFACE, "edgecolor": "none", "pad": 1.5},
            )
    ax.set_xlabel("added latency per call (log scale)", fontsize=14)
    ax.set_ylabel("calls", fontsize=14)
    ticks = [t for t in (50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000)
             if ax.get_xlim()[0] <= t <= ax.get_xlim()[1]]  # fmt: skip
    ax.set_xticks(ticks, [tick_label(t) for t in ticks], fontsize=13)
    ax.xaxis.set_minor_formatter(plt.NullFormatter())
    ax.set_yticks([t for t in ax.get_yticks() if 0 <= t <= top])
    ax.tick_params(axis="y", labelsize=13)
    ax.grid(axis="y", color=style.RULE, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    # Direct labels for the two series, in their colors, above the markers.
    for row, (mode, color, _, summary) in enumerate(series):
        text = (
            "warm: one token reused, verify cache hit"
            if mode == "warm"
            else "cold: new token every call, signature checked"
        )
        ax.text(
            0.0,
            0.985 - 0.065 * row,
            f"{text} (mean {fmt_us(summary['mean_us'])})",
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=14,
            color=color,
            fontweight="bold",
        )
    ax.text(
        0.0,
        -0.17,
        f"Audit fsync replaced by a no-op: warm p50 {fmt_us(off['warm']['p50_us'])}, "
        f"p99 {fmt_us(off['warm']['p99_us'])}; cold p50 {fmt_us(off['cold']['p50_us'])}, "
        f"p99 {fmt_us(off['cold']['p99_us'])}.",
        transform=ax.transAxes,
        fontsize=13,
        color=style.MUTED,
    )

    # -- right: stage medians -----------------------------------------------
    bx = fig.add_axes((0.72, 0.2, 0.23, 0.6))
    stages = data["stages"]
    rules = data["method"].get("policy_rules", "?")
    rows = [
        (label.format(rules=rules), stages[key]["p50_us"], main)
        for key, label, main in STAGES
        if key in stages
    ]
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
        "A call verifies once (cold or warm), then rechecks.\n"
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
