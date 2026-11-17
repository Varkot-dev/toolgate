"""Audit chain figure for M2: edit one entry and verification fails at that entry.

Builds a real 8-entry log through toolgate.audit.AuditLog with a fixed clock,
copies it, changes one field of entry 3 in the copy (leaving its stored hash
alone), runs the real verify on both files, and writes

    assets/audit_tamper.png
    assets/audit_tamper.svg
    results/m2_audit_tamper.json

Run from the repo root: .venv/bin/python scripts/fig_audit_tamper.py
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from itertools import count
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import FancyBboxPatch

import style
from toolgate.audit import AuditLog, VerifyResult, canonical_json, verify

T0_NS = 1_800_000_000 * 10**9  # fixed start time, one entry per second after it
EDIT_INDEX, EDIT_FIELD, EDIT_VALUE = 3, "decision", "rejected"
CALLS = [  # tool, arguments (hashed, never stored), decision, rule, approver
    ("read_file", {"path": "reports/q3.txt"}, "allow", "allow-file-reads", None),
    ("read_email", {"id": "m-17"}, "allow", "allow-email-read", None),
    (
        "send_email",
        {"to": "kim@partner.org", "body": "Q3 summary"},
        "approve",
        "approve-external-email",
        None,
    ),
    (
        "send_email",
        {"to": "kim@partner.org", "body": "Q3 summary"},
        "approved",
        "approve-external-email",
        "ana",
    ),
    ("get_event", {"id": "e-4"}, "allow", "allow-calendar-read", None),
    (
        "write_file",
        {"path": "reports/q3.txt", "content": "v2"},
        "approve",
        "approve-writes-outside-drafts",
        None,
    ),
    (
        "write_file",
        {"path": "reports/q3.txt", "content": "v2"},
        "rejected",
        "approve-writes-outside-drafts",
        "ben",
    ),
    ("read_file", {"path": "drafts/notes.md"}, "allow", "allow-file-reads", None),
]

SHORT = 5  # hex characters of each hash shown in a block
BLOCK_W, BLOCK_H, GAP, LEFT = 164, 178, 30, 39
PAD, LINE = 12, 30


def build_log(path: Path) -> str:
    ticks = count(T0_NS, 10**9)
    with AuditLog(path, clock=lambda: next(ticks)) as log:
        for tool, args, decision, rule, approver in CALLS:
            log.append(
                jti="tok-7f3a",
                actors=["orchestrator", "mailer"],
                tool=tool,
                args=args,
                decision=decision,
                rule=rule,
                approver=approver,
            )
        return log.head().hash


def read_entries(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def tamper(source: Path, target: Path) -> dict:
    """Copy the log, changing one field of one entry and nothing else."""
    lines = source.read_bytes().splitlines(keepends=True)
    entry = json.loads(lines[EDIT_INDEX])
    before = entry[EDIT_FIELD]
    entry[EDIT_FIELD] = EDIT_VALUE
    lines[EDIT_INDEX] = canonical_json(entry) + b"\n"
    target.write_bytes(b"".join(lines))
    return {"index": EDIT_INDEX, "field": EDIT_FIELD, "before": before, "after": EDIT_VALUE}


def block_left(i: int) -> float:
    return LEFT + i * (BLOCK_W + GAP)


def draw_block(ax: Axes, entry: dict, top: float, state: str, edited_field: str | None) -> None:
    """state: ok (verified), bad (the first bad entry) or after (not verified)."""
    left = block_left(entry["seq"])
    edge = {"ok": style.ALLOW, "bad": style.DENY, "after": style.RULE}[state]
    ink = style.MUTED if state == "after" else style.INK
    ax.add_patch(
        FancyBboxPatch(
            (left, top),
            BLOCK_W,
            BLOCK_H,
            boxstyle="round,pad=0,rounding_size=10",
            facecolor=style.SURFACE if state == "after" else style.PANEL,
            edgecolor=edge,
            linewidth=3.5 if state == "bad" else 2,
            linestyle=(0, (4, 3)) if state == "after" else "solid",
        )
    )
    y = top + PAD + 14
    ax.text(
        left + PAD,
        y,
        f"entry {entry['seq']}",
        fontsize=16,
        fontweight="bold",
        color=ink,
        va="center",
    )
    rows = [
        ("tool", entry["tool"]),
        ("decision", entry["decision"]),
        ("prev", "prev " + entry["prev"][:SHORT]),
        ("hash", "hash " + entry["hash"][:SHORT]),
    ]
    y += 8
    for name, text in rows:
        y += LINE
        changed = state == "bad" and name == edited_field
        if changed:
            ax.add_patch(
                FancyBboxPatch(
                    (left + 5, y - 13),
                    BLOCK_W - 10,
                    26,
                    boxstyle="round,pad=0,rounding_size=5",
                    facecolor=style.SURFACE,
                    edgecolor=style.DENY,
                    linewidth=1.5,
                )
            )
        ax.text(
            left + PAD,
            y,
            text,
            fontsize=16,
            family=style.MONO,
            fontweight="bold" if changed else "normal",
            color=style.DENY if changed else ink,
            va="center",
        )


def draw_link(ax: Axes, i: int, top: float, color: str, dashed: bool) -> None:
    """Arrow from entry i's hash row to entry i+1's prev row: that hash is the next prev."""
    y_hash = top + PAD + 22 + 4 * LINE
    y_prev = y_hash - LINE
    ax.annotate(
        "",
        xy=(block_left(i + 1) - 3, y_prev),
        xytext=(block_left(i) + BLOCK_W + 3, y_hash),
        arrowprops={
            "arrowstyle": "-|>",
            "color": color,
            "linewidth": 2,
            "linestyle": (0, (4, 3)) if dashed else "solid",
            "mutation_scale": 14,
            "shrinkA": 0,
            "shrinkB": 0,
        },
    )


def draw_row(
    ax: Axes, entries: list[dict], top: float, result: VerifyResult, edited_field: str | None
) -> None:
    bad = result.first_bad_index
    for entry in entries:
        i = entry["seq"]
        state = "ok" if bad is None or i < bad else ("bad" if i == bad else "after")
        if i + 1 < len(entries):
            trusted = bad is None or i + 1 <= bad
            draw_link(ax, i, top, style.ALLOW if trusted else style.MUTED, dashed=not trusted)
        draw_block(ax, entry, top, state, edited_field)


def span_label(ax: Axes, first: int, last: int, y: float, text: str, color: str) -> None:
    x0, x1 = block_left(first), block_left(last) + BLOCK_W
    ax.plot([x0, x0, x1, x1], [y - 8, y, y, y - 8], color=color, linewidth=2)
    ax.text(
        (x0 + x1) / 2,
        y + 24,
        text,
        fontsize=16,
        fontweight="bold",
        color=color,
        ha="center",
        va="center",
    )


def main() -> None:
    # 1. Build the real log, tamper with a copy, and ask the real verifier about both.
    with tempfile.TemporaryDirectory() as tmp:
        intact_path, edited_path = Path(tmp) / "audit.jsonl", Path(tmp) / "audit.edited.jsonl"
        head = build_log(intact_path)
        edit = tamper(intact_path, edited_path)
        intact, edited = read_entries(intact_path), read_entries(edited_path)
        ok = verify(intact_path, head)
        broken = verify(edited_path)
        broken_with_head = verify(edited_path, head)
    assert ok.ok and ok.entries == len(CALLS)
    assert not broken.ok and broken.first_bad_index == EDIT_INDEX
    assert not broken_with_head.ok

    # 2. Save the data behind the figure.
    record = {
        "clock_start_ns": T0_NS,
        "head": head,
        "edit": edit,
        "verify_intact": asdict(ok),
        "verify_edited": asdict(broken),
        "intact_entries": intact,
        "edited_entries": edited,
    }
    style.RESULTS.mkdir(exist_ok=True)
    out = style.RESULTS / "m2_audit_tamper.json"
    out.write_text(json.dumps(record, indent=2) + "\n")

    # 3. Draw. One axes in pixel units, y pointing down.
    style.apply()
    fig = plt.figure(figsize=style.SIZE)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1600)
    ax.set_ylim(900, 0)
    ax.axis("off")

    ax.text(
        40, 50, "Edit one entry and the chain breaks at that entry", fontsize=26, fontweight="bold"
    )
    ax.text(
        40,
        90,
        "A real 8-entry audit log. Each entry stores the hash of the one before it (prev) "
        "and a hash of its own content.",
        fontsize=16,
        color=style.MUTED,
    )

    top_a, top_b = 180, 482
    ax.text(40, top_a - 28, "The log as written", fontsize=18, fontweight="bold", va="center")
    ax.text(
        1560,
        top_a - 28,
        f"✓ verify: ok, {ok.entries} entries",
        fontsize=18,
        fontweight="bold",
        color=style.ALLOW,
        ha="right",
        va="center",
    )
    draw_row(ax, intact, top_a, ok, None)

    ax.text(
        40,
        top_b - 28,
        f"A copy with one field changed: entry {edit['index']} {edit['field']} "
        f'"{edit["before"]}" → "{edit["after"]}"',
        fontsize=18,
        fontweight="bold",
        va="center",
    )
    ax.text(
        1560,
        top_b - 28,
        f"✕ verify: failed at entry {broken.first_bad_index}",
        fontsize=18,
        fontweight="bold",
        color=style.DENY,
        ha="right",
        va="center",
    )
    draw_row(ax, edited, top_b, broken, edit["field"])

    y = top_b + BLOCK_H + 22
    bad = broken.first_bad_index
    span_label(ax, 0, bad - 1, y, "✓ verified", style.ALLOW)
    span_label(ax, bad, bad, y, "✕ first bad entry", style.DENY)
    span_label(
        ax, bad + 1, len(edited) - 1, y, "not verified: checking stops at the break", style.MUTED
    )

    ax.text(40, 778, "The verifier says:", fontsize=16, color=style.MUTED, va="center")
    ax.text(
        40,
        812,
        f"entry {broken.first_bad_index}: {broken.problem}",
        fontsize=17,
        color=style.DENY,
        va="center",
    )
    ax.text(
        40,
        868,
        "Limit: without a trusted copy of the last hash, someone who can rewrite the whole file "
        "can rebuild every hash after an edit.   Data: results/m2_audit_tamper.json",
        fontsize=13.5,
        color=style.MUTED,
        va="center",
    )

    png, svg = style.save(fig, "audit_tamper")
    for path in (png, svg, out):
        print(path.relative_to(style.ROOT))
    print(f"edited log: entry {broken.first_bad_index}: {broken.problem}")


if __name__ == "__main__":
    main()
