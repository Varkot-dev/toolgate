"""Audit chain figure for M2: edit one entry and verification fails at that entry.

Builds a real 8-entry log through caveat.audit.AuditLog with a fixed clock,
copies it, changes one field of entry 3 in the copy (leaving its stored hash
alone), runs the real verify on both files, and writes

    results/m2_audit_tamper.json
    assets/audit_tamper.png    2x, drawn from scripts/design/audit_tamper.html

The figure is an HTML page on the shared design system in scripts/design/,
captured with headless Chromium (see scripts/design/render.py), and drawn
only from the record above.

Run from the repo root: .venv/bin/python scripts/fig_audit_tamper.py
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict
from itertools import count
from pathlib import Path

import style
from design.render import Shot, render
from caveat.audit import AuditLog, canonical_json, verify

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

SHORT = 5  # hex characters of each hash shown on an entry


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


def entry_view(entry: dict, state: str) -> dict:
    """state: ok (verified), bad (the first bad entry) or after (not reached)."""
    return {
        "seq": entry["seq"],
        "tool": entry["tool"],
        "decision": entry["decision"],
        "hash": entry["hash"][:SHORT],
        "state": state,
        "focus": entry["seq"] == EDIT_INDEX,  # drawn with its edited field on its own line
    }


def row_view(entries: list[dict], bad: int | None) -> list[dict]:
    def state(i: int) -> str:
        if bad is None or i < bad:
            return "ok"
        return "bad" if i == bad else "after"

    return [entry_view(e, state(e["seq"])) for e in entries]


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

    # 3. Draw, only from the record: the real entries and the real verify results.
    assert edit["field"] == "decision", "the page shows the edit in the decision pill"
    bad = broken.first_bad_index
    view = {
        "title": "Change one entry and the chain breaks there",
        "field": edit["field"],
        "logs": [
            {
                "name": "Original",
                "ok": ok.ok,
                "badge": "chain verifies",
                "entries": row_view(intact, None),
            },
            {
                "name": "Edited copy",
                "ok": broken.ok,
                "badge": f"fails at entry {bad}",
                "entries": row_view(edited, bad),
                "edit": edit,
            },
        ],
    }
    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "audit_tamper.png"
    render("audit_tamper.html", view, [Shot(str(png), scale=2)])
    for path in (png, out):
        print(path.relative_to(style.ROOT))
    print(f"edited log: entry {broken.first_bad_index}: {broken.problem}")


if __name__ == "__main__":
    main()
