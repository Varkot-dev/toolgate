"""README hero: one tool call allowed, one denied, both written to the audit log.

Drives a real Gateway in-process (fixed signing key, fixed clock, token ids
tok-1, tok-2, ..., the repo's config/policy.example.yaml, an audit log in a
throwaway directory) through two calls made with one sub-agent token:

  1. read_file on a path inside the grant: allowed, the tool runs
  2. delete_file, which the grant allows but operator policy denies

The real outcomes and audit entries go to results/m6_hero.json, and the
figure is drawn only from that record. Writes

    results/m6_hero.json
    assets/hero.gif          the animation, 1200 px wide (1.5x), loops
    assets/hero_poster.png   the final state at 2x, for places that do not animate

The figure is an HTML page on the shared design system in scripts/design/
(hero.html), posed frame by frame at fixed times and captured with headless
Chromium (see scripts/design/render.py). No CSS animation runs during capture,
so every frame is a pure function of its time.

Run from the repo root: .venv/bin/python scripts/fig_hero.py
"""

from __future__ import annotations

import hashlib
import itertools
import json
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from PIL import Image

import style
from caveat.approvals import ApprovalQueue
from caveat.audit import AuditLog, verify
from caveat.capability import Capability, Grant
from caveat.gateway import Gateway
from caveat.policy import Policy
from caveat.store import MemoryStore
from caveat.tokens import Authority
from design.render import Shot, render

# ---------------------------------------------------------------- the real run

POLICY_FILE = style.ROOT / "config" / "policy.example.yaml"
KEY_SEED = "caveat hero figure key, not a secret"
START = 1_794_873_600  # 2026-11-17 00:00:00 UTC
ISSUER = "https://gateway.example"
AUDIENCE = "caveat-demo"
ROOT_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 5},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
]
CHILD_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}, "max_calls": 3},
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
]
CALLS = [
    ("read_file", {"path": "reports/q3/summary.txt"}),
    ("delete_file", {"path": "reports/q3/summary.txt"}),
]


class Tools:
    """Stand-in tools that count how often they really ran."""

    def __init__(self) -> None:
        self.ran = {"read_file": 0, "delete_file": 0}

    def read_file(self, path: str) -> dict[str, Any]:
        self.ran["read_file"] += 1
        return {"path": path, "content": "Q3 revenue: up 4% on Q2."}

    def delete_file(self, path: str) -> dict[str, Any]:
        self.ran["delete_file"] += 1
        return {"deleted": path}


def run_gateway() -> dict[str, Any]:
    """Mint, exchange, make the two calls, and return everything that happened."""
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED.encode()).digest())
    token_ids = (f"tok-{n}" for n in itertools.count(1))
    approval_ids = (f"apr-{n}" for n in itertools.count(1))
    ticks = itertools.count(START * 1_000_000_000, 1_000_000)  # 1 ms per audit entry
    tools = Tools()
    with tempfile.TemporaryDirectory() as directory:
        audit_path = Path(directory) / "audit.jsonl"
        authority = Authority(
            key,
            ISSUER,
            AUDIENCE,
            MemoryStore(),
            clock=lambda: START,
            new_id=lambda: next(token_ids),
        )
        gateway = Gateway(
            authority,
            Policy.from_file(POLICY_FILE),
            AuditLog(audit_path, clock=lambda: next(ticks)),
            ApprovalQueue(new_id=lambda: next(approval_ids)),
            {"read_file": tools.read_file, "delete_file": tools.delete_file},
            clock=lambda: START,
        )
        grant = Grant(tuple(Capability.from_dict(c) for c in ROOT_CAPS), START + 600)
        root, _ = gateway.mint_token("user:alice", grant, "agent:orchestrator", 600)
        child, verified = gateway.exchange_token(root, CHILD_CAPS, "agent:researcher", 300)
        calls = []
        for tool, args in CALLS:
            outcome = gateway.handle_call(child, tool, args)
            calls.append(
                {
                    "tool": tool,
                    "args": args,
                    "status": outcome.status,
                    "stage": outcome.stage,
                    "reason": outcome.reason,
                    "rule": outcome.rule,
                    "code": outcome.code,
                    "audit_seq": outcome.audit_seq,
                }
            )
        head = gateway.audit.head()
        gateway.audit.close()
        offline = verify(audit_path, head.hash)
        entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
    return {
        "description": "Hero animation data: two real calls through the gateway with one token",
        "config": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "start_unix": START,
            "key_seed": KEY_SEED,
            "policy_file": str(POLICY_FILE.relative_to(style.ROOT)),
            "policy_sha256": hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest(),
            "root_capabilities": ROOT_CAPS,
        },
        "token": {
            "jti": verified.jti,
            "sub": verified.sub,
            "actors": list(verified.actors),
            "chain": list(verified.chain),
            "capabilities": CHILD_CAPS,
        },
        "calls": calls,
        "tool_executions": dict(tools.ran),
        "audit_log": entries,
        "audit_verify": {"ok": offline.ok, "entries": offline.entries, "head_hash": head.hash},
    }


# ---------------------------------------------------------------- the figure

FPS = 20
DURATION = 9.0  # seconds per loop
FINAL = 8.0  # a moment in the closing hold, used for the poster
GIF_SCALE = 1.5  # 1200 px wide
POSTER_SCALE = 2

# When each step happens, seconds into the loop. The page reads these.
TIMELINE: dict[str, Any] = {
    "calls": [
        {"start": 0.4, "arrive": 1.3, "verdict": 1.5, "onward": 1.95, "reach": 2.6, "log": 3.0},
        {"start": 3.8, "arrive": 4.7, "verdict": 4.9, "onward": None, "reach": None, "log": 5.5},
    ],
    "verified": 6.3,
    "fade": [8.45, 8.95],
    "poster": FINAL,
}


def short(actor: str) -> str:
    return actor.split(":", 1)[-1]


def view(data: dict[str, Any]) -> dict[str, Any]:
    """What the page shows, derived only from the recorded run."""
    token, calls, log = data["token"], data["calls"], data["audit_log"]
    entries = {e["seq"]: e for e in log}
    seqs = [c["audit_seq"] for c in calls]
    if None in seqs or seqs[1] != seqs[0] + 1 or sorted(entries) != list(range(seqs[1] + 1)):
        raise SystemExit(f"unexpected audit seqs {seqs}")
    if calls[0]["status"] != "allowed" or calls[1]["status"] != "denied":
        raise SystemExit(f"unexpected outcomes {calls}")
    granted = {c["tool"] for c in token["capabilities"]}
    if not {c["tool"] for c in calls} <= granted or calls[1]["stage"] != "policy":
        raise SystemExit("the run no longer shows a granted call denied by policy")
    if not data["audit_verify"]["ok"]:
        raise SystemExit("the audit chain did not verify")

    runs = data["tool_executions"]
    log_at = {c["audit_seq"]: t["log"] for c, t in zip(calls, TIMELINE["calls"], strict=True)}
    return {
        "title": "Every tool call is checked before it runs",
        "agent": short(token["actors"][0]),
        "calls": [
            {
                "tool": c["tool"],
                "ok": c["status"] == "allowed",
                "verdict": c["status"].capitalize(),
                "rule": c["rule"],
                "ran": runs[c["tool"]] > 0,
                "ran_text": {0: "never ran", 1: "ran once"}.get(runs[c["tool"]], "ran"),
            }
            for c in calls
        ],
        "audit": [
            {
                "seq": e["seq"],
                "tool": e["tool"],
                "kind": "token"
                if e["tool"].startswith("token:")
                else ("ok" if e["decision"] == "allow" else "no"),
                "hash": e["hash"][:6],
                "appears": log_at.get(e["seq"]),
            }
            for e in (entries[s] for s in sorted(entries))
        ],
        "timeline": TIMELINE,
    }


def write_gif(frames: list[Image.Image], target: Path) -> tuple[int, int]:
    """Quantize to one shared palette, merge repeated frames, save. Returns (unique, total)."""
    durations: list[int] = []
    unique: list[Image.Image] = []
    for frame in frames:
        if unique and frame.tobytes() == unique[-1].tobytes():
            durations[-1] += 1000 // FPS
        else:
            unique.append(frame)
            durations.append(1000 // FPS)
    w, h = unique[0].size
    picks = unique[:: max(1, len(unique) // 16)]  # sampled across the loop, so every color is in
    sheet = Image.new("RGB", (w, h * len(picks)))
    for i, im in enumerate(picks):
        sheet.paste(im, (0, h * i))
    # Max coverage keeps every hue close (small coral and green areas too), where
    # median cut spends the palette on the large soft background.
    palette = sheet.quantize(
        colors=256, method=Image.Quantize.MAXCOVERAGE, dither=Image.Dither.NONE
    )
    # Dither against the shared palette so soft gradients and shadows do not band,
    # then keep the previous frame's pixels wherever the source did not change, so
    # dither noise never spreads into still areas and each frame stores only what moved.
    indexed: list[Image.Image] = []
    prev_src: np.ndarray | None = None
    prev_idx: np.ndarray | None = None
    for im in unique:
        src = np.asarray(im)
        idx = np.asarray(im.quantize(palette=palette, dither=Image.Dither.FLOYDSTEINBERG)).copy()
        if prev_src is not None and prev_idx is not None:
            same = (src == prev_src).all(axis=2)
            idx[same] = prev_idx[same]
        frame = Image.fromarray(idx, mode="P")
        frame.putpalette(palette.getpalette())
        indexed.append(frame)
        prev_src, prev_idx = src, idx
    indexed[0].save(
        target,
        save_all=True,
        append_images=indexed[1:],
        duration=durations,
        loop=0,
        optimize=False,
        disposal=1,
    )
    return len(unique), len(frames)


def main() -> None:
    data = run_gateway()
    data["animation"] = {"fps": FPS, "loop_seconds": DURATION, "poster_at_seconds": FINAL}
    style.RESULTS.mkdir(exist_ok=True)
    out = style.RESULTS / "m6_hero.json"
    out.write_text(json.dumps(data, indent=2) + "\n")
    data = json.loads(out.read_text())  # draw only from what was recorded

    page = view(data)
    style.ASSETS.mkdir(exist_ok=True)
    poster = style.ASSETS / "hero_poster.png"
    with tempfile.TemporaryDirectory() as tmp:
        times = [i / FPS for i in range(round(DURATION * FPS))]
        shots = [Shot(str(poster), FINAL, POSTER_SCALE)] + [
            Shot(str(Path(tmp) / f"f{i:04d}.png"), t, GIF_SCALE, square=True)
            for i, t in enumerate(times)
        ]
        render("hero.html", page, shots)
        frames = [Image.open(s.path).convert("RGB") for s in shots[1:]]
    unique, total = write_gif(frames, style.ASSETS / "hero.gif")
    (style.ASSETS / "hero.svg").unlink(missing_ok=True)  # replaced by the GIF and poster

    for call in data["calls"]:
        print(f"{call['tool']:<12} {call['status']:<8} stage={call['stage']} rule={call['rule']}")
    for e in data["audit_log"]:
        print(f"  #{e['seq']} {e['decision']:<6} {e['tool']:<15} {e['rule']}  {e['hash'][:6]}")
    print(f"GIF: {unique} distinct frames of {total} at {FPS} fps")


if __name__ == "__main__":
    main()
