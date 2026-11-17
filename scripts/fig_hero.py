"""README hero: one tool call allowed, one denied, both written to the audit log.

Drives a real Gateway in-process (fixed signing key, fixed clock, token ids
tok-1, tok-2, ..., the repo's config/policy.example.yaml, an audit log in a
throwaway directory) through two calls made with one sub-agent token:

  1. read_file on a path inside the grant: allowed, the tool runs
  2. delete_file, which the grant allows but operator policy denies

The real outcomes and audit entries go to results/m6_hero.json, and the
animation is drawn only from that record. Writes

    assets/hero.svg          animated with CSS keyframes, no JavaScript; with
                             prefers-reduced-motion it shows the final frame
    assets/hero.gif          the same animation as frames (1x), for places without SVG
    assets/hero_poster.png   the final frame at 2x, for places that do not animate

Drawn with the shared look in scripts/style.py.
    results/m6_hero.json

Run from the repo root: .venv/bin/python scripts/fig_hero.py
"""

from __future__ import annotations

import hashlib
import io
import itertools
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from matplotlib.artist import Artist
from matplotlib.figure import Figure
from matplotlib.transforms import Affine2D
from PIL import Image

import style
from toolgate.approvals import ApprovalQueue
from toolgate.audit import AuditLog, verify
from toolgate.capability import Capability, Grant
from toolgate.gateway import Gateway
from toolgate.policy import Policy
from toolgate.store import MemoryStore
from toolgate.tokens import Authority

# ---------------------------------------------------------------- the real run

POLICY_FILE = style.ROOT / "config" / "policy.example.yaml"
KEY_SEED = "toolgate hero figure key, not a secret"
START = 1_794_873_600  # 2026-11-17 00:00:00 UTC
ISSUER = "https://gateway.example"
AUDIENCE = "toolgate-demo"
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


# ---------------------------------------------------------------- animation model

FPS = 20
DURATION = 9.0  # seconds per loop
FINAL = 8.0  # a moment in the closing hold, used for the poster and reduced motion
W, H = 800, 400  # logical px; y points down
PT = style.PT  # SVG user units (points) per logical px


def ease(u: float) -> float:
    return u * u * (3 - 2 * u)


def interp(keys: list[tuple[float, ...]], t: float) -> tuple[float, ...]:
    """Piecewise-linear value of keyframes [(t, v1, v2, ...), ...] at time t."""
    if t <= keys[0][0]:
        return keys[0][1:]
    for (t0, *a), (t1, *b) in itertools.pairwise(keys):
        if t0 <= t <= t1:
            u = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
            return tuple(x + (y - x) * u for x, y in zip(a, b, strict=True))
    return keys[-1][1:]


def fade(on: float, off: float = DURATION - 0.6, d: float = 0.25) -> list[tuple[float, float]]:
    """Opacity keys: invisible, fade in at `on`, fade out at `off`."""
    return [(0.0, 0.0), (on, 0.0), (on + d, 1.0), (off, 1.0), (off + d, 0.0), (DURATION, 0.0)]


def path(stops: list[tuple[float, float, float]], steps: int = 8) -> list[tuple[float, ...]]:
    """Movement keys through (t, dx, dy) stops, eased between stops that move."""
    keys: list[tuple[float, ...]] = [(0.0, *stops[0][1:])]
    for (t0, x0, y0), (t1, x1, y1) in itertools.pairwise(stops):
        n = steps if (x0, y0) != (x1, y1) else 1
        for k in range(1, n + 1):
            u = ease(k / n)
            keys.append((t0 + (t1 - t0) * k / n, x0 + (x1 - x0) * u, y0 + (y1 - y0) * u))
    if keys[-1][0] < DURATION:
        keys.append((DURATION, *keys[-1][1:]))
    return keys


@dataclass
class Track:
    """A group of artists that fade and move together."""

    name: str
    opacity: list[tuple[float, float]]
    move: list[tuple[float, ...]] = field(default_factory=lambda: [(0.0, 0.0, 0.0)])
    artists: list[Artist] = field(default_factory=list)

    def state(self, t: float) -> tuple[float, float, float]:
        (alpha,) = interp(self.opacity, t)
        dx, dy = interp(self.move, t)
        return alpha, dx, dy

    def keyframes(self) -> str:
        times = sorted({k[0] for k in self.opacity} | {k[0] for k in self.move})
        rows = []
        for t in times:
            alpha, dx, dy = self.state(t)
            rows.append(
                f"{100 * t / DURATION:.3f}%{{opacity:{alpha:.3f};"
                f"transform:translate({dx * PT:.2f}px,{dy * PT:.2f}px)}}"
            )
        return f"@keyframes {self.name}{{{''.join(rows)}}}"


class Scene:
    """A style.Canvas whose artists can be grouped into animated tracks."""

    def __init__(self, canvas: style.Canvas) -> None:
        self.c = canvas
        self.tracks: list[Track] = []

    def track(self, name: str, opacity: list[tuple[float, float]], move: Any = None) -> Track:
        tr = Track(name, opacity) if move is None else Track(name, opacity, move)
        self.tracks.append(tr)
        return tr

    def grab(self, tr: Track, made: Any) -> Any:
        """Put every artist the canvas call `made` into track `tr`."""
        found = made[0] if isinstance(made, tuple) else made
        for artist in found if isinstance(found, list) else [found]:
            artist.set_gid(f"{tr.name}-{len(tr.artists)}")
            tr.artists.append(artist)
        return made

    def pose(self, t: float | None) -> None:
        """Put every track at time t; None shows everything at rest (for the SVG)."""
        for tr in self.tracks:
            alpha, dx, dy = (1.0, 0.0, 0.0) if t is None else tr.state(t)
            moved = Affine2D().translate(dx, dy) + self.c.ax.transData
            for artist in tr.artists:
                artist.set_alpha(None if t is None else alpha)
                artist.set_transform(moved)


# ---------------------------------------------------------------- the drawing

# Layout, logical px: three nodes on one row, two lanes through them, a log strip.
ROW_Y, ROW_H = 100, 168
AGENT = (32, 176)  # x, width
GATE = (296, 208)
TOOLS = (592, 176)
LANES = [180, 232]  # y of call 1 and call 2
HEAD_DY = 30
LOG_Y = 348  # center of the audit chips
LOG_LABEL_Y = 304
GAP = 28  # between audit chips

# Timings, seconds.
CALL_T = [
    {"start": 0.4, "gate": 1.4, "verdict": 1.6, "tool": 2.5, "log": 2.9},
    {"start": 3.9, "gate": 4.9, "verdict": 5.1, "tool": None, "log": 5.6},
]


def short(actor: str) -> str:
    return actor.split(":", 1)[-1]


def draw(data: dict[str, Any]) -> Scene:
    token, calls, log = data["token"], data["calls"], data["audit_log"]
    entries = {e["seq"]: e for e in log}
    seqs = [c["audit_seq"] for c in calls]
    if None in seqs or seqs[1] != seqs[0] + 1 or sorted(entries) != list(range(seqs[1] + 1)):
        raise SystemExit(f"unexpected audit seqs {seqs}")
    if calls[0]["status"] != "allowed" or calls[1]["status"] != "denied":
        raise SystemExit(f"unexpected outcomes {calls}")

    c = style.Canvas(W, H)
    s = Scene(c)
    c.title("Every tool call is checked before it runs")

    # The three parties.
    for (x, w), name, sub in [
        (AGENT, "agent", short(token["actors"][0])),
        (GATE, "gateway", ""),
        (TOOLS, "tools", ""),
    ]:
        c.box(x, ROW_Y, w, ROW_H)
        c.text(x + 16, ROW_Y + HEAD_DY, name, size=style.LABEL, weight=style.STRONG)
        if sub:
            c.text(x + w - 16, ROW_Y + HEAD_DY, sub, size=style.SMALL, color=style.GRAY, ha="right")

    agent_right, gate_left = AGENT[0] + AGENT[1], GATE[0]
    gate_right, tools_left = GATE[0] + GATE[1], TOOLS[0]
    tool_x: dict[str, float] = {}
    for call, y in zip(calls, LANES, strict=True):
        c.chip(AGENT[0] + 16, y, call["tool"], tone="plain", code=True)  # what the agent asks
        _, w = c.chip(TOOLS[0] + 16, y, call["tool"], tone="plain", code=True)
        tool_x[call["tool"]] = TOOLS[0] + 16

    # The audit strip: the entries before the calls are already there.
    c.text(
        32,
        LOG_LABEL_Y,
        "hash-chained audit log",
        size=style.SMALL,
        color=style.GRAY,
        weight=style.STRONG,
    )
    log_x: dict[int, tuple[float, float]] = {}
    x = 32.0
    for seq in sorted(entries):
        entry = entries[seq]
        mark = None
        if not entry["tool"].startswith("token:"):
            mark = "good" if entry["decision"] == "allow" else "bad"
        w = style.text_width(entry["tool"], style.SMALL, code=True) + 24 + (18 if mark else 0)
        log_x[seq] = (x, w)
        x += w + GAP

    def log_chip(seq: int, tr: Track | None) -> None:
        entry = entries[seq]
        lx, _ = log_x[seq]
        mark = None
        tone = "neutral"
        if not entry["tool"].startswith("token:"):
            mark = "good" if entry["decision"] == "allow" else "bad"
            tone = mark
        made = c.chip(lx, LOG_Y, entry["tool"], tone=tone, code=True, size=style.SMALL, mark=mark)
        if tr is not None:
            s.grab(tr, made)
        if seq > 0:
            px, pw = log_x[seq - 1]
            link = c.arrow((px + pw + 4, LOG_Y), (lx - 4, LOG_Y), lw=1.5)
            if tr is not None:
                s.grab(tr, link)

    for seq in sorted(entries):
        if seq < seqs[0]:
            log_chip(seq, None)

    for n, (call, y, tm) in enumerate(zip(calls, LANES, CALL_T, strict=True)):
        allowed = call["status"] == "allowed"
        tone = "good" if allowed else "bad"

        # The call in motion: from the agent's chip to the gateway's edge.
        pill_w = style.text_width(call["tool"], code=True) + 24
        to_gate = gate_left - 6 - pill_w - (AGENT[0] + 16)
        trip = path([(0.0, 0, 0), (tm["start"], 0, 0), (tm["gate"], to_gate, 0)])
        pill = s.track(f"p{n}", fade(tm["start"], tm["gate"] - 0.1, 0.15), trip)
        s.grab(pill, c.chip(AGENT[0] + 16, y, call["tool"], tone="highlight", code=True, z=8))

        # The verdict: the path up to the gateway, a mark, the reason.
        seg = s.track(f"a{n}", fade(tm["gate"] - 0.25))
        s.grab(
            seg, c.arrow((agent_right + 6, y), (gate_left - 6, y), tone=tone, dashed=not allowed)
        )
        verdict = s.track(f"v{n}", fade(tm["verdict"]))
        s.grab(verdict, c.badge(gate_left + 30, y, tone))
        words = f"{call['status']} by {call['stage']}"
        s.grab(
            verdict,
            c.text(
                gate_left + 52,
                y,
                words,
                color=style.GOOD if allowed else style.BAD,
                weight=style.STRONG,
            ),
        )

        if allowed:
            # On to the tool, which runs.
            out = s.track(f"o{n}", fade(tm["verdict"] + 0.3))
            s.grab(out, c.arrow((gate_right + 6, y), (tools_left - 6, y), tone="good"))
            leg = gate_right + 6 - (AGENT[0] + 16)
            trip = path(
                [
                    (0.0, leg, 0),
                    (tm["verdict"] + 0.3, leg, 0),
                    (tm["tool"], tool_x[call["tool"]] - AGENT[0] - 16, 0),
                ]
            )
            pill = s.track(f"q{n}", fade(tm["verdict"] + 0.3, tm["tool"], 0.15), trip)
            s.grab(pill, c.chip(AGENT[0] + 16, y, call["tool"], tone="highlight", code=True, z=8))
            ran = s.track(f"t{n}", fade(tm["tool"]))
            s.grab(
                ran,
                c.chip(
                    tool_x[call["tool"]], y, call["tool"], tone="good", code=True, mark="good", z=6
                ),
            )

        # Written to the log, chained to the entry before.
        slide = path([(0.0, 0, 10), (tm["log"], 0, 10), (tm["log"] + 0.35, 0, 0)], 6)
        log_chip(call["audit_seq"], s.track(f"e{n}", fade(tm["log"]), slide))
    return s


# ---------------------------------------------------------------- output


def rgba(fig: Figure, dpi: float) -> Image.Image:
    fig.set_dpi(dpi)
    fig.canvas.draw()
    return Image.fromarray(np.asarray(fig.canvas.buffer_rgba())).copy()


def on_white(im: Image.Image) -> Image.Image:
    base = Image.new("RGBA", im.size, style.CARD)
    base.alpha_composite(im)
    return base.convert("RGB")


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
    palette = sheet.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
    indexed = [im.quantize(palette=palette, dither=Image.Dither.NONE) for im in unique]
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


def write_svg(fig: Figure, scene: Scene, target: Path) -> None:
    scene.pose(None)
    buffer = io.StringIO()
    fig.savefig(buffer, format="svg", metadata={"Date": None, "Creator": None}, transparent=True)
    svg = buffer.getvalue()
    css = [
        "<style>",
        *(tr.keyframes() for tr in scene.tracks),
        *(
            ",".join(f"#{a.get_gid()}" for a in tr.artists)
            + f"{{animation:{tr.name} {DURATION}s linear infinite both}}"
            for tr in scene.tracks
        ),
        "@media (prefers-reduced-motion: reduce){*{animation-play-state:paused !important;"
        f"animation-delay:-{FINAL}s !important}}}}",
        "</style>",
    ]
    marker = "<defs>"
    if marker not in svg:
        raise SystemExit("unexpected SVG layout from matplotlib")
    svg = svg.replace(marker, "\n".join(css) + "\n" + marker, 1)
    target.write_text(svg)


def main() -> None:
    data = run_gateway()
    data["animation"] = {"fps": FPS, "loop_seconds": DURATION, "poster_at_seconds": FINAL}
    style.RESULTS.mkdir(exist_ok=True)
    out = style.RESULTS / "m6_hero.json"
    out.write_text(json.dumps(data, indent=2) + "\n")
    data = json.loads(out.read_text())  # draw only from what was recorded

    scene = draw(data)
    fig = scene.c.fig
    style.ASSETS.mkdir(exist_ok=True)
    frames = []
    for i in range(round(DURATION * FPS)):
        scene.pose(i / FPS)
        frames.append(on_white(rgba(fig, style.PX_PER_INCH)))
    scene.pose(FINAL)
    rgba(fig, style.PX_PER_INCH * style.SCALE).save(
        style.ASSETS / "hero_poster.png", optimize=False
    )
    fig.set_dpi(style.PX_PER_INCH)
    unique, total = write_gif(frames, style.ASSETS / "hero.gif")
    write_svg(fig, scene, style.ASSETS / "hero.svg")
    plt.close(fig)

    for call in data["calls"]:
        print(f"{call['tool']:<12} {call['status']:<8} stage={call['stage']} rule={call['rule']}")
    for e in data["audit_log"]:
        print(f"  #{e['seq']} {e['decision']:<6} {e['tool']:<15} {e['rule']}  {e['hash'][:6]}")
    print(f"GIF: {unique} distinct frames of {total} at {FPS} fps")


if __name__ == "__main__":
    main()
