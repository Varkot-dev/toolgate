"""README hero: one tool call allowed, one denied, both written to the audit log.

Drives a real Gateway in-process (fixed signing key, fixed clock, token ids
tok-1, tok-2, ..., the repo's config/policy.example.yaml, an audit log in a
throwaway directory) through two calls made with one sub-agent token:

  1. read_file on a path inside the grant: allowed, the tool runs
  2. delete_file, which the grant allows but operator policy denies

The real outcomes and audit entries go to results/m6_hero.json, and the
animation is drawn only from that record. Writes

    assets/hero.svg          animated with CSS keyframes, no JavaScript
    assets/hero.gif          the same animation as frames, for places without SVG
    assets/hero_poster.png   the final frame, for places that do not animate
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
from matplotlib.axes import Axes
from matplotlib.figure import Figure
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
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
DURATION = 11.5  # seconds per loop
FINAL = 10.6  # a moment in the closing hold, used for the poster
W, H = 1200, 600  # pixels; the axes use pixel coordinates, origin bottom left
PT = 72 / style.DPI  # SVG user units (points) per pixel

ALLOW_TINT = "#e3efe1"
DENY_TINT = "#f8e3e2"
MONO_PX = 14 * style.DPI / 72 * 0.602  # width of one 14 pt DejaVu Sans Mono glyph


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


def fade(on: float, off: float = DURATION - 0.5, d: float = 0.25) -> list[tuple[float, float]]:
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
                f"transform:translate({dx * PT:.2f}px,{-dy * PT:.2f}px)}}"
            )
        return f"@keyframes {self.name}{{{''.join(rows)}}}"


class Scene:
    def __init__(self, ax: Axes) -> None:
        self.ax = ax
        self.tracks: list[Track] = []

    def track(self, name: str, opacity: list[tuple[float, float]], move: Any = None) -> Track:
        tr = Track(name, opacity) if move is None else Track(name, opacity, move)
        self.tracks.append(tr)
        return tr

    def add(self, artist: Artist, tr: Track | None) -> Artist:
        artist.set_clip_on(False)
        if tr is not None:
            artist.set_gid(f"{tr.name}-{len(tr.artists)}")
            tr.artists.append(artist)
        return artist

    def box(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fc: str = style.PANEL,
        ec: str = style.RULE,
        lw: float = 1.5,
        r: float = 8,
        tr: Track | None = None,
        z: float = 1,
        ls: str = "-",
    ) -> Artist:
        patch = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad=0,rounding_size={r}",
            facecolor=fc,
            edgecolor=ec,
            linewidth=lw,
            linestyle=ls,
            zorder=z,
        )
        return self.add(self.ax.add_patch(patch), tr)

    def text(
        self,
        x: float,
        y: float,
        s: str,
        size: float = 14,
        color: str = style.INK,
        bold: bool = False,
        mono: bool = False,
        ha: str = "left",
        tr: Track | None = None,
        z: float = 5,
    ) -> Artist:
        artist = self.ax.text(
            x,
            y,
            s,
            fontsize=size,
            color=color,
            fontweight="bold" if bold else "normal",
            family=style.MONO if mono else style.FONT,
            ha=ha,
            va="center",
            zorder=z,
        )
        return self.add(artist, tr)

    def arrow(
        self,
        a: tuple[float, float],
        b: tuple[float, float],
        color: str = style.MUTED,
        tr: Track | None = None,
    ) -> Artist:
        patch = FancyArrowPatch(
            a, b, arrowstyle="-|>", mutation_scale=16, color=color, linewidth=2, zorder=4
        )
        return self.add(self.ax.add_patch(patch), tr)

    def pose(self, t: float | None) -> None:
        """Put every track at time t; None shows everything at rest (for the SVG)."""
        for tr in self.tracks:
            alpha, dx, dy = (1.0, 0.0, 0.0) if t is None else tr.state(t)
            moved = Affine2D().translate(dx, dy) + self.ax.transData
            for artist in tr.artists:
                artist.set_alpha(None if t is None else alpha)
                artist.set_transform(moved)


# ---------------------------------------------------------------- formatting


def cap_text(cap: dict[str, Any]) -> str:
    """One capability in the notation of the other figures."""
    parts = []
    for arg, con in cap["args"].items():
        if "glob" in con:
            parts.append(f"{arg} ~ {con['glob']}")
        elif "eq" in con:
            parts.append(f"{arg} = {con['eq']}")
        elif "in" in con:
            parts.append(f"{arg} in {{{', '.join(map(str, con['in']))}}}")
        elif "max" in con:
            parts.append(f"{arg} <= {con['max']}")
        else:
            parts.append(f"{arg}: any")
    return f"{cap['tool']}({', '.join(parts)})"


def call_text(call: dict[str, Any]) -> str:
    args = ", ".join(f'{k} = "{v}"' for k, v in call["args"].items())
    return f"{call['tool']}({args})"


# ---------------------------------------------------------------- the drawing

# Layout, pixels.
LANE_Y = 285
AGENT = (20, 255, 417, 225)
GATE = (459, 255, 531, 225)
TOOLS = (1012, 255, 168, 225)
STAGE_W, STAGE_Y, STAGE_H = 165, 322, 115
STAGE_X = [469 + i * (STAGE_W + 8) for i in range(3)]
STAGE_CX = [x + STAGE_W / 2 for x in STAGE_X]
TOOL_BOX = {"read_file": (1020, 262, 152, 72), "delete_file": (1020, 350, 152, 72)}
CARD_X, CARD_W, CARD_Y, CARD_H = [20, 425, 830], 350, 58, 150
LINE_Y = [187, 161, 135, 109, 83]  # header, decision, rule, prev, hash
STAGES = [("verify", "token"), ("check grant", "and policy"), ("write audit", "entry")]
# Which pipeline box decided, by CallOutcome.stage.
STAGE_OF = {"token": 0, "call": 1, "grant": 1, "tool": 1, "policy": 1, "budget": 1}

# Timings, seconds: (stage reached, ...) per call.
CALL_T = [
    {"start": 0.5, "leave": 0.8, "stages": [1.5, 2.4, 3.3], "pause": 0.6, "tool": 4.4},
    {"start": 5.6, "leave": 5.9, "stages": [6.6, 7.5, 8.4], "pause": 0.6, "tool": None},
]
RESET = 5.2  # call 1's lights go out


def card(scene: Scene, x: float, entry: dict[str, Any], tr: Track | None) -> None:
    color = {"allow": style.ALLOW, "deny": style.DENY}.get(entry["decision"], style.INK)
    mark = {"allow": "✓ ", "deny": "× "}.get(entry["decision"], "")
    scene.box(x, CARD_Y, CARD_W, CARD_H, tr=tr, z=2)
    pad = x + 14
    scene.text(
        pad, LINE_Y[0], f"entry {entry['seq']}  {entry['tool']}", bold=True, mono=True, tr=tr
    )
    scene.text(pad, LINE_Y[1], mark + entry["decision"], color=color, bold=True, tr=tr)
    scene.text(pad, LINE_Y[2], entry["rule"], color=style.MUTED, mono=True, tr=tr)
    scene.text(pad, LINE_Y[3], f"prev {entry['prev'][:6]}", mono=True, tr=tr)
    scene.text(pad, LINE_Y[4], f"hash {entry['hash'][:6]}", mono=True, tr=tr)


def draw(data: dict[str, Any]) -> tuple[Figure, Scene]:
    style.apply()
    fig = plt.figure(figsize=(W / style.DPI, H / style.DPI))
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, W)
    ax.set_ylim(0, H)
    ax.axis("off")
    s = Scene(ax)

    token, calls, log = data["token"], data["calls"], data["audit_log"]
    entries = {e["seq"]: e for e in log}
    seqs = [c["audit_seq"] for c in calls]
    if None in seqs or seqs[1] != seqs[0] + 1 or seqs[0] - 1 not in entries:
        raise SystemExit(f"unexpected audit seqs {seqs}")
    denied_at = STAGE_OF[calls[1]["stage"]]
    if calls[0]["status"] != "allowed" or calls[1]["status"] != "denied" or denied_at != 1:
        raise SystemExit(f"unexpected outcomes {calls}")

    # Title and footers.
    s.text(20, 570, "Every tool call passes through the gateway", size=22, bold=True)
    s.text(
        20,
        22,
        f"One real run: a sub-agent token, {data['config']['policy_file']}, fixed clock.",
        color=style.MUTED,
    )
    s.text(W - 20, 22, "Data: results/m6_hero.json", color=style.MUTED, ha="right")

    # Agent, holding its token.
    x, y, w, h = AGENT
    s.box(x, y, w, h)
    s.text(x + 16, 456, token["actors"][0], size=16, bold=True)
    chain = " <- ".join([token["jti"], *reversed(token["chain"])])
    s.text(x + 16, 428, f"holds token {chain}", color=style.MUTED)
    s.box(x + 12, 322, w - 24, 84, fc=style.SURFACE, r=6, z=2)
    for k, cap in enumerate(token["capabilities"][:2]):
        s.text(x + 26, 385 - 27 * k, cap_text(cap), mono=True)

    # Gateway and its three stages.
    x, y, w, h = GATE
    s.box(x, y, w, h)
    s.text(x + 16, 456, "gateway", size=16, bold=True)
    for sx, (l1, l2) in zip(STAGE_X, STAGES, strict=True):
        s.box(sx, STAGE_Y, STAGE_W, STAGE_H, fc=style.SURFACE, z=2)
        s.text(sx + STAGE_W / 2, 421, l1, size=15, bold=True, ha="center", z=6)
        s.text(sx + STAGE_W / 2, 398, l2, size=15, bold=True, ha="center", z=6)
        s.ax.plot([sx + STAGE_W / 2] * 2, [LANE_Y + 16, STAGE_Y], color=style.RULE, lw=2, zorder=1)

    # Tools.
    x, y, w, h = TOOLS
    s.box(x, y, w, h)
    s.text(x + 14, 456, "tools", size=16, bold=True)
    for name, (bx, by, bw, bh) in TOOL_BOX.items():
        s.box(bx, by, bw, bh, fc=style.SURFACE, z=2)
        s.text(bx + bw / 2, by + bh - 20, name, mono=True, bold=True, ha="center", z=6)

    # The lane a call travels along.
    lane_x0 = AGENT[0] + AGENT[2] / 2
    read_box = TOOL_BOX["read_file"]
    lane_x1 = read_box[0] + read_box[2] / 2
    s.ax.plot([lane_x0, lane_x1], [LANE_Y, LANE_Y], color=style.RULE, lw=2, zorder=1)

    # Audit log strip; the entry before call 1 is already there.
    s.text(20, 228, "audit log", size=16, bold=True)
    s.text(140, 228, "each entry stores the hash of the one before it (prev)", color=style.MUTED)
    card(s, CARD_X[0], entries[seqs[0] - 1], None)

    for n, (call, tm) in enumerate(zip(calls, CALL_T, strict=True)):
        last = n == len(calls) - 1
        off = DURATION - 0.5 if last else RESET
        allowed = call["status"] == "allowed"
        entry = entries[call["audit_seq"]]

        # Caption: the call, then its outcome.
        cap = s.track(f"c{n}", fade(0.0 if n == 0 else tm["start"] - 0.2, off))
        s.text(20, 532, f"call {n + 1}   {call_text(call)}", size=15, mono=True, tr=cap)
        if allowed:
            ran = data["tool_executions"][call["tool"]]
            outcome = (
                f"✓ allowed by {call['rule']}: entry {entry['seq']} was written, "
                f"then {call['tool']} ran ({ran}x in this run)"
            )
            color = style.ALLOW
        else:
            outcome = f"× denied by {call['stage']} rule {call['rule']}: “{call['reason']}”"
            color = style.DENY
        when = (tm["tool"] + 0.3) if allowed else tm["stages"][2] + 0.3
        s.text(20, 504, outcome, size=15, color=color, tr=s.track(f"o{n}", fade(when, off)))

        # The packet: travels the lane, pausing under each stage it reaches.
        width = len(call["tool"]) * MONO_PX * 15 / 14 + 30
        stops = [(0.0, 0.0, 0.0), (tm["leave"], 0.0, 0.0)]
        reached = 3 if allowed else denied_at + 1
        for k in range(reached):
            t_at = tm["stages"][k] if allowed or k < denied_at else tm["stages"][k] - 0.6
            dx = STAGE_CX[k] - lane_x0
            stops += [(t_at, dx, 0.0), (t_at + tm["pause"], dx, 0.0)]
        if allowed:
            stops.append((tm["tool"], read_box[0] - 6 - width / 2 - lane_x0, 0.0))
            p_off = tm["tool"] - 0.15
        else:
            p_off = tm["stages"][denied_at] - 0.35
        pk = s.track(f"p{n}", fade(tm["start"], p_off, 0.2), path(stops))
        s.box(
            lane_x0 - width / 2,
            LANE_Y - 16,
            width,
            32,
            fc=style.SURFACE,
            ec=style.ACCENT,
            lw=2,
            r=16,
            tr=pk,
            z=8,
        )
        s.text(lane_x0, LANE_Y, call["tool"], size=15, mono=True, ha="center", tr=pk, z=9)
        if not allowed:
            # Stopped where it was refused; it never moves on to the tool.
            dead = s.track(f"x{n}", fade(p_off + 0.2, off, 0.2))
            cx = STAGE_CX[denied_at]
            s.box(
                cx - width / 2 - 14,
                LANE_Y - 16,
                width + 28,
                32,
                fc=DENY_TINT,
                ec=style.DENY,
                lw=2,
                r=16,
                tr=dead,
                z=8,
            )
            s.text(
                cx,
                LANE_Y,
                f"× {call['tool']}",
                size=15,
                mono=True,
                ha="center",
                color=style.INK,
                tr=dead,
                z=9,
            )

        # Stage lights and what each stage says.
        for k in range(3):
            if k > denied_at and not allowed and k != 2:
                continue
            t_on = tm["stages"][k]
            if not allowed and k == denied_at:
                t_on -= 0.35  # lights as the packet arrives (it does not pause first)
            bad = not allowed and k >= denied_at
            tint, edge, ink = (
                (DENY_TINT, style.DENY, style.DENY)
                if bad
                else (ALLOW_TINT, style.ALLOW, style.ALLOW)
            )
            lit = s.track(f"s{n}{k}", fade(t_on, off))
            cx = STAGE_CX[k]
            s.box(STAGE_X[k], STAGE_Y, STAGE_W, STAGE_H, fc=tint, ec=edge, lw=2.5, tr=lit, z=3)
            if k == 0:
                head, detail = "✓ verified", f"token {token['jti']}"
            elif k == 1:
                head = "✓ allow" if allowed else "× deny"
                detail = call["rule"] or call["reason"]
            else:
                head, detail = f"logged: {entry['decision']}", f"entry {entry['seq']}"
            s.text(cx, 365, head, color=ink, bold=True, ha="center", tr=lit, z=6)
            s.text(cx, 341, detail, ha="center", tr=lit, z=6)

        # The audit entry slides into the strip, chained to the one before.
        t_log = tm["stages"][2] + 0.15
        slide = path([(0.0, 0.0, -14.0), (t_log, 0.0, -14.0), (t_log + 0.35, 0.0, 0.0)], 6)
        cd = s.track(f"e{n}", fade(t_log, DURATION - 0.5), slide)
        card(s, CARD_X[n + 1], entry, cd)
        link = s.track(f"l{n}", fade(t_log + 0.45, DURATION - 0.5))
        s.arrow((CARD_X[n] + CARD_W, LINE_Y[4]), (CARD_X[n + 1], LINE_Y[3]), tr=link)

        # The tool: ran, or never reached.
        bx, by, bw, bh = TOOL_BOX[call["tool"]]
        ran = data["tool_executions"][call["tool"]]
        if allowed:
            lit = s.track(f"t{n}", fade(tm["tool"] - 0.1, off))
            s.box(bx, by, bw, bh, fc=ALLOW_TINT, ec=style.ALLOW, lw=2.5, tr=lit, z=3)
            s.text(
                bx + bw / 2,
                by + 20,
                f"✓ ran {ran}x",
                color=style.ALLOW,
                bold=True,
                ha="center",
                tr=lit,
                z=6,
            )
        else:
            never = s.track(f"t{n}", fade(tm["stages"][2] + 0.6, off))
            s.text(
                bx + bw / 2,
                by + 20,
                f"ran {ran}x",
                color=style.MUTED,
                bold=True,
                ha="center",
                tr=never,
                z=6,
            )
    return fig, s


# ---------------------------------------------------------------- output


def rgb(fig: Figure) -> Image.Image:
    fig.canvas.draw()
    return Image.fromarray(np.asarray(fig.canvas.buffer_rgba())).convert("RGB")


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
    picks = [unique[0], unique[len(unique) // 2], unique[-1]]
    sheet = Image.new("RGB", (W, H * len(picks)))
    for i, im in enumerate(picks):
        sheet.paste(im, (0, H * i))
    palette = sheet.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE)
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
    fig.savefig(buffer, format="svg", metadata={"Date": None, "Creator": None})
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

    fig, scene = draw(data)
    style.ASSETS.mkdir(exist_ok=True)
    frames = []
    for i in range(round(DURATION * FPS)):
        scene.pose(i / FPS)
        frames.append(rgb(fig))
    scene.pose(FINAL)
    rgb(fig).save(style.ASSETS / "hero_poster.png", optimize=False)
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
