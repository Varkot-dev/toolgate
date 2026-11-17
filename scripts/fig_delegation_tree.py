"""Delegation tree figure for M0: authority only shrinks down the chain.

Builds four grants with the real library, validates every edge with
toolgate.check_attenuation, adds one request the checker rejects, and writes

    assets/delegation_tree.png
    assets/delegation_tree.svg
    results/m0_delegation_tree.json

Run from the repo root: .venv/bin/python scripts/fig_delegation_tree.py
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import FancyBboxPatch

import style
from toolgate import Capability, Constraint, Grant, check_attenuation

T0 = 1_800_000_000  # fixed "now" in epoch seconds, so the output never changes
ADDRESSES = ("ana@x.com", "ben@x.com", "cy@x.com")


def grant(minutes: int, *caps: dict) -> Grant:
    return Grant(tuple(Capability.from_dict(c) for c in caps), T0 + 60 * minutes)


ANY = {"any": True}
GRANTS: dict[str, Grant] = {
    "user": grant(
        60,
        {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}},
        {
            "tool": "send_email",
            "args": {"to": {"in": list(ADDRESSES)}, "subject": ANY, "body": ANY},
            "max_calls": 5,
        },
        {"tool": "search_calendar", "args": {"days": {"max": 30}, "query": ANY}},
    ),
    "orchestrator": grant(
        30,
        {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}},
        {
            "tool": "send_email",
            "args": {"to": {"in": list(ADDRESSES[:2])}, "subject": ANY, "body": ANY},
            "max_calls": 3,
        },
        {"tool": "search_calendar", "args": {"days": {"max": 7}, "query": ANY}},
    ),
    "research": grant(10, {"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}}),
    "mailer": grant(
        5,
        {
            "tool": "send_email",
            "args": {"to": {"eq": ADDRESSES[0]}, "subject": ANY, "body": ANY},
            "max_calls": 1,
        },
    ),
}
# The one request that asks for more than its parent holds.
REJECTED = grant(10, {"tool": "read_file", "args": {"path": {"glob": "*"}}})
EDGES = [("user", "orchestrator"), ("orchestrator", "research"), ("orchestrator", "mailer")]
REJECTED_EDGE = ("orchestrator", "research (wider request)")


def format_constraint(c: Constraint) -> str:
    if c.op == "eq":
        return f"{c.arg} = {c.value}"
    if c.op == "in":
        return f"{c.arg} in {{{', '.join(str(v) for v in c.value)}}}"
    if c.op == "max":
        return f"{c.arg} <= {c.value}"
    if c.op == "glob":
        return f"{c.arg} ~ {c.value}"
    return f"{c.arg}: any"


def format_capability(cap: Capability, width: int) -> list[str]:
    """`tool(arg ~ pattern, arg: any) xN`, wrapped at argument boundaries to `width` chars."""
    budget = f" x{cap.max_calls}" if cap.max_calls is not None else ""
    parts = [format_constraint(c) for c in cap.constraints]
    parts = [p + "," for p in parts[:-1]] + [(parts[-1] if parts else "") + ")" + budget]
    lines, current = [], cap.tool + "("
    for i, part in enumerate(parts):
        candidate = current + ("" if i == 0 else " ") + part
        if len(candidate) > width and i > 0:
            lines.append(current)
            candidate = "    " + part
        current = candidate
    return [*lines, current]


@dataclass
class Node:
    title: str
    grant: Grant
    cx: float
    top: float
    width: float
    height: float = 0.0
    lines: tuple[str, ...] = ()
    note: tuple[str, ...] = ()  # the checker's reason, on the rejected node only

    @property
    def bottom(self) -> float:
        return self.top + self.height


CHAR_W = 0.602 * 14 * style.DPI / 72  # advance of one 14 pt DejaVu Sans Mono glyph, in px
PAD, HEAD, LINE, NOTE_LINE = 22, 40, 29, 24


def layout(node: Node) -> Node:
    chars = int((node.width - 2 * PAD) / CHAR_W)
    lines = [ln for cap in node.grant.capabilities for ln in format_capability(cap, chars)]
    node.lines = tuple(lines)
    node.height = PAD + HEAD + LINE * len(lines) + PAD - 8
    if node.note:
        node.height += 14 + NOTE_LINE * (len(node.note) + 1)
    return node


def draw_node(ax: Axes, node: Node, rejected: bool = False) -> None:
    left = node.cx - node.width / 2
    ax.add_patch(
        FancyBboxPatch(
            (left, node.top),
            node.width,
            node.height,
            boxstyle="round,pad=0,rounding_size=12",
            facecolor=style.SURFACE if rejected else style.PANEL,
            edgecolor=style.DENY if rejected else style.RULE,
            linewidth=2 if rejected else 1.2,
            linestyle=(0, (5, 4)) if rejected else "solid",
        )
    )
    minutes = round((node.grant.expires_at - T0) / 60)
    y = node.top + PAD + 10
    ax.text(left + PAD, y, node.title, fontsize=16, fontweight="bold", va="center")
    ax.text(
        left + node.width - PAD,
        y,
        f"expires in {minutes} min",
        fontsize=13,
        color=style.MUTED,
        ha="right",
        va="center",
    )
    y = node.top + PAD + HEAD + LINE / 2 - 4
    for line in node.lines:
        ax.text(left + PAD, y, line, fontsize=14, family=style.MONO, va="center")
        y += LINE
    if node.note:
        y += 14
        ax.text(left + PAD, y, "checker says:", fontsize=13, color=style.MUTED, va="center")
        for line in node.note:
            y += NOTE_LINE
            ax.text(left + PAD, y, line, fontsize=13, color=style.DENY, va="center")


def draw_edge(ax: Axes, parent: Node, child: Node, ok: bool) -> None:
    """Elbow connector: leave the parent's bottom edge, jog sideways, drop onto the child."""
    color = style.ALLOW if ok else style.DENY
    dash = "solid" if ok else (0, (5, 4))
    x1, y0, y1 = child.cx, parent.bottom + 3, child.top - 3
    half = parent.width / 2 - 120
    x0 = min(max(x1, parent.cx - half), parent.cx + half)
    mid = (y0 + y1) / 2
    ax.plot([x0, x0, x1, x1], [y0, mid, mid, mid + 6], color=color, linewidth=2, linestyle=dash)
    ax.annotate(
        "",
        xy=(x1, y1),
        xytext=(x1, mid + 4),
        arrowprops={
            "arrowstyle": "-|>",
            "color": color,
            "linewidth": 2,
            "linestyle": dash,
            "mutation_scale": 18,
            "shrinkA": 0,
            "shrinkB": 0,
        },
    )
    ax.text(
        x1 + 14,
        mid + (y1 - mid) / 2,
        "\u2713 narrower: accepted" if ok else "\u2715 wider: rejected",
        fontsize=13,
        fontweight="bold",
        color=color,
        va="center",
    )


def main() -> None:
    # 1. Ask the real checker about every edge.
    results = {edge: check_attenuation(GRANTS[edge[0]], GRANTS[edge[1]]) for edge in EDGES}
    for edge, result in results.items():
        assert result.ok, f"{edge} should be a valid attenuation: {result.reason}"
    denied = check_attenuation(GRANTS[REJECTED_EDGE[0]], REJECTED)
    assert not denied.ok, "the wider request must be rejected"

    # 2. Save the data behind the figure.
    def edge_record(parent: str, child: str, result: object) -> dict:
        return {
            "parent": parent,
            "child": child,
            "ok": result.ok,
            "reason": result.reason,
            "derivation": list(result.derivation),
        }

    record = {
        "now": T0,
        "grants": {name: g.to_dict() for name, g in GRANTS.items()},
        "rejected_request": {"name": REJECTED_EDGE[1], "grant": REJECTED.to_dict()},
        "edges": [edge_record(p, c, r) for (p, c), r in results.items()]
        + [edge_record(*REJECTED_EDGE, denied)],
    }
    style.RESULTS.mkdir(exist_ok=True)
    out = style.RESULTS / "m0_delegation_tree.json"
    out.write_text(json.dumps(record, indent=2) + "\n")

    # 3. Draw. One axes in pixel units, y pointing down.
    style.apply()
    fig = plt.figure(figsize=style.SIZE)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1600)
    ax.set_ylim(900, 0)
    ax.axis("off")

    ax.text(
        40, 50, "Authority only shrinks down the delegation chain", fontsize=26, fontweight="bold"
    )
    ax.text(
        40,
        88,
        "Every arrow is a real check_attenuation(parent, child) call: "
        "a child grant may allow nothing its parent does not, and must expire no later.",
        fontsize=14,
        color=style.MUTED,
    )

    gap, leaf_w = 78, 490
    user = layout(Node("user grant", GRANTS["user"], 800, 122, 1010))
    orch = layout(Node("orchestrator", GRANTS["orchestrator"], 800, user.bottom + gap, 1010))
    leaf_top = orch.bottom + gap + 12
    research = layout(Node("research agent", GRANTS["research"], 285, leaf_top, leaf_w))
    mailer = layout(Node("mailer agent", GRANTS["mailer"], 800, leaf_top, leaf_w))
    wider = layout(
        Node(
            "research, 2nd ask",
            REJECTED,
            1315,
            leaf_top,
            leaf_w,
            note=tuple(textwrap.wrap(denied.reason, 46)),
        )
    )
    nodes = {"user": user, "orchestrator": orch, "research": research, "mailer": mailer}

    for (parent, child), result in results.items():
        draw_edge(ax, nodes[parent], nodes[child], result.ok)
    draw_edge(ax, orch, wider, denied.ok)
    for node in nodes.values():
        draw_node(ax, node)
    draw_node(ax, wider, rejected=True)

    ax.text(
        40,
        872,
        "Notation:   ~ glob pattern    = exact value    in {..} allow-list    <= ceiling    "
        "any: must be present, any value    xN call budget        "
        "Data: results/m0_delegation_tree.json",
        fontsize=12.5,
        color=style.MUTED,
    )

    png, svg = style.save(fig, "delegation_tree")
    for path in (png, svg, out):
        print(path.relative_to(style.ROOT))
    print(f"rejected: {denied.reason}")


if __name__ == "__main__":
    main()
