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
from dataclasses import dataclass

import style
from toolgate import Capability, Grant, check_attenuation

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


# ---------------------------------------------------------------- plain-language chips

VERB = {"read_file": "read", "send_email": "email", "search_calendar": "calendar"}


def who(address: str) -> str:
    return address.split("@")[0]


def chip_text(cap: Capability) -> str:
    """One capability as a short phrase: "read reports/q3/*", "email ana, 1x"."""
    by_arg = {c.arg: c for c in cap.constraints}
    words = VERB.get(cap.tool, cap.tool)
    if cap.tool == "read_file":
        path = by_arg["path"]
        words += " all files" if path.op == "glob" and path.value == "*" else f" {path.value}"
    elif cap.tool == "send_email":
        to = by_arg["to"]
        names = [who(v) for v in to.value] if to.op == "in" else [who(to.value)]
        words += " " + ", ".join(names)
    elif cap.tool == "search_calendar":
        words += f", {by_arg['days'].value} days"
    if cap.max_calls is not None:
        words += f", {cap.max_calls}x"
    return words


# ---------------------------------------------------------------- layout, logical px

W, H = 800, 584
PAD = 16  # inside a node
NODE_H = 104
HEAD_DY, CHIP_DY = 28, 70  # name baseline row and chip row, from a node's top
CHIP_GAP = 8
COL_W, COL_GAP = 232, 20
ROW_Y = [96, 272, 448]  # node tops


@dataclass
class Node:
    name: str
    grant: Grant
    x: float
    y: float
    w: float
    rejected: bool = False

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def bottom(self) -> float:
        return self.y + NODE_H

    def chips(self) -> list[str]:
        return [chip_text(cap) for cap in self.grant.capabilities]


def chips_width(texts: list[str]) -> float:
    return sum(style.text_width(t) + 24 for t in texts) + CHIP_GAP * (len(texts) - 1)


def draw_node(c: style.Canvas, node: Node) -> None:
    if node.rejected:
        c.box(node.x, node.y, node.w, NODE_H, fill=style.CARD, edge=style.BAD, dashed=True)
    else:
        c.box(node.x, node.y, node.w, NODE_H)
    minutes = round((node.grant.expires_at - T0) / 60)
    c.text(node.x + PAD, node.y + HEAD_DY, node.name, size=style.LABEL, weight=style.STRONG)
    expiry = f"{minutes} min"
    right = node.x + node.w - PAD
    c.text(right, node.y + HEAD_DY, expiry, size=style.SMALL, color=style.GRAY, ha="right")
    c.clock(right - style.text_width(expiry, style.SMALL) - 15, node.y + HEAD_DY)
    x = node.x + PAD
    for text in node.chips():
        _, w = c.chip(x, node.y + CHIP_DY, text, tone="bad" if node.rejected else "plain")
        x += w + CHIP_GAP


def draw_edge(c: style.Canvas, parent: Node, child: Node, ok: bool, label: str = "") -> None:
    """Straight down from parent to child, with the checker's verdict as a badge."""
    x, y0, y1 = child.cx, parent.bottom + 6, child.y - 4
    tone = "good" if ok else "bad"
    c.arrow((x, y0), (x, y1), tone=tone, dashed=not ok)
    mid = (y0 + y1) / 2 - 2
    c.badge(x, mid, tone)
    if label:
        right = child.cx < W / 2 + 1  # label on the side with room
        c.text(
            x + 22 if right else x - 22,
            mid,
            label,
            size=style.SMALL,
            color=style.GOOD if ok else style.BAD,
            weight=style.STRONG,
            ha="left" if right else "right",
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

    # 3. Draw, from the same grants the checker just judged.
    c = style.Canvas(W, H)
    c.title("Each hand-off can only narrow authority")

    names = {
        "user": "user",
        "orchestrator": "orchestrator",
        "research": "researcher",
        "mailer": "mailer",
    }
    top_w = (
        max(
            chips_width([chip_text(cap) for cap in GRANTS[k].capabilities])
            for k in ("user", "orchestrator")
        )
        + 2 * PAD
    )
    top_w = max(top_w, 3 * COL_W + 2 * COL_GAP - 2 * 96)
    nodes = {
        "user": Node(names["user"], GRANTS["user"], (W - top_w) / 2, ROW_Y[0], top_w),
        "orchestrator": Node(
            names["orchestrator"], GRANTS["orchestrator"], (W - top_w) / 2, ROW_Y[1], top_w
        ),
    }
    left = (W - 3 * COL_W - 2 * COL_GAP) / 2
    cols = [left + k * (COL_W + COL_GAP) for k in range(3)]
    nodes["research"] = Node(names["research"], GRANTS["research"], cols[0], ROW_Y[2], COL_W)
    nodes["mailer"] = Node(names["mailer"], GRANTS["mailer"], cols[1], ROW_Y[2], COL_W)
    wider = Node("researcher", REJECTED, cols[2], ROW_Y[2], COL_W, rejected=True)
    for node in nodes.values():
        assert chips_width(node.chips()) + 2 * PAD <= node.w, node.name

    for (parent, child), result in results.items():
        draw_edge(
            c,
            nodes[parent],
            nodes[child],
            result.ok,
            "narrower: accepted" if parent == "user" else "",
        )
    draw_edge(c, nodes["orchestrator"], wider, denied.ok, "wider: rejected")
    for node in [*nodes.values(), wider]:
        draw_node(c, node)
    for path in (*c.save("delegation_tree"), out):
        print(path.relative_to(style.ROOT))
    print(f"rejected: {denied.reason}")


if __name__ == "__main__":
    main()
