"""Delegation tree figure for M0: authority only shrinks down the chain.

Builds four grants with the real library, validates every edge with
caveat.check_attenuation, adds one request the checker rejects, and writes

    results/m0_delegation_tree.json
    assets/delegation_tree.png    2x, drawn from scripts/design/delegation_tree.html

The figure is an HTML page on the shared design system in scripts/design/,
captured with headless Chromium (see scripts/design/render.py).

Run from the repo root: .venv/bin/python scripts/fig_delegation_tree.py
"""

from __future__ import annotations

import json

import style
from caveat import Capability, Grant, check_attenuation
from design.render import Shot, render

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


# ---------------------------------------------------------------- the page

NAMES = {
    "user": "user",
    "orchestrator": "orchestrator",
    "research": "researcher",
    "mailer": "mailer",
}


def node_view(key: str, name: str, g: Grant, rejected: bool = False) -> dict:
    minutes = round((g.expires_at - T0) / 60)
    return {
        "key": key,
        "name": name,
        "role": "user" if key == "user" else "agent",
        "rejected": rejected,
        "note": f"{minutes} min",
        "chips": [{"text": chip_text(c)} for c in g.capabilities],
    }


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
    view = {
        "title": "Each hand-off can only narrow authority",
        "nodes": {k: node_view(k, NAMES[k], GRANTS[k]) for k in GRANTS}
        | {"wider": node_view("wider", "researcher", REJECTED, rejected=True)},
        "edges": [
            {"parent": p, "child": c, "ok": r.ok, "label": "narrower"}
            for (p, c), r in results.items()
        ]
        + [
            {"parent": "orchestrator", "child": "wider", "ok": denied.ok, "label": "wider, refused"}
        ],
    }
    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "delegation_tree.png"
    render("delegation_tree.html", view, [Shot(str(png), scale=2)])
    for path in (png, out):
        print(path.relative_to(style.ROOT))
    print(f"rejected: {denied.reason}")


if __name__ == "__main__":
    main()
