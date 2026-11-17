"""Provenance graph for M4b: one class d attack, every value colored by where it came from.

Runs task misuse-04 (the budget leaked through the URL of a fetch to the
allowed host) with the hijacked scripted agent under configuration
4-value-labels, takes the provenance layer's RECORDED labels for that run,
writes them to results/m4b_provenance_graph.json and draws from that JSON:

    assets/provenance_graph.png
    assets/provenance_graph.svg

Columns are the calls in order. In each column: the arguments (top), the call
(middle) and its result (bottom). Above them runs the session context: the
label every literal the agent writes inherits (the join of the user's request
and every result returned so far). Solid edges are references to a stored
value (a handle); dashed edges are inheritance through the context. Colors:
user (blue), trusted tool (aqua), untrusted (orange); a blocked call is drawn
in the deny color with the id of the policy rule that refused it.

Scripted agents, not a language model. Deterministic.

Run from the repo root: .venv/bin/python scripts/fig_provenance_graph.py
"""

from __future__ import annotations

import json
from typing import Any

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

import style
from toolgate.provenance import USER_LABEL, Label
from toolgate.sandbox.agents import HijackedAgent
from toolgate.sandbox.runner import configuration, run_task
from toolgate.sandbox.tasks import all_tasks

TASK, CONFIG = "misuse-04", "4-value-labels"
USER_C, TRUSTED_C, UNTRUSTED_C = "#2a78d6", "#1baf7a", "#eb6834"
X0, DX = 300, 220
Y_CTX, Y_ARG, Y_CALL, Y_RES = 205, 370, 530, 690
W, H = 196, 92
ARG_GAP = 62  # vertical step between stacked arguments of one call
SHORT = {"tool:web_fetch": "web", "tool:read_file": "file", "tool:write_file": "write"}


def kind(label: dict[str, Any]) -> str:
    if "untrusted" in label["sources"]:
        return "untrusted"
    return "user" if set(label["sources"]) <= {"user"} else "trusted tool"


def describe(label: dict[str, Any]) -> str:
    order = sorted(label["sources"], key=lambda s: (s != "untrusted", s == "user", s))
    names = [SHORT.get(s, s) for s in order]
    sources = (
        ", ".join(names)
        if len(names) <= 4
        else (", ".join(names[:3]) + ",\n" + ", ".join(names[3:]))
    )
    readers = label["readers"]
    who = "anyone" if readers == "any" else ", ".join(r.split("@")[0] for r in readers) + " only"
    return f"from: {sources}\nreaders: {who}"


def to_label(data: dict[str, Any]) -> Label:
    return Label(frozenset(data["sources"]), None if data["readers"] == "any" else data["readers"])


def build() -> dict[str, Any]:
    """Nodes and edges from a real run's provenance records."""
    task = next(t for t in all_tasks() if t.id == TASK)
    run = run_task(task, HijackedAgent(), configuration(CONFIG))
    calls = [h for h in run.history if h["kind"] == "call" and h["status"] != "pending"]
    origins = [e.origin for e in run.transcript if e.status != "skipped"]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    producer: dict[str, str] = {}
    context = USER_LABEL
    nodes.append(
        {
            "id": "ctx0",
            "type": "context",
            "step": 0,
            "label": context.to_json(),
            "text": "user's request",
        }
    )
    for i, h in enumerate(calls, start=1):
        call_id = f"call{i}"
        blocked = h["status"] != "allowed"
        nodes.append(
            {
                "id": call_id,
                "type": "call",
                "step": i,
                "tool": h["tool"],
                "status": h["status"],
                "origin": origins[i - 1],
                "rule": h["rule"],
                "blocked": blocked,
            }
        )
        for name, arg in h["args"].items():
            arg_id = f"{call_id}.{name}"
            nodes.append(
                {
                    "id": arg_id,
                    "type": "argument",
                    "step": i,
                    "name": name,
                    "label": arg["label"],
                    "literal": not arg["refs"],
                }
            )
            edges.append({"from": arg_id, "to": call_id, "kind": "argument"})
            if arg["refs"]:
                for ref in arg["refs"]:
                    edges.append({"from": producer[ref], "to": arg_id, "kind": "reference"})
            else:
                # The recorded label of a literal must be the session context.
                assert to_label(arg["label"]) == context, (arg_id, arg["label"])
                edges.append({"from": f"ctx{i - 1}", "to": arg_id, "kind": "context"})
        if not blocked and h["result_label"] is not None:
            res_id = f"res{i}"
            nodes.append({"id": res_id, "type": "result", "step": i, "label": h["result_label"]})
            edges.append({"from": call_id, "to": res_id, "kind": "result"})
            producer[h["handle"]] = res_id
            context = context.join(to_label(h["result_label"]))
            if i < len(calls):
                edges.append({"from": res_id, "to": f"ctx{i}", "kind": "seen"})
        if i < len(calls):  # the context a literal of the NEXT call inherits
            nodes.append(
                {
                    "id": f"ctx{i}",
                    "type": "context",
                    "step": i,
                    "label": context.to_json(),
                    "text": f"context after call {i}",
                }
            )
            edges.append({"from": f"ctx{i - 1}", "to": f"ctx{i}", "kind": "carry"})
    stopped = next(n for n in nodes if n["type"] == "call" and n["blocked"])
    return {
        "description": "Provenance graph of one real run, " + "scripted agents, not a language "
        "model. Labels are the ones the provenance layer recorded.",
        "task": TASK,
        "configuration": CONFIG,
        "agent": "hijacked",
        "attack_succeeded": run.attack_succeeded,
        "stopped_by": run.stopped_by,
        "blocked_call": {"node": stopped["id"], "tool": stopped["tool"], "rule": stopped["rule"]},
        "world_web_requests": [e["url"] for e in run.world.effects_of("web_request")],
        "nodes": nodes,
        "edges": edges,
    }


def color(node: dict[str, Any]) -> str:
    return {"user": USER_C, "trusted tool": TRUSTED_C, "untrusted": UNTRUSTED_C}[
        kind(node["label"])
    ]


def main() -> None:
    style.apply()
    data = build()
    out = style.RESULTS / "m4b_provenance_graph.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    data = json.loads(out.read_text(encoding="utf-8"))

    fig = plt.figure(figsize=style.SIZE)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1600)
    ax.set_ylim(900, 0)
    ax.axis("off")
    ax.text(
        40,
        48,
        "Provenance graph: budget leaked through a URL to the allowed host (misuse-04)",
        fontsize=19,
        fontweight="bold",
        va="center",
    )
    ax.text(
        40,
        86,
        "Hijacked scripted agent, configuration 4 (value labels, handles). Every "
        "label below is the one the gateway recorded in this run.",
        fontsize=12.5,
        color=style.MUTED,
        va="center",
    )
    for y, text in (
        (Y_CTX, "session\ncontext"),
        (Y_ARG, "arguments"),
        (Y_CALL, "calls"),
        (Y_RES, "results"),
    ):
        ax.text(40, y, text, fontsize=13, color=style.MUTED, va="center")

    where: dict[str, tuple[float, float]] = {}
    per_step: dict[int, list[str]] = {}
    for node in data["nodes"]:
        if node["type"] == "argument":
            per_step.setdefault(node["step"], []).append(node["id"])
    for node in data["nodes"]:
        # A context node sits above the call whose literals inherit it.
        column = node["step"] + 1 if node["type"] == "context" else node["step"]
        x = X0 + (column - 1) * DX
        y = {"context": Y_CTX, "argument": Y_ARG, "call": Y_CALL, "result": Y_RES}[node["type"]]
        if node["type"] == "argument" and len(per_step[node["step"]]) > 1:
            siblings = per_step[node["step"]]
            y += (siblings.index(node["id"]) - (len(siblings) - 1) / 2) * ARG_GAP
        where[node["id"]] = (x, y)

    def box(x: float, y: float, w: float, h: float, face: str, edge: str, lw: float = 0) -> None:
        ax.add_patch(
            FancyBboxPatch(
                (x - w / 2, y - h / 2),
                w,
                h,
                boxstyle="round,pad=0,rounding_size=8",
                facecolor=face,
                edgecolor=edge,
                linewidth=lw,
                zorder=2,
            )
        )

    for edge in data["edges"]:
        (x1, y1), (x2, y2) = where[edge["from"]], where[edge["to"]]
        if edge["kind"] == "reference":
            # Up the gap between two columns: result's top-right to argument's bottom-left.
            x1, y1, x2, y2 = x1 + W / 2 - 12, y1 - H / 2, x2 - W / 2 + 12, y2 + H / 2
        dashed = edge["kind"] in ("context", "seen", "carry")
        c = style.INK if edge["kind"] == "reference" else style.MUTED
        lw = 2.4 if edge["kind"] == "reference" else 1.3
        rad = 0.0
        if edge["kind"] == "reference":
            rad = 0.0
        ax.add_patch(
            FancyArrowPatch(
                (x1, y1),
                (x2, y2),
                arrowstyle="-|>",
                mutation_scale=12,
                color=c,
                linewidth=lw,
                linestyle="--" if dashed else "-",
                shrinkA=0 if edge["kind"] == "reference" else 34,
                shrinkB=0 if edge["kind"] == "reference" else 40,
                zorder=1,
                connectionstyle=f"arc3,rad={rad}",
            )
        )

    for node in data["nodes"]:
        x, y = where[node["id"]]
        if node["type"] == "context":
            box(x, y, W, 64, color(node), "none")
            title = node["text"] if node["step"] == 0 else f"after call {node['step']}"
            ax.text(
                x,
                y - 13,
                title,
                ha="center",
                va="center",
                fontsize=10.5,
                color="white",
                fontweight="bold",
                zorder=3,
            )
            readers = node["label"]["readers"]
            ax.text(
                x,
                y + 13,
                "readers: " + ("anyone" if readers == "any" else "alice only"),
                ha="center",
                va="center",
                fontsize=10,
                color="white",
                zorder=3,
            )
        elif node["type"] in ("argument", "result"):
            stacked = node["type"] == "argument" and len(per_step[node["step"]]) > 1
            box(x, y, W, 58 if stacked else H, color(node), "none")
            head = (
                node["name"] + (" (literal)" if node.get("literal") else " (reference)")
                if (node["type"] == "argument")
                else "result"
            )
            ax.text(
                x,
                y - (17 if stacked else 26),
                head,
                ha="center",
                va="center",
                fontsize=10.5,
                color="white",
                fontweight="bold",
                zorder=3,
            )
            ax.text(
                x,
                y + (9 if stacked else 12),
                describe(node["label"]),
                ha="center",
                va="center",
                fontsize=8.6,
                color="white",
                zorder=3,
                linespacing=1.1 if stacked else 1.3,
            )
        else:
            blocked = node["blocked"]
            box(
                x,
                y,
                W,
                H,
                style.DENY if blocked else style.PANEL,
                style.DENY if blocked else style.RULE,
                1.5,
            )
            ink = "white" if blocked else style.INK
            tag = " (injected)" if node["origin"] != "legit" else ""
            ax.text(
                x,
                y - 26,
                node["tool"] + tag,
                ha="center",
                va="center",
                fontsize=11,
                color=ink,
                fontweight="bold",
                zorder=3,
            )
            status = "DENIED by rule" if blocked else "allowed"
            ax.text(x, y + 2, status, ha="center", va="center", fontsize=10, color=ink, zorder=3)
            if blocked:
                ax.text(
                    x,
                    y + 24,
                    node["rule"],
                    ha="center",
                    va="center",
                    fontsize=8.0,
                    color=ink,
                    zorder=3,
                    family=style.MONO,
                )

    lx, ly = 40, 790
    for i, (name, c) in enumerate(
        (
            ("from the user only", USER_C),
            ("trusted tool", TRUSTED_C),
            ("untrusted", UNTRUSTED_C),
            ("blocked call", style.DENY),
        )
    ):
        box(lx + i * 230 + 14, ly, 26, 26, c, "none")
        ax.text(lx + i * 230 + 36, ly, name, fontsize=12, va="center")
    ax.plot([980, 1030], [ly, ly], color=style.INK, linewidth=2.4)
    ax.text(1040, ly, "reference to a stored value", fontsize=12, va="center")
    ax.plot([980, 1030], [ly + 34, ly + 34], color=style.MUTED, linewidth=1.3, linestyle="--")
    ax.text(1040, ly + 34, "inherited through the session context", fontsize=12, va="center")
    outcome = "did not succeed" if not data["attack_succeeded"] else "SUCCEEDED"
    ax.text(
        40,
        ly + 80,
        f"Attack {outcome}. The second fetch, the legitimate one, is denied "
        "too: once the agent has read the budget, every URL it writes may carry it "
        "(label creep).",
        fontsize=11,
        color=style.MUTED,
        va="center",
    )
    style.save(fig, "provenance_graph")


if __name__ == "__main__":
    main()
