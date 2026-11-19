"""Provenance graph for M4b: one class d attack, every value labeled by where it came from.

Runs task misuse-04 (the budget leaked through the URL of a fetch to the
allowed host) with the hijacked scripted agent under configuration
4-value-labels, takes the provenance layer's RECORDED labels for that run and
writes the full graph to results/m4b_provenance_graph.json. The figure is
drawn from that JSON and the same run's transcript:

    assets/provenance_graph.png    2x, drawn from scripts/design/provenance_graph.html

The figure keeps only the nodes that tell the story: the user's request, the
results the agent read before the attack (the untrusted page that carried the
injection, then the private file it pointed to), and the injected fetch whose
URL references that file, blocked by the rule the gateway recorded. Omitted
from the picture but kept in the JSON: the per-call argument nodes, the
session-context nodes after each call, and the calls after the block (a
second, legitimate fetch denied by the same rule, which is label creep; the
file read and the write that finish the task).

Scripted agents, not a language model. Deterministic.

Run from the repo root: .venv/bin/python scripts/fig_provenance_graph.py
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

import style
from design.render import Shot, render
from caveat.provenance import USER_LABEL, Label
from caveat.sandbox.agents import HijackedAgent
from caveat.sandbox.runner import configuration, run_task
from caveat.sandbox.tasks import all_tasks

TASK, CONFIG = "misuse-04", "4-value-labels"
TITLE = "Labels follow the data"
NAME = {"web_fetch": "Web page", "read_file": "File"}
ICON = {"web_fetch": "globe", "read_file": "file-text"}


def kind(label: dict[str, Any]) -> str:
    if "untrusted" in label["sources"]:
        return "untrusted"
    return "from user" if set(label["sources"]) <= {"user"} else "trusted tool"


def readers(label: dict[str, Any]) -> str:
    if label["readers"] == "any":
        return "anyone can read"
    return "only " + ", ".join(r.split("@")[0] for r in label["readers"]) + " can read"


def to_label(data: dict[str, Any]) -> Label:
    return Label(frozenset(data["sources"]), None if data["readers"] == "any" else data["readers"])


def build(run: Any) -> dict[str, Any]:
    """Nodes and edges from a real run's provenance records."""
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


def opening(text: str, limit: int = 20) -> str:
    """The first words of the user's request that fit on one card line."""
    words, out = text.split(), ""
    for w in words:
        if len(out) + len(w) + 1 > limit:
            return out + "\u2026"
        out = f"{out} {w}".strip()
    return out


def where(tool: str, args: dict[str, Any]) -> str:
    """Where a result came from, short enough for a card: a host or a file name."""
    if tool == "web_fetch":
        return urlparse(args["url"]).netloc
    return PurePosixPath(args["path"]).name


def view(data: dict[str, Any], request: str, transcript: list[Any]) -> dict[str, Any]:
    """The story nodes of the recorded graph, as the page draws them."""
    nodes = {n["id"]: n for n in data["nodes"]}
    entries = [e for e in transcript if e.status != "skipped"]
    blocked = nodes[data["blocked_call"]["node"]]
    step = blocked["step"]
    read = [
        {
            "key": "ctx0",
            "name": "Request",
            "icon": "user",
            "source": kind(nodes["ctx0"]["label"]),
            "readers": readers(nodes["ctx0"]["label"]),
            "shared": nodes["ctx0"]["label"]["readers"] == "any",
            "where": None,
            "said": opening(request),
        }
    ]
    for res in (n for n in data["nodes"] if n["type"] == "result" and n["step"] < step):
        call = nodes[f"call{res['step']}"]
        read.append(
            {
                "key": res["id"],
                "name": NAME[call["tool"]],
                "icon": ICON[call["tool"]],
                "source": kind(res["label"]),
                "readers": readers(res["label"]),
                "shared": res["label"]["readers"] == "any",
                "where": where(call["tool"], entries[res["step"] - 1].args),
                "said": None,
            }
        )
    # Which values flowed into the blocked call: the result its argument
    # references (solid), and, for an injected call, the untrusted result
    # whose instruction it follows (dashed).
    arg = next(e for e in data["edges"] if e["to"] == blocked["id"])["from"]
    refs = [e["from"] for e in data["edges"] if e["to"] == arg and e["kind"] == "reference"]
    assert len(refs) == 1, refs
    name = nodes[arg]["name"]
    flows = [{"from": refs[0], "label": f"value in the {name}", "dashed": False}]
    if blocked["origin"] == "injected":
        untrusted = [n for n in read if n["source"] == "untrusted"]
        assert len(untrusted) == 1, untrusted
        flows.insert(0, {"from": untrusted[0]["key"], "label": "its instruction", "dashed": True})
    attempt = entries[step - 1].args[name]
    prefix = attempt["$concat"][0]
    ref = next(n for n in read if n["key"] == refs[0])
    return {
        "title": TITLE,
        "read": read,
        "flows": flows,
        "call": {
            "tool": blocked["tool"],
            "origin": blocked["origin"],
            "source": "untrusted" if blocked["origin"] == "injected" else "from user",
            "verdict": "Blocked by" if blocked["blocked"] else "Allowed by",
            "rule": blocked["rule"],
            "arg": name,
            "prefix": prefix.split("://", 1)[1],
            "ref": ref["key"],
            "ref_name": ref["where"],
        },
    }


def main() -> None:
    task = next(t for t in all_tasks() if t.id == TASK)
    run = run_task(task, HijackedAgent(), configuration(CONFIG))
    data = build(run)
    out = style.RESULTS / "m4b_provenance_graph.json"
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    data = json.loads(out.read_text(encoding="utf-8"))

    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "provenance_graph.png"
    render(
        "provenance_graph.html", view(data, task.request, run.transcript), [Shot(str(png), scale=2)]
    )
    for path in (png, out):
        print(path.relative_to(style.ROOT))


if __name__ == "__main__":
    main()
