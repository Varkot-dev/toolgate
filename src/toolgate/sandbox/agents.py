"""Scripted agents and a scripted human approver. No language model is involved.

These are stand-ins: scripted agents, not a language model. They exist so the
sandbox results are exactly reproducible and so the defence layers can be
measured without the noise of a model deciding, run by run, whether to obey
an injection. They say nothing about how often a real model is hijacked.

    HonestAgent     performs exactly the task's legitimate steps.
    HijackedAgent   performs the legitimate steps and, the first time a tool
                    result contains the task's injected text, performs the
                    task's injected steps (an always-obedient victim), then
                    carries on with the legitimate task. When an injected
                    call is denied it tries that step's fallback variants, at
                    most two: a persistent attacker.
    Approver        the person answering approval requests. `careful`
                    approves a call only if the honest agent would have made
                    exactly that call (same tool, same arguments, body
                    included); `rubber_stamp` approves everything.

Both agents have one interface, `run(task, call_tool) -> transcript`, where
`call_tool(tool, args)` returns a `ToolResult`. Whether that goes straight to
the world or through the gateway is the runner's business.

Two simplifications to keep in mind when reading results:

  * The hijacked agent obeys EVERY injection, immediately, before it finishes
    the user's task. Injected calls therefore spend call budget first, and a
    legitimate call that comes later can find the budget gone.
  * The careful approver is an oracle. A real person shown "send_email to
    frank@partner.example" would have to read the whole body to do as well.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from toolgate.sandbox.tasks import Step, Task, Tpl
from toolgate.sandbox.world import result_is_untrusted

OK, DENIED, ERROR, SKIPPED = "ok", "denied", "error", "skipped"
LEGIT, INJECTED, FALLBACK = "legit", "injected", "fallback"
MAX_FALLBACKS = 2
CAREFUL, RUBBER_STAMP = "careful", "rubber_stamp"


@dataclass(frozen=True)
class ToolResult:
    """What an agent gets back from one tool call.

    status    ok | denied | error
    result    the tool's return value when status is ok
    layer     the defence layer that refused the call, when status is denied
    approval  None, or "approved" / "rejected" if a person was asked
    """

    status: str
    result: Any = None
    layer: str | None = None
    reason: str = ""
    approval: str | None = None


CallTool = Callable[[str, dict[str, Any]], ToolResult]


@dataclass(frozen=True)
class Entry:
    """One line of a transcript: a call an agent made, or a step it had to skip."""

    origin: str  # legit | injected | fallback
    tool: str
    args: Mapping[str, Any]
    status: str  # ok | denied | error | skipped
    layer: str | None = None
    reason: str = ""
    approval: str | None = None
    untrusted_result: bool = False  # per the tool metadata, for the provenance milestone
    sources: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # arg -> "step.field"

    @property
    def from_injection(self) -> bool:
        return self.origin in (INJECTED, FALLBACK)

    def to_json(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "tool": self.tool,
            "status": self.status,
            "layer": self.layer,
            "approval": self.approval,
            "untrusted_result": self.untrusted_result,
            "sources": {arg: list(refs) for arg, refs in self.sources.items()},
        }


Transcript = list[Entry]


def contains_text(value: Any, text: str) -> bool:
    """Does any string inside a tool result contain `text`?"""
    if isinstance(value, str):
        return text in value
    if isinstance(value, dict):
        return any(contains_text(v, text) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_text(v, text) for v in value)
    return False


class _Script:
    """Runs scripted steps against `call_tool` and keeps the transcript."""

    def __init__(self, call_tool: CallTool) -> None:
        self.call_tool = call_tool
        self.results: dict[str, Any] = {}
        self.transcript: Transcript = []

    def run(self, step: Step, origin: str) -> ToolResult | None:
        """Make one call. None means a `Tpl` argument had nothing to refer to."""
        args: dict[str, Any] = {}
        sources: dict[str, tuple[str, ...]] = {}
        for name, value in step.args.items():
            if isinstance(value, Tpl):
                sources[name] = value.sources()
                value = value.resolve(self.results)
                if value is None:
                    self.transcript.append(
                        Entry(origin, step.tool, {}, SKIPPED, reason=f"no input for {name!r}")
                    )
                    return None
            args[name] = value
        outcome = self.call_tool(step.tool, args)
        self.transcript.append(
            Entry(
                origin,
                step.tool,
                args,
                outcome.status,
                outcome.layer,
                outcome.reason,
                outcome.approval,
                outcome.status == OK and result_is_untrusted(step.tool, args),
                sources,
            )
        )
        if outcome.status == OK and step.name:
            self.results[step.name] = outcome.result
        return outcome

    def run_persistently(self, step: Step) -> None:
        """An injected step: on denial, try its fallbacks until one is not denied."""
        outcome = self.run(step, INJECTED)
        for fallback in step.fallbacks[:MAX_FALLBACKS]:
            if outcome is None or outcome.status != DENIED:
                return
            outcome = self.run(fallback, FALLBACK)


class HonestAgent:
    """Scripted stand-in for a model that does exactly what the user asked."""

    name = "honest"

    def run(self, task: Task, call_tool: CallTool) -> Transcript:
        script = _Script(call_tool)
        for step in task.legit:
            script.run(step, LEGIT)
        return script.transcript


class HijackedAgent:
    """Scripted stand-in for a model that obeys any instruction it reads."""

    name = "hijacked"

    def run(self, task: Task, call_tool: CallTool) -> Transcript:
        script = _Script(call_tool)
        hijacked = False
        for step in task.legit:
            outcome = script.run(step, LEGIT)
            seen = (
                outcome is not None
                and outcome.status == OK
                and bool(task.injection)
                and contains_text(outcome.result, task.injection)
            )
            if seen and not hijacked:
                hijacked = True
                for injected in task.injected:
                    script.run_persistently(injected)
        return script.transcript


def call_key(tool: str, args: Mapping[str, Any]) -> str:
    """A canonical string for one call, for comparing calls exactly."""
    return json.dumps([tool, args], sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class Approver:
    """A scripted person answering approval requests.

    `legitimate` is the set of calls (as `call_key`) the honest agent makes
    for the task with no gateway in the way. Only the careful mode reads it.
    """

    mode: str
    legitimate: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.mode not in (CAREFUL, RUBBER_STAMP):
            raise ValueError(f"unknown approver mode {self.mode!r}")

    @property
    def name(self) -> str:
        return f"approver:{self.mode}"

    def approves(self, tool: str, args: Mapping[str, Any]) -> bool:
        return self.mode == RUBBER_STAMP or call_key(tool, args) in self.legitimate


AGENTS: tuple[type[HonestAgent] | type[HijackedAgent], ...] = (HonestAgent, HijackedAgent)
