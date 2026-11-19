"""Plan-then-execute, following CaMeL, in a small and scripted form (plan 3.7).

The property this mode exists for: text an attacker plants in a tool result
can change an EXTRACTED VALUE, but never the plan's control flow, that is,
never which tools run, in which order, or any argument the planner wrote.

Three roles:

  planner    privileged. Sees ONLY the user's request (in the sandbox also the
             grant the user delegated for it, which the user wrote too) and
             returns a `Plan`. It never sees a tool result.
  extractor  quarantined. Has no tool access. Gets one `ExtractStep` (its
             instruction and schema) and the VALUES of its inputs, and
             returns one value. The value is checked against the schema and
             stored as a new handle whose label is the join of its inputs'
             labels (so: untrusted, with the inputs' readers, whenever it
             parsed untrusted content).
  executor   `execute` below, trusted code. Runs the steps in order, each tool
             step through the gateway, turning references to earlier steps
             into handle references. It makes no decision of its own.

A plan is a fixed list. There are no branches, loops or tool names computed
from data, and `validate` refuses anything else: a tool name must be a literal
string, a reference must name an EARLIER step, an argument is a JSON literal,
`Ref`, `Cat` or `UrlEncode`. Literals in a plan are labeled "user" (readers
ANY): the planner saw nothing else (`Provenance.use_planner_literals`).

What an injection CAN still do here, stated precisely:

  * change the value an extract step returns, within its schema (a "text"
    slot can become any text, including copies of the extractor's other
    inputs; an "email" slot any address), and so the arguments that refer to
    it;
  * make an extract step fail its schema, so the steps that depend on it are
    skipped: whether a call happens can depend on untrusted data. That is an
    implicit flow, and nothing here labels it.

It can never add a call, remove a call that does not depend on an extracted
value, change a tool, or change a literal argument.

What is modeled and what is not. The planner and extractor here are
deterministic functions (caveat.sandbox.plans), not models: the planner is
written per task from the request alone, the extractor returns what an
accurate model would, and a "fooled" extractor returns the attacker's text
whenever its input contains the injection. This shows the mechanism, not how
well a real planner plans or how often a real extractor is fooled. Unlike
CaMeL, this runs no interpreter over model-written code and tracks no
control-flow dependencies inside the plan; enforcement is at the tool
boundary, by the gateway's policy, on the labels of the arguments.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from caveat.canonical import CanonicalError, canonical_email, canonical_path, canonical_url

TEXT, EMAIL, DATE, ID, URL, PATH = "text", "email", "date", "id", "url", "path"
SCHEMAS = frozenset({TEXT, EMAIL, DATE, ID, URL, PATH})
MAX_TEXT = 64 * 1024
_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


class PlanError(ValueError):
    """The plan is not in the restricted format."""


@dataclass(frozen=True)
class Ref:
    """The output of an earlier step, optionally one field of it."""

    step: str
    path: tuple[str | int, ...] = ()


@dataclass(frozen=True)
class Cat:
    """Parts joined into one string (non-strings written as JSON)."""

    parts: tuple[Any, ...]


@dataclass(frozen=True)
class UrlEncode:
    part: Any


@dataclass(frozen=True)
class ToolStep:
    name: str
    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExtractStep:
    """Quarantined parsing: `instruction` applied to the inputs' values."""

    name: str
    inputs: tuple[str, ...]
    instruction: str
    schema: str = TEXT


@dataclass(frozen=True)
class Plan:
    request: str
    steps: tuple[ToolStep | ExtractStep, ...]

    def tools(self) -> tuple[str, ...]:
        """Which tools run, in order. Fixed when the plan is written."""
        return tuple(s.tool for s in self.steps if type(s) is ToolStep)


def _check_expr(value: Any, earlier: set[str], where: str, depth: int = 0) -> None:
    if depth > 16:
        raise PlanError(f"{where}: nested too deeply")
    if type(value) is Ref:
        if value.step not in earlier:
            raise PlanError(f"{where}: refers to {value.step!r}, which is not an earlier step")
        if not all(type(p) in (str, int) for p in value.path):
            raise PlanError(f"{where}: a path holds field names and list indices only")
        return
    if type(value) is Cat:
        for part in value.parts:
            _check_expr(part, earlier, where, depth + 1)
        return
    if type(value) is UrlEncode:
        _check_expr(value.part, earlier, where, depth + 1)
        return
    if type(value) in (list, tuple):
        for item in value:
            _check_expr(item, earlier, where, depth + 1)
        return
    if type(value) is dict:
        for k, v in value.items():
            if type(k) is not str or k.startswith("$"):
                raise PlanError(f"{where}: object keys must be plain strings")
            _check_expr(v, earlier, where, depth + 1)
        return
    if value is None or type(value) in (str, int, float, bool):
        return
    raise PlanError(f"{where}: {type(value).__name__} is not allowed in a plan")


def validate(plan: Plan) -> None:
    """Refuse anything outside the restricted format."""
    if type(plan) is not Plan:
        raise PlanError("not a Plan")
    earlier: set[str] = set()
    for step in plan.steps:
        if type(step) not in (ToolStep, ExtractStep):
            raise PlanError("a step is a ToolStep or an ExtractStep")
        if type(step.name) is not str or not _NAME.fullmatch(step.name) or step.name in earlier:
            raise PlanError(f"step name {step.name!r} is not a fresh short identifier")
        if type(step) is ToolStep:
            if type(step.tool) is not str or not step.tool:
                raise PlanError(f"step {step.name}: the tool must be a literal name")
            for arg, value in step.args.items():
                if type(arg) is not str or arg.startswith("$"):
                    raise PlanError(f"step {step.name}: bad argument name")
                _check_expr(value, earlier, f"step {step.name} argument {arg}")
        else:
            if not step.inputs or not all(i in earlier for i in step.inputs):
                raise PlanError(f"step {step.name}: inputs must be earlier steps")
            if step.schema not in SCHEMAS:
                raise PlanError(f"step {step.name}: unknown schema {step.schema!r}")
        earlier.add(step.name)


def check_schema(schema: str, value: Any) -> Any:
    """The extractor's output if it fits the schema, else PlanError. Never repaired."""
    if type(value) is not str:
        raise PlanError("extracted value is not a string")
    if schema == TEXT:
        if len(value) > MAX_TEXT:
            raise PlanError("extracted text is too long")
        return value
    try:
        if schema == EMAIL:
            if canonical_email(value) != value:
                raise PlanError("extracted address is not canonical")
            return value
        if schema == URL:
            if canonical_url(value) != value:
                raise PlanError("extracted url is not canonical")
            return value
        if schema == PATH:
            if canonical_path(value) != value:
                raise PlanError("extracted path is not canonical")
            return value
    except CanonicalError as exc:
        raise PlanError(f"extracted value does not fit {schema}") from exc
    pattern = _DATE if schema == DATE else _ID
    if not pattern.fullmatch(value):
        raise PlanError(f"extracted value does not fit {schema}")
    return value


Extractor = Callable[[ExtractStep, list[Any]], Any]
CallTool = Callable[[str, dict[str, Any]], Any]


@dataclass
class StepRecord:
    """What happened to one plan step."""

    name: str
    kind: str  # "tool" or "extract"
    tool: str | None
    status: str  # ok | denied | error | skipped
    args: dict[str, Any] | None = None  # resolved arguments of a tool step
    wire: dict[str, Any] | None = None
    outcome: Any = None
    handle: str | None = None
    depends_on: tuple[str, ...] = ()
    reason: str = ""


def references(value: Any) -> list[str]:
    """The step names a plan expression refers to."""
    if type(value) is Ref:
        return [value.step]
    if type(value) is Cat:
        return [r for p in value.parts for r in references(p)]
    if type(value) is UrlEncode:
        return references(value.part)
    if type(value) in (list, tuple):
        return [r for v in value for r in references(v)]
    if type(value) is dict:
        return [r for v in value.values() for r in references(v)]
    return []


def _wire(value: Any, handles: Mapping[str, str]) -> Any:
    if type(value) is Ref:
        return {"$ref": handles[value.step], "path": list(value.path)}
    if type(value) is Cat:
        return {"$concat": [_wire(p, handles) for p in value.parts]}
    if type(value) is UrlEncode:
        return {"$urlencode": _wire(value.part, handles)}
    if type(value) in (list, tuple):
        return [_wire(v, handles) for v in value]
    if type(value) is dict:
        return {k: _wire(v, handles) for k, v in value.items()}
    return value


def execute(
    plan: Plan,
    *,
    provenance: Any,
    session: str,
    call_tool: Callable[[str, dict[str, Any]], tuple[str, Any, str | None]],
    extractor: Extractor,
) -> list[StepRecord]:
    """Run a validated plan. Returns one record per step, in plan order.

    `call_tool(tool, wire_args) -> (status, outcome, handle)` sends one call
    through the gateway (and answers any approval); `session` is the token id
    the gateway files the handles under. A step whose inputs did not all
    produce a handle is skipped; nothing else depends on any value.
    """
    validate(plan)
    provenance.use_planner_literals(session)
    handles: dict[str, str] = {}
    records: list[StepRecord] = []
    for step in plan.steps:
        if type(step) is ExtractStep:
            deps = tuple(step.inputs)
        else:
            deps = tuple(dict.fromkeys(r for v in step.args.values() for r in references(v)))
        missing = [d for d in deps if d not in handles]
        tool = step.tool if type(step) is ToolStep else None
        kind = "tool" if type(step) is ToolStep else "extract"
        if missing:
            records.append(
                StepRecord(step.name, kind, tool, "skipped", depends_on=deps, reason="no input")
            )
            continue
        if type(step) is ExtractStep:
            values = [provenance.value(session, handles[i]) for i in step.inputs]
            try:
                value = check_schema(step.schema, extractor(step, json.loads(json.dumps(values))))
            except PlanError as exc:
                records.append(
                    StepRecord(step.name, kind, None, "error", depends_on=deps, reason=str(exc))
                )
                continue
            handle = provenance.derive(session, [handles[i] for i in step.inputs], value)
            handles[step.name] = handle
            records.append(StepRecord(step.name, kind, None, "ok", handle=handle, depends_on=deps))
            continue
        wire = {arg: _wire(v, handles) for arg, v in step.args.items()}
        resolved = provenance.resolve_args(session, wire)[0]
        status, outcome, handle = call_tool(step.tool, wire)
        if status == "ok" and handle is not None:
            handles[step.name] = handle
        records.append(
            StepRecord(step.name, kind, step.tool, status, resolved, wire, outcome, handle, deps)
        )
    return records
