"""Provenance: permissions that depend on where data came from (plan 3.7, M4b).

Argument constraints ask "may this agent call this tool with these
arguments?". This module adds "where did these arguments come from, and who
may see them?", and makes the gateway's policy able to ask it.

Labels
------

Every value the gateway knows about carries a `Label`:

    sources   a set drawn from "user", "tool:<name>" and "untrusted"
    readers   who may receive the data: a finite set of principals, or ANY
              (everyone). A principal is an email address, a whole domain
              written "*@northwind.example", or "public"; a set holding
              "public" is the same as ANY.

Two values combine (`Label.join`) by the UNION of their sources and the
INTERSECTION of their readers. Union, because a value built from an untrusted
part is as untrusted as that part; intersection, because data may only go
where every one of its parts may go. Readers intersect with domains taken into
account: {"*@northwind.example"} meet {"bob@northwind.example", "x@y.example"}
is {"bob@northwind.example"}.

Where labels come from, explicitly:

  * the user's request, and every literal in a plan written by a planner that
    saw only the request: sources {"user"}, readers ANY (`USER_LABEL`);
  * a tool result: whatever the operator's `declare(tool, args, result,
    arg_labels)` function says. Each deployment declares its tools (the
    sandbox's declarations are in toolgate.sandbox.labels: a calendar entry is
    readable by its attendees and the user, a private file by the user, a
    fetched web page by anyone but its source is untrusted);
  * a literal written by an AGENT (a model that sees tool results): the join
    of the user's label and the label of every result this session has
    returned so far (`Session.seen`). So a literal counts as untrusted exactly
    when, before the call carrying it was sent, the session had returned at
    least one result whose label holds "untrusted"; and its readers are the
    intersection of the readers of everything returned so far, because the
    agent could have copied any of it into the text it writes. This is the
    sound rule for an agent that reads what it is given, and it is where
    label creep comes from (results/m4b_label_creep.json measures it);
  * a value made by the quarantined extractor of plan-then-execute
    (toolgate.plan): the join of the labels of its inputs.

Handles (level 2)
-----------------

In value mode the gateway keeps every result and gives the agent a handle for
it: an opaque id (default: 128 random bits from `secrets`), valid only in the
session that received it. A session is one token id (MCP has no sessions any
more, decision log, reference check item 1). A handle from another token, a
made-up handle and an expired one are the same error, so a handle cannot be
used to test what exists. Stored values are kept as canonical JSON text and
decoded afresh on every read, so nothing can change a stored value, and no
API overwrites a handle.

The wire form of an argument (`resolve_args`):

    a JSON literal                         labeled as a literal (see above)
    {"$ref": "<handle>"}                   the stored value, with its label
    {"$ref": "<handle>", "path": [k, i]}   a field of it (keys are strings,
                                           list indices are integers); a
                                           field carries the label of the
                                           WHOLE stored value: labels are
                                           per result, not per field
    {"$concat": [part, ...]}               the parts joined as one string;
                                           non-strings are written as JSON
                                           with sorted keys; label = join of
                                           the parts, plus the literal label
                                           unless there is exactly one part
    {"$urlencode": part}                   the part percent-encoded for a
                                           URL (nothing is safe); label kept
    a list or an object                    resolved element by element;
                                           label = join of the elements and,
                                           for an object or a list that does
                                           not hold exactly one element, the
                                           literal label

The rule behind these labels: every BYTE of the resolved value either comes
from a stored value, and carries that value's label, or was placed there by
whoever wrote the expression, and carries the literal label. The writer
places bytes with literals, with object keys, and with ARRANGEMENT: the order
and number of the parts of a list or a "$concat". Arrangement counts because
it is enough to write new text: a "$concat" of references only, each picking
one short field, can spell an address or a URL that no stored value holds.
So an expression of two or more parts carries the literal label even when
every part is a reference. One part arranges nothing ("$concat" of one
string, a one-element list, "$urlencode" are fixed functions of their part),
so those keep the part's label.

What the label does NOT cover is SELECTION: which handle, and which field of
it (`path`), the writer picked. Both are choices among values the store
already labels, so no attacker-written byte reaches the tool through them,
but an injection can steer them ("send it to the second contact"). They are
deliberately not joined, for two reasons. Selection is control, not data:
it leaks at most which of the offered values was chosen, the same kind of
implicit flow the section below says labels do not track. And joining it
for `path` alone would be inconsistent, not safer: the same choice is
available by picking a different handle, or by calling a lookup tool with a
steered query (its result is labeled by the tool, not by the query). Joining
every choice made after an untrusted read makes every argument carry the
session's `seen` label, which is level 1 (session labels) again. The
defence against steered selection is plan-then-execute (toolgate.plan),
where the planner picks handles and fields before any untrusted text is
read; in agent mode a steered choice can only pick a value whose own label
the policy still checks (its sources, and who may read it).

Any other object key starting with "$" is refused. The gateway decides on,
and the tool receives, the RESOLVED value. Each top-level argument's label is
passed to policy in a `PolicyContext`.

Session labels (level 1)
------------------------

Once a call returns a result whose label holds "untrusted", the session is
tainted for the rest of its life. Policy reads that with `session: tainted`.
In session mode no handles are issued and arguments are not resolved; labels
are still computed (for measurement) but not given to policy.

What this does and does not stop
--------------------------------

It stops misuse that stays inside the allowed arguments: a recipient the
grant allows but that came out of an attacker's email, a body holding a file
whose readers do not include the recipient, a URL carrying private text to
an allowed host. Argument constraints cannot express any of these, because
they look at one argument's VALUE and not at where it came from.

It cannot see implicit flows. Labels follow data, not decisions: if an agent
sends "yes" to Frank because the budget allows the price, the literal "yes"
is labeled by the context rule above (so in agent mode it carries the
budget's readers), but in plan mode a branch taken, or a call made or not
made, can still leak information that no label records. Whether a call
happened at all is visible to whoever receives it.

How this differs from CaMeL (Debenedetti et al., arXiv 2503.18813): CaMeL
runs the plan as code in its own interpreter around the model and tracks
control-flow dependencies inside the plan (a value computed inside a branch
on untrusted data is itself dependent on that data). This module enforces at
the TOOL BOUNDARY: it sees only the tool calls and the references they
carry, so it has no view of the agent's control flow and does not claim
CaMeL's guarantees. In agent mode the context rule over-approximates instead
(everything the agent saw); in plan mode the planner's control flow is fixed
before any data is read, which is what makes literals clean there.

This module assumes an agent runtime that passes handles. Real agents do not
do that unless they run in a plan-then-execute mode like toolgate.plan.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import re
import secrets
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from toolgate.policy import CLEAN, TAINTED, PolicyContext

USER, UNTRUSTED, PUBLIC = "user", "untrusted", "public"
SESSION, VALUE = "session", "value"
AGENT, PLANNER = "agent", "planner"
CODES = frozenset(
    {"unknown_handle", "bad_reference", "bad_path", "too_deep", "not_plain_data", "bad_session"}
)

_SOURCE = re.compile(r"user|untrusted|tool:[A-Za-z0-9_.:/-]{1,128}")
_HANDLE = re.compile(r"h-[A-Za-z0-9_-]{16,86}")
_MAX_DEPTH = 32


class ProvenanceError(ValueError):
    """A reference was refused. `code` is one of CODES and never quotes the input."""

    def __init__(self, code: str) -> None:
        self.code = code if code in CODES else "bad_reference"
        super().__init__(self.code)


def tool_source(name: str) -> str:
    return f"tool:{name}"


def _principal_ok(p: Any) -> bool:
    return type(p) is str and bool(p) and not any(c.isspace() for c in p)


def _domain(address: str) -> str | None:
    if address.startswith("*@") or address.count("@") != 1:
        return None
    return address.split("@")[1].lower()


def _covered(principal: str, readers: frozenset[str]) -> bool:
    """Is `principal` (an address or a domain principal) inside the set `readers`?"""
    if principal in readers:
        return True
    domain = _domain(principal)
    return domain is not None and f"*@{domain}" in readers


@dataclass(frozen=True)
class Label:
    """Where a value came from and who may read it. Immutable.

    `readers` is None for ANY (no restriction); otherwise a frozenset of
    principals. "public" in the readers means ANY and is normalized away.
    """

    sources: frozenset[str]
    readers: frozenset[str] | None = None

    def __post_init__(self) -> None:
        sources = frozenset(self.sources)
        if not all(type(s) is str and _SOURCE.fullmatch(s) for s in sources):
            raise ValueError("label sources must be user, untrusted or tool:<name>")
        object.__setattr__(self, "sources", sources)
        if self.readers is not None:
            readers = frozenset(self.readers)
            if not all(_principal_ok(p) for p in readers):
                raise ValueError("readers must be non-empty strings without whitespace")
            object.__setattr__(self, "readers", None if PUBLIC in readers else readers)

    @property
    def untrusted(self) -> bool:
        return UNTRUSTED in self.sources

    def readable_by(self, principal: str) -> bool:
        """May `principal` receive a value with this label?"""
        if type(principal) is not str:
            return False
        if self.readers is None:
            return True
        if principal == PUBLIC:
            return False
        return _covered(principal, self.readers)

    def join(self, other: Label) -> Label:
        """Union of sources, intersection of readers."""
        if self.readers is None:
            readers = other.readers
        elif other.readers is None:
            readers = self.readers
        else:
            readers = frozenset(p for p in self.readers if _covered(p, other.readers)) | frozenset(
                p for p in other.readers if _covered(p, self.readers)
            )
        return Label(self.sources | other.sources, readers)

    def to_json(self) -> dict[str, Any]:
        return {
            "sources": sorted(self.sources),
            "readers": "any" if self.readers is None else sorted(self.readers),
        }


BOTTOM = Label(frozenset(), None)  # identity of join: no sources, everyone may read
USER_LABEL = Label(frozenset({USER}), None)


def join_all(labels: Iterable[Label]) -> Label:
    out = BOTTOM
    for label in labels:
        out = out.join(label)
    return out


def random_handles() -> Callable[[], str]:
    """The default: 128 bits from `secrets` per handle."""
    return lambda: "h-" + secrets.token_urlsafe(16)


def keyed_handles(key: bytes) -> Callable[[], str]:
    """Deterministic but unguessable without `key`: HMAC-SHA256 of a counter.

    For reproducible runs (the sandbox). Whoever holds the key can predict
    handles, so a deployment uses `random_handles`.
    """
    counter = itertools.count(1)
    return lambda: (
        "h-" + hmac.new(key, str(next(counter)).encode(), hashlib.sha256).hexdigest()[:32]
    )


def _plain_json(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise ProvenanceError("not_plain_data") from None


@dataclass
class Session:
    """What the layer knows about one token id."""

    key: str
    tainted: bool = False
    seen: Label = USER_LABEL
    literals: str = AGENT  # AGENT: literals carry `seen`; PLANNER: literals are USER_LABEL
    handles: dict[str, tuple[str, Label]] = field(default_factory=dict)
    calls: int = 0

    def literal_label(self) -> Label:
        return USER_LABEL if self.literals == PLANNER else self.seen


Declare = Callable[[str, Mapping[str, Any], Any, Mapping[str, Label]], Label]


class Provenance:
    """The provenance layer: pass it to `Gateway(provenance=...)`.

    mode     "session" (level 1: taint only, no handles) or "value" (level 2)
    declare  the operator's label declarations for tool results
    handles  a function returning a fresh handle string (default random)

    The gateway calls `prepare`, `context` and `record`; a plan executor
    (toolgate.plan) also calls `use_planner_literals`, `derive` and `value`.
    Nothing here is reachable by an agent except through the gateway.
    """

    def __init__(
        self, declare: Declare, *, mode: str = VALUE, handles: Callable[[], str] | None = None
    ) -> None:
        if mode not in (SESSION, VALUE):
            raise ValueError("mode must be 'session' or 'value'")
        self.mode = mode
        self._declare = declare
        self._new_handle = handles or random_handles()
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()
        # One record per finished decision, for measurement and figures.
        self.history: list[dict[str, Any]] = []

    # -- sessions ---------------------------------------------------------------

    def session(self, key: str) -> Session:
        if type(key) is not str or not key:
            raise ProvenanceError("bad_session")
        with self._lock:
            if key not in self._sessions:
                self._sessions[key] = Session(key)
            return self._sessions[key]

    def tainted(self, key: str) -> bool:
        with self._lock:
            return key in self._sessions and self._sessions[key].tainted

    def use_planner_literals(self, key: str) -> None:
        """Mark a session as run by a plan executor: its literals come from the planner.

        Only trusted code calls this, for a token no model holds.
        """
        self.session(key).literals = PLANNER

    # -- handles ----------------------------------------------------------------

    def _store(self, s: Session, value: Any, label: Label) -> str:
        text = _plain_json(value)
        handle = self._new_handle()
        if not _HANDLE.fullmatch(handle) or handle in s.handles:
            raise ProvenanceError("bad_reference")  # a broken generator, never reuse
        s.handles[handle] = (text, label)
        return handle

    def _load(self, s: Session, handle: Any) -> tuple[Any, Label]:
        if type(handle) is not str or handle not in s.handles:
            raise ProvenanceError("unknown_handle")
        text, label = s.handles[handle]
        return json.loads(text), label

    def value(self, key: str, handle: str) -> Any:
        """A fresh copy of a stored value (for a plan executor; agents see results)."""
        with self._lock:
            return self._load(self.session(key), handle)[0]

    def label(self, key: str, handle: str) -> Label:
        with self._lock:
            return self._load(self.session(key), handle)[1]

    def derive(self, key: str, inputs: Iterable[str], value: Any, kind: str = "extract") -> str:
        """Store a value computed from stored values; its label is the join of theirs."""
        with self._lock:
            s = self.session(key)
            inputs = list(inputs)
            label = join_all(self._load(s, h)[1] for h in inputs)
            handle = self._store(s, value, label)
            s.seen = s.seen.join(label)
            self.history.append(
                {
                    "session": key,
                    "kind": kind,
                    "inputs": inputs,
                    "handle": handle,
                    "label": label.to_json(),
                }
            )
            return handle

    # -- resolving the wire form ------------------------------------------------

    def resolve_args(self, key: str, args: Any) -> tuple[Any, dict[str, Label], dict[str, list]]:
        """(resolved args, label per top-level argument, handles each one used)."""
        with self._lock:
            s = self.session(key)
            if type(args) is not dict:
                return args, {}, {}
            out: dict[str, Any] = {}
            labels: dict[str, Label] = {}
            used: dict[str, list[str]] = {}
            for name, node in args.items():
                refs: list[str] = []
                out[name], labels[name] = self._resolve(s, node, refs, 0)
                used[name] = refs
            return out, labels, used

    def _resolve(self, s: Session, node: Any, refs: list[str], depth: int) -> tuple[Any, Label]:
        if depth > _MAX_DEPTH:
            raise ProvenanceError("too_deep")
        literal = s.literal_label()
        if type(node) is dict:
            special = [k for k in node if type(k) is str and k.startswith("$")]
            if not special:
                out, label = {}, literal
                for k, v in node.items():
                    out[k], part = self._resolve(s, v, refs, depth + 1)
                    label = label.join(part)
                return out, label
            if "$ref" in node:
                if set(node) - {"$ref", "path"}:
                    raise ProvenanceError("bad_reference")
                path = node.get("path", [])
                if type(path) is not list:
                    raise ProvenanceError("bad_path")
                value, label = self._load(s, node["$ref"])
                refs.append(node["$ref"])
                for step in path:
                    value = _select(value, step)
                return value, label
            if set(node) == {"$concat"}:
                parts = node["$concat"]
                if type(parts) is not list:
                    raise ProvenanceError("bad_reference")
                # One part arranges nothing; none, or two or more, is the writer's text.
                texts, label = [], BOTTOM if len(parts) == 1 else literal
                for part in parts:
                    value, part_label = self._resolve(s, part, refs, depth + 1)
                    texts.append(_text(value))
                    label = label.join(part_label)
                return "".join(texts), label
            if set(node) == {"$urlencode"}:
                value, label = self._resolve(s, node["$urlencode"], refs, depth + 1)
                return quote(_text(value), safe=""), label
            raise ProvenanceError("bad_reference")
        if type(node) is list:
            out_list, label = [], BOTTOM if len(node) == 1 else literal
            for item in node:
                value, part = self._resolve(s, item, refs, depth + 1)
                out_list.append(value)
                label = label.join(part)
            return out_list, label
        return node, literal

    # -- the gateway's hooks ----------------------------------------------------

    def prepare(self, key: str, tool: str, args: Any) -> tuple[Any, dict[str, Label], dict]:
        """Before the decision: resolve references (value mode) and label each argument."""
        with self._lock:
            s = self.session(key)
            if self.mode == VALUE:
                return self.resolve_args(key, args)
            literal = s.literal_label()
            names = list(args) if type(args) is dict else []
            return args, {n: literal for n in names}, {n: [] for n in names}

    def context(self, key: str, labels: Mapping[str, Label] | None) -> PolicyContext:
        """What policy may know about this call: the session state, and labels in value mode."""
        with self._lock:
            state = TAINTED if self.tainted(key) else CLEAN
            return PolicyContext(state, dict(labels or {}) if self.mode == VALUE else None)

    def record(
        self,
        key: str,
        tool: str,
        args: Mapping[str, Any],
        outcome: Any,
        labels: Mapping[str, Label] | None,
        used: Mapping[str, list] | None = None,
    ) -> str | None:
        """After the decision. Stores an allowed result and returns its handle (value mode).

        The result is what the agent is given, so it joins the session's
        `seen` label, and an untrusted result taints the session.
        """
        with self._lock:
            s = self.session(key)
            labels = dict(labels or {})
            entry: dict[str, Any] = {
                "session": key,
                "kind": "call",
                "step": s.calls,
                "tool": tool,
                "tainted_before": s.tainted,
                "args": {
                    name: {"label": label.to_json(), "refs": list((used or {}).get(name, []))}
                    for name, label in labels.items()
                },
                "status": outcome.status,
                "stage": outcome.stage,
                "rule": outcome.rule,
                "handle": None,
                "result_label": None,
            }
            if outcome.status != "pending":
                s.calls += 1
            handle = None
            if outcome.status == "allowed":
                label = self._declare(tool, args, outcome.result, labels)
                if type(label) is not Label:
                    raise ValueError("declare must return a Label")
                if self.mode == VALUE:
                    handle = self._store(s, outcome.result, label)
                s.seen = s.seen.join(label)
                if label.untrusted:
                    s.tainted = True
                entry["handle"], entry["result_label"] = handle, label.to_json()
            self.history.append(entry)
            return handle


def _text(value: Any) -> str:
    return value if type(value) is str else json.dumps(value, sort_keys=True)


def _select(value: Any, step: Any) -> Any:
    if type(step) is str and type(value) is dict and step in value:
        return value[step]
    if type(step) is int and type(value) is list and -len(value) <= step < len(value):
        return value[step]
    raise ProvenanceError("bad_path")
