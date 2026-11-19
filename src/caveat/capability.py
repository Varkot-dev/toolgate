"""Calls, capabilities and grants, and the decision `allows(call)`.

A capability names one tool and constrains its arguments. The rules are
closed-world and fail closed:

  * the call's tool must be the capability's tool
  * every argument in the call must be named by at least one constraint
  * every constraint must hold, and a constraint on a missing argument fails

So a capability with no constraints permits only a call with no arguments,
and an argument nobody thought about (say `bcc`) is refused, not waved through.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from caveat.constraints import Constraint

_MISSING = object()
_MAX_DEPTH = 32

# Limits on what a Call may carry. Each one exists so that every Call that can
# be built can also be written to the audit log (see the Call docstring).

# An integer argument must satisfy abs(n) < 2**MAX_INT_BITS. The audit log
# writes integers in decimal, and Python refuses to convert an int of more than
# 4300 digits to a string. 2**4096 has 1234 digits, well under that limit.
MAX_INT_BITS = 4096
# Longest tool name and longest argument name (at any depth), in characters.
MAX_NAME_LENGTH = 256
# Most arguments at one level: the top level or any nested object.
MAX_ARGS_PER_LEVEL = 256
# Most nodes in the arguments as a whole. Every scalar and every container
# counts as one node, including the top-level arguments object itself.
MAX_ARG_NODES = 10_000

# A lone surrogate (U+D800 to U+DFFF) cannot be encoded as UTF-8.
_SURROGATE = re.compile("[\ud800-\udfff]")


def _check_text(value: str, what: str) -> None:
    if _SURROGATE.search(value):
        raise ValueError(f"{what} contains a surrogate code point")


def _check_name(name: str, what: str) -> None:
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"{what} is longer than {MAX_NAME_LENGTH} characters")
    _check_text(name, what)


def _plain(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Copy JSON-like data into fresh builtin objects, rejecting anything else.

    Only exact builtin types pass: a subclass of str or dict can override
    hashing, equality or iteration and show the checker one thing and the
    tool another. Values the audit log could not record are rejected too:
    non-finite floats, strings with surrogates, integers of MAX_INT_BITS bits
    or more, and data past the name, width and node limits above.

    `budget` is a one-item list holding how many nodes may still be visited.
    It is shared by the whole walk, so the limit is on the total.
    """
    if budget is None:
        budget = [MAX_ARG_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError(f"arguments contain more than {MAX_ARG_NODES} values")
    if depth > _MAX_DEPTH:
        raise ValueError("arguments are nested too deeply")
    t = type(value)
    if value is None or t is bool:
        return value
    if t is int:
        # bit_length() > MAX_INT_BITS is the same as abs(value) >= 2**MAX_INT_BITS
        if value.bit_length() > MAX_INT_BITS:
            raise ValueError(f"integer argument needs more than {MAX_INT_BITS} bits")
        return value
    if t is float:
        if not math.isfinite(value):
            raise ValueError("NaN and infinity are not permitted in arguments")
        return value
    if t is str:
        _check_text(value, "string argument")
        return value
    if t in (list, tuple):
        return tuple(_plain(v, depth + 1, budget) for v in value)
    if t is dict:
        if len(value) > MAX_ARGS_PER_LEVEL:
            raise ValueError(f"more than {MAX_ARGS_PER_LEVEL} arguments at one level")
        out = {}
        for k, v in value.items():
            if type(k) is not str:
                raise ValueError("argument names must be strings")
            _check_name(k, "argument name")
            out[k] = _plain(v, depth + 1, budget)
        return MappingProxyType(out)
    raise ValueError(f"unsupported argument type {t.__name__}")


def _is_time(value: Any) -> bool:
    return type(value) is int or (type(value) is float and math.isfinite(value))


@dataclass(frozen=True)
class Call:
    """A tool call as the gateway sees it: a tool name and named arguments.

    Construction takes a private, read-only copy of the arguments made only of
    builtin JSON types (lists become tuples). The gateway must decide on this
    copy and forward this copy, so what was checked is what runs. Anything that
    is not plain JSON data raises ValueError, which the gateway treats as deny.

    Rule: every Call that can be built can be recorded in the audit log.
    Reason: the gateway decides on Calls and logs each decision, and the log
    refuses data it cannot write as canonical JSON. If a Call could hold such
    data, an attacker could send it on purpose and make attempts that leave no
    record. So construction also raises ValueError for:

      * a float that is NaN, inf or -inf, anywhere in the arguments
      * a surrogate code point (U+D800 to U+DFFF) in the tool name, in an
        argument name or in a string value, at any depth
      * an integer n with abs(n) >= 2**MAX_INT_BITS
      * a tool name or argument name longer than MAX_NAME_LENGTH characters
      * more than MAX_ARGS_PER_LEVEL arguments at one level
      * more than MAX_ARG_NODES values in total (scalars and containers)

    Constraint values are not limited this way. A constraint literal that no
    Call can carry (a surrogate string, a huge integer) simply never matches.
    """

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.tool) is not str or not self.tool:
            raise ValueError("tool name must be a non-empty string")
        _check_name(self.tool, "tool name")
        if type(self.args) not in (dict, MappingProxyType):
            raise ValueError("arguments must be a dict")
        object.__setattr__(self, "args", _plain(dict(self.args)))


# Machine-readable codes a Decision made in this module can carry. `reason` is
# for people and may quote the caller's own tool and argument names; `code` is
# one of these fixed words and is the only part fit for a log.
DECISION_CODES: frozenset[str] = frozenset(
    {
        "ok",
        "not_a_call",
        "wrong_tool",
        "no_capability",
        "argument_not_permitted",
        "argument_missing",
        "constraint_failed",
        "expired",
        "invalid_time",
    }
)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    capability: int | None = None  # index of the capability that permitted the call
    # One of DECISION_CODES, or "" when whoever built the Decision set none.
    # Not part of equality: two decisions with the same answer and reason are equal.
    code: str = field(default="", compare=False)

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class Capability:
    tool: str
    constraints: tuple[Constraint, ...] = ()
    max_calls: int | None = None  # call budget; enforced by the token ledger

    def __post_init__(self) -> None:
        if type(self.tool) is not str or not self.tool:
            raise ValueError("tool name must be a non-empty string")
        object.__setattr__(self, "constraints", tuple(self.constraints))
        if not all(type(c) is Constraint for c in self.constraints):
            raise ValueError("constraints must be Constraint objects")
        if self.max_calls is not None and (type(self.max_calls) is not int or self.max_calls < 1):
            raise ValueError("max_calls must be a positive integer")

    @property
    def arg_names(self) -> frozenset[str]:
        return frozenset(c.arg for c in self.constraints)

    def decide(self, call: Call) -> Decision:
        """Stateless check of one call. The call budget is not consulted here."""
        if type(call) is not Call:
            return Decision(False, "not a Call", code="not_a_call")
        if call.tool != self.tool:
            return Decision(False, f"tool {call.tool!r} is not {self.tool!r}", code="wrong_tool")
        extra = sorted(a for a in call.args if a not in self.arg_names)
        if extra:
            return Decision(
                False, f"argument {extra[0]!r} is not permitted", code="argument_not_permitted"
            )
        for c in self.constraints:
            value = call.args.get(c.arg, _MISSING)
            if value is _MISSING:
                return Decision(False, f"argument {c.arg!r} is missing", code="argument_missing")
            if not c.holds(value):
                return Decision(False, f"argument {c.arg!r} fails {c.op}", code="constraint_failed")
        return Decision(True, "ok", code="ok")

    def permits(self, call: Call) -> bool:
        return self.decide(call).allowed

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Capability:
        """Parse {"tool": t, "args": {name: {op: value, ...}}, "max_calls": n}.

        Unknown keys and unknown operators raise ValueError: a grant that
        cannot be fully understood is never built.
        """
        if not isinstance(data, Mapping):
            raise ValueError("capability must be a mapping")
        unknown = set(data) - {"tool", "args", "max_calls"}
        if unknown:
            raise ValueError(f"unknown capability keys {sorted(map(repr, unknown))}")
        args = data.get("args", {})
        if not isinstance(args, Mapping):
            raise ValueError("args must be a mapping")
        constraints = []
        for arg, ops in args.items():
            if not isinstance(ops, Mapping) or not ops:
                raise ValueError(f"argument {arg!r} needs at least one operator")
            for op, value in ops.items():
                if op == "any":
                    if value is not True:
                        raise ValueError("any must be written as {'any': true}")
                    value = None
                constraints.append(Constraint(arg, op, value))
        return cls(data.get("tool"), tuple(constraints), data.get("max_calls"))

    def to_dict(self) -> dict[str, Any]:
        args: dict[str, dict[str, Any]] = {}
        for c in self.constraints:
            if c.op in args.setdefault(c.arg, {}):
                raise ValueError(f"cannot serialize two {c.op} constraints on {c.arg!r}")
            value = True if c.op == "any" else c.value
            args[c.arg][c.op] = list(value) if c.op == "in" else value
        out: dict[str, Any] = {"tool": self.tool, "args": args}
        if self.max_calls is not None:
            out["max_calls"] = self.max_calls
        return out


@dataclass(frozen=True)
class Grant:
    """What was delegated: a set of capabilities and when the grant expires.

    `expires_at` is seconds since the Unix epoch. The delegation chain is
    carried by the token layer, not here.
    """

    capabilities: tuple[Capability, ...]
    expires_at: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        if not all(type(c) is Capability for c in self.capabilities):
            raise ValueError("capabilities must be Capability objects")
        if not _is_time(self.expires_at):
            raise ValueError("expires_at must be a finite number")

    def decide(self, call: Call, now: float) -> Decision:
        """Allow if the grant is unexpired and some capability permits the call."""
        if type(call) is not Call:
            return Decision(False, "not a Call", code="not_a_call")
        if not _is_time(now):
            return Decision(False, "invalid time", code="invalid_time")
        if not now < self.expires_at:
            return Decision(False, "grant expired", code="expired")
        reason, code = f"no capability for tool {call.tool!r}", "no_capability"
        for i, cap in enumerate(self.capabilities):
            d = cap.decide(call)
            if d.allowed:
                return Decision(True, "ok", i, code="ok")
            if cap.tool == call.tool:
                reason, code = d.reason, d.code
        return Decision(False, reason, code=code)

    def allows(self, call: Call, now: float) -> bool:
        return self.decide(call, now).allowed

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Grant:
        if not isinstance(data, Mapping):
            raise ValueError("grant must be a mapping")
        unknown = set(data) - {"capabilities", "expires_at"}
        if unknown:
            raise ValueError(f"unknown grant keys {sorted(map(repr, unknown))}")
        caps = data.get("capabilities")
        if not isinstance(caps, (list, tuple)):
            raise ValueError("capabilities must be a list")
        return cls(tuple(Capability.from_dict(c) for c in caps), data.get("expires_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [c.to_dict() for c in self.capabilities],
            "expires_at": self.expires_at,
        }
