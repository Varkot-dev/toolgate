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

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from toolgate.constraints import Constraint

_MISSING = object()


@dataclass(frozen=True)
class Call:
    """A tool call as the gateway sees it: a tool name and named arguments."""

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    capability: int | None = None  # index of the capability that permitted the call

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class Capability:
    tool: str
    constraints: tuple[Constraint, ...] = ()
    max_calls: int | None = None  # call budget; enforced by the token ledger (M1)

    def __post_init__(self) -> None:
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError("tool name must be a non-empty string")
        object.__setattr__(self, "constraints", tuple(self.constraints))
        if not all(isinstance(c, Constraint) for c in self.constraints):
            raise ValueError("constraints must be Constraint objects")
        if self.max_calls is not None and (
            isinstance(self.max_calls, bool)
            or not isinstance(self.max_calls, int)
            or self.max_calls < 1
        ):
            raise ValueError("max_calls must be a positive integer")

    @property
    def arg_names(self) -> frozenset[str]:
        return frozenset(c.arg for c in self.constraints)

    def decide(self, call: Call) -> Decision:
        """Stateless check of one call. The call budget is not consulted here."""
        if call.tool != self.tool:
            return Decision(False, f"tool {call.tool!r} is not {self.tool!r}")
        if not isinstance(call.args, Mapping):
            return Decision(False, "arguments are not a mapping")
        extra = sorted(str(a) for a in call.args if a not in self.arg_names)
        if extra:
            return Decision(False, f"argument {extra[0]!r} is not permitted")
        for c in self.constraints:
            value = call.args.get(c.arg, _MISSING)
            if value is _MISSING:
                return Decision(False, f"argument {c.arg!r} is missing")
            if not c.holds(value):
                return Decision(False, f"argument {c.arg!r} fails {c.op}")
        return Decision(True, "ok")

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
            raise ValueError(f"unknown capability keys {sorted(unknown)}")
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
    carried by the token layer (M1), not here.
    """

    capabilities: tuple[Capability, ...]
    expires_at: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "capabilities", tuple(self.capabilities))
        if not all(isinstance(c, Capability) for c in self.capabilities):
            raise ValueError("capabilities must be Capability objects")
        e = self.expires_at
        if isinstance(e, bool) or not isinstance(e, (int, float)) or e != e:
            raise ValueError("expires_at must be a number")

    def decide(self, call: Call, now: float) -> Decision:
        """Allow if the grant is unexpired and some capability permits the call."""
        if not now < self.expires_at:
            return Decision(False, "grant expired")
        reason = f"no capability for tool {call.tool!r}"
        for i, cap in enumerate(self.capabilities):
            d = cap.decide(call)
            if d.allowed:
                return Decision(True, "ok", i)
            if cap.tool == call.tool:
                reason = d.reason
        return Decision(False, reason)

    def allows(self, call: Call, now: float) -> bool:
        return self.decide(call, now).allowed

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Grant:
        if not isinstance(data, Mapping):
            raise ValueError("grant must be a mapping")
        unknown = set(data) - {"capabilities", "expires_at"}
        if unknown:
            raise ValueError(f"unknown grant keys {sorted(unknown)}")
        caps = data.get("capabilities")
        if not isinstance(caps, (list, tuple)):
            raise ValueError("capabilities must be a list")
        return cls(tuple(Capability.from_dict(c) for c in caps), data.get("expires_at"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "capabilities": [c.to_dict() for c in self.capabilities],
            "expires_at": self.expires_at,
        }
