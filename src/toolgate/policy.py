"""Operator policy: what the organization permits, checked after the grant.

A grant says what the USER delegated. Policy says what the ORGANIZATION
permits. A call runs only if both agree, and policy is evaluated on every
call, after the grant check.

File format (YAML, version 1)
-----------------------------

    version: 1
    rules:
      - id: approve-external-email      # unique string
        effect: approve                 # allow | deny | approve
        tools: ["send_*"]               # glob patterns, "*" is the only wildcard
        when:                           # optional: argument -> {operator: value}
          attachments: {max: 3}
        unless:                         # optional: same shape as `when`
          to: {glob: "*@example.com"}
        absent: [bcc]                   # optional: arguments that must not be present
        reason: External mail needs a human.   # optional free text

`when` and `unless` reuse the constraint language of capabilities (eq, in,
max, glob, any), so the project has one constraint language. Several operators
on one argument are a conjunction. The per-argument operator mapping is where
the provenance operators of plan section 3.7 (`source_in`, `readers_include`)
will be added later; nothing here implements them, and until then they are
rejected as unknown operators.

Decision
--------

Collect every rule that matches the call. Deny beats approve, approve beats
allow, and if no rule matches the answer is deny (default deny). The reported
rule is the first matching rule of the winning effect, in file order. The
order of rules never changes the effect, only which rule id is reported.

Matching
--------

Policy is open-world, unlike capabilities: arguments a rule does not mention
are ignored. (A capability is a whitelist written for one call shape, so an
unmentioned argument is a hole. A policy rule is a statement about many tools
at once and cannot list every argument of each.)

A rule can only match if the tool name matches one of its patterns and none
of its `absent` arguments is present. Then each condition is evaluated to one
of three values:

    TRUE     the argument is present and satisfies the operator
    FALSE    the argument is present, has a type the operator can compare,
             and does not satisfy it
    UNKNOWN  the argument is missing, or its type cannot be compared with the
             rule's value (a list where a string is expected, a string where
             a number is expected, null, a nested object, ...)

`any` is a pure presence test, so it is never UNKNOWN: TRUE if the argument is
present, FALSE if it is not. `absent` is likewise definite.

The two kinds of rule then read UNKNOWN in opposite directions, always toward
the more restrictive outcome:

    allow rule          matches only if every `when` condition is TRUE, and,
                        if it has `unless`, some `unless` condition is FALSE.
    deny/approve rule   matches unless some `when` condition is FALSE, or it
                        has `unless` and every `unless` condition is TRUE.

In one sentence: an allow rule fires only when everything is proven in the
call's favour; a restrictive rule fires unless something is proven that lets
the call off.

Why. The naive single rule ("a condition on a missing argument does not
hold") is right for allow rules and a loophole for deny rules. Take

    deny send_email when to glob "*@evil.com"

Under the naive rule a call that sends `to` as a list (["x@evil.com"]), or
omits `to` and lets the tool fall back to a default recipient, does not match
the deny rule and goes on to an allow rule. The gateway cannot know how the
tool treats a missing or oddly typed argument, so it must assume the worst.
With three values the deny rule matches both calls. The cost is some
over-blocking: a deny rule with a value condition also catches calls that
leave that argument out. An author who really means "only when the argument
is present" says so by adding `any: true` next to the value operator, because
`any` is FALSE on a missing argument:

    when: {to: {any: true, glob: "*@evil.com"}}

`unless` exists because the precedence order has no other way to say
"restrict everything except X": an allow rule for X cannot override an approve
rule. It follows the same pessimism: the exception to a restrictive rule
applies only when it is proven.

Loading
-------

Everything is validated when the policy is loaded and nothing at decision
time: unknown keys, effects and operators, duplicate rule ids, duplicate
mapping keys, non-string keys, YAML anchors, aliases and merge keys, and
plain scalars that YAML 1.1 would silently reinterpret (`no`, `on`, `010`,
`1:30`, `1_000`) all raise `PolicyError`. The loader is a subclass of
`yaml.SafeLoader` that only removes features; `yaml.safe_load` alone cannot
see duplicate keys, because it keeps the last one silently.

Limits: conditions address top-level arguments only. Matching is exact string
comparison with no Unicode normalization and no path canonicalization, so the
gateway must hand the policy the same canonical tool name and argument values
the tool will act on.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from toolgate.capability import Call
from toolgate.constraints import OPS, Constraint, glob_match

ALLOW, DENY, APPROVE = "allow", "deny", "approve"
EFFECTS: tuple[str, ...] = (ALLOW, DENY, APPROVE)
OPERATORS: frozenset[str] = OPS  # M4b adds the provenance operators here
MAX_POLICY_BYTES = 1_000_000

_TOP_KEYS = frozenset({"version", "rules"})
_RULE_KEYS = frozenset({"id", "effect", "tools", "when", "unless", "absent", "reason"})
_INT = re.compile(r"-?(0|[1-9][0-9]*)")
_FLOAT = re.compile(r"-?(0|[1-9][0-9]*)\.[0-9]+([eE][-+]?[0-9]+)?")


class PolicyError(ValueError):
    """The policy could not be loaded. Raised at load time only."""


# --------------------------------------------------------------------------- YAML


def _where(node: yaml.Node) -> str:
    return f"line {node.start_mark.line + 1}"


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader with the surprising parts of YAML removed."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            line = event.start_mark.line + 1
            raise PolicyError(f"line {line}: YAML anchors and aliases are not allowed")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
        # No merge-key handling on purpose: "<<" has no constructor here and fails.
        if not isinstance(node, yaml.MappingNode):
            raise PolicyError(f"{_where(node)}: expected a mapping")
        out: dict[str, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if type(key) is not str:
                raise PolicyError(
                    f"{_where(key_node)}: mapping key {key!r} is not a string (quote it)"
                )
            if key in out:
                raise PolicyError(f"{_where(key_node)}: duplicate key {key!r}")
            out[key] = self.construct_object(value_node, deep=deep)
        return out


def _strict_bool(loader: _StrictLoader, node: yaml.ScalarNode) -> bool:
    if node.value not in ("true", "false"):
        raise PolicyError(
            f"{_where(node)}: {node.value[:40]!r} is ambiguous, YAML reads it as a boolean; "
            "write true or false, or quote it to mean the text"
        )
    return node.value == "true"


def _strict_int(loader: _StrictLoader, node: yaml.ScalarNode) -> int:
    if not _INT.fullmatch(node.value) or len(node.value) > 30:
        raise PolicyError(
            f"{_where(node)}: {node.value[:40]!r} is ambiguous, YAML reads it as a number; "
            "write a plain decimal integer, or quote it to mean the text"
        )
    return int(node.value)


def _strict_float(loader: _StrictLoader, node: yaml.ScalarNode) -> float:
    if not _FLOAT.fullmatch(node.value) or len(node.value) > 30:
        raise PolicyError(
            f"{_where(node)}: {node.value[:40]!r} is ambiguous, YAML reads it as a number; "
            "write a plain decimal such as 1.5, or quote it to mean the text"
        )
    return float(node.value)


_StrictLoader.add_constructor("tag:yaml.org,2002:bool", _strict_bool)
_StrictLoader.add_constructor("tag:yaml.org,2002:int", _strict_int)
_StrictLoader.add_constructor("tag:yaml.org,2002:float", _strict_float)


def _load_yaml(text: str) -> Any:
    if type(text) is not str:
        raise PolicyError("policy text must be a string")
    if len(text) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy is larger than {MAX_POLICY_BYTES} bytes")
    try:
        return yaml.load(text, Loader=_StrictLoader)  # noqa: S506 (a SafeLoader subclass)
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML: {exc}") from exc
    except RecursionError as exc:
        raise PolicyError("invalid YAML: nested too deeply") from exc


# --------------------------------------------------------------------------- rules


def _kind(value: Any) -> str | None:
    """The comparable kind of a call argument, or None if it has none."""
    if type(value) is bool:
        return "bool"
    if type(value) is str:
        return "str"
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return "number"
    return None


def evaluate(condition: Constraint, args: Mapping[str, Any]) -> bool | None:
    """Three-valued result of one condition: True, False, or None for UNKNOWN."""
    if condition.arg not in args:
        return False if condition.op == "any" else None
    if condition.op == "any":
        return True
    value = args[condition.arg]
    if condition.holds(value):
        return True
    kind = _kind(value)
    if condition.op == "max":
        comparable = kind == "number"
    elif condition.op == "glob":
        comparable = kind == "str"
    else:  # eq, in: comparable if some listed value has the argument's kind
        comparable = kind is not None and any(
            _kind(v) == kind for v in condition.finite_values() or ()
        )
    return False if comparable else None


def _names(value: Any, what: str) -> tuple[str, ...]:
    if type(value) not in (list, tuple) or not value:
        raise PolicyError(f"{what} must be a non-empty list of strings")
    if not all(type(v) is str and v for v in value):
        raise PolicyError(f"{what} must be a non-empty list of non-empty strings")
    if len(set(value)) != len(value):
        raise PolicyError(f"{what} lists the same name twice")
    return tuple(value)


def _conditions(value: Any, what: str) -> tuple[Constraint, ...]:
    if type(value) is not dict or not value:
        raise PolicyError(f"{what} must be a non-empty mapping of argument to operators")
    out = []
    for arg, ops in value.items():
        if type(arg) is not str or not arg:
            raise PolicyError(f"{what}: argument names must be non-empty strings")
        if type(ops) is not dict or not ops:
            raise PolicyError(f"{what}: argument {arg!r} needs a mapping of operator to value")
        for op, operand in ops.items():
            if type(op) is not str or op not in OPERATORS:
                raise PolicyError(f"{what}: unknown operator {op!r} on argument {arg!r}")
            if op == "any":
                if operand is not True:
                    raise PolicyError(f"{what}: write `any: true` on argument {arg!r}")
                operand = None
            try:
                out.append(Constraint(arg, op, operand))
            except ValueError as exc:
                raise PolicyError(f"{what}: argument {arg!r}: {exc}") from exc
    return tuple(out)


@dataclass(frozen=True)
class Rule:
    """One validated policy rule. Build with `Rule.from_dict` or directly."""

    id: str
    effect: str
    tools: tuple[str, ...]
    when: tuple[Constraint, ...] = ()
    unless: tuple[Constraint, ...] = ()
    absent: tuple[str, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        if type(self.id) is not str or not self.id:
            raise PolicyError(f"rule id must be a non-empty string, got {self.id!r}")
        what = f"rule {self.id!r}"
        if type(self.effect) is not str or self.effect not in EFFECTS:
            raise PolicyError(f"{what}: unknown effect {self.effect!r}")
        object.__setattr__(self, "tools", _names(self.tools, f"{what}: tools"))
        for name in ("when", "unless"):
            value = tuple(getattr(self, name))
            if not all(type(c) is Constraint for c in value):
                raise PolicyError(f"{what}: {name} must hold Constraint objects")
            object.__setattr__(self, name, value)
        if self.absent:
            object.__setattr__(self, "absent", _names(self.absent, f"{what}: absent"))
            clash = sorted({c.arg for c in self.when} & set(self.absent))
            if clash:
                raise PolicyError(f"{what}: argument {clash[0]!r} is in both when and absent")
        else:
            object.__setattr__(self, "absent", ())
        if self.reason is not None and type(self.reason) is not str:
            raise PolicyError(f"{what}: reason must be a string")

    @classmethod
    def from_dict(cls, data: Any) -> Rule:
        if type(data) is not dict:
            raise PolicyError("each rule must be a mapping")
        rule_id = data.get("id")
        if type(rule_id) is not str or not rule_id:
            raise PolicyError(f"rule id must be a non-empty string, got {rule_id!r}")
        what = f"rule {rule_id!r}"
        unknown = sorted(str(k) for k in set(data) - _RULE_KEYS)
        if unknown:
            raise PolicyError(f"{what}: unknown key {unknown[0]!r}")
        for key in ("effect", "tools"):
            if key not in data:
                raise PolicyError(f"{what}: missing key {key!r}")
        if type(data["tools"]) is not list:
            raise PolicyError(f"{what}: tools must be a non-empty list of strings")
        if "absent" in data and type(data["absent"]) is not list:
            raise PolicyError(f"{what}: absent must be a non-empty list of strings")
        if "reason" in data and type(data["reason"]) is not str:
            raise PolicyError(f"{what}: reason must be a string")
        return cls(
            id=rule_id,
            effect=data["effect"],
            tools=tuple(data["tools"]),
            when=_conditions(data["when"], f"{what}: when") if "when" in data else (),
            unless=_conditions(data["unless"], f"{what}: unless") if "unless" in data else (),
            absent=_names(data["absent"], f"{what}: absent") if "absent" in data else (),
            reason=data.get("reason"),
        )

    def matches(self, call: Call) -> bool:
        """Does this rule apply to the call? See the module docstring for the semantics."""
        if not any(glob_match(pattern, call.tool) for pattern in self.tools):
            return False
        args = call.args
        if any(name in args for name in self.absent):
            return False
        when = [evaluate(c, args) for c in self.when]
        unless = [evaluate(c, args) for c in self.unless]
        if self.effect == ALLOW:
            # Proven: every condition TRUE, and the exception proven not to apply.
            return all(v is True for v in when) and (not unless or any(v is False for v in unless))
        # Restrictive: applies unless a condition is proven FALSE or the exception proven.
        if any(v is False for v in when):
            return False
        return not (unless and all(v is True for v in unless))


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome for one call. `rule_id` is None only for the default deny."""

    effect: str
    rule_id: str | None
    reason: str


@dataclass(frozen=True)
class Policy:
    """An ordered, validated list of rules."""

    rules: tuple[Rule, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rules", tuple(self.rules))
        seen: set[str] = set()
        for rule in self.rules:
            if type(rule) is not Rule:
                raise PolicyError("rules must be Rule objects")
            if rule.id in seen:
                raise PolicyError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)

    @classmethod
    def from_dict(cls, data: Any) -> Policy:
        """Build from already parsed data: {"version": 1, "rules": [...]}."""
        if type(data) is not dict:
            raise PolicyError("policy must be a mapping with `version` and `rules`")
        unknown = sorted(str(k) for k in set(data) - _TOP_KEYS)
        if unknown:
            raise PolicyError(f"unknown top-level key {unknown[0]!r}")
        version = data.get("version")
        if type(version) is not int or version != 1:
            raise PolicyError(f"unsupported policy version {version!r}, expected 1")
        rules = data.get("rules")
        if type(rules) is not list:
            raise PolicyError("`rules` must be a list (use [] for a deny-everything policy)")
        return cls(tuple(Rule.from_dict(r) for r in rules))

    @classmethod
    def from_yaml(cls, text: str) -> Policy:
        return cls.from_dict(_load_yaml(text))

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        try:
            with open(path, "rb") as handle:
                raw = handle.read(MAX_POLICY_BYTES + 1)
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise PolicyError(f"cannot read policy file: {exc}") from exc
        return cls.from_yaml(text)

    def decide(self, call: Call) -> PolicyDecision:
        """Deny beats approve beats allow; no matching rule means deny."""
        if type(call) is not Call:
            return PolicyDecision(DENY, None, "not a Call")
        first: dict[str, Rule] = {}
        for rule in self.rules:
            if rule.effect not in first and rule.matches(call):
                first[rule.effect] = rule
                if rule.effect == DENY:
                    break
        for effect in (DENY, APPROVE, ALLOW):
            if effect in first:
                rule = first[effect]
                return PolicyDecision(effect, rule.id, rule.reason or f"matched rule {rule.id!r}")
        return PolicyDecision(DENY, None, "no rule matched (default deny)")
