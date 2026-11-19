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
on one argument are a conjunction.

Provenance conditions (plan section 3.7, milestone M4b)
-------------------------------------------------------

Two more per-argument operators and one rule key read where the arguments
CAME FROM rather than what they are. They are only ever evaluated against a
`PolicyContext` handed in by trusted code (caveat.provenance), never
against anything the caller sends.

    source_in: [user, "tool:search_contacts"]
        every source in the argument's label is in the list
    readers_include: to                    (the name of another argument)
    readers_include: {literal: public}     (a fixed principal)
        every destination principal (a string, or each string of a list) is
        an allowed reader of the argument's value
    session: tainted                       (rule key, not an argument operator)
        the session has returned a result from a tool whose output is
        untrusted (plan 3.7, level 1)

They fit the three-valued logic like every other condition. A provenance
condition is UNKNOWN when there is no context, when the argument has no
label in it, when the argument is missing, or (readers_include) when the
destination argument is missing or not a string or list of strings. So with
no provenance layer configured, an allow rule that needs a provenance
condition never fires, and a deny or approve rule with one always does: the
missing layer fails closed. `session: tainted` is TRUE in a tainted session,
FALSE in a clean one and UNKNOWN with no context.

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

Numbers. YAML 1.1 (what PyYAML implements) and YAML 1.2 disagree about which
unquoted scalars are numbers: `1e3` is text in 1.1 and 1000.0 in 1.2, `0o17`
is text in 1.1 and 15 in 1.2, `010` is 8 in 1.1 and 10 in 1.2. So an unquoted
scalar that looks numeric must be a plain decimal integer (`1000`) or a plain
decimal number with digits on both sides of the point (`1.5`); every other
numeric-looking form, exponents included, must be quoted to mean text or is
refused. A decimal that a float cannot hold to the digits written
(`9007199254740993.0`) is refused as well, because the rule would compare
against a different number than the one in the file. `%YAML` and `%TAG`
directives are refused: the loader cannot honour a requested version, and
pretending to would be worse than saying so.

Also refused: a file larger than `MAX_POLICY_BYTES` (measured in bytes, and
never read in part); a tool pattern holding whitespace or a control character
(which is also what an unquoted scalar running over several lines turns into);
and, when loading YAML, a rule that names one argument in both `absent` and
`unless`, since the exception could never be proven.

What a policy author must know
------------------------------

Each of these is a property of the language, not a bug, and `Policy.warnings`
lists the ones that can be spotted mechanically ((a) and (c)).

(a) `absent` and `any` are pure presence tests. On a RESTRICTIVE rule (deny or
    approve) the caller decides whether the rule applies.

        approve transfer absent: [confirmation]
        is dodged by sending  confirmation: null

(b) Approve rules do not preserve default deny. An approve rule creates a path
    to execution (through a human) for calls that no allow rule covers.

        approve "*"  with no allow rule at all: every tool can run once a
        person clicks yes

(c) Deny rules match exact strings. Tool names and values must be made
    canonical upstream (case, whitespace, Unicode look-alikes), and a broad
    allow next to an exact deny is fragile. Prefer listing what is allowed.

        allow "*" plus deny delete_file  lets "Delete_File" through if the
        tool layer folds case

(d) A glob on a recipient-style string proves the shape of the string only.
    Tools must take one address per value.

        to glob "*@corp.com"  is satisfied by  "evil@x.com, a@corp.com"

(e) `max` is an upper bound only, so negative numbers satisfy it.

        unless {amount: {max: 100}}  is satisfied by  amount: -5000

Limits: conditions address top-level arguments only. Matching is exact string
comparison with no Unicode normalization and no path canonicalization, so the
gateway must hand the policy the same canonical tool name and argument values
the tool will act on.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml

from caveat.capability import Call
from caveat.constraints import OPS, Constraint, glob_match

ALLOW, DENY, APPROVE = "allow", "deny", "approve"
EFFECTS: tuple[str, ...] = (ALLOW, DENY, APPROVE)
PROVENANCE_OPS: frozenset[str] = frozenset({"source_in", "readers_include"})
OPERATORS: frozenset[str] = OPS | PROVENANCE_OPS
TAINTED, CLEAN = "tainted", "clean"
MAX_POLICY_BYTES = 1_000_000

_TOP_KEYS = frozenset({"version", "rules"})
_RULE_KEYS = frozenset({"id", "effect", "tools", "when", "unless", "absent", "reason", "session"})
_SOURCE = re.compile(r"user|untrusted|tool:[A-Za-z0-9_.:/-]{1,128}")
_INT = re.compile(r"-?(0|[1-9][0-9]*)")
_FLOAT = re.compile(r"-?(0|[1-9][0-9]*)\.[0-9]+")
# Unquoted text that YAML 1.1 or YAML 1.2 (or a reader) could take for a number.
_NUMBERISH = re.compile(
    r"""[-+]?(?:
        0[oO][0-7_]* | 0[xX][0-9a-fA-F_]* | 0[bB][01_]*
      | [0-9][0-9_]*(?:\.[0-9_]*)?(?:[eE][-+]?[0-9_]*)?
      | \.[0-9][0-9_]*(?:[eE][-+]?[0-9_]*)?
      | [0-9][0-9_]*(?::[0-9_]+)+(?:\.[0-9_]*)?
      | \.(?:inf|Inf|INF|nan|NaN|NAN)
    )""",
    re.VERBOSE,
)
_BAD_PATTERN_CATEGORIES = frozenset({"Cc", "Cf", "Zs", "Zl", "Zp"})


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

    def process_directives(self) -> Any:
        if self.check_token(yaml.DirectiveToken):
            token = self.peek_token()
            line = token.start_mark.line + 1
            raise PolicyError(
                f"line {line}: YAML directives (%{token.name}) are not allowed; this loader "
                "applies one fixed set of rules whatever version a file asks for"
            )
        return super().process_directives()

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
    value = float(node.value)
    if not math.isfinite(value) or Decimal(repr(value)) != Decimal(node.value):
        raise PolicyError(
            f"{_where(node)}: {node.value[:40]!r} cannot be held exactly as written, a float "
            f"would make it {value!r}; write a number a float can hold, or quote it to mean "
            "the text"
        )
    return value


def _strict_str(loader: _StrictLoader, node: yaml.ScalarNode) -> str:
    if not node.style and _NUMBERISH.fullmatch(node.value):
        raise PolicyError(
            f"{_where(node)}: {node.value[:40]!r} is ambiguous, it looks like a number but "
            "YAML versions disagree on it; write a plain decimal such as 1000 or 1.5, or "
            "quote it to mean the text"
        )
    return loader.construct_scalar(node)


_StrictLoader.add_constructor("tag:yaml.org,2002:bool", _strict_bool)
_StrictLoader.add_constructor("tag:yaml.org,2002:int", _strict_int)
_StrictLoader.add_constructor("tag:yaml.org,2002:float", _strict_float)
_StrictLoader.add_constructor("tag:yaml.org,2002:str", _strict_str)


def _load_yaml(text: str) -> Any:
    if type(text) is not str:
        raise PolicyError("policy text must be a string")
    if (
        len(text) > MAX_POLICY_BYTES
        or len(text.encode("utf-8", "surrogatepass")) > MAX_POLICY_BYTES
    ):
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


@dataclass(frozen=True)
class PolicyContext:
    """What a provenance layer knows about one call. Built by trusted code only.

    session  "tainted", "clean", or None (unknown)
    labels   argument name -> label, or None. A label needs `sources` (a
             frozenset of strings) and `readable_by(principal) -> bool`;
             caveat.provenance.Label is the one used.
    """

    session: str | None = None
    labels: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class ProvenanceCondition:
    """`source_in` or `readers_include` on one argument. See the module docstring.

    For source_in, `value` is a tuple of source strings. For readers_include
    it is ("arg", name) or ("literal", principal).
    """

    arg: str
    op: str
    value: Any

    def __post_init__(self) -> None:
        if type(self.arg) is not str or not self.arg:
            raise ValueError("condition argument name must be a non-empty string")
        if self.op == "source_in":
            if type(self.value) not in (list, tuple) or not self.value:
                raise ValueError("source_in needs a non-empty list of sources")
            value = tuple(self.value)
            for source in value:
                if type(source) is not str or not _SOURCE.fullmatch(source):
                    raise ValueError(
                        f"source_in: {source!r} is not a source (user, untrusted, or tool:<name>)"
                    )
            object.__setattr__(self, "value", value)
        elif self.op == "readers_include":
            value = self.value
            if type(value) is str and value:
                value = ("arg", value)
            elif type(value) is dict and set(value) == {"literal"}:
                principal = value["literal"]
                if type(principal) is not str or not principal:
                    raise ValueError("readers_include literal must be a non-empty string")
                value = ("literal", principal)
            elif not (
                type(value) is tuple
                and len(value) == 2
                and value[0] in ("arg", "literal")
                and type(value[1]) is str
                and value[1]
            ):
                raise ValueError("readers_include needs an argument name or {literal: <principal>}")
            object.__setattr__(self, "value", value)
        else:
            raise ValueError(f"unknown provenance operator {self.op!r}")

    def finite_values(self) -> None:
        return None


def _destinations(value: Any) -> tuple[str, ...] | None:
    """The principals named by a destination value, or None if it names none clearly."""
    if type(value) is str:
        return (value,)
    if type(value) in (list, tuple) and all(type(v) is str for v in value):
        return tuple(value)
    return None


def _evaluate_provenance(
    condition: ProvenanceCondition, args: Mapping[str, Any], context: PolicyContext | None
) -> bool | None:
    if condition.arg not in args or context is None or context.labels is None:
        return None
    label = context.labels.get(condition.arg)
    if label is None:
        return None
    if condition.op == "source_in":
        return all(source in condition.value for source in label.sources)
    kind, name = condition.value
    if kind == "literal":
        principals: tuple[str, ...] | None = (name,)
    else:
        principals = _destinations(args[name]) if name in args else None
    if principals is None:
        return None
    return all(label.readable_by(p) for p in principals)


def evaluate(
    condition: Constraint | ProvenanceCondition,
    args: Mapping[str, Any],
    context: PolicyContext | None = None,
) -> bool | None:
    """Three-valued result of one condition: True, False, or None for UNKNOWN."""
    if type(condition) is ProvenanceCondition:
        return _evaluate_provenance(condition, args, context)
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


def _pattern_problem(pattern: str) -> str | None:
    """Why this tool pattern is refused, or None. Tool names never hold blanks."""
    for ch in pattern:
        if ch.isspace() or unicodedata.category(ch) in _BAD_PATTERN_CATEGORIES:
            return (
                f"tool pattern {pattern[:60]!r} contains whitespace or a control character "
                f"(U+{ord(ch):04X}); if it is an unquoted YAML scalar that runs over several "
                "lines, a list dash is missing"
            )
    return None


def _conditions(value: Any, what: str) -> tuple[Constraint | ProvenanceCondition, ...]:
    if type(value) is not dict or not value:
        raise PolicyError(f"{what} must be a non-empty mapping of argument to operators")
    out: list[Constraint | ProvenanceCondition] = []
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
            if op in PROVENANCE_OPS:
                try:
                    out.append(ProvenanceCondition(arg, op, operand))
                except ValueError as exc:
                    raise PolicyError(f"{what}: argument {arg!r}: {exc}") from exc
                continue
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
    when: tuple[Constraint | ProvenanceCondition, ...] = ()
    unless: tuple[Constraint | ProvenanceCondition, ...] = ()
    absent: tuple[str, ...] = ()
    reason: str | None = None
    session: str | None = None  # "tainted": an extra `when` condition (M4b)

    def __post_init__(self) -> None:
        if type(self.id) is not str or not self.id:
            raise PolicyError(f"rule id must be a non-empty string, got {self.id!r}")
        what = f"rule {self.id!r}"
        if type(self.effect) is not str or self.effect not in EFFECTS:
            raise PolicyError(f"{what}: unknown effect {self.effect!r}")
        object.__setattr__(self, "tools", _names(self.tools, f"{what}: tools"))
        for pattern in self.tools:
            problem = _pattern_problem(pattern)
            if problem:
                raise PolicyError(f"{what}: {problem}")
        for name in ("when", "unless"):
            value = tuple(getattr(self, name))
            if not all(type(c) in (Constraint, ProvenanceCondition) for c in value):
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
        if self.session is not None and (type(self.session) is not str or self.session != TAINTED):
            raise PolicyError(f"{what}: session must be {TAINTED!r}")

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
        if "session" in data and data["session"] != TAINTED:
            raise PolicyError(f"{what}: session must be {TAINTED!r}")
        return cls(
            id=rule_id,
            effect=data["effect"],
            tools=tuple(data["tools"]),
            when=_conditions(data["when"], f"{what}: when") if "when" in data else (),
            unless=_conditions(data["unless"], f"{what}: unless") if "unless" in data else (),
            absent=_names(data["absent"], f"{what}: absent") if "absent" in data else (),
            reason=data.get("reason"),
            session=data.get("session"),
        )

    def matches(self, call: Call, context: PolicyContext | None = None) -> bool:
        """Does this rule apply to the call? See the module docstring for the semantics."""
        if not any(glob_match(pattern, call.tool) for pattern in self.tools):
            return False
        args = call.args
        if any(name in args for name in self.absent):
            return False
        when = [evaluate(c, args, context) for c in self.when]
        if self.session is not None:
            state = None if context is None else context.session
            when.append(True if state == TAINTED else False if state == CLEAN else None)
        unless = [evaluate(c, args, context) for c in self.unless]
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


def _warnings(rules: tuple[Rule, ...]) -> tuple[str, ...]:
    """The traps of "What a policy author must know" that can be seen in the rules."""
    out: list[str] = []
    for rule in rules:
        if rule.effect == ALLOW:
            continue
        if rule.absent:
            out.append(
                f"rule {rule.id!r}: `absent` on a {rule.effect} rule is a presence test the "
                f"caller controls; sending {rule.absent[0]!r} with any value, even null, "
                "switches the rule off"
            )
        for condition in rule.when:
            if condition.op == "any":
                out.append(
                    f"rule {rule.id!r}: `any` in `when` on a {rule.effect} rule is a presence "
                    f"test the caller controls; leaving {condition.arg!r} out switches the "
                    "rule off"
                )
    broad = [rule.id for rule in rules if rule.effect == ALLOW and "*" in rule.tools]
    if broad:
        for rule in rules:
            exact = [t for t in rule.tools if "*" not in t]
            if rule.effect == DENY and exact:
                out.append(
                    f"rule {rule.id!r}: denies the exact tool name {exact[0]!r} while rule "
                    f'{broad[0]!r} allows "*"; any other spelling the tool layer accepts '
                    "is allowed, so list the allowed tools instead"
                )
    return tuple(out)


def _absent_unless_clash(rule: Rule) -> str | None:
    clash = sorted({c.arg for c in rule.unless} & set(rule.absent))
    if not clash:
        return None
    return (
        f"rule {rule.id!r}: argument {clash[0]!r} is in both absent and unless; the rule only "
        "applies when the argument is missing, so the exception can never be proven"
    )


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
        object.__setattr__(self, "_warnings", _warnings(self.rules))

    @property
    def warnings(self) -> tuple[str, ...]:
        """Load-time advice about rules a caller can steer. Never changes a decision."""
        return self._warnings

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
        loaded = cls.from_dict(_load_yaml(text))
        for rule in loaded.rules:
            problem = _absent_unless_clash(rule)
            if problem:
                raise PolicyError(problem)
        return loaded

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        try:
            with open(path, "rb") as handle:
                raw = handle.read()  # all of it: a partial read must never be parsed
        except OSError as exc:
            raise PolicyError(f"cannot read policy file: {exc}") from exc
        if len(raw) > MAX_POLICY_BYTES:
            raise PolicyError(f"policy is larger than {MAX_POLICY_BYTES} bytes")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError(f"cannot read policy file: {exc}") from exc
        return cls.from_yaml(text)

    def decide(self, call: Call, context: PolicyContext | None = None) -> PolicyDecision:
        """Deny beats approve beats allow; no matching rule means deny.

        `context` carries provenance (M4b); None means none is known, which
        makes every provenance condition UNKNOWN.
        """
        if type(call) is not Call:
            return PolicyDecision(DENY, None, "not a Call")
        if context is not None and type(context) is not PolicyContext:
            return PolicyDecision(DENY, None, "not a PolicyContext")
        first: dict[str, Rule] = {}
        for rule in self.rules:
            if rule.effect not in first and rule.matches(call, context):
                first[rule.effect] = rule
                if rule.effect == DENY:
                    break
        for effect in (DENY, APPROVE, ALLOW):
            if effect in first:
                rule = first[effect]
                return PolicyDecision(effect, rule.id, rule.reason or f"matched rule {rule.id!r}")
        return PolicyDecision(DENY, None, "no rule matched (default deny)")
