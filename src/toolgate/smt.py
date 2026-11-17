"""A Z3 model of the constraint language, used to verify the attenuation rules.

This module is verification tooling, not part of the gateway's decision path.
It needs the optional `z3-solver` dependency (`pip install toolgate[verify]`).

The model. An argument value is one of four kinds:

    B(bool) | N(real) | S(string) | Other

Python ints and finite floats are exact rationals, so both map to N. Everything
a constraint other than `any` rejects outright (None, NaN, infinities, lists,
dicts) is collapsed into the single value Other. Each operator becomes a
formula over a value v:

    eq a     v == lit(a)
    in S     v == lit(a1) or ... or v == lit(ak)
    max m    v is N and n(v) <= m
    glob g   v is S and s(v) is in the regular language of g
    any      true

What a result here means, and what it does not:

  * An `unsat` answer is a proof about these formulas. The Python code is tied
    to the formulas by differential tests, not by proof.
  * The model is deliberately at least as permissive as the code, so "no
    escalation in the model" carries over to the code. N is every rational,
    a superset of ints and finite floats. Call validation (plain JSON types,
    nesting depth), expiry and call budgets are not modeled; each only removes
    calls on the Python side.
  * The other direction is not exact. Because N is the rationals, the solver
    can find an "escalation" at a number between two adjacent floats that no
    Python value can hit. Every witness is therefore replayed through the real
    code, and a witness that does not replay raises Inconclusive.
  * Z3 strings stop at code point 0x2FFFF. Constraint literals above that
    raise Inconclusive. Glob treats every character alike ("*" is the only
    special one), so the missing characters cannot change an inclusion answer.
  * Timeouts and `unknown` raise Inconclusive. Nothing is ever guessed.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

import z3

from toolgate.capability import Call, Capability, Grant
from toolgate.constraints import Constraint

TIMEOUT_MS = 30_000


class Inconclusive(RuntimeError):
    """The solver gave no usable answer: neither a proof nor a replayable witness."""


def _make_value_sort() -> z3.DatatypeSortRef:
    v = z3.Datatype("Value")
    v.declare("B", ("b", z3.BoolSort()))
    v.declare("N", ("n", z3.RealSort()))
    v.declare("S", ("s", z3.StringSort()))
    v.declare("Other")
    return v.create()


Value = _make_value_sort()


MAX_CODE_POINT = 0x2FFFF  # the largest character Z3's default string theory has


def string_lit(text: str) -> z3.SeqRef:
    """A Z3 string constant for exactly this Python string.

    Every character is written as an explicit code point escape, because Z3
    would otherwise read a literal backslash-u sequence in the text as an escape.
    """
    if any(ord(ch) > MAX_CODE_POINT for ch in text):
        raise Inconclusive("character outside the range of the solver's string theory")
    return z3.StringVal("".join(f"\\u{{{ord(ch):x}}}" for ch in text))


def lit(value: Any) -> z3.ExprRef:
    """The model value for a Python constraint value (bool, int, float or str)."""
    if type(value) is bool:
        return Value.B(z3.BoolVal(value))
    if type(value) in (int, float):
        f = Fraction(value)
        return Value.N(z3.Q(f.numerator, f.denominator))
    if type(value) is str:
        return Value.S(string_lit(value))
    raise ValueError(f"no model literal for {type(value).__name__}")


def glob_regex(pattern: str) -> z3.ReRef:
    """The regular language of a glob pattern: literals joined by 'any string'."""
    string = z3.StringSort()
    anything = z3.Full(z3.ReSort(string))
    pieces: list[z3.ReRef] = []
    for i, part in enumerate(pattern.split("*")):
        if i:
            pieces.append(anything)
        if part:
            pieces.append(z3.Re(string_lit(part)))
    if not pieces:
        return z3.Re(string_lit(""))
    return pieces[0] if len(pieces) == 1 else z3.Concat(*pieces)


def holds(c: Constraint, v: z3.ExprRef) -> z3.BoolRef:
    """The formula 'value v satisfies constraint c'. Mirrors Constraint.holds."""
    if c.op == "eq":
        return v == lit(c.value)
    if c.op == "in":
        return z3.Or([v == lit(x) for x in c.value])
    if c.op == "max":
        f = Fraction(c.value)
        return z3.And(Value.is_N(v), Value.n(v) <= z3.Q(f.numerator, f.denominator))
    if c.op == "glob":
        return z3.And(Value.is_S(v), z3.InRe(Value.s(v), glob_regex(c.value)))
    if c.op == "any":
        return z3.BoolVal(True)
    raise ValueError(f"unknown operator {c.op!r}")


def not_holds(c: Constraint, v: z3.ExprRef) -> z3.BoolRef:
    """The negation of holds(c, v), with glob written as membership in the
    complement language. The solver decides that form far faster than a
    negated membership."""
    if c.op == "glob":
        return z3.Or(z3.Not(Value.is_S(v)), z3.InRe(Value.s(v), z3.Complement(glob_regex(c.value))))
    return z3.Not(holds(c, v))


def _child_not_parent(parent: Constraint, child: Constraint, v: z3.ExprRef) -> z3.BoolRef:
    """'child accepts v and parent rejects v'."""
    if parent.op == "glob" and child.op == "glob":
        both = z3.Intersect(glob_regex(child.value), z3.Complement(glob_regex(parent.value)))
        return z3.And(Value.is_S(v), z3.InRe(Value.s(v), both))
    return z3.And(holds(child, v), not_holds(parent, v))


def _solver() -> z3.Solver:
    s = z3.Solver()
    s.set("timeout", TIMEOUT_MS)
    return s


def _check(s: z3.Solver) -> bool:
    """True if satisfiable, False if unsatisfiable. Never guesses on 'unknown'."""
    try:
        r = s.check()
    except (z3.Z3Exception, ValueError, OverflowError) as e:
        raise Inconclusive(f"solver error: {e}") from e
    if r == z3.sat:
        return True
    if r == z3.unsat:
        return False
    raise Inconclusive(f"solver returned {r}: {s.reason_unknown()}")


class _NoWitness:
    def __repr__(self) -> str:
        return "NO_WITNESS"


NO_WITNESS = _NoWitness()


def to_python(v: z3.ExprRef) -> Any:
    """Turn a model value back into a Python value. Other becomes None.

    A non-integer rational is converted to the nearest float, which may not be
    exactly the solver's number, so every caller replays the result in Python.
    """
    if z3.is_true(z3.simplify(Value.is_B(v))):
        return z3.is_true(z3.simplify(Value.b(v)))
    if z3.is_true(z3.simplify(Value.is_N(v))):
        q = z3.simplify(Value.n(v))
        f = Fraction(q.numerator_as_long(), q.denominator_as_long())
        try:
            return f.numerator if f.denominator == 1 else float(f)
        except OverflowError as e:
            raise Inconclusive("witness is not a representable number") from e
    if z3.is_true(z3.simplify(Value.is_S(v))):
        text = z3.simplify(Value.s(v))
        length = z3.simplify(z3.Length(text)).as_long()
        codes = [z3.simplify(z3.StrToCode(z3.SubString(text, i, 1))) for i in range(length)]
        return "".join(chr(c.as_long()) for c in codes)
    return None


def find_escalation(parent: Constraint, child: Constraint) -> Any:
    """A Python value the child constraint accepts and the parent rejects.

    Returns NO_WITNESS if the solver proves the formulas admit none. Compare
    with `is NO_WITNESS`: None, 0, False and "" are all legitimate witnesses.
    Raises Inconclusive on a timeout or a witness that fails to replay.
    Argument names are ignored.
    """
    v = z3.Const("v", Value)
    s = _solver()
    try:
        s.add(_child_not_parent(parent, child, v))
    except (z3.Z3Exception, ValueError, OverflowError) as e:
        raise Inconclusive(f"cannot model constraint: {e}") from e
    if not _check(s):
        return NO_WITNESS
    w = to_python(s.model().eval(v, model_completion=True))
    if not (child.holds(w) and not parent.holds(w)):
        raise Inconclusive(f"witness {w!r} exists in the model but does not replay in Python")
    return w


def constraint_included(parent: Constraint, child: Constraint) -> bool:
    """Does the parent accept every value the child accepts? Proven in the
    model when True; backed by a replayed Python witness when False."""
    return find_escalation(parent, child) is NO_WITNESS


def _capability_formula(
    cap: Capability, present: dict[str, z3.BoolRef], value: dict[str, z3.ExprRef]
) -> z3.BoolRef:
    """'This capability permits the call' for a symbolic call over fixed arg names."""
    names = cap.arg_names
    parts = [present[a] if a in names else z3.Not(present[a]) for a in present]
    parts += [holds(c, value[c.arg]) for c in cap.constraints]
    return z3.And(parts)


def _not_capability_formula(
    cap: Capability, present: dict[str, z3.BoolRef], value: dict[str, z3.ExprRef]
) -> z3.BoolRef:
    """The negation of _capability_formula, pushed inward so globs use complements."""
    names = cap.arg_names
    parts = [z3.Not(present[a]) if a in names else present[a] for a in present]
    parts += [not_holds(c, value[c.arg]) for c in cap.constraints]
    return z3.Or(parts)


def find_grant_escalation(parent: Grant, child: Grant) -> Call | None:
    """A call the child grant allows and the parent denies, or None if the
    solver proves the formulas admit none.

    A returned call has been replayed through the real Grant.allows. Raises
    Inconclusive on a timeout or when the model's witness does not replay
    (possible when two parent capabilities bracket a gap containing no float).
    Expiry and call budgets are not modeled here, so "no escalation" is NOT
    the same as "check_attenuation would accept"; this is the single-call
    question only. The symbolic call has one presence flag and one value per
    argument name used by either grant, plus one extra name standing for every
    argument neither grant mentions (they all behave alike: they must be absent).
    """
    tools = sorted({c.tool for c in child.capabilities})
    for tool in tools:
        p_caps = [c for c in parent.capabilities if c.tool == tool]
        c_caps = [c for c in child.capabilities if c.tool == tool]
        names = sorted(set().union(*(c.arg_names for c in p_caps + c_caps)))
        other = "_unmentioned"
        while other in names:
            other += "_"
        names.append(other)
        present = {a: z3.Bool(f"present_{i}") for i, a in enumerate(names)}
        value = {a: z3.Const(f"value_{i}", Value) for i, a in enumerate(names)}
        s = _solver()
        try:
            s.add(z3.Or([_capability_formula(c, present, value) for c in c_caps]))
            s.add(*[_not_capability_formula(c, present, value) for c in p_caps])
        except (z3.Z3Exception, ValueError, OverflowError) as e:
            raise Inconclusive(f"cannot model grant: {e}") from e
        if _check(s):
            m = s.model()
            args = {
                a: to_python(m.eval(value[a], model_completion=True))
                for a in names
                if z3.is_true(m.eval(present[a], model_completion=True))
            }
            call = Call(tool, args)
            now = min(parent.expires_at, child.expires_at) - 1
            if not child.allows(call, now) or parent.allows(call, now):
                raise Inconclusive(f"witness {call!r} does not replay in Python")
            return call
    return None


def grant_included(parent: Grant, child: Grant) -> bool:
    """The single-call question, ignoring expiry and budgets. True is a proof
    in the model; False is backed by a replayed Python witness."""
    return find_grant_escalation(parent, child) is None
