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

What a result here means: an `unsat` answer is a proof about these formulas.
The Python implementation is tied to the formulas by differential tests, not
by proof. Z3 strings are sequences of Unicode code points up to its own limit;
the model assumes glob treats every character alike, which holds because "*"
is the only special character.
"""

from __future__ import annotations

from fractions import Fraction
from typing import Any

import z3

from toolgate.capability import Call, Capability, Grant
from toolgate.constraints import Constraint

TIMEOUT_MS = 30_000


def _make_value_sort() -> z3.DatatypeSortRef:
    v = z3.Datatype("Value")
    v.declare("B", ("b", z3.BoolSort()))
    v.declare("N", ("n", z3.RealSort()))
    v.declare("S", ("s", z3.StringSort()))
    v.declare("Other")
    return v.create()


Value = _make_value_sort()


def lit(value: Any) -> z3.ExprRef:
    """The model value for a Python constraint value (bool, int, float or str)."""
    if type(value) is bool:
        return Value.B(z3.BoolVal(value))
    if type(value) in (int, float):
        f = Fraction(value)
        return Value.N(z3.Q(f.numerator, f.denominator))
    if type(value) is str:
        return Value.S(z3.StringVal(value))
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
            pieces.append(z3.Re(z3.StringVal(part)))
    if not pieces:
        return z3.Re(z3.StringVal(""))
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


def _solver() -> z3.Solver:
    s = z3.Solver()
    s.set("timeout", TIMEOUT_MS)
    return s


def _check(s: z3.Solver) -> bool:
    """True if satisfiable, False if unsatisfiable. Never guesses on 'unknown'."""
    r = s.check()
    if r == z3.sat:
        return True
    if r == z3.unsat:
        return False
    raise RuntimeError(f"solver returned {r}: {s.reason_unknown()}")


class _NoWitness:
    def __repr__(self) -> str:
        return "NO_WITNESS"


NO_WITNESS = _NoWitness()


def to_python(v: z3.ExprRef) -> Any:
    """Turn a model value back into a Python value. Other becomes None.

    A non-integer rational is converted to the nearest float, which may not be
    exactly the solver's number; callers that replay a witness must re-check it.
    """
    if z3.is_true(z3.simplify(Value.is_B(v))):
        return z3.is_true(z3.simplify(Value.b(v)))
    if z3.is_true(z3.simplify(Value.is_N(v))):
        q = z3.simplify(Value.n(v))
        f = Fraction(q.numerator_as_long(), q.denominator_as_long())
        return f.numerator if f.denominator == 1 else float(f)
    if z3.is_true(z3.simplify(Value.is_S(v))):
        text = z3.simplify(Value.s(v))
        length = z3.simplify(z3.Length(text)).as_long()
        codes = [z3.simplify(z3.StrToCode(z3.SubString(text, i, 1))) for i in range(length)]
        return "".join(chr(c.as_long()) for c in codes)
    return None


def find_escalation(parent: Constraint, child: Constraint) -> Any:
    """A value the child constraint accepts and the parent rejects.

    Returns NO_WITNESS if the solver proves there is none, in which case the
    child is truly at least as strict as the parent. Argument names are ignored.
    """
    v = z3.Const("v", Value)
    s = _solver()
    s.add(holds(child, v), z3.Not(holds(parent, v)))
    if not _check(s):
        return NO_WITNESS
    return to_python(s.model().eval(v, model_completion=True))


def constraint_included(parent: Constraint, child: Constraint) -> bool:
    """Exact answer: does the parent accept every value the child accepts?"""
    return find_escalation(parent, child) is NO_WITNESS


def _capability_formula(
    cap: Capability, present: dict[str, z3.BoolRef], value: dict[str, z3.ExprRef]
) -> z3.BoolRef:
    """'This capability permits the call' for a symbolic call over fixed arg names."""
    names = cap.arg_names
    parts = [present[a] if a in names else z3.Not(present[a]) for a in present]
    parts += [holds(c, value[c.arg]) for c in cap.constraints]
    return z3.And(parts)


def find_grant_escalation(parent: Grant, child: Grant) -> Call | None:
    """A call the child grant allows and the parent denies, or None if proven none.

    Expiry and call budgets are not modeled here; this is the single-call
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
        s.add(z3.Or([_capability_formula(c, present, value) for c in c_caps]))
        s.add(z3.Not(z3.Or([_capability_formula(c, present, value) for c in p_caps])))
        if _check(s):
            m = s.model()
            args = {
                a: to_python(m.eval(value[a], model_completion=True))
                for a in names
                if z3.is_true(m.eval(present[a], model_completion=True))
            }
            return Call(tool, args)
    return None


def grant_included(parent: Grant, child: Grant) -> bool:
    """Exact answer to the single-call question, ignoring expiry and budgets."""
    return find_grant_escalation(parent, child) is None
