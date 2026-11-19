"""Differential tests: the Python checker against the Z3 model.

The solver proves things about formulas (src/caveat/smt.py). These tests are
what ties the Python implementation to those formulas, in three layers:

  a. model fidelity    Constraint.holds(x) and glob_match agree with the model
                       on concrete values, including the awkward ones
  b. constraint level  at_least_as_strict(p, c) is True only if the solver
                       proves inclusion, and solver witnesses replay in Python
  c. grant level       check_attenuation(p, c).ok only if the solver proves
                       inclusion, and witness calls replay through Grant.allows

A case where the checker accepts and the solver finds a witness is a security
bug. The reverse (checker rejects, solver proves safe) is the completeness gap,
which is expected; scripts/measure_completeness.py measures it.

Solver calls are slow, so the default is 2,000 examples per test. Set
CAVEAT_SMT_EXAMPLES to change it.

One input restriction: Z3's string theory has no character above code point
0x2FFFF, so generated strings stay at or below it.

Inconclusive answers: smt raises Inconclusive when the solver times out or
when its witness does not replay in Python (the model's numbers are rationals,
so a witness can sit between two adjacent floats). Such a pair is counted on
its own, never as safe and never as unsafe. A test fails if a pair the checker
ACCEPTED is inconclusive more than rarely, because that is an acceptance
nobody confirmed; each one is printed.
"""

from __future__ import annotations

import os
from typing import Any

import z3
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import strategies as pools
from caveat import (
    Call,
    Constraint,
    Grant,
    at_least_as_strict,
    check_attenuation,
    glob_match,
    smt,
)

EXAMPLES = int(os.environ.get("CAVEAT_SMT_EXAMPLES", "2000"))
SETTINGS = settings(
    max_examples=EXAMPLES,
    derandomize=True,
    deadline=None,
    suppress_health_check=list(HealthCheck),
)
# Share of checker-accepted pairs that may come back Inconclusive from the solver.
MAX_ACCEPTED_INCONCLUSIVE_RATE = 0.005


def model_value(x: Any) -> z3.ExprRef:
    """The model's value for a Python call argument.

    Exact bools, ints, finite floats and strings are literals. Everything else
    (None, NaN, infinities, lists, tuples, dicts) is the single value Other.
    """
    if type(x) in (bool, int, str) or (type(x) is float and x == x and abs(x) != float("inf")):
        return smt.lit(x)
    return smt.Value.Other


def model_true(formula: z3.BoolRef) -> bool:
    """Evaluate a closed formula. The simplifier usually decides it; else the solver does."""
    reduced = z3.simplify(formula)
    if z3.is_true(reduced):
        return True
    if z3.is_false(reduced):
        return False
    s = z3.Solver()
    s.set("timeout", smt.TIMEOUT_MS)
    s.add(formula)
    result = s.check()
    assert result != z3.unknown, f"solver gave up on {formula}"
    return result == z3.sat


# ---------------------------------------------------------------------------
# Generators. The pools in strategies.py are tiny on purpose, so values collide.
# The "wild" generators add what the pools lack: huge ints, odd floats, "*",
# backslashes and non-ASCII text.
# ---------------------------------------------------------------------------

_CHARS = st.characters(max_codepoint=smt.MAX_CODE_POINT, exclude_categories=("Cs",))
_TRICKY_TEXT = st.text(st.sampled_from("ab/*\\u{}0é中\U0001f600 \n"), max_size=6)
_TEXT = st.one_of(st.sampled_from(pools.TEXTS), _TRICKY_TEXT, st.text(_CHARS, max_size=5))
_PATTERN = st.one_of(st.sampled_from(pools.PATTERNS), _TRICKY_TEXT, st.text(_CHARS, max_size=5))
_INT = st.one_of(
    st.sampled_from([n for n in pools.NUMBERS if type(n) is int]),
    st.integers(-(10**6), 10**6),
    st.sampled_from([10**400, -(10**400), 2**53, 2**53 + 1, -(2**63), 10**18]),
)
_FINITE_FLOAT = st.one_of(
    st.sampled_from([0.0, -0.0, 0.5, 1.5, 2.0, 2.5, 0.1, 1e308, -1e308, 5e-324, 2.0**53]),
    st.floats(allow_nan=False, allow_infinity=False),
)
_NUMBER = st.one_of(_INT, _FINITE_FLOAT)
_SCALAR = st.one_of(st.sampled_from(pools.SCALARS), st.booleans(), _NUMBER, _TEXT)
_NON_SCALAR = st.one_of(
    st.none(),
    st.sampled_from([float("nan"), float("inf"), float("-inf")]),
    st.lists(st.one_of(st.integers(-3, 3), st.sampled_from(["a", "*"])), max_size=3),
    st.just({"x": 1}),
)
ANY_VALUE = st.one_of(_SCALAR, _SCALAR, _SCALAR, _NON_SCALAR)


@st.composite
def wild_constraints(draw: st.DrawFn, arg: str = "x") -> Constraint:
    op = draw(st.sampled_from(("eq", "in", "max", "glob", "glob", "any")))
    if op == "eq":
        return Constraint(arg, "eq", draw(_SCALAR))
    if op == "in":
        return Constraint(arg, "in", draw(st.lists(_SCALAR, min_size=1, max_size=4)))
    if op == "max":
        return Constraint(arg, "max", draw(_NUMBER))
    if op == "glob":
        return Constraint(arg, "glob", draw(_PATTERN))
    return Constraint(arg, "any")


def any_constraint(arg: str = "x") -> st.SearchStrategy[Constraint]:
    return st.one_of(pools.constraints(arg), wild_constraints(arg))


@st.composite
def constraint_and_value(draw: st.DrawFn) -> tuple[Constraint, Any]:
    """A constraint and a value, half the time a value aimed at the constraint."""
    c = draw(any_constraint())
    aim = draw(st.integers(0, 3))
    if aim == 0 and c.op in ("eq", "in"):
        x = draw(st.sampled_from(c.finite_values()))
        if type(x) is int and abs(x) < 2**53 and draw(st.booleans()):
            x = float(x)  # 3 and 3.0 must be the same value
    elif aim == 0 and c.op == "max":
        steps = [0, 1, -1] if type(c.value) is int else [0, 1, 0.5, -1, -0.5]
        x = c.value - draw(st.sampled_from(steps))
    elif aim == 0 and c.op == "glob":
        x = _fill(draw, c.value)
    else:
        x = draw(ANY_VALUE)
    return c, x


def _fill(draw: st.DrawFn, pattern: str) -> str:
    """A string matching `pattern`: every "*" replaced by some text."""
    return "".join(draw(_TEXT) if ch == "*" else ch for ch in pattern)


def _wild_child(draw: st.DrawFn, parent: Constraint) -> Constraint:
    """A child related to a wild parent: usually inside it, sometimes just outside."""
    arg, value = parent.arg, parent.value
    if parent.op == "in":
        return Constraint(arg, "eq", draw(st.sampled_from(value)))
    if parent.op == "eq":
        return Constraint(arg, "in", [value, *draw(st.lists(_SCALAR, max_size=1))])
    if parent.op == "max":
        if type(value) is int:
            return Constraint(arg, draw(st.sampled_from(("max", "eq"))), value - draw(_INT) % 3 + 1)
        return Constraint(arg, draw(st.sampled_from(("max", "eq"))), value)
    if parent.op == "glob":
        kind = draw(st.integers(0, 3))
        if kind == 0:
            return Constraint(arg, "eq", _fill(draw, value))
        if kind == 1:
            return Constraint(arg, "glob", _fill(draw, value))
        if kind == 2:
            return Constraint(arg, "glob", value.replace("*", "**"))
        return Constraint(arg, "glob", value + draw(_TRICKY_TEXT))
    return draw(any_constraint(arg))


@st.composite
def constraint_pairs(draw: st.DrawFn) -> tuple[Constraint, Constraint]:
    """(parent, child) on the same argument: derived stricter, derived looser, or unrelated."""
    kind = draw(st.integers(0, 4))
    if kind == 0:
        parent = draw(pools.constraints("x"))
        return parent, pools._stricter(draw, parent)
    if kind == 1:
        parent = draw(pools.constraints("x"))
        return parent, pools._looser(draw, parent)
    if kind == 2:
        parent = draw(wild_constraints())
        return parent, _wild_child(draw, parent)
    return draw(any_constraint()), draw(any_constraint())


@st.composite
def grant_pairs(draw: st.DrawFn) -> tuple[Grant, Grant]:
    """(parent, child): child narrowed from the parent (some with one fault) or random."""
    parent = draw(pools.grants())
    kind = draw(st.integers(0, 4))
    if kind == 0:
        return parent, draw(pools.grants())
    return parent, draw(pools.narrowed(parent, fault_one_in=3 if kind < 3 else 1))


# ---------------------------------------------------------------------------
# a. Model fidelity
# ---------------------------------------------------------------------------


@SETTINGS
@given(constraint_and_value())
def test_holds_agrees_with_model(case: tuple[Constraint, Any]) -> None:
    c, x = case
    assert c.holds(x) == model_true(smt.holds(c, model_value(x))), (c, x)


@st.composite
def pattern_and_text(draw: st.DrawFn) -> tuple[str, str]:
    pattern = draw(_PATTERN)
    if draw(st.booleans()):  # a text built to match, so both answers are exercised
        return pattern, _fill(draw, pattern)
    return pattern, draw(_TEXT)


@SETTINGS
@given(pattern_and_text())
def test_glob_match_agrees_with_model_regex(case: tuple[str, str]) -> None:
    pattern, text = case
    in_language = model_true(z3.InRe(smt.string_lit(text), smt.glob_regex(pattern)))
    assert glob_match(pattern, text) == in_language, (pattern, text)


# ---------------------------------------------------------------------------
# b. Constraint level
# ---------------------------------------------------------------------------


def new_tally() -> dict[str, int]:
    return {
        "pairs": 0,
        "accepted": 0,
        "witnesses": 0,
        "gap": 0,
        "inconclusive": 0,
        "accepted_inconclusive": 0,
    }


def check_tally(level: str, seen: dict[str, int]) -> None:
    print(f"\n{level}: {seen}")
    assert seen["accepted"] > 0 and seen["witnesses"] > 0, seen
    limit = MAX_ACCEPTED_INCONCLUSIVE_RATE * seen["accepted"]
    assert seen["accepted_inconclusive"] <= limit, seen


def note_inconclusive(seen: dict[str, int], accepted: bool, pair: Any, why: Exception) -> None:
    seen["inconclusive"] += 1
    if accepted:
        seen["accepted_inconclusive"] += 1
        print(f"\naccepted by the checker, not confirmed by the solver ({why}): {pair!r}")


def test_constraint_checker_never_accepts_what_the_solver_refutes() -> None:
    seen = new_tally()

    @SETTINGS
    @given(constraint_pairs())
    def run(pair: tuple[Constraint, Constraint]) -> None:
        parent, child = pair
        accepted = at_least_as_strict(parent, child)
        seen["pairs"] += 1
        seen["accepted"] += accepted
        try:
            witness = smt.find_escalation(parent, child)
        except smt.Inconclusive as why:
            note_inconclusive(seen, accepted, pair, why)
            return
        if witness is smt.NO_WITNESS:
            seen["gap"] += not accepted
            return
        # The security property: an accepted pair has no escalation witness.
        assert not accepted, f"SECURITY BUG: accepted {child} under {parent}, witness {witness!r}"
        seen["witnesses"] += 1
        # smt replays its witnesses before returning them; this pins that promise.
        assert child.holds(witness) and not parent.holds(witness), (parent, child, witness)

    run()
    check_tally("constraint level", seen)


# ---------------------------------------------------------------------------
# c. Grant level
# ---------------------------------------------------------------------------


def test_grant_checker_never_accepts_what_the_solver_refutes() -> None:
    seen = new_tally()

    @SETTINGS
    @given(grant_pairs())
    def run(pair: tuple[Grant, Grant]) -> None:
        parent, child = pair
        accepted = check_attenuation(parent, child).ok
        seen["pairs"] += 1
        seen["accepted"] += accepted
        try:
            witness = smt.find_grant_escalation(parent, child)
        except smt.Inconclusive as why:
            note_inconclusive(seen, accepted, pair, why)
            return
        if witness is None:
            # Expiry and budgets are outside the model, so a rejection here is
            # only a completeness gap if those were not the reason.
            seen["gap"] += not accepted
            return
        assert not accepted, f"SECURITY BUG: accepted {child} under {parent}, witness {witness!r}"
        seen["witnesses"] += 1
        assert type(witness) is Call
        now = min(parent.expires_at, child.expires_at) - 1  # both grants are unexpired
        assert child.allows(witness, now) and not parent.allows(witness, now), (pair, witness)

    run()
    check_tally("grant level", seen)
