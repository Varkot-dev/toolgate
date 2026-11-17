"""Hypothesis strategies for the capability model.

The pools are deliberately tiny (three tools, three argument names, strings
over "ab/", integers from -3 to 6) so that independently drawn values collide
often. A property about "child allows implies parent allows" is only tested
when the child really does allow the call, and with large pools that almost
never happens by chance.

Three layers:

  constraints / capabilities / grants   fully random objects
  narrowed(parent)                       a child derived from a parent, mostly
                                         by legal narrowing, sometimes sloppy
  calls_for(grant)                       calls the grant probably allows, with
                                         occasional perturbations

`scenarios()` and `chains()` bundle these into what the properties consume.
"""

from __future__ import annotations

from collections.abc import Sequence
from itertools import product
from typing import Any, NamedTuple

from hypothesis import strategies as st

from toolgate import Call, Capability, Constraint, Grant

TOOLS: tuple[str, ...] = ("read", "send", "pay")
ARGS: tuple[str, ...] = ("x", "y", "z")
TEXT_ALPHABET = "ab/"


def _words(alphabet: str, max_size: int) -> tuple[str, ...]:
    """Every string over `alphabet` up to `max_size`, shortest first."""
    return tuple("".join(p) for n in range(max_size + 1) for p in product(alphabet, repeat=n))


# Every pool is ordered simplest first: Hypothesis shrinks an index towards 0,
# so counterexamples shrink towards the front of each pool.
TEXTS = _words(TEXT_ALPHABET, 3)  # 40 strings
SHORT_TEXTS = _words(TEXT_ALPHABET, 2)  # 13 strings
_all_patterns = _words(TEXT_ALPHABET + "*", 3)
# "P*" with P literal is the shape the prefix rule is about, so it gets extra weight.
_prefix_patterns = tuple(p for p in _all_patterns if p.endswith("*") and "*" not in p[:-1])
PATTERNS = _all_patterns + _prefix_patterns * 4
NUMBERS: tuple[int | float, ...] = (0, 1, 2, 3, 4, 5, 6, -1, -2, -3, 0.5, 2.0, 2.5, 3.0, -1.5)
SCALARS: tuple[Any, ...] = TEXTS + NUMBERS * 2 + (False, True) * 3
# Values a call may carry that no constraint can be built from. They must be denied
# (or accepted only by `any`), and the checker must stay sound in their presence.
ODD_VALUES: tuple[Any, ...] = (None, float("nan"), float("inf"), [1], {"x": 1}, 10**9, "*")
EXPIRIES: tuple[int | float, ...] = (1, 2, 3, 4, 5, 6, 2.5, 100)

_OPS = ("eq", "in", "in", "max", "max", "glob", "glob", "any")
_STEPS_DOWN = (0, 0, 1, 2, 0.5)

# Speed: 10,000 cases per property is the milestone bar, and each case is built
# from dozens of choices. Building a new strategy object per choice costs far
# more than the choice, so every choice below is one draw from a cached
# integers() strategy and the builders are plain functions that take `draw`.
_below = [st.integers(0, max(n - 1, 0)) for n in range(len(PATTERNS) + 1)]

Draw = st.DrawFn


def _pick(draw: Draw, pool: Sequence[Any]) -> Any:
    return pool[draw(_below[len(pool)])]


def _chance(draw: Draw, one_in: int) -> bool:
    return draw(_below[one_in]) == 0


def _call_value(draw: Draw) -> Any:
    return _pick(draw, ODD_VALUES) if _chance(draw, 5) else _pick(draw, SCALARS)


def _constraint(draw: Draw, arg: str | None = None) -> Constraint:
    name = _pick(draw, ARGS) if arg is None else arg
    op = _pick(draw, _OPS)
    value: Any = None
    if op == "eq":
        value = _pick(draw, SCALARS)
    elif op == "in":
        value = tuple(_pick(draw, SCALARS) for _ in range(_pick(draw, (1, 2, 2, 3, 4))))
    elif op == "max":
        value = _pick(draw, NUMBERS)
    elif op == "glob":
        value = _pick(draw, PATTERNS)
    return Constraint(name, op, value)


_ARG_SETS = ((), ("x",), ("y",), ("z",), ("x", "y"), ("x", "z"), ("y", "z"), ("x", "y", "z"))


def _capability(draw: Draw) -> Capability:
    names = _pick(draw, _ARG_SETS)
    cons = [_constraint(draw, n) for n in names]
    if names and _chance(draw, 5):  # a second constraint on an argument already named
        cons.append(_constraint(draw, _pick(draw, names)))
    max_calls = _pick(draw, (None, None, 1, 2, 3, 4))
    return Capability(_pick(draw, TOOLS), tuple(cons), max_calls)


def _grant(draw: Draw) -> Grant:
    n = _pick(draw, (1, 1, 1, 1, 2, 2, 2, 2, 3, 0))
    return Grant(tuple(_capability(draw) for _ in range(n)), _pick(draw, EXPIRIES))


@st.composite
def constraints(draw: Draw, arg: str | None = None) -> Constraint:
    """A random constraint, on `arg` if given, else on a random argument name."""
    return _constraint(draw, arg)


@st.composite
def capabilities(draw: Draw) -> Capability:
    """A random capability. Usually one constraint per argument, sometimes two."""
    return _capability(draw)


@st.composite
def grants(draw: Draw) -> Grant:
    """A random grant with zero to three capabilities."""
    return _grant(draw)


# ---------------------------------------------------------------------------
# Deriving a child from a parent
# ---------------------------------------------------------------------------


def _is_prefix_pattern(pattern: str) -> bool:
    return pattern.endswith("*") and "*" not in pattern[:-1]


def _matching(draw: Draw, pattern: str) -> str:
    """A string that matches `pattern`: every "*" replaced by a short string."""
    parts = pattern.split("*")
    out = parts[0]
    for part in parts[1:]:
        out += _pick(draw, SHORT_TEXTS) + part
    return out


def _stricter(draw: Draw, c: Constraint) -> Constraint:
    """A constraint the checker should accept under `c` (one row of the table)."""
    arg = c.arg
    if c.op == "any":
        return c if _chance(draw, 2) else _constraint(draw, arg)
    if c.op == "eq":
        return c
    if c.op == "in":
        subset = tuple(_pick(draw, c.value) for _ in range(draw(_below[len(c.value)]) + 1))
        if len(subset) == 1 and _chance(draw, 2):
            return Constraint(arg, "eq", subset[0])
        return Constraint(arg, "in", subset)
    if c.op == "max":
        kind = _pick(draw, ("max", "max", "eq", "in"))
        if kind == "in":
            n = _pick(draw, (1, 2, 3))
            return Constraint(
                arg, "in", tuple(c.value - _pick(draw, _STEPS_DOWN) for _ in range(n))
            )
        return Constraint(arg, kind, c.value - _pick(draw, _STEPS_DOWN))
    # glob
    kind = _pick(draw, ("same", "extend", "extend", "eq", "in"))
    if kind == "extend" and _is_prefix_pattern(c.value):
        tail = _pick(draw, ("*", "*", "", "*a", "*/*"))
        return Constraint(arg, "glob", c.value[:-1] + _pick(draw, SHORT_TEXTS) + tail)
    if kind == "eq":
        return Constraint(arg, "eq", _matching(draw, c.value))
    if kind == "in":
        n = _pick(draw, (1, 2, 3))
        return Constraint(arg, "in", tuple(_matching(draw, c.value) for _ in range(n)))
    return c


def _looser(draw: Draw, c: Constraint) -> Constraint:
    """A constraint that is probably NOT at least as strict as `c`.

    These are the near misses a buggy checker would wave through: one more
    value in an allow-list, a ceiling raised by one, a pattern prefix cut
    short. The real checker should reject most of them.
    """
    arg = c.arg
    kind = draw(_below[8])
    if kind == 0:
        return Constraint(arg, "any")
    if kind == 1 or c.op == "any":
        return _constraint(draw, arg)
    if c.op == "eq":
        return Constraint(arg, "in", (c.value, _pick(draw, SCALARS)))
    if c.op == "in":
        return Constraint(arg, "in", (*c.value, _pick(draw, SCALARS)))
    if c.op == "max":
        return Constraint(
            arg, _pick(draw, ("max", "max", "eq")), c.value + _pick(draw, (1, 0.5, 2))
        )
    head = c.value.split("*")[0]
    if _is_prefix_pattern(c.value):
        if not head:  # "*" already matches every string
            return _constraint(draw, arg)
        # cut the literal prefix short: "ab*" becomes "a*" or "*"
        return Constraint(arg, "glob", head[: draw(_below[len(head)])] + "*")
    # keep the literal head, forget whatever the parent required after it
    return Constraint(arg, "glob", head + _pick(draw, SHORT_TEXTS) + _pick(draw, ("*", "")))


# The single mistakes a sloppy child can contain. Exactly one is applied, to one
# capability, so a checker that forgets exactly one rule accepts the result.
_FAULTS = (
    "loosen",
    "loosen",
    "loosen",
    "loosen",
    "drop",
    "drop",
    "new_arg",
    "tool",
    "budget",
    "expiry",
)


def _narrowed_capability(draw: Draw, pc: Capability, fault: str | None) -> Capability:
    cons = [_stricter(draw, c) for c in pc.constraints]
    tool = pc.tool
    if pc.max_calls is None:
        max_calls = _pick(draw, (None, None, 1, 3))
    else:
        max_calls = draw(_below[pc.max_calls]) + 1
    if fault is None:
        if cons and _chance(draw, 8):  # an extra conjunct on a known argument is legal
            cons.append(_constraint(draw, _pick(draw, cons).arg))
    elif fault == "loosen" and cons:
        i = draw(_below[len(cons)])
        cons[i] = _looser(draw, pc.constraints[i])
    elif fault == "new_arg":  # a constraint on a possibly new argument
        cons.append(_constraint(draw))
    elif fault == "drop" and cons:  # forget one of the parent's constraints
        args = [c.arg for c in cons]
        twice = [i for i, a in enumerate(args) if args.count(a) > 1]
        del cons[_pick(draw, twice or range(len(cons)))]
    elif fault == "tool":
        tool = _pick(draw, TOOLS)
    elif fault == "budget":
        max_calls = None if pc.max_calls is None or _chance(draw, 2) else pc.max_calls + 1
    return Capability(tool, tuple(cons), max_calls)


def _narrowed(draw: Draw, parent: Grant, fault_one_in: int = 5) -> tuple[Grant, int | None]:
    """The child, and the index of the capability that got the fault (if any)."""
    fault = _pick(draw, _FAULTS) if _chance(draw, fault_one_in) else None
    kept = [pc for pc in parent.capabilities for _ in range(_pick(draw, (1, 1, 1, 1, 1, 1, 0, 2)))]
    faulty = draw(_below[len(kept)]) if kept and fault is not None else None
    caps = [
        _narrowed_capability(draw, pc, fault if i == faulty else None) for i, pc in enumerate(kept)
    ]
    if len(caps) > 1 and _chance(draw, 2):
        caps.reverse()  # so derivation[i] is not always i
        if faulty is not None:
            faulty = len(caps) - 1 - faulty
    if fault == "expiry":
        expires = parent.expires_at + _pick(draw, (1, 0.5))
    else:
        expires = parent.expires_at - _pick(draw, (0, 0, 0, 1, 0.5))
    return Grant(tuple(caps), expires), faulty


@st.composite
def narrowed(draw: Draw, parent: Grant, fault_one_in: int = 5) -> Grant:
    """A child grant derived from `parent`.

    Four times in five the derivation uses only legal narrowing steps (drop a
    capability, shrink an allow-list, lower a ceiling, pin a value, extend a
    pattern prefix, lower the budget, expire earlier), so the checker usually
    accepts it. One time in five it is "sloppy": exactly one step goes the
    wrong way (see _FAULTS), which is what a checker with one missing rule
    would let through. `fault_one_in` changes that rate: 1 means always sloppy.
    """
    return _narrowed(draw, parent, fault_one_in)[0]


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def _random_call(draw: Draw) -> Call:
    names = _pick(draw, _ARG_SETS)
    return Call(_pick(draw, TOOLS), {n: _call_value(draw) for n in names})


def _satisfying(draw: Draw, cons: list[Constraint]) -> Any:
    """A value for one argument that probably satisfies all of `cons`.

    The most specific constraint drives the choice: a finite list first, then
    a ceiling, then a pattern.
    """
    for c in cons:
        if c.op == "eq":
            return c.value
        if c.op == "in":
            return _pick(draw, c.value)
    for c in cons:
        if c.op == "max":
            return c.value - _pick(draw, _STEPS_DOWN)
    for c in cons:
        if c.op == "glob":
            return _matching(draw, c.value)
    return _call_value(draw)


def _call_for(draw: Draw, grant: Grant, focus: int | None = None) -> Call:
    if not grant.capabilities or _chance(draw, 16):
        return _random_call(draw)
    if focus is not None and not _chance(draw, 4):
        cap = grant.capabilities[focus]
    else:
        cap = _pick(draw, grant.capabilities)
    by_arg: dict[str, list[Constraint]] = {}
    for c in cap.constraints:
        by_arg.setdefault(c.arg, []).append(c)
    args = {name: _satisfying(draw, cons) for name, cons in by_arg.items()}
    tool = cap.tool
    tweak = draw(_below[20])
    if tweak == 1 and args:  # wrong value
        args[_pick(draw, sorted(args))] = _call_value(draw)
    elif tweak == 2:  # extra (or overwritten) argument
        args[_pick(draw, ARGS)] = _call_value(draw)
    elif tweak == 3 and args:  # missing argument
        del args[_pick(draw, sorted(args))]
    elif tweak == 4:
        tool = _pick(draw, TOOLS)
    return Call(tool, args)


@st.composite
def random_calls(draw: Draw) -> Call:
    """A call unrelated to any grant."""
    return _random_call(draw)


@st.composite
def calls_for(draw: Draw, grant: Grant, focus: int | None = None) -> Call:
    """A call that `grant` probably allows, sometimes perturbed, sometimes random.

    `focus` is the index of a capability to aim at three times in four.
    """
    return _call_for(draw, grant, focus)


def _time(draw: Draw, grant: Grant) -> float:
    kind = draw(_below[12])
    if kind == 10:
        return grant.expires_at  # exactly at expiry: must be denied
    if kind == 11:
        return _pick(draw, (0, 1, 2, 3, 4, 5, 6, 7, -1, 3.5, float("nan")))
    return grant.expires_at - _pick(draw, (1, 1, 2, 0.5, 0.25))


@st.composite
def times(draw: Draw, grant: Grant) -> float:
    """A `now`, mostly before the grant expires, sometimes at or after it."""
    return _time(draw, grant)


# ---------------------------------------------------------------------------
# Bundles consumed by the properties
# ---------------------------------------------------------------------------


class Scenario(NamedTuple):
    parent: Grant
    child: Grant
    call: Call
    now: float
    child_kind: str  # "narrowed" or "random"


class Chain(NamedTuple):
    grandparent: Grant
    parent: Grant
    child: Grant
    call: Call
    now: float


@st.composite
def scenarios(draw: Draw, fault_one_in: int = 5) -> Scenario:
    """Parent, child (mostly narrowed, about one in four fully random), call, time.

    `fault_one_in` is passed to the narrowing step. The properties use the
    default; the mutation tests use 1, so every narrowed child carries exactly
    one mistake for a broken checker to miss.
    """
    parent = _grant(draw)
    focus = None
    if _chance(draw, 5):
        child, kind = _grant(draw), "random"
    else:
        (child, focus), kind = _narrowed(draw, parent, fault_one_in), "narrowed"
    # Aim the call at the child, and at the capability that was tampered with if
    # there is one: the invariant only bites when the child allows the call.
    call = _call_for(draw, parent) if _chance(draw, 10) else _call_for(draw, child, focus)
    return Scenario(parent, child, call, _time(draw, child), kind)


@st.composite
def chains(draw: Draw) -> Chain:
    """Grandparent, parent narrowed from it, child narrowed from the parent."""
    grandparent = _grant(draw)
    parent, _ = _narrowed(draw, grandparent)
    child, focus = _narrowed(draw, parent)
    return Chain(grandparent, parent, child, _call_for(draw, child, focus), _time(draw, child))
