"""Property-based security tests for the attenuation check (milestone M0).

The invariant of the whole system (docs/PLAN.md section 3.2):

    if check_attenuation(parent, child) is ok, then for every call and every
    time `now`:  child.allows(call, now)  implies  parent.allows(call, now)

The second half of this file is mutation testing: deliberately broken copies
of the checker, each of which Hypothesis must catch. A property that cannot
tell a broken checker from a correct one proves nothing.

Set CAVEAT_EXAMPLES to run fewer cases locally. The default is 10,000.
"""

from __future__ import annotations

import os
import random
from collections.abc import Callable

import pytest
from hypothesis import HealthCheck, Phase, find, given, settings
from hypothesis.errors import NoSuchExample

from caveat import (
    AttenuationResult,
    Call,
    Capability,
    Constraint,
    Grant,
    check_attenuation,
)
from strategies import RawCall, Scenario, chains, grants, raw_calls, scenarios

Checker = Callable[[Grant, Grant], AttenuationResult]

EXAMPLES = int(os.environ.get("CAVEAT_EXAMPLES", "10000"))
MUTANT_BUDGET = 20000  # examples Hypothesis may spend looking for each counterexample
MUTANT_SEED = 0

# derandomize=True: the examples are a fixed function of the test, so every run
# and every machine sees the same cases. No example database is needed.
PROPERTY = settings(
    max_examples=EXAMPLES,
    deadline=None,
    derandomize=True,
    database=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


# ---------------------------------------------------------------------------
# The invariants, written once and used against the real checker and mutants
# ---------------------------------------------------------------------------


def grant_violation(
    check: Checker, parent: Grant, child: Grant, call: Call, now: float
) -> str | None:
    """The security invariant. Returns a description of the breach, or None."""
    if not check(parent, child).ok:
        return None
    if child.allows(call, now) and not parent.allows(call, now):
        return "accepted child allows a call the parent denies"
    return None


def derivation_violation(check: Checker, parent: Grant, child: Grant, call: Call) -> str | None:
    """The per-capability invariant the token layer relies on to charge budgets."""
    result = check(parent, child)
    if not result.ok:
        return None
    if len(result.derivation) != len(child.capabilities):
        return "derivation does not have one entry per child capability"
    for i, cc in enumerate(child.capabilities):
        j = result.derivation[i]
        if not 0 <= j < len(parent.capabilities):
            return f"derivation[{i}] = {j} is not a parent capability"
        pc = parent.capabilities[j]
        if cc.permits(call) and not pc.permits(call):
            return f"child capability {i} permits a call that parent capability {j} denies"
        if pc.max_calls is not None and (cc.max_calls is None or cc.max_calls > pc.max_calls):
            return f"child capability {i} has a larger call budget than parent capability {j}"
    return None


def describe(s: Scenario) -> str:
    return f"parent={s.parent!r}\nchild={s.child!r}\ncall={s.call!r}\nnow={s.now!r}"


# ---------------------------------------------------------------------------
# Properties of the real checker
# ---------------------------------------------------------------------------


@PROPERTY
@given(scenarios())
def test_attenuation_is_sound(s: Scenario) -> None:
    # Rejected children assert nothing: grant_violation returns None for them.
    problem = grant_violation(check_attenuation, s.parent, s.child, s.call, s.now)
    assert problem is None, f"{problem}\n{describe(s)}"


@PROPERTY
@given(scenarios())
def test_derivation_is_sound(s: Scenario) -> None:
    problem = derivation_violation(check_attenuation, s.parent, s.child, s.call)
    assert problem is None, f"{problem}\n{describe(s)}"


@PROPERTY
@given(grants())
def test_reflexive(g: Grant) -> None:
    result = check_attenuation(g, g)
    assert result.ok, result.reason
    # The checker takes the first parent capability that covers, so a capability
    # can only map to itself or to an earlier one.
    assert all(j <= i for i, j in enumerate(result.derivation))


@PROPERTY
@given(chains())
def test_transitive_soundness(c) -> None:
    if not check_attenuation(c.grandparent, c.parent).ok:
        return
    if not check_attenuation(c.parent, c.child).ok:
        return
    if c.child.allows(c.call, c.now):
        assert c.parent.allows(c.call, c.now)
        assert c.grandparent.allows(c.call, c.now)


@PROPERTY
@given(raw_calls())
def test_call_refuses_exactly_the_unrecordable_values(raw: RawCall) -> None:
    # Non-finite floats, surrogate strings and huge ints used to be ordinary
    # call values in the scenarios. Now no Call can hold them, so they are
    # generated raw here and Call must refuse them, and nothing else.
    if raw.unrecordable:
        with pytest.raises(ValueError):
            Call(raw.tool, raw.args)
        for name in raw.unrecordable:  # each bad value is refused on its own too
            with pytest.raises(ValueError):
                Call(raw.tool, {name: raw.args[name]})
        rest = {k: v for k, v in raw.args.items() if k not in raw.unrecordable}
        assert Call(raw.tool, rest).tool == raw.tool
    else:
        call = Call(raw.tool, raw.args)
        assert set(call.args) == set(raw.args)


# ---------------------------------------------------------------------------
# Mutation testing
# ---------------------------------------------------------------------------

# name -> (invariant that must catch it, what was broken)
MUTANTS: dict[str, tuple[str, str]] = {
    "max_flipped": ("grant", "max under max accepts child ceiling >= parent ceiling"),
    "arg_names_unchecked": ("grant", "child may constrain arguments the parent never named"),
    "glob_prefix_reversed": ("grant", "prefix rule asks parent head to start with child head"),
    "glob_heads_only": ("grant", "prefix rule ignores what follows the parent's first star"),
    "in_any_common": ("grant", "finite child accepted if ANY of its values satisfies the parent"),
    "star_free_glob_unchecked": ("grant", "star-free child glob accepted under every parent"),
    "any_glob_as_literal": ("grant", "every child glob, starred or not, checked as one literal"),
    "child_any_accepted": ("grant", "child `any` accepted under every parent constraint"),
    "quantifiers_swapped": ("grant", "every child constraint under some parent constraint"),
    "tool_unchecked": ("grant", "parent capability for a different tool may cover"),
    "expiry_unchecked": ("grant", "child may expire later than the parent"),
    "max_calls_unchecked": ("derivation", "child budget may exceed the parent's"),
    "derivation_first": ("derivation", "derivation always names parent capability 0"),
}


def make_checker(mutation: str | None = None) -> Checker:
    """A line-for-line copy of caveat.attenuation with one switchable fault.

    With mutation=None it must behave exactly like the real checker;
    test_reference_copy_matches_real_checker holds it to that, so a mutant is
    the real algorithm with one change and nothing else.
    """
    if mutation is not None and mutation not in MUTANTS:
        raise ValueError(f"unknown mutation {mutation!r}")

    def prefix_extends(parent: str, child: str) -> bool:
        if mutation == "glob_heads_only":
            return child.split("*")[0].startswith(parent.split("*")[0])
        if not parent.endswith("*") or "*" in parent[:-1]:
            return False
        if mutation == "glob_prefix_reversed":
            return parent[:-1].startswith(child.split("*")[0])
        return child.split("*")[0].startswith(parent[:-1])

    def at_least_as_strict(parent: Constraint, child: Constraint) -> bool:
        if parent.arg != child.arg:
            return False
        if parent.op == "any":
            return True
        if mutation == "child_any_accepted" and child.op == "any":
            return True
        values = child.finite_values()
        if mutation == "any_glob_as_literal" and child.op == "glob":
            values = (child.value,)
        if values is not None:
            if mutation == "star_free_glob_unchecked" and child.op == "glob":
                return True
            if mutation == "in_any_common":
                return any(parent.holds(v) for v in values)
            return all(parent.holds(v) for v in values)
        if parent.op == "max" and child.op == "max":
            if mutation == "max_flipped":
                return child.value >= parent.value
            return child.value <= parent.value
        if parent.op == "glob" and child.op == "glob":
            return child.value == parent.value or prefix_extends(parent.value, child.value)
        return False

    def covers(parent: Capability, child: Capability) -> bool:
        if parent.tool != child.tool and mutation != "tool_unchecked":
            return False
        if parent.arg_names != child.arg_names and mutation != "arg_names_unchecked":
            return False
        if mutation == "quantifiers_swapped":
            for cc in child.constraints:
                if not any(at_least_as_strict(pc, cc) for pc in parent.constraints):
                    return False
        else:
            for pc in parent.constraints:
                if not any(at_least_as_strict(pc, cc) for cc in child.constraints):
                    return False
        if parent.max_calls is not None and mutation != "max_calls_unchecked":
            return child.max_calls is not None and child.max_calls <= parent.max_calls
        return True

    def check(parent: Grant, child: Grant) -> AttenuationResult:
        if mutation != "expiry_unchecked" and not child.expires_at <= parent.expires_at:
            return AttenuationResult(False, "child expires later than parent")
        derivation: list[int] = []
        for i, cc in enumerate(child.capabilities):
            for j, pc in enumerate(parent.capabilities):
                if covers(pc, cc):
                    derivation.append(0 if mutation == "derivation_first" else j)
                    break
            else:
                return AttenuationResult(False, f"child capability {i} is not covered")
        return AttenuationResult(True, "ok", tuple(derivation))

    return check


def violation(invariant: str, check: Checker, s: Scenario) -> str | None:
    if invariant == "grant":
        return grant_violation(check, s.parent, s.child, s.call, s.now)
    return derivation_violation(check, s.parent, s.child, s.call)


def _without(items: tuple, i: int) -> tuple:
    return items[:i] + items[i + 1 :]


def _without_arg(grant: Grant, arg: str) -> Grant:
    caps = tuple(
        Capability(c.tool, tuple(k for k in c.constraints if k.arg != arg), c.max_calls)
        for c in grant.capabilities
    )
    return Grant(caps, grant.expires_at)


def simplify(s: Scenario, still_fails: Callable[[Scenario], bool]) -> Scenario:
    """Greedily delete whatever is not needed for the failure.

    Hypothesis shrinks the choices that built a scenario, but a child is built
    from its parent, so it often cannot delete a bystander capability without
    disturbing the rest. This pass deletes whole capabilities and whole
    arguments directly and keeps each deletion that still fails.
    """
    changed = True
    while changed:
        changed = False
        candidates = [
            s._replace(parent=Grant(_without(s.parent.capabilities, i), s.parent.expires_at))
            for i in range(len(s.parent.capabilities))
        ]
        candidates += [
            s._replace(child=Grant(_without(s.child.capabilities, i), s.child.expires_at))
            for i in range(len(s.child.capabilities))
        ]
        for arg in sorted(
            {k.arg for g in (s.parent, s.child) for c in g.capabilities for k in c.constraints}
        ):
            call = Call(s.call.tool, {k: v for k, v in s.call.args.items() if k != arg})
            candidates.append(
                s._replace(
                    parent=_without_arg(s.parent, arg), child=_without_arg(s.child, arg), call=call
                )
            )
        for candidate in candidates:
            if still_fails(candidate):
                s, changed = candidate, True
                break
    return s


def kill(
    mutation: str, budget: int = MUTANT_BUDGET, seed: int = MUTANT_SEED, shrink: bool = False
) -> Scenario | None:
    """Search for a scenario where the mutant breaks its invariant.

    Returns a simplified counterexample, or None if the mutant survived
    `budget` examples. The search stops at the first hit. With shrink=True
    Hypothesis also shrinks it, which gives a smaller example but takes
    seconds per mutant; the test suite only needs to know a hit exists.
    """
    invariant = MUTANTS[mutation][0]
    check = make_checker(mutation)

    def fails(s: Scenario) -> bool:
        return violation(invariant, check, s) is not None

    phases = [Phase.generate, Phase.shrink] if shrink else [Phase.generate]
    try:
        found = find(
            scenarios(fault_one_in=1),
            fails,
            settings=settings(
                max_examples=budget,
                deadline=None,
                database=None,
                phases=phases,
                suppress_health_check=list(HealthCheck),
            ),
            random=random.Random(seed),
        )
    except NoSuchExample:
        return None
    return simplify(found, fails)


@PROPERTY
@given(scenarios())
def test_reference_copy_matches_real_checker(s: Scenario) -> None:
    real = check_attenuation(s.parent, s.child)
    copy = make_checker(None)(s.parent, s.child)
    assert (real.ok, real.derivation) == (copy.ok, copy.derivation), describe(s)


@pytest.mark.parametrize("mutation", sorted(MUTANTS))
def test_mutant_is_killed(mutation: str) -> None:
    invariant = MUTANTS[mutation][0]
    s = kill(mutation)
    assert s is not None, (
        f"mutant {mutation!r} survived {MUTANT_BUDGET} examples: "
        f"the {invariant} property cannot see this bug"
    )
    # The counterexample is a real breach under the mutant...
    assert violation(invariant, make_checker(mutation), s) is not None
    # ...and the real checker is not fooled by the same input.
    assert violation(invariant, check_attenuation, s) is None, describe(s)
