"""The attenuation check, one group of tests per row of the table in PLAN.md 3.2.

The check is sound but deliberately incomplete. Tests whose name starts with
`test_incomplete_` pin down safe children that are rejected on purpose.
"""

import pytest

from caveat.attenuation import AttenuationResult, at_least_as_strict, check_attenuation, covers
from caveat.capability import Call, Capability, Grant
from caveat.constraints import Constraint


def C(op, value=None, arg="x"):
    return Constraint(arg, op, value)


def cap(*constraints, tool="t", max_calls=None):
    return Capability(tool, constraints, max_calls)


def grant(*caps, expires_at=1000):
    return Grant(caps, expires_at)


# --- row 1: parent `eq a` ---------------------------------------------------


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "a"),
        C("in", ["a"]),  # a one-element allow-list is the same set
        C("in", ["a", "a"]),
    ],
)
def test_parent_eq_accepts_same_value(child):
    assert at_least_as_strict(C("eq", "a"), child)


def test_parent_eq_number_accepts_numerically_equal_child():
    assert at_least_as_strict(C("eq", 3), C("eq", 3.0))
    assert at_least_as_strict(C("eq", 3.0), C("in", [3, 3.0]))


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "b"),
        C("eq", "A"),
        C("eq", ""),
        C("in", ["a", "b"]),
        C("in", ["b"]),
        C("max", 1),
        C("glob", "a*"),
        C("glob", "*"),
        C("any"),
    ],
)
def test_parent_eq_rejects_anything_else(child):
    assert not at_least_as_strict(C("eq", "a"), child)


@pytest.mark.parametrize(
    ("parent_value", "child_value"),
    [(1, True), (True, 1), (0, False), (1, "1"), ("1", 1), (3, 4)],
)
def test_parent_eq_uses_strict_equality(parent_value, child_value):
    assert not at_least_as_strict(C("eq", parent_value), C("eq", child_value))


def test_parent_eq_number_rejects_max_with_same_ceiling():
    assert not at_least_as_strict(C("eq", 3), C("max", 3))


# --- row 2: parent `in S` ---------------------------------------------------

S = ["a", "b", "c"]


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "a"),
        C("eq", "c"),
        C("in", ["a"]),
        C("in", ["a", "b"]),
        C("in", ["c", "a"]),  # order does not matter
        C("in", ["a", "b", "c"]),  # the same set
        C("in", ["b", "b"]),
        C("glob", "a"),  # no star: accepts exactly "a", a member (rule A)
    ],
)
def test_parent_in_accepts_member_or_subset(child):
    assert at_least_as_strict(C("in", S), child)


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "d"),  # non-member
        C("eq", ""),
        C("eq", "A"),
        C("in", ["d"]),
        C("in", ["a", "d"]),  # overlaps but is not a subset
        C("in", ["a", "b", "c", "d"]),  # superset
        C("max", 1),
        C("glob", "*"),
        C("any"),
    ],
)
def test_parent_in_rejects_non_member_superset_and_other_operators(child):
    assert not at_least_as_strict(C("in", S), child)


def test_parent_in_uses_strict_equality():
    parent = C("in", [1, 2, "x"])
    assert at_least_as_strict(parent, C("eq", 1.0))
    assert at_least_as_strict(parent, C("in", [2.0, "x"]))
    assert not at_least_as_strict(parent, C("eq", True))
    assert not at_least_as_strict(parent, C("eq", "1"))
    assert not at_least_as_strict(parent, C("in", [1, True]))


# --- row 3: parent `max m` --------------------------------------------------


@pytest.mark.parametrize(
    "child",
    [
        C("max", 100),  # equal ceiling
        C("max", 99),
        C("max", 99.5),
        C("max", 0),
        C("max", -5),
        C("eq", 100),
        C("eq", 100.0),
        C("eq", 7),
        C("eq", -1000),
        C("in", [1, 50, 100]),
        C("in", [0.5, -3]),
    ],
)
def test_parent_max_accepts_smaller_ceiling_or_values_under_it(child):
    assert at_least_as_strict(C("max", 100), child)


@pytest.mark.parametrize(
    "child",
    [
        C("max", 101),
        C("max", 100.0001),
        C("max", 10**9),
        C("eq", 101),
        C("eq", 100.5),
        C("in", [1, 50, 101]),  # one value over the ceiling
        C("in", [101, 102]),
        C("eq", "50"),  # a string is not a number
        C("eq", True),  # nor is a bool
        C("in", [50, "50"]),
        C("in", [50, False]),
        C("glob", "5*"),
        C("glob", "*"),
        C("any"),
    ],
)
def test_parent_max_rejects_larger_ceiling_values_over_it_and_non_numbers(child):
    assert not at_least_as_strict(C("max", 100), child)


def test_parent_max_negative_ceiling():
    assert at_least_as_strict(C("max", -1), C("max", -2))
    assert at_least_as_strict(C("max", -1), C("eq", -1))
    assert not at_least_as_strict(C("max", -1), C("max", 0))
    assert not at_least_as_strict(C("max", -1), C("eq", 0))


# --- row 4: parent `glob g` -------------------------------------------------


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "reports/q3.csv"),
        C("eq", "reports/"),
        C("eq", "reports/a/b/c"),
        C("in", ["reports/q1", "reports/q2"]),
        C("in", ["reports/"]),
    ],
)
def test_parent_glob_accepts_eq_and_in_when_every_value_matches(child):
    assert at_least_as_strict(C("glob", "reports/*"), child)


@pytest.mark.parametrize(
    "child",
    [
        C("eq", "reports"),
        C("eq", "secrets/q3.csv"),
        C("eq", ""),
        C("eq", "xreports/q3"),
        C("in", ["reports/q1", "secrets/q2"]),  # one value does not match
        C("in", ["secrets/a", "secrets/b"]),
        C("eq", 5),  # a number is not a string
        C("eq", True),
        C("in", ["reports/q1", 5]),
    ],
)
def test_parent_glob_rejects_eq_and_in_when_some_value_does_not_match(child):
    assert not at_least_as_strict(C("glob", "reports/*"), child)


@pytest.mark.parametrize("pattern", ["reports/*", "*.csv", "a*b*c", "*", "", "abc", "*a*"])
def test_parent_glob_accepts_identical_pattern(pattern):
    assert at_least_as_strict(C("glob", pattern), C("glob", pattern))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        ("reports/*", "reports/q3/*"),
        ("reports/*", "reports/q3/*.csv"),
        ("reports/*", "reports/*/final/*"),
        ("reports/*", "reports/*.csv"),  # same literal head, extra suffix
        ("reports/*", "reports/**"),
        ("reports/*", "reports/q3.csv"),  # child with no star at all
        ("reports/*", "reports/"),
        ("rep*", "reports/*"),
        ("*", "reports/*"),  # empty literal prefix
        ("*", "*.csv"),
        ("*", "a*b*c"),
        ("*", "abc"),
        ("*", ""),
    ],
)
def test_parent_glob_accepts_literal_prefix_extension(parent, child):
    assert at_least_as_strict(C("glob", parent), C("glob", child))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        ("reports/*", "repo*"),  # shorter head: also matches "repository"
        ("reports/*", "reports*"),  # drops the "/": also matches "reportsX"
        ("reports/*", "*"),
        ("reports/*", "*reports/*"),
        ("reports/*", "*/q3"),
        ("reports/*", "secrets/*"),
        ("reports/*", "Reports/*"),
        ("reports/*", "reports"),
        ("reports/*", ""),
        ("reports/q3/*", "reports/*"),  # the row read backwards
        ("abc", "abd"),
        ("abc", "abc*"),
        ("abc", "*"),
        ("", "*"),
        ("*.csv", "*"),
        ("*.csv", "*.txt"),
        ("a*c", "a*"),
        ("a*c", "*c"),
    ],
)
def test_parent_glob_rejects_patterns_that_match_more(parent, child):
    assert not at_least_as_strict(C("glob", parent), C("glob", child))


@pytest.mark.parametrize("child", [C("max", 5), C("any")])
def test_parent_glob_rejects_max_and_any(child):
    assert not at_least_as_strict(C("glob", "reports/*"), child)
    assert not at_least_as_strict(C("glob", "*"), child)


# --- rule A: a child glob with no star is the single string of its pattern ---
# Such a child is finite (Constraint.finite_values), so it goes through the
# same enumeration path as eq: accepted exactly when the parent accepts that
# one string, whatever the parent's operator.


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (C("eq", "abc"), "abc"),
        (C("eq", ""), ""),
        (C("in", ["a", "b"]), "a"),
        (C("glob", "*a"), "ba"),  # parent is not of the form P*
        (C("glob", "a*b*c"), "aXbYc"),
        (C("glob", "a*b*c"), "abc"),  # every star matches the empty string
        (C("glob", "*.gz"), "x.tar.gz"),
        (C("glob", "abc"), "abc"),
        (C("glob", "reports/*"), "reports/q3.csv"),
    ],
)
def test_rule_a_star_free_child_glob_accepted_when_parent_accepts_its_string(parent, child):
    assert parent.holds(child)
    assert at_least_as_strict(parent, C("glob", child))
    assert covers(cap(parent), cap(C("glob", child)))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (C("eq", "abc"), "abd"),
        (C("eq", "abc"), ""),
        (C("in", ["a", "b"]), "c"),
        (C("glob", "*a"), "ab"),
        (C("glob", "a*b*c"), "acb"),
        (C("glob", "abc"), "abd"),
        (C("max", 3), "1"),  # the child accepts the STRING "1", not a number
        (C("eq", 1), "1"),
        (C("in", [1, True]), "1"),
    ],
)
def test_rule_a_star_free_child_glob_rejected_when_parent_rejects_its_string(parent, child):
    assert not parent.holds(child)
    assert not at_least_as_strict(parent, C("glob", child))
    assert not covers(cap(parent), cap(C("glob", child)))


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (C("eq", "a"), "a*"),  # also accepts "ab"
        (C("eq", "a*"), "a*"),  # the literal string "a*" is one of many matches
        (C("in", ["a", "a*"]), "a*"),
        (C("eq", ""), "*"),
        (C("glob", "*a"), "b*a*"),
        (C("max", 3), "1*"),
    ],
)
def test_rule_a_does_not_apply_to_a_child_glob_with_a_star(parent, child):
    assert C("glob", child).finite_values() is None
    assert not at_least_as_strict(parent, C("glob", child))


def test_rule_a_respects_the_argument_name():
    assert not at_least_as_strict(C("eq", "abc"), C("glob", "abc", arg="y"))


# --- parent `any` and child `any` -------------------------------------------


@pytest.mark.parametrize(
    "child",
    [
        C("any"),
        C("eq", "a"),
        C("eq", True),
        C("in", [1, "a", False]),
        C("max", 10),
        C("glob", "*"),
        C("glob", "reports/*"),
    ],
)
def test_parent_any_accepts_every_child_on_the_same_argument(child):
    assert at_least_as_strict(C("any"), child)


@pytest.mark.parametrize(
    "parent",
    [C("eq", "a"), C("in", ["a", "b"]), C("max", 10), C("glob", "reports/*"), C("glob", "*")],
)
def test_child_any_under_non_any_parent_is_rejected(parent):
    assert not at_least_as_strict(parent, C("any"))


def test_child_any_under_parent_glob_star_is_a_real_escalation():
    # Not incompleteness: glob "*" admits only strings, `any` admits everything.
    parent, child = cap(C("glob", "*")), cap(C("any"))
    call = Call("t", {"x": 5})
    assert child.permits(call)
    assert not parent.permits(call)
    assert not covers(parent, child)


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        (C("any"), C("any", arg="y")),
        (C("eq", "a"), C("eq", "a", arg="y")),
        (C("max", 10), C("max", 5, arg="y")),
        (C("glob", "a*"), C("glob", "a*", arg="y")),
    ],
)
def test_constraints_on_different_arguments_never_compare(parent, child):
    assert not at_least_as_strict(parent, child)


# --- covers: capability against capability ----------------------------------


def test_covers_identical_capability():
    c = cap(C("glob", "reports/*", arg="path"), C("max", 10, arg="n"))
    assert covers(c, c)


def test_covers_every_parent_constraint_needs_a_stricter_child_constraint():
    parent = cap(C("glob", "reports/*", arg="path"), C("max", 10, arg="n"))
    assert covers(parent, cap(C("eq", "reports/q3", arg="path"), C("max", 5, arg="n")))
    # constraint order in the child does not matter
    assert covers(parent, cap(C("max", 5, arg="n"), C("eq", "reports/q3", arg="path")))
    assert not covers(parent, cap(C("eq", "reports/q3", arg="path"), C("max", 11, arg="n")))
    assert not covers(parent, cap(C("eq", "secrets/q3", arg="path"), C("max", 5, arg="n")))


def test_covers_child_may_add_constraints_on_an_argument_the_parent_names():
    parent = cap(C("glob", "reports/*"))
    child = cap(C("glob", "reports/*"), C("glob", "*.csv"))
    assert covers(parent, child)
    assert not covers(child, parent)


def test_covers_two_parent_constraints_on_one_argument_both_need_cover():
    parent = cap(C("glob", "reports/*"), C("max", 5, arg="n"), C("in", [1, 2, 9], arg="n"))
    assert covers(parent, cap(C("glob", "reports/*"), C("in", [1, 2], arg="n")))
    assert not covers(parent, cap(C("glob", "reports/*"), C("eq", 9, arg="n")))
    assert not covers(parent, cap(C("glob", "reports/*"), C("max", 5, arg="n")))


def test_covers_different_tool_is_rejected():
    assert not covers(cap(C("any"), tool="read"), cap(C("any"), tool="write"))
    assert not covers(cap(tool="read"), cap(tool="read_all"))
    assert not covers(cap(tool="read"), cap(tool="Read"))


def test_covers_no_constraints_on_either_side():
    assert covers(cap(), cap())


@pytest.mark.parametrize(
    ("parent", "child"),
    [
        # child drops an argument the parent names
        (cap(C("any"), C("any", arg="y")), cap(C("any"))),
        (cap(C("eq", "a")), cap()),
        # child adds an argument the parent does not name: the parent would
        # refuse every call that carries it
        (cap(C("any")), cap(C("any"), C("eq", 1, arg="y"))),
        (cap(), cap(C("eq", "a"))),
        # same number of arguments, different names
        (cap(C("any")), cap(C("any", arg="y"))),
    ],
)
def test_covers_argument_name_sets_must_match(parent, child):
    assert not covers(parent, child)


def test_covers_added_argument_would_be_a_real_escalation():
    parent, child = cap(C("eq", "a", arg="to")), cap(C("eq", "a", arg="to"), C("any", arg="bcc"))
    call = Call("t", {"to": "a", "bcc": "evil"})
    assert child.permits(call)
    assert not parent.permits(call)
    assert not covers(parent, child)


# --- covers: call budgets ---------------------------------------------------


@pytest.mark.parametrize(
    ("parent_budget", "child_budget", "expected"),
    [
        (None, None, True),  # neither side has a budget
        (None, 1, True),  # child adds a budget
        (None, 10**6, True),
        (5, 5, True),
        (5, 4, True),
        (5, 1, True),
        (5, 6, False),  # larger budget
        (1, 2, False),
        (5, None, False),  # child drops the parent's budget
        (1, None, False),
    ],
)
def test_covers_max_calls(parent_budget, child_budget, expected):
    parent = cap(C("any"), max_calls=parent_budget)
    child = cap(C("any"), max_calls=child_budget)
    assert covers(parent, child) is expected


def test_covers_budget_does_not_rescue_a_wider_constraint():
    assert not covers(cap(C("max", 5), max_calls=5), cap(C("max", 6), max_calls=1))


# --- check_attenuation: grants ----------------------------------------------

PARENT = grant(
    cap(C("glob", "reports/*", arg="path"), tool="read"),
    cap(C("in", ["a@x.com", "b@x.com"], arg="to"), C("max", 100, arg="size"), tool="send"),
    cap(tool="ping", max_calls=3),
)


def test_attenuation_accepts_identical_grant():
    r = check_attenuation(PARENT, PARENT)
    assert r == AttenuationResult(True, "ok", (0, 1, 2))
    assert bool(r) is True


def test_attenuation_accepts_narrower_grant():
    child = grant(
        cap(C("eq", "a@x.com", arg="to"), C("max", 10, arg="size"), tool="send"),
        cap(C("glob", "reports/q3/*", arg="path"), tool="read"),
        expires_at=500,
    )
    r = check_attenuation(PARENT, child)
    assert r.ok
    assert r.reason == "ok"
    assert r.derivation == (1, 0)


def test_attenuation_accepts_empty_child():
    assert check_attenuation(PARENT, grant()) == AttenuationResult(True, "ok", ())
    assert check_attenuation(grant(), grant()).ok


def test_attenuation_rejects_any_capability_from_an_empty_parent():
    assert not check_attenuation(grant(), grant(cap(tool="ping")))


def test_attenuation_rejects_uncovered_capability_and_names_it():
    child = grant(
        cap(C("eq", "reports/q3", arg="path"), tool="read"),
        cap(C("eq", "c@x.com", arg="to"), C("max", 10, arg="size"), tool="send"),
    )
    r = check_attenuation(PARENT, child)
    assert not r
    assert r.ok is False
    assert r.reason == "child capability 1 (send) is not covered by any parent capability"
    assert r.derivation == ()


def test_attenuation_rejects_tool_the_parent_does_not_have():
    r = check_attenuation(PARENT, grant(cap(tool="delete")))
    assert not r.ok
    assert r.reason == "child capability 0 (delete) is not covered by any parent capability"


def test_attenuation_one_bad_capability_rejects_the_whole_grant():
    child = grant(cap(tool="ping", max_calls=1), cap(tool="ping", max_calls=4))
    assert not check_attenuation(PARENT, child).ok


def test_attenuation_budget_rules_apply_through_grants():
    assert check_attenuation(PARENT, grant(cap(tool="ping", max_calls=3))).ok
    assert not check_attenuation(PARENT, grant(cap(tool="ping", max_calls=4))).ok
    assert not check_attenuation(PARENT, grant(cap(tool="ping"))).ok


@pytest.mark.parametrize(
    ("parent_expiry", "child_expiry", "expected"),
    [
        (1000, 1000, True),  # equal is allowed
        (1000, 999, True),
        (1000, 0, True),
        (1000, 999.999, True),
        (1000, 1000.001, False),
        (1000, 1001, False),
        (1000, 10**12, False),
        (-5, -6, True),
        (-5, -4, False),
    ],
)
def test_attenuation_expiry(parent_expiry, child_expiry, expected):
    c = cap(C("any"))
    r = check_attenuation(grant(c, expires_at=parent_expiry), grant(c, expires_at=child_expiry))
    assert r.ok is expected
    if not expected:
        assert r.reason == "child expires later than parent"
        assert r.derivation == ()


def test_attenuation_expiry_is_checked_even_for_an_empty_child():
    r = check_attenuation(grant(expires_at=10), grant(expires_at=11))
    assert not r.ok
    assert r.reason == "child expires later than parent"


# --- check_attenuation: the derivation mapping ------------------------------


def test_derivation_maps_each_child_capability_to_its_covering_parent():
    parent = grant(
        cap(C("in", ["a", "b"]), tool="t"),
        cap(C("in", ["c", "d"]), tool="t"),
        cap(C("any"), tool="u"),
    )
    child = grant(
        cap(C("eq", "d"), tool="t"),
        cap(C("eq", "z"), tool="u"),
        cap(C("eq", "a"), tool="t"),
        cap(C("eq", "c"), tool="t"),
    )
    r = check_attenuation(parent, child)
    assert r.ok
    assert r.derivation == (1, 2, 0, 1)
    assert len(r.derivation) == len(child.capabilities)
    for i, j in enumerate(r.derivation):
        assert covers(parent.capabilities[j], child.capabilities[i])


def test_derivation_picks_the_first_covering_parent():
    parent = grant(cap(C("glob", "*")), cap(C("glob", "reports/*")), cap(C("any")))
    r = check_attenuation(parent, grant(cap(C("eq", "reports/q3"))))
    assert r.derivation == (0,)


def test_derivation_may_map_several_children_to_one_parent():
    parent = grant(cap(C("in", ["a", "b"]), max_calls=5))
    child = grant(cap(C("eq", "a"), max_calls=5), cap(C("eq", "b"), max_calls=5))
    assert check_attenuation(parent, child).derivation == (0, 0)


def test_derivation_skips_a_parent_whose_budget_is_too_small():
    parent = grant(cap(C("any"), max_calls=1), cap(C("any"), max_calls=10))
    assert check_attenuation(parent, grant(cap(C("any"), max_calls=5))).derivation == (1,)


def test_attenuation_result_defaults():
    r = AttenuationResult(False, "no")
    assert bool(r) is False
    assert r.derivation == ()


# --- documented incompleteness ----------------------------------------------
# Every child below is SAFE (it allows nothing its parent denies) and is still
# rejected. That is the intended trade: sound, not complete. See PLAN.md 3.2.


def test_incomplete_child_covered_only_by_union_of_two_parent_capabilities():
    # INCOMPLETE BY DESIGN: parent allows x in {a,b} via cap 0 and x in {c,d}
    # via cap 1. Child `in [b, c]` is inside the union but inside neither one.
    parent = grant(cap(C("in", ["a", "b"])), cap(C("in", ["c", "d"])))
    child = grant(cap(C("in", ["b", "c"])))
    for value in ["b", "c"]:  # the child really is safe
        assert parent.allows(Call("t", {"x": value}), now=0)
    r = check_attenuation(parent, child)
    assert not r.ok
    assert r.reason == "child capability 0 (t) is not covered by any parent capability"
    # splitting the child into one capability per parent capability is accepted
    split = grant(cap(C("eq", "b")), cap(C("eq", "c")))
    assert check_attenuation(parent, split).derivation == (0, 1)


def test_incomplete_union_of_two_parent_glob_capabilities():
    # INCOMPLETE BY DESIGN: the same shape with two glob parents. Each value
    # of the child is allowed by one parent capability, but no single parent
    # capability allows both.
    parent = grant(cap(C("glob", "reports/*")), cap(C("glob", "notes/*")))
    child = grant(cap(C("in", ["reports/x", "notes/x"])))
    for value in ["reports/x", "notes/x"]:
        assert parent.allows(Call("t", {"x": value}), now=0)
    assert not check_attenuation(parent, child).ok


def test_child_glob_without_star_under_parent_eq_is_accepted():
    # Formerly rejected (documented incompleteness), accepted since rule A:
    # glob "abc" has no star, so it accepts exactly the string "abc", the same
    # set as eq "abc", and is checked like eq "abc".
    assert at_least_as_strict(C("eq", "abc"), C("glob", "abc"))
    assert at_least_as_strict(C("in", ["abc", "abd"]), C("glob", "abc"))


def test_incomplete_child_glob_with_longer_suffix_under_parent_suffix_glob():
    # INCOMPLETE BY DESIGN: everything matching "*.tar.gz" matches "*.gz", but
    # only literal-PREFIX extension is recognized, not suffix extension.
    assert not at_least_as_strict(C("glob", "*.gz"), C("glob", "*.tar.gz"))


def test_incomplete_child_glob_under_parent_glob_with_inner_star():
    # INCOMPLETE BY DESIGN: everything matching "a/x/*/b" matches "a/*/b", but
    # the parent has a star before its end, so prefix extension does not apply.
    assert not at_least_as_strict(C("glob", "a/*/b"), C("glob", "a/x/*/b"))
    assert not at_least_as_strict(C("glob", "a*b*"), C("glob", "a*b*c"))


def test_incomplete_child_glob_under_equivalent_double_star_parent():
    # INCOMPLETE BY DESIGN: "reports/**" and "reports/*" match the same
    # strings, but the parent "reports/**" is not of the form literal + "*".
    assert at_least_as_strict(C("glob", "reports/*"), C("glob", "reports/**"))
    assert not at_least_as_strict(C("glob", "reports/**"), C("glob", "reports/*"))


def test_incomplete_child_stricter_only_by_conjunction_of_its_constraints():
    # INCOMPLETE BY DESIGN: the child's two constraints together admit only
    # the number 5 (in [5, "a"] and max 10), which the parent `eq 5` allows.
    # Each parent constraint must be covered by ONE child constraint, and
    # neither child constraint alone is as strict as `eq 5`.
    parent = cap(C("eq", 5))
    child = cap(C("in", [5, "a"]), C("max", 10))
    assert child.permits(Call("t", {"x": 5}))
    assert not child.permits(Call("t", {"x": "a"}))
    assert not covers(parent, child)


def test_incomplete_unsatisfiable_child_is_rejected():
    # INCOMPLETE BY DESIGN: this child allows no call at all (x cannot be
    # both "a" and "b"), so it is trivially safe, yet it is not covered.
    parent = cap(C("eq", "c"))
    child = cap(C("eq", "a"), C("eq", "b"))
    assert not child.permits(Call("t", {"x": "a"}))
    assert not child.permits(Call("t", {"x": "b"}))
    assert not covers(parent, child)


# --- a small exhaustive soundness check -------------------------------------
# Not a replacement for the Hypothesis property test: a fixed, tiny universe
# in which every accepted (parent, child) pair is checked against every call.

_VALUES = ["", "a", "ab", "abc", "b", "a/b", 0, 1, 2, 1.5, True, False, None]
_CONSTRAINTS = [
    C("any"),
    C("eq", "a"),
    C("eq", "ab"),
    C("eq", 1),
    C("eq", True),
    C("in", ["a", "ab"]),
    C("in", ["a", 1]),
    C("in", [0, 1, 2]),
    C("max", 0),
    C("max", 1),
    C("max", 2),
    C("glob", "*"),
    C("glob", "a*"),
    C("glob", "ab*"),
    C("glob", "a*c"),
    C("glob", "*b"),
    C("glob", "a"),
    C("glob", ""),
]


def test_soundness_single_constraints_exhaustive():
    accepted = 0
    for parent in _CONSTRAINTS:
        for child in _CONSTRAINTS:
            if not at_least_as_strict(parent, child):
                continue
            accepted += 1
            for v in _VALUES:
                assert not child.holds(v) or parent.holds(v), (parent, child, v)
    assert accepted > len(_CONSTRAINTS)  # more than the reflexive pairs


def test_soundness_capabilities_exhaustive():
    caps = [cap()]
    caps += [cap(c) for c in _CONSTRAINTS]
    caps += [cap(a, b) for a in _CONSTRAINTS[:8] for b in _CONSTRAINTS[8:]]
    caps += [cap(c, C("any", arg="y")) for c in _CONSTRAINTS[:6]]
    calls = [Call("t", {})]
    calls += [Call("t", {"x": v}) for v in _VALUES]
    calls += [Call("t", {"x": v, "y": 1}) for v in _VALUES]
    calls += [Call("t", {"y": 1}), Call("u", {"x": "a"})]
    for parent in caps:
        for child in caps:
            if covers(parent, child):
                for call in calls:
                    assert not child.permits(call) or parent.permits(call), (parent, child, call)
