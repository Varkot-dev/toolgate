"""Constraint language: glob matching, strict equality and each operator."""

import math

import pytest

from toolgate.constraints import Constraint, glob_match, same_value

NAN = float("nan")
INF = float("inf")


# --- glob_match -------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        # no star: plain string equality
        ("abc", "abc", True),
        ("abc", "abcd", False),
        ("abc", "ab", False),
        ("abc", "ABC", False),
        ("abc", "", False),
        # empty pattern matches only the empty string
        ("", "", True),
        ("", "a", False),
        # a lone star matches everything, including the empty string and "/"
        ("*", "", True),
        ("*", "anything", True),
        ("*", "a/b/c", True),
        ("*", "*", True),
        # trailing star
        ("reports/*", "reports/q3.csv", True),
        ("reports/*", "reports/", True),
        ("reports/*", "reports/a/b/c", True),
        ("reports/*", "reports", False),
        ("reports/*", "xreports/q3", False),
        ("reports/*", "", False),
        # leading star
        ("*.csv", "a.csv", True),
        ("*.csv", ".csv", True),
        ("*.csv", "dir/a.csv", True),
        ("*.csv", "a.csv.bak", False),
        ("*.csv", "csv", False),
        # star in the middle
        ("a*c", "ac", True),
        ("a*c", "abc", True),
        ("a*c", "a/b/c", True),
        ("a*c", "abcd", False),
        ("a*c", "bac", False),
        # head and tail may not overlap in the text
        ("ab*bc", "abc", False),
        ("ab*bc", "abbc", True),
        ("ab*bc", "abxbc", True),
        ("a*a", "a", False),
        ("a*a", "aa", True),
        ("aa*aa", "aaa", False),
        ("aa*aa", "aaaa", True),
        # multiple stars
        ("a*b*c", "abc", True),
        ("a*b*c", "aXbYc", True),
        ("a*b*c", "ac", False),
        ("a*b*c", "acb", False),
        ("a*b*c", "abcbc", True),
        ("*a*", "a", True),
        ("*a*", "xax", True),
        ("*a*", "", False),
        ("*a*", "xyz", False),
        ("*a*b*", "ba", False),
        ("*a*b*", "ab", True),
        ("*ab*ab*", "ab", False),
        ("*ab*ab*", "abab", True),
        ("*ab*ab*", "aab", False),
        # the middle part must be found between head and tail, not inside them
        ("a*b*b", "ab", False),
        ("a*b*b", "abb", True),
        ("ab*b*c", "abc", False),
        ("ab*b*c", "abbc", True),
        # adjacent stars behave like one star
        ("a**b", "ab", True),
        ("a**b", "axb", True),
        ("**", "", True),
        ("**", "x", True),
    ],
)
def test_glob_match(pattern, text, expected):
    assert glob_match(pattern, text) is expected


@pytest.mark.parametrize(
    ("pattern", "text", "expected"),
    [
        # "?" , "[...]" and "\" are ordinary characters
        ("a?c", "abc", False),
        ("a?c", "a?c", True),
        ("[ab]", "a", False),
        ("[ab]", "[ab]", True),
        ("a\\*", "a*", False),
        ("a\\*", "a\\", True),
        ("a\\*", "a\\anything", True),
        ("a.c", "abc", False),
    ],
)
def test_glob_only_star_is_special(pattern, text, expected):
    assert glob_match(pattern, text) is expected


def test_glob_does_not_normalize_paths():
    # Documented: plain string matching, callers must canonicalize paths first.
    assert glob_match("reports/*", "reports/../secrets")


# --- same_value -------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (1, 1),
        (3, 3.0),
        (3.0, 3),
        (0, -0.0),
        (-2.5, -2.5),
        ("a", "a"),
        ("", ""),
        (True, True),
        (False, False),
        (10**30, 10**30),
    ],
)
def test_same_value_equal(a, b):
    assert same_value(a, b) is True


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (True, 1),
        (1, True),
        (False, 0),
        (0, False),
        (True, 1.0),
        (True, False),
        (True, "True"),
        ("1", 1),
        (1, "1"),
        ("a", "A"),
        ("a", "a "),
        (1, 2),
        (3, 3.5),
        (None, None),
        (None, 0),
        (None, ""),
        (NAN, NAN),
        (NAN, 1),
        (INF, INF),
        (-INF, -INF),
        ([1], [1]),
        ((1,), (1,)),
        ({"a": 1}, {"a": 1}),
        ([], ""),
        (b"a", "a"),
        (2**53 + 1, float(2**53)),
    ],
)
def test_same_value_not_equal(a, b):
    assert same_value(a, b) is False


# --- construction -----------------------------------------------------------


@pytest.mark.parametrize("op", ["EQ", "equals", "regex", "min", "max_calls", "", None, 1])
def test_unknown_operator_raises(op):
    with pytest.raises(ValueError):
        Constraint("x", op, 1)


@pytest.mark.parametrize("arg", ["", None, 1, ("x",)])
def test_bad_argument_name_raises(arg):
    with pytest.raises(ValueError):
        Constraint(arg, "eq", 1)


@pytest.mark.parametrize("value", [None, NAN, INF, -INF, [1], (1,), {"a": 1}, b"x", 1j])
def test_eq_rejects_non_scalar_value(value):
    with pytest.raises(ValueError):
        Constraint("x", "eq", value)


@pytest.mark.parametrize("value", ["a", "", 0, 1.5, True, False, -3])
def test_eq_accepts_scalars(value):
    assert Constraint("x", "eq", value).value == value


@pytest.mark.parametrize(
    "value",
    [None, [], (), set(), "abc", 1, {"a": 1}, [None], [1, NAN], [INF], [[1]], ["a", None]],
)
def test_in_rejects_bad_value(value):
    with pytest.raises(ValueError):
        Constraint("x", "in", value)


def test_in_normalizes_list_to_tuple():
    c = Constraint("x", "in", ["a", "b"])
    assert c.value == ("a", "b")
    assert Constraint("x", "in", ("a", "b")) == c


@pytest.mark.parametrize("value", [{"a"}, frozenset({"a", "b"})])
def test_in_rejects_sets_because_their_order_is_not_fixed(value):
    with pytest.raises(ValueError):
        Constraint("x", "in", value)


@pytest.mark.parametrize("value", [None, "10", True, False, NAN, INF, -INF, [1], 1j])
def test_max_rejects_non_number(value):
    with pytest.raises(ValueError):
        Constraint("x", "max", value)


@pytest.mark.parametrize("value", [None, 1, True, ["a*"], b"a*"])
def test_glob_rejects_non_string(value):
    with pytest.raises(ValueError):
        Constraint("x", "glob", value)


@pytest.mark.parametrize("value", [True, 1, "", "x", [], False])
def test_any_takes_no_value(value):
    with pytest.raises(ValueError):
        Constraint("x", "any", value)


def test_any_default_value():
    assert Constraint("x", "any").value is None


def test_constraint_is_immutable_and_hashable():
    c = Constraint("x", "in", [1, 2])
    with pytest.raises(AttributeError):
        c.value = (1, 2, 3)
    assert hash(c) == hash(Constraint("x", "in", (1, 2)))


# --- holds ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "x", "expected"),
    [
        ("a", "a", True),
        ("a", "b", False),
        ("a", "", False),
        (3, 3, True),
        (3, 3.0, True),
        (3.0, 3, True),
        (3, 4, False),
        (3, "3", False),
        ("3", 3, False),
        (1, True, False),
        (0, False, False),
        (True, 1, False),
        (True, True, True),
        (True, False, False),
        (False, False, True),
        (False, 0, False),
        (False, None, False),
        (3, None, False),
        (3, NAN, False),
        (3, INF, False),
        (3, [3], False),
        ("a", ["a"], False),
        ("a", {"a": 1}, False),
    ],
)
def test_eq_holds(value, x, expected):
    assert Constraint("x", "eq", value).holds(x) is expected


@pytest.mark.parametrize(
    ("values", "x", "expected"),
    [
        (["a", "b"], "a", True),
        (["a", "b"], "b", True),
        (["a", "b"], "c", False),
        (["a", "b"], "ab", False),
        (["a", "b"], ["a"], False),
        (["a", "b"], ["a", "b"], False),
        (["a", "b"], ("a", "b"), False),
        (["a", "b"], None, False),
        ([1, 2], 1, True),
        ([1, 2], 2.0, True),
        ([1, 2], 3, False),
        ([1, 2], True, False),
        ([1, 2], "1", False),
        ([1, 2], NAN, False),
        ([1, 2], INF, False),
        ([0, 1], False, False),
        ([True], True, True),
        ([True], 1, False),
        ([True], False, False),
        (["1", 1], "1", True),
        (["1", 1], 1, True),
        (["1", 1], True, False),
    ],
)
def test_in_holds(values, x, expected):
    assert Constraint("x", "in", values).holds(x) is expected


@pytest.mark.parametrize(
    ("ceiling", "x", "expected"),
    [
        (10, 10, True),
        (10, 9, True),
        (10, 10.0, True),
        (10, 9.999, True),
        (10, -1000, True),
        (10, 0, True),
        (10, 11, False),
        (10, 10.0001, False),
        (10.5, 10, True),
        (10.5, 10.5, True),
        (10.5, 11, False),
        (-1, -1, True),
        (-1, 0, False),
        # wrong types are denied, never coerced
        (10, True, False),
        (10, False, False),
        (10, "5", False),
        (10, "", False),
        (10, None, False),
        (10, NAN, False),
        (10, INF, False),
        (10, -INF, False),
        (10, [1], False),
        (10, [], False),
        (10, {"n": 1}, False),
        (10, 1j, False),
    ],
)
def test_max_holds(ceiling, x, expected):
    assert Constraint("x", "max", ceiling).holds(x) is expected


def test_max_holds_compares_big_ints_exactly():
    c = Constraint("x", "max", 2**53)
    assert c.holds(2**53)
    assert not c.holds(2**53 + 1)


@pytest.mark.parametrize(
    ("pattern", "x", "expected"),
    [
        ("reports/*", "reports/q3", True),
        ("reports/*", "reports/", True),
        ("reports/*", "reports/a/b", True),
        ("reports/*", "other/q3", False),
        ("reports/*", "", False),
        ("*", "", True),
        ("", "", True),
        ("abc", "abc", True),
        ("abc", "abd", False),
        # non-strings never match, even the catch-all pattern
        ("*", None, False),
        ("*", 1, False),
        ("*", True, False),
        ("*", NAN, False),
        ("*", ["a"], False),
        ("*", b"a", False),
        ("1*", 1, False),
        ("reports/*", ["reports/q3"], False),
    ],
)
def test_glob_holds(pattern, x, expected):
    assert Constraint("x", "glob", pattern).holds(x) is expected


@pytest.mark.parametrize("x", ["a", "", 0, 1.5, True, None, NAN, INF, [1], {"a": 1}])
def test_any_holds_for_every_value(x):
    assert Constraint("x", "any").holds(x) is True


def test_holds_nan_is_never_equal_even_to_itself():
    assert not Constraint("x", "in", [1.0]).holds(math.nan)


# --- finite_values ----------------------------------------------------------


def test_finite_values():
    assert Constraint("x", "eq", "a").finite_values() == ("a",)
    assert Constraint("x", "in", ["a", 1]).finite_values() == ("a", 1)
    assert Constraint("x", "max", 5).finite_values() is None
    assert Constraint("x", "glob", "a").finite_values() is None
    assert Constraint("x", "any").finite_values() is None
