"""Argument constraints: the small, closed language a capability is written in.

A constraint is a predicate on one named argument of a tool call. There are
exactly five operators. Anything else is rejected when the constraint is
built, so an unknown operator can never reach an authorization decision.

    eq    argument equals a value
    in    argument is one of a finite allow-list
    max   numeric argument is at most a ceiling
    glob  string argument matches a pattern in which only "*" is special
    any   argument must be present, any value is accepted
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

OPS: frozenset[str] = frozenset({"eq", "in", "max", "glob", "any"})


def _is_number(value: Any) -> bool:
    """True for a finite int or float. bool is not a number here."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value)


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (bool, str)) or _is_number(value)


def same_value(a: Any, b: Any) -> bool:
    """Equality used by `eq` and `in`.

    Stricter than Python's `==`: True never equals 1, a string never equals a
    number, and non-scalars (lists, dicts, None, NaN) equal nothing. Numbers
    compare by value, so 3 equals 3.0.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if _is_number(a) and _is_number(b):
        return a == b
    return False


def glob_match(pattern: str, text: str) -> bool:
    """Match `text` against `pattern`, where "*" matches any run of characters.

    "*" is the only special character and it also matches "/" and the empty
    string. There is no "?", no character class and no escape. This is plain
    string matching: it does not normalize paths, so "reports/../x" matches
    "reports/*". Callers that mean file paths must canonicalize first.
    """
    parts = pattern.split("*")
    if len(parts) == 1:
        return text == pattern
    head, tail = parts[0], parts[-1]
    if len(text) < len(head) + len(tail):
        return False
    if not text.startswith(head) or not text.endswith(tail):
        return False
    pos, end = len(head), len(text) - len(tail)
    for part in parts[1:-1]:
        found = text.find(part, pos, end)
        if found < 0:
            return False
        pos = found + len(part)
    return True


@dataclass(frozen=True)
class Constraint:
    """One predicate on one argument. Immutable and validated on creation."""

    arg: str
    op: str
    value: Any = None

    def __post_init__(self) -> None:
        if not isinstance(self.arg, str) or not self.arg:
            raise ValueError("constraint argument name must be a non-empty string")
        if self.op not in OPS:
            raise ValueError(f"unknown operator {self.op!r}")
        if self.op == "eq":
            if not _is_scalar(self.value):
                raise ValueError("eq needs a string, bool or finite number")
        elif self.op == "in":
            if isinstance(self.value, (list, set, frozenset)):
                object.__setattr__(self, "value", tuple(self.value))
            if not isinstance(self.value, tuple) or not self.value:
                raise ValueError("in needs a non-empty list of values")
            if not all(_is_scalar(v) for v in self.value):
                raise ValueError("in values must be strings, bools or finite numbers")
        elif self.op == "max":
            if not _is_number(self.value):
                raise ValueError("max needs a finite number")
        elif self.op == "glob":
            if not isinstance(self.value, str):
                raise ValueError("glob needs a string pattern")
        elif self.value is not None:
            raise ValueError("any takes no value")

    def holds(self, x: Any) -> bool:
        """Does the argument value `x` satisfy this constraint?"""
        if self.op == "eq":
            return same_value(x, self.value)
        if self.op == "in":
            return any(same_value(x, v) for v in self.value)
        if self.op == "max":
            return _is_number(x) and x <= self.value
        if self.op == "glob":
            return isinstance(x, str) and glob_match(self.value, x)
        return True  # any

    def finite_values(self) -> tuple[Any, ...] | None:
        """The complete list of accepted values for eq/in, else None."""
        if self.op == "eq":
            return (self.value,)
        if self.op == "in":
            return self.value
        return None
