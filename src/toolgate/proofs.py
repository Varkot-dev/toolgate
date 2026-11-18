"""Solver proofs of the attenuation rules (PLAN.md sections 3.2 and 3.9).

`toolgate.smt` answers the escalation question for one concrete pair of
constraints. This module asks it for a whole RULE at once: the constraint
parameters (the ceiling, the allow-lists, the pattern prefix, even the parent
predicate itself) are solver variables, so one `unsat` covers every instance
of the rule.

Each lemma is the query

    side condition of the rule  and  child accepts v  and  parent rejects v

and the rule is sound exactly when that is unsatisfiable. Each wrong variant
is the same query with the side condition weakened or reversed; it must be
satisfiable, and the model the solver returns is a concrete escalation. The
wrong variants are the evidence that the lemmas are not vacuous.

What a result means: `unsat` is a proof about these formulas. The link from
the formulas to the Python checker is the differential tests, not a proof.
`unknown` (a timeout, or a quantifier the solver gave up on) is reported as
`unknown` and is never counted as success.

Needs the optional `z3-solver` dependency.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import z3

from toolgate.smt import Value, glob_regex, string_lit

TIMEOUT_MS = 20_000

# Sizes of the bounded lemmas.
MAX_STARS = 4  # child glob patterns with 0..MAX_STARS stars
N_ARGS = 3  # argument names in the symbolic call
N_CONSTRAINTS = 3  # constraints per capability
N_CAPS = 3  # capabilities per grant
CHAIN_LENGTH = 6  # delegation hops in the bounded budget chain

# Concrete prefixes for the check that glob_regex(P + "*") means "starts with P".
REGEX_PREFIXES: tuple[str, ...] = ("", "a", "reports/", "reports/q3/", "a b", "?[x]", "é/ü")

# Concrete star-free patterns for the check that such a pattern accepts exactly itself.
STAR_FREE_PATTERNS: tuple[str, ...] = (
    "",
    "a",
    "abc",
    "reports/q3.csv",
    "a b",
    "?[x].+(y)|z\\^$",
    "é/ü",
)

_BOOL = z3.BoolSort()
_STRING = z3.StringSort()


@dataclass(frozen=True)
class Lemma:
    """One solver query and its outcome.

    `result` is "unsat", "sat" or "unknown". For a lemma, "unsat" is the proof.
    For a wrong variant, "sat" is expected and `counterexample` is the model.
    """

    name: str
    table_row: str
    statement: str
    bound: str | None
    result: str
    counterexample: str | None
    seconds: float


# A query is the list of assertions plus what to print from a model: either
# labelled terms to evaluate, or a function that renders the model itself.
# Convention: the LAST assertion is the goal ("the parent rejects"); everything
# before it is the rule's side condition and "the child accepts".
Terms = Sequence[tuple[str, z3.ExprRef]] | Callable[[z3.ModelRef], str]
Query = tuple[list[z3.BoolRef], Terms]

# Set only by all_premise_checks(): solve each query without its goal.
_premises_only = False


def _result_name(r: z3.CheckSatResult) -> str:
    if r == z3.unsat:
        return "unsat"
    if r == z3.sat:
        return "sat"
    return "unknown"


def _solve(formulas: list[z3.BoolRef]) -> tuple[str, z3.ModelRef | None]:
    s = z3.Solver()
    s.set("timeout", TIMEOUT_MS)
    s.add(*(formulas[:-1] if _premises_only else formulas))
    result = _result_name(s.check())
    return result, (s.model() if result == "sat" else None)


def _show(model: z3.ModelRef, terms: Terms) -> str:
    if callable(terms):
        return terms(model)
    return "; ".join(f"{label} = {model.eval(e, model_completion=True)}" for label, e in terms)


def _lemma(name: str, table_row: str, statement: str, bound: str | None, query: Query) -> Lemma:
    """Run one query."""
    formulas, terms = query
    start = time.perf_counter()
    result, model = _solve(formulas)
    seconds = time.perf_counter() - start
    counterexample = _show(model, terms) if model is not None else None
    return Lemma(name, table_row, statement, bound, result, counterexample, round(seconds, 4))


def _lemma_all(
    name: str, table_row: str, statement: str, bound: str, cases: Sequence[tuple[str, Query]]
) -> Lemma:
    """Run a family of queries that must ALL be unsat; report the first that is not."""
    start = time.perf_counter()
    expected = "sat" if _premises_only else "unsat"
    result, counterexample = expected, None
    for label, (formulas, terms) in cases:
        r, model = _solve(formulas)
        if r != expected:
            result = r
            counterexample = f"[{label}] " + (_show(model, terms) if model is not None else "")
            break
    seconds = time.perf_counter() - start
    return Lemma(name, table_row, statement, bound, result, counterexample, round(seconds, 4))


# --- shared pieces of the model ----------------------------------------------


def _v() -> z3.ExprRef:
    return z3.Const("v", Value)


def _max_holds(v: z3.ExprRef, ceiling: z3.ArithRef) -> z3.BoolRef:
    """`max m` on a symbolic ceiling. Same shape as toolgate.smt.holds."""
    return z3.And(Value.is_N(v), Value.n(v) <= ceiling)


def _prefix_holds(v: z3.ExprRef, prefix: z3.SeqRef) -> z3.BoolRef:
    """`glob P*` for a star-free P: a string that starts with P."""
    return z3.And(Value.is_S(v), z3.PrefixOf(prefix, Value.s(v)))


def _value_set(name: str) -> z3.ArrayRef:
    """A set of values of any size, as its membership function."""
    return z3.Const(name, z3.ArraySort(Value, _BOOL))


def _subset_of_predicate(
    members: z3.ArrayRef, pred: Callable[[z3.ExprRef], z3.BoolRef]
) -> z3.BoolRef:
    """What the enumeration rule checks: the parent holds on every listed value."""
    u = z3.Const("u", Value)
    return z3.ForAll([u], z3.Implies(members[u], pred(u)))


def _child_glob_text(stars: int) -> tuple[z3.SeqRef, z3.SeqRef]:
    """A string matched by a child pattern p0*p1*...*pk, and its literal head p0.

    The literals p0..pk and the texts x1..xk the stars matched are all symbolic.
    """
    head = z3.String("p0")
    parts: list[z3.SeqRef] = [head]
    for i in range(1, stars + 1):
        parts += [z3.String(f"x{i}"), z3.String(f"p{i}")]
    return (head if stars == 0 else z3.Concat(*parts)), head


# --- L1: the enumeration rule (child is eq or in) ----------------------------


def enumeration_rule() -> Lemma:
    """L1. Child eq/in under ANY parent predicate, any allow-list size."""
    v = _v()
    phi = z3.Function("parent", Value, _BOOL)
    members = _value_set("T")
    return _lemma(
        "L1 enumeration rule",
        "eq, in, max, glob, any (child is eq/in)",
        "If the parent accepts every value in the child's allow-list T, then no value "
        "is in T and rejected by the parent. The parent predicate is an arbitrary "
        "function of the value and T is an arbitrary set.",
        None,
        ([_subset_of_predicate(members, phi), members[v], z3.Not(phi(v))], [("v", v)]),
    )


def eq_under_eq() -> Lemma:
    """L1 instance, row eq: parent eq a, child eq a."""
    v, a = _v(), z3.Const("a", Value)
    return _lemma(
        "L1a parent eq a, child eq a",
        "eq",
        "The same single value on both sides: v equals a and v does not equal a.",
        None,
        ([v == a, z3.Not(v == a)], [("v", v), ("a", a)]),
    )


def in_under_in() -> Lemma:
    """L1 instance, row in: parent in S, child in T with T a subset of S."""
    v = _v()
    parent, child = _value_set("S"), _value_set("T")
    return _lemma(
        "L1b parent in S, child in T, T subset of S",
        "in",
        "T is a subset of S (sets of any size; a child eq a is T = {a}), v is in T "
        "and v is not in S.",
        None,
        (
            [_subset_of_predicate(child, lambda u: parent[u]), child[v], z3.Not(parent[v])],
            [("v", v)],
        ),
    )


def in_under_max() -> Lemma:
    """L1 instance, row max: parent max m, child eq/in with every value <= m."""
    v, m = _v(), z3.Real("m")
    child = _value_set("T")
    return _lemma(
        "L1c parent max m, child eq/in with all values <= m",
        "max",
        "Every value in T is a number <= m (m any real), v is in T and v is not a number <= m.",
        None,
        (
            [
                _subset_of_predicate(child, lambda u: _max_holds(u, m)),
                child[v],
                z3.Not(_max_holds(v, m)),
            ],
            [("v", v), ("m", m)],
        ),
    )


def in_under_glob() -> Lemma:
    """L1 instance, row glob: parent glob g, child eq/in whose values all match g."""
    v = _v()
    language = z3.Function("matches_g", _STRING, _BOOL)
    child = _value_set("T")

    def parent(u: z3.ExprRef) -> z3.BoolRef:
        return z3.And(Value.is_S(u), language(Value.s(u)))

    return _lemma(
        "L1d parent glob g, child eq/in with all values matching g",
        "glob",
        "Every value in T is a string matching g, v is in T and v is not a string "
        "matching g. The language of g is an arbitrary set of strings, so this holds "
        "for every pattern, not only prefix patterns.",
        None,
        ([_subset_of_predicate(child, parent), child[v], z3.Not(parent(v))], [("v", v)]),
    )


# --- L2: max under max -------------------------------------------------------


def _star_free_query(pattern: str) -> Query:
    t = z3.String("t")
    return [z3.InRe(t, glob_regex(pattern)) != (t == string_lit(pattern))], [("t", t)]


def star_free_glob_is_literal() -> Lemma:
    """L1 side condition for rule A: a star-free pattern g accepts exactly the string g."""
    return _lemma_all(
        "L1e a star-free glob g accepts exactly the string g",
        "glob",
        "A string t on which membership in toolgate.smt.glob_regex(g) and t == g "
        "disagree, for a pattern g that contains no star. A regex cannot be built from "
        "a symbolic pattern, so this is checked for fixed g only. Together with L1 "
        "(the enumeration rule for an arbitrary parent predicate, taking T = {g}) this "
        "covers rule A: a child glob with no star is accepted exactly when the parent "
        "accepts the string g.",
        "concrete g in " + ", ".join(repr(g) for g in STAR_FREE_PATTERNS),
        [(repr(g), _star_free_query(g)) for g in STAR_FREE_PATTERNS],
    )


def max_under_max() -> Lemma:
    """L2. Parent max m, child max n with n <= m."""
    v, m, n = _v(), z3.Real("m"), z3.Real("n")
    return _lemma(
        "L2 parent max m, child max n, n <= m",
        "max",
        "n <= m, v is a number <= n, and v is not a number <= m. Over the reals, "
        "which contain every Python int and finite float exactly.",
        None,
        ([n <= m, _max_holds(v, n), z3.Not(_max_holds(v, m))], [("v", v), ("m", m), ("n", n)]),
    )


# --- L3, L4: glob under glob -------------------------------------------------


def glob_identical() -> Lemma:
    """L3. Parent and child carry the identical pattern."""
    v = _v()
    language = z3.Function("matches_g", _STRING, _BOOL)
    holds = z3.And(Value.is_S(v), language(Value.s(v)))
    return _lemma(
        "L3 parent glob g, child glob g",
        "glob",
        "The same pattern on both sides (its language is an arbitrary set of "
        "strings): v matches and v does not match.",
        None,
        ([holds, z3.Not(holds)], [("v", v)]),
    )


def _glob_prefix_query(stars: int) -> Query:
    v, prefix = _v(), z3.String("P")
    text, head = _child_glob_text(stars)
    formulas = [
        z3.PrefixOf(prefix, head),
        Value.is_S(v),
        Value.s(v) == text,
        z3.Not(_prefix_holds(v, prefix)),
    ]
    return formulas, [("P", prefix), ("p0", head), ("v", v)]


def glob_prefix_bounded() -> Lemma:
    """L4. Parent P*, child p0*p1*...*pk with p0 starting with P, k = 0..MAX_STARS."""
    return _lemma_all(
        "L4 parent glob P*, child head starts with P",
        "glob",
        "The child pattern is p0*p1*...*pk and its head p0 starts with P. v is a "
        "string p0 x1 p1 ... xk pk (so the child matches it) that does not start "
        "with P. P, every literal piece and every star's text are symbolic strings.",
        f"one query per number of child stars k = 0..{MAX_STARS}; strings of any length",
        [(f"k={k}", _glob_prefix_query(k)) for k in range(MAX_STARS + 1)],
    )


def glob_head_is_prefix() -> Lemma:
    """L4 unbounded, step 1: whatever the child matches starts with its head."""
    t, head, rest = z3.String("t"), z3.String("p0"), z3.String("rest")
    return _lemma(
        "L4a a match starts with the child's head",
        "glob",
        "t = p0 followed by anything (the rest of the match, for any number of "
        "stars), and t does not start with p0.",
        None,
        ([t == z3.Concat(head, rest), z3.Not(z3.PrefixOf(head, t))], [("p0", head), ("t", t)]),
    )


def prefix_transitive() -> Lemma:
    """L4 unbounded, step 2: P prefix of p0 and p0 prefix of t give P prefix of t."""
    t, head, prefix = z3.String("t"), z3.String("p0"), z3.String("P")
    return _lemma(
        "L4b prefix is transitive",
        "glob",
        "p0 starts with P, t starts with p0, and t does not start with P. With L4a "
        "this is the prefix rule for any number of stars.",
        None,
        (
            [z3.PrefixOf(prefix, head), z3.PrefixOf(head, t), z3.Not(z3.PrefixOf(prefix, t))],
            [("P", prefix), ("p0", head), ("t", t)],
        ),
    )


def _regex_prefix_query(prefix: str) -> Query:
    t = z3.String("t")
    in_model = z3.InRe(t, glob_regex(prefix + "*"))
    return [in_model != z3.PrefixOf(string_lit(prefix), t)], [("t", t)]


def glob_regex_is_prefix() -> Lemma:
    """L4 link to the model: glob_regex(P + "*") is exactly 'starts with P'."""
    return _lemma_all(
        "L4c the model's regex for P* means 'starts with P'",
        "glob",
        "A string t on which membership in toolgate.smt.glob_regex(P + '*') and "
        "PrefixOf(P, t) disagree. A regex cannot be built from a symbolic pattern, "
        "so this is checked for fixed P only.",
        "concrete P in " + ", ".join(repr(p) for p in REGEX_PREFIXES),
        [(repr(p), _regex_prefix_query(p)) for p in REGEX_PREFIXES],
    )


# --- L5: parent any ----------------------------------------------------------


def anything_under_any() -> Lemma:
    """L5. Parent any accepts every value, so no child can exceed it."""
    v = _v()
    child = z3.Function("child", Value, _BOOL)
    return _lemma(
        "L5 parent any, child anything",
        "any",
        "The parent accepts every value. v is accepted by an arbitrary child "
        "predicate and rejected by the parent.",
        None,
        ([child(v), z3.Not(z3.BoolVal(True))], [("v", v)]),
    )


# --- L6: capability composition (covers) -------------------------------------


@dataclass(frozen=True)
class _SymCall:
    tool: z3.ArithRef
    present: tuple[z3.BoolRef, ...]
    value: tuple[z3.ExprRef, ...]

    def present_at(self, index: z3.ArithRef) -> z3.BoolRef:
        return z3.Or([z3.And(index == i, p) for i, p in enumerate(self.present)])

    def value_at(self, index: z3.ArithRef) -> z3.ExprRef:
        out = self.value[-1]
        for i in range(len(self.value) - 2, -1, -1):
            out = z3.If(index == i, self.value[i], out)
        return out


@dataclass(frozen=True)
class _SymCap:
    """A capability with up to N_CONSTRAINTS constraints; slot j is used iff active[j]."""

    tool: z3.ArithRef
    active: tuple[z3.BoolRef, ...]
    arg: tuple[z3.ArithRef, ...]
    pred: tuple[z3.FuncDeclRef, ...]

    def well_formed(self) -> z3.BoolRef:
        return z3.And([z3.And(a >= 0, a < N_ARGS) for a in self.arg])

    def names(self, i: int) -> z3.BoolRef:
        """Argument name i is named by some constraint."""
        return z3.Or([z3.And(act, a == i) for act, a in zip(self.active, self.arg, strict=True)])

    def permits(self, call: _SymCall) -> z3.BoolRef:
        """Mirrors Capability.decide: same tool, no unnamed argument, every constraint holds."""
        parts = [call.tool == self.tool]
        parts += [z3.Implies(call.present[i], self.names(i)) for i in range(N_ARGS)]
        for act, a, pred in zip(self.active, self.arg, self.pred, strict=True):
            parts.append(z3.Implies(act, z3.And(call.present_at(a), pred(call.value_at(a)))))
        return z3.And(parts)


def _sym_call() -> _SymCall:
    return _SymCall(
        z3.Int("call_tool"),
        tuple(z3.Bool(f"present_{i}") for i in range(N_ARGS)),
        tuple(z3.Const(f"value_{i}", Value) for i in range(N_ARGS)),
    )


def _sym_cap(side: str) -> _SymCap:
    return _SymCap(
        z3.Int(f"{side}_tool"),
        tuple(z3.Bool(f"{side}_active_{j}") for j in range(N_CONSTRAINTS)),
        tuple(z3.Int(f"{side}_arg_{j}") for j in range(N_CONSTRAINTS)),
        tuple(z3.Function(f"{side}_pred_{j}", Value, _BOOL) for j in range(N_CONSTRAINTS)),
    )


def _implies_everywhere(child: z3.FuncDeclRef, parent: z3.FuncDeclRef) -> z3.BoolRef:
    """What at_least_as_strict guarantees (L1 to L5): child(u) implies parent(u) for all u."""
    u = z3.Const("u", Value)
    return z3.ForAll([u], z3.Implies(child(u), parent(u)))


def _same_names(parent: _SymCap, child: _SymCap) -> z3.BoolRef:
    return z3.And([parent.names(i) == child.names(i) for i in range(N_ARGS)])


def _each_parent_constraint_matched(parent: _SymCap, child: _SymCap) -> z3.BoolRef:
    """For every parent constraint, SOME child constraint on that argument is as strict."""
    out = []
    for p_act, p_arg, p_pred in zip(parent.active, parent.arg, parent.pred, strict=True):
        some = [
            z3.And(c_act, c_arg == p_arg, _implies_everywhere(c_pred, p_pred))
            for c_act, c_arg, c_pred in zip(child.active, child.arg, child.pred, strict=True)
        ]
        out.append(z3.Implies(p_act, z3.Or(some)))
    return z3.And(out)


def _each_child_constraint_matched(parent: _SymCap, child: _SymCap) -> z3.BoolRef:
    """The quantifiers the wrong way round: every child constraint has some parent one."""
    out = []
    for c_act, c_arg, c_pred in zip(child.active, child.arg, child.pred, strict=True):
        some = [
            z3.And(p_act, c_arg == p_arg, _implies_everywhere(c_pred, p_pred))
            for p_act, p_arg, p_pred in zip(parent.active, parent.arg, parent.pred, strict=True)
        ]
        out.append(z3.Implies(c_act, z3.Or(some)))
    return z3.And(out)


def _cap_terms(call: _SymCall, parent: _SymCap, child: _SymCap) -> Callable[[z3.ModelRef], str]:
    """Render a model as a call and two capabilities, leaving out unused slots."""

    def render(model: z3.ModelRef) -> str:
        def ev(e: z3.ExprRef) -> z3.ExprRef:
            return model.eval(e, model_completion=True)

        args = [
            f"arg{i} = {ev(call.value[i])}"
            for i in range(N_ARGS)
            if z3.is_true(ev(call.present[i]))
        ]
        out = ["call(" + ", ".join(args) + ")"]
        for side, cap in (("parent", parent), ("child", child)):
            cons = []
            for j in range(N_CONSTRAINTS):
                if not z3.is_true(ev(cap.active[j])):
                    continue
                a = ev(cap.arg[j]).as_long()
                if z3.is_true(ev(call.present[a])):
                    verdict = f"holds: {ev(cap.pred[j](call.value[a]))}"
                else:
                    verdict = "argument missing"
                cons.append(f"{side}_pred_{j} on arg{a} ({verdict})")
            out.append(f"{side} constraints: " + (", ".join(cons) if cons else "none"))
        return "; ".join(out)

    return render


def _covers_query(
    side_conditions: Callable[[_SymCap, _SymCap], list[z3.BoolRef]],
) -> Query:
    call, parent, child = _sym_call(), _sym_cap("parent"), _sym_cap("child")
    formulas = [parent.well_formed(), child.well_formed()]
    formulas += side_conditions(parent, child)
    formulas += [child.permits(call), z3.Not(parent.permits(call))]
    return formulas, _cap_terms(call, parent, child)


_COVERS_BOUND = (
    f"calls over {N_ARGS} argument names; at most {N_CONSTRAINTS} constraints per "
    "capability; which argument each constraint is on is symbolic; each constraint's "
    "predicate is an arbitrary function of the value"
)


def covers_composition() -> Lemma:
    """L6. The side conditions of covers() make 'child permits' imply 'parent permits'."""
    return _lemma(
        "L6 capability composition (covers)",
        "capability",
        "Same tool, the two capabilities name the same set of arguments, and every "
        "parent constraint has some child constraint on the same argument that implies "
        "it. A call the child capability permits and the parent capability refuses.",
        _COVERS_BOUND,
        _covers_query(
            lambda p, c: [
                p.tool == c.tool,
                _same_names(p, c),
                _each_parent_constraint_matched(p, c),
            ]
        ),
    )


# --- L7: grant level ---------------------------------------------------------


def _grant_query(*, covered: bool, expiry_checked: bool) -> Query:
    """Two grants of up to N_CAPS capabilities over an abstract 'permits' relation."""
    cap_sort = z3.DeclareSort("Capability")
    call_sort = z3.DeclareSort("Call")
    permits = z3.Function("permits", cap_sort, call_sort, _BOOL)
    call = z3.Const("call", call_sort)
    now, p_exp, c_exp = z3.Real("now"), z3.Real("parent_expires"), z3.Real("child_expires")
    p_caps = [z3.Const(f"parent_cap_{j}", cap_sort) for j in range(N_CAPS)]
    c_caps = [z3.Const(f"child_cap_{i}", cap_sort) for i in range(N_CAPS)]
    p_act = [z3.Bool(f"parent_has_{j}") for j in range(N_CAPS)]
    c_act = [z3.Bool(f"child_has_{i}") for i in range(N_CAPS)]

    def covers(p: z3.ExprRef, c: z3.ExprRef) -> z3.BoolRef:
        x = z3.Const("x", call_sort)
        return z3.ForAll([x], z3.Implies(permits(c, x), permits(p, x)))

    def allows(caps: list[z3.ExprRef], act: list[z3.BoolRef], exp: z3.ArithRef) -> z3.BoolRef:
        some = z3.Or([z3.And(a, permits(c, call)) for a, c in zip(act, caps, strict=True)])
        return z3.And(now < exp, some)

    formulas: list[z3.BoolRef] = []
    if covered:
        for a, c in zip(c_act, c_caps, strict=True):
            some = z3.Or([z3.And(pa, covers(p, c)) for pa, p in zip(p_act, p_caps, strict=True)])
            formulas.append(z3.Implies(a, some))
    if expiry_checked:
        formulas.append(c_exp <= p_exp)
    formulas += [allows(c_caps, c_act, c_exp), z3.Not(allows(p_caps, p_act, p_exp))]

    def render(model: z3.ModelRef) -> str:
        def ev(e: z3.ExprRef) -> z3.ExprRef:
            return model.eval(e, model_completion=True)

        out = [f"now = {ev(now)}", f"child_expires = {ev(c_exp)}", f"parent_expires = {ev(p_exp)}"]
        for side, caps, act in (("child", c_caps, c_act), ("parent", p_caps, p_act)):
            held = [
                f"{side}_cap_{i} (permits the call: {ev(permits(c, call))})"
                for i, c in enumerate(caps)
                if z3.is_true(ev(act[i]))
            ]
            out.append(f"{side} capabilities: " + (", ".join(held) if held else "none"))
        return "; ".join(out)

    return formulas, render


def grant_composition() -> Lemma:
    """L7. check_attenuation's conditions make 'child grant allows' imply 'parent allows'."""
    return _lemma(
        "L7 grant composition (check_attenuation)",
        "grant",
        "Every child capability is covered by some parent capability (covered means: "
        "whatever it permits, the parent capability permits) and the child expires no "
        "later than the parent. A call and a time at which the child grant allows and "
        "the parent grant does not.",
        f"at most {N_CAPS} capabilities per grant; 'permits' is an arbitrary relation; "
        "times are reals",
        _grant_query(covered=True, expiry_checked=True),
    )


def grant_composition_any_size() -> Lemma:
    """L7 with capability sets of any size instead of at most N_CAPS."""
    cap_sort = z3.DeclareSort("Capability")
    call_sort = z3.DeclareSort("Call")
    permits = z3.Function("permits", cap_sort, call_sort, _BOOL)
    in_parent = z3.Function("in_parent", cap_sort, _BOOL)
    in_child = z3.Function("in_child", cap_sort, _BOOL)
    # covered_by(c) is the parent capability the checker found for c (the derivation).
    covered_by = z3.Function("covered_by", cap_sort, cap_sort)
    c, p = z3.Const("c", cap_sort), z3.Const("p", cap_sort)
    x, call = z3.Const("x", call_sort), z3.Const("call", call_sort)
    witness = z3.Const("child_cap", cap_sort)
    derivation = z3.ForAll(
        [c, x],
        z3.Implies(
            in_child(c),
            z3.And(
                in_parent(covered_by(c)),
                z3.Implies(permits(c, x), permits(covered_by(c), x)),
            ),
        ),
    )
    parent_denies = z3.ForAll([p], z3.Implies(in_parent(p), z3.Not(permits(p, call))))
    return _lemma(
        "L7a grant composition, any number of capabilities",
        "grant",
        "Every capability in the child grant has a covering capability in the parent "
        "grant (the derivation). Some child capability permits a call that no parent "
        "capability permits.",
        None,
        ([derivation, in_child(witness), permits(witness, call), parent_denies], []),
    )


def expiry_monotone() -> Lemma:
    """L7 expiry on its own: an unexpired child implies an unexpired parent."""
    now, p_exp, c_exp = z3.Real("now"), z3.Real("parent_expires"), z3.Real("child_expires")
    return _lemma(
        "L7b expiry",
        "grant",
        "child_expires <= parent_expires, now < child_expires, and not "
        "now < parent_expires. Over the reals.",
        None,
        (
            [c_exp <= p_exp, now < c_exp, z3.Not(now < p_exp)],
            [("now", now), ("child_expires", c_exp), ("parent_expires", p_exp)],
        ),
    )


# --- L8: call budgets --------------------------------------------------------


def _budget(name: str) -> Budget:
    """max_calls: (limited, n). `limited` false is Python's None, meaning no limit."""
    return z3.Bool(f"{name}_limited"), z3.Int(f"{name}_calls")


Budget = tuple[z3.BoolRef, z3.ArithRef]


def _budget_ok(parent: Budget, child: Budget) -> z3.BoolRef:
    """The budget line of covers(): a limited parent needs a limited, no larger child."""
    return z3.Implies(parent[0], z3.And(child[0], child[1] <= parent[1]))


def budget_step() -> Lemma:
    """L8. The inductive step: 'within the root's budget' survives one more hop."""
    root, mid, leaf = _budget("root"), _budget("mid"), _budget("leaf")
    return _lemma(
        "L8 budget is preserved along a chain (inductive step)",
        "budget",
        "mid is within root's budget and leaf is within mid's budget, and leaf is not "
        "within root's budget. Budgets are integers or 'no limit'. With the base case "
        "(root is within its own budget) this is induction over a chain of any length.",
        None,
        (
            [_budget_ok(root, mid), _budget_ok(mid, leaf), z3.Not(_budget_ok(root, leaf))],
            [
                (f"{name}_{field}", b[i])
                for name, b in (("root", root), ("mid", mid), ("leaf", leaf))
                for i, field in enumerate(("limited", "calls"))
            ],
        ),
    )


def budget_chain() -> Lemma:
    """L8 unrolled: a concrete chain of CHAIN_LENGTH hops, as a cross-check of the step."""
    chain = [_budget(f"hop{i}") for i in range(CHAIN_LENGTH + 1)]
    formulas = [_budget_ok(chain[i], chain[i + 1]) for i in range(CHAIN_LENGTH)]
    formulas.append(z3.Not(_budget_ok(chain[0], chain[-1])))
    return _lemma(
        "L8a budget along an unrolled chain",
        "budget",
        "Each hop is within the previous hop's budget, and the last hop is not within "
        "the first hop's budget.",
        f"a chain of exactly {CHAIN_LENGTH} hops",
        (formulas, [(f"hop{i}_calls", b[1]) for i, b in enumerate(chain)]),
    )


# --- wrong variants: each must be SAT ----------------------------------------


def wrong_max_reversed() -> Lemma:
    """Teeth for L2: the comparison the wrong way round."""
    v, m, n = _v(), z3.Real("m"), z3.Real("n")
    return _lemma(
        "W1 max with n >= m",
        "max",
        "Accept child max n when n >= m instead of n <= m.",
        None,
        ([n >= m, _max_holds(v, n), z3.Not(_max_holds(v, m))], [("m", m), ("n", n), ("v", v)]),
    )


def wrong_prefix_reversed() -> Lemma:
    """Teeth for L4: the prefix test the wrong way round."""
    v, prefix = _v(), z3.String("P")
    text, head = _child_glob_text(1)
    return _lemma(
        "W2 prefix rule reversed",
        "glob",
        "Accept child p0*p1 when P starts with p0 (the child's head is SHORTER than "
        "the parent's prefix) instead of p0 starting with P.",
        "child pattern with one star",
        (
            [
                z3.PrefixOf(head, prefix),
                Value.is_S(v),
                Value.s(v) == text,
                z3.Not(_prefix_holds(v, prefix)),
            ],
            [("P", prefix), ("p0", head), ("p1", z3.String("p1")), ("v", v)],
        ),
    )


def wrong_prefix_parent_with_tail() -> Lemma:
    """Teeth for L4: the parent must be exactly P*, with nothing after the star."""
    v, prefix, tail = _v(), z3.String("P"), z3.String("Q")
    text, head = _child_glob_text(1)
    s = Value.s(v)
    parent = z3.And(
        Value.is_S(v),
        z3.PrefixOf(prefix, s),
        z3.SuffixOf(tail, s),
        z3.Length(s) >= z3.Length(prefix) + z3.Length(tail),
    )
    return _lemma(
        "W3 prefix rule applied to a parent P*Q",
        "glob",
        "Apply the prefix rule to a parent pattern P*Q that has a literal tail, looking only at P.",
        "parent with one star, child pattern with one star",
        (
            [z3.PrefixOf(prefix, head), Value.is_S(v), s == text, z3.Not(parent)],
            [("P", prefix), ("Q", tail), ("p0", head), ("p1", z3.String("p1")), ("v", v)],
        ),
    )


def wrong_regex_reading() -> Lemma:
    """Teeth for L4c: without the star the pattern is NOT 'starts with P'."""
    t = z3.String("t")
    prefix = "reports/"
    return _lemma(
        "W4 glob_regex(P) read as 'starts with P'",
        "glob",
        "Membership in glob_regex('reports/') (no star) and PrefixOf('reports/', t) "
        "disagree on some t.",
        "concrete P = 'reports/'",
        ([z3.InRe(t, glob_regex(prefix)) != z3.PrefixOf(string_lit(prefix), t)], [("t", t)]),
    )


def wrong_starred_glob_as_literal() -> Lemma:
    """Teeth for L1e: a pattern WITH a star is not the single string of its pattern."""
    t = z3.String("t")
    pattern = "a*"
    return _lemma(
        "W12 a glob with a star read as one literal string",
        "glob",
        "Apply rule A to the pattern 'a*', which has a star: a string t that the "
        "pattern accepts and that is not the string 'a*' itself.",
        "concrete g = 'a*'",
        ([z3.InRe(t, glob_regex(pattern)), t != string_lit(pattern)], [("t", t)]),
    )


def wrong_sets_intersect() -> Lemma:
    """Teeth for L1: 'some listed value is allowed' instead of 'every listed value'."""
    v = _v()
    s = [z3.Const(f"s{i}", Value) for i in (1, 2)]
    t = [z3.Const(f"t{i}", Value) for i in (1, 2)]
    intersect = z3.Or([a == b for a in s for b in t])
    return _lemma(
        "W5 sets intersect instead of subset",
        "in",
        "Accept child in T under parent in S when T and S share a value.",
        "two values per list",
        (
            [intersect, z3.Or([v == a for a in t]), z3.Not(z3.Or([v == a for a in s]))],
            [("s1", s[0]), ("s2", s[1]), ("t1", t[0]), ("t2", t[1]), ("v", v)],
        ),
    )


def wrong_any_under_max() -> Lemma:
    """Teeth for L5: any is only safe on the PARENT side."""
    v, m = _v(), z3.Real("m")
    return _lemma(
        "W6 child any under parent max",
        "max",
        "Accept child any under parent max m.",
        None,
        ([z3.BoolVal(True), z3.Not(_max_holds(v, m))], [("m", m), ("v", v)]),
    )


def wrong_names_not_equal() -> Lemma:
    """Teeth for L6: drop the 'same argument names' condition."""
    return _lemma(
        "W7 argument-name sets not required equal",
        "capability",
        "covers() without the arg_names equality: the child may constrain an argument "
        "the parent never mentions.",
        _COVERS_BOUND,
        _covers_query(lambda p, c: [p.tool == c.tool, _each_parent_constraint_matched(p, c)]),
    )


def wrong_quantifiers_swapped() -> Lemma:
    """Teeth for L6: 'every child constraint has a parent one' is the wrong direction."""
    return _lemma(
        "W8 constraint quantifiers swapped",
        "capability",
        "covers() asking that every CHILD constraint implies some parent constraint on "
        "its argument, instead of every parent constraint being implied by some child "
        "constraint. Argument names still equal.",
        _COVERS_BOUND,
        _covers_query(
            lambda p, c: [
                p.tool == c.tool,
                _same_names(p, c),
                _each_child_constraint_matched(p, c),
            ]
        ),
    )


def wrong_expiry_dropped() -> Lemma:
    """Teeth for L7: no expiry comparison."""
    return _lemma(
        "W9 expiry check dropped",
        "grant",
        "check_attenuation without 'child expires no later than parent'.",
        f"at most {N_CAPS} capabilities per grant",
        _grant_query(covered=True, expiry_checked=False),
    )


def wrong_cover_dropped() -> Lemma:
    """Teeth for L7: no coverage requirement, expiry still checked."""
    return _lemma(
        "W10 capability coverage dropped",
        "grant",
        "check_attenuation with only the expiry comparison.",
        f"at most {N_CAPS} capabilities per grant",
        _grant_query(covered=False, expiry_checked=True),
    )


def wrong_unlimited_child_budget() -> Lemma:
    """Teeth for L8: a child with no limit under a limited parent."""
    parent, child = _budget("parent"), _budget("child")
    loose = z3.Implies(z3.And(parent[0], child[0]), child[1] <= parent[1])
    return _lemma(
        "W11 unlimited child budget under a limited parent",
        "budget",
        "Compare budgets only when both are limited, so a child with max_calls=None "
        "passes under a parent with a limit.",
        None,
        (
            [loose, z3.Not(_budget_ok(parent, child))],
            [
                ("parent_limited", parent[0]),
                ("parent_calls", parent[1]),
                ("child_limited", child[0]),
            ],
        ),
    )


LEMMAS: tuple[Callable[[], Lemma], ...] = (
    enumeration_rule,
    eq_under_eq,
    in_under_in,
    in_under_max,
    in_under_glob,
    star_free_glob_is_literal,
    max_under_max,
    glob_identical,
    glob_prefix_bounded,
    glob_head_is_prefix,
    prefix_transitive,
    glob_regex_is_prefix,
    anything_under_any,
    covers_composition,
    grant_composition,
    grant_composition_any_size,
    expiry_monotone,
    budget_step,
    budget_chain,
)

WRONG_VARIANTS: tuple[Callable[[], Lemma], ...] = (
    wrong_max_reversed,
    wrong_prefix_reversed,
    wrong_prefix_parent_with_tail,
    wrong_regex_reading,
    wrong_sets_intersect,
    wrong_any_under_max,
    wrong_names_not_equal,
    wrong_quantifiers_swapped,
    wrong_expiry_dropped,
    wrong_cover_dropped,
    wrong_unlimited_child_budget,
    wrong_starred_glob_as_literal,
)


def all_lemmas() -> list[Lemma]:
    """Run every lemma. Each must come back 'unsat'."""
    return [f() for f in LEMMAS]


def all_wrong_variants() -> list[Lemma]:
    """Run every wrong variant. Each must come back 'sat' with a counterexample."""
    return [f() for f in WRONG_VARIANTS]


def all_premise_checks() -> list[Lemma]:
    """Run every lemma WITHOUT its goal. Each must come back 'sat'.

    A lemma whose side condition contradicts itself would be 'unsat' for the
    wrong reason. This shows each lemma's premises (side condition and 'the
    child accepts') can hold together, so the 'unsat' comes from the goal.
    """
    global _premises_only
    _premises_only = True
    try:
        return [f() for f in LEMMAS]
    finally:
        _premises_only = False
