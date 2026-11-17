"""Measure how incomplete the attenuation checker is (milestone M0b).

For a pair (parent, child) the checker says accept or reject, and the Z3 model
(src/toolgate/smt.py) says whether the child is truly safe. Four outcomes:

    accepted and safe       the checker did its job
    rejected and unsafe     the checker did its job
    rejected but safe       the COMPLETENESS GAP: expected, this script measures it
    accepted but unsafe     a SECURITY BUG: must be zero, the script exits 1 if not

A fifth count sits outside that table: `inconclusive`, for pairs where the
solver gave no usable answer (smt.Inconclusive: a timeout, or a witness between
two adjacent floats that no Python value can hit). Those are never counted as
safe and never as unsafe. The ones the checker accepted are listed in full.

Section 1 is exhaustive: every ordered pair of single-argument constraints from
a small universe that is listed in full in the output. Each gap pair is put in
exactly one category that says why the checker missed it.

Section 2 samples capability pairs and grant pairs with the generators in
tests/strategies.py and a fixed seed. Call budgets and expiry are outside the
solver model, so budgets are removed and expiries made equal before comparing.

The output also counts what a few candidate rule extensions WOULD close. Those
are measurements only: nothing in src/ implements them.

Every rate in the output describes this universe and this sampling
distribution. None of them says anything about real workloads.

Usage:  python scripts/m0b_completeness.py [--out PATH] [--seed 0] [--samples 5000]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections import Counter
from collections.abc import Callable
from itertools import combinations, product
from pathlib import Path
from typing import Any

import hypothesis
import z3
from hypothesis import HealthCheck, Phase, given, seed, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import strategies as pools  # noqa: E402
from toolgate import (  # noqa: E402
    Capability,
    Constraint,
    Grant,
    at_least_as_strict,
    check_attenuation,
    covers,
    smt,
)

OPS = ("eq", "in", "max", "glob", "any")
OUTCOMES = ("accepted_safe", "rejected_safe_gap", "rejected_unsafe", "accepted_unsafe_BUG")
EXAMPLES_PER_CATEGORY = 3
ARG = "x"

# The universe of section 1, stated once.
VALUES: tuple[Any, ...] = ("a", "ab", "a/b", 0, 1, 2, True)
IN_SET_SIZES = (1, 2)
CEILINGS: tuple[int | float, ...] = (0, 1, 2, 1.5)
GLOB_ALPHABET = "ab/*"
GLOB_MAX_LENGTH = 3

CAVEAT = (
    "Every count and rate in this file is a property of the universe and sampling "
    "distribution chosen here, not of real workloads. The completeness rate moves freely "
    "when the universe changes (for example, more star-free globs lower it). The only "
    "number that carries over is accepted_unsafe_BUG = 0, and that one is bounded by what "
    "was enumerated or sampled plus what the solver model covers."
)


RETRIES: dict[str, Any] = {
    "first_try_inconclusive": 0,
    "still_inconclusive_after_retry": 0,
    "first_try_reasons": [],
}


def ask(question: Callable[..., Any], parent: Any, child: Any) -> Any:
    """Put one question to the solver, asking a second time if it is inconclusive.

    Z3's running time on these queries is erratic inside a long process: a
    query that takes 10 ms in a fresh process has been seen to hit the 30 s
    timeout here. Either answer it does give is exact, so asking again cannot
    change a verdict, only turn "no answer" into an answer. Both counts are
    written to the output.
    """
    try:
        return question(parent, child)
    except smt.Inconclusive as why:
        RETRIES["first_try_inconclusive"] += 1
        RETRIES["first_try_reasons"].append(str(why))
    try:
        return question(parent, child)
    except smt.Inconclusive:
        RETRIES["still_inconclusive_after_retry"] += 1
        raise


def outcome(accepted: bool, safe: bool) -> str:
    if accepted:
        return "accepted_safe" if safe else "accepted_unsafe_BUG"
    return "rejected_safe_gap" if safe else "rejected_unsafe"


def inconclusive(accepted: bool) -> str:
    return "inconclusive_accepted" if accepted else "inconclusive_rejected"


def table(counts: Counter[str]) -> dict[str, Any]:
    """The 2x2 counts plus the completeness rate (accepted and safe / all truly safe).

    Inconclusive pairs are in `pairs` and in their own two counts, and in nothing else.
    """
    out: dict[str, Any] = {k: counts[k] for k in OUTCOMES}
    out["inconclusive_accepted"] = counts["inconclusive_accepted"]
    out["inconclusive_rejected"] = counts["inconclusive_rejected"]
    out["pairs"] = sum(counts.values())
    safe = out["accepted_safe"] + out["rejected_safe_gap"]
    out["truly_safe"] = safe
    out["completeness_rate"] = round(out["accepted_safe"] / safe, 4) if safe else None
    return out


# ---------------------------------------------------------------------------
# Section 1: exhaustive, single constraints
# ---------------------------------------------------------------------------


def build_universe() -> list[Constraint]:
    universe = [Constraint(ARG, "eq", v) for v in VALUES]
    for size in IN_SET_SIZES:
        universe += [Constraint(ARG, "in", combo) for combo in combinations(VALUES, size)]
    universe += [Constraint(ARG, "max", m) for m in CEILINGS]
    patterns = dict.fromkeys(
        "".join(p) for n in range(GLOB_MAX_LENGTH + 1) for p in product(GLOB_ALPHABET, repeat=n)
    )
    universe += [Constraint(ARG, "glob", p) for p in patterns]
    universe.append(Constraint(ARG, "any"))
    return universe


def show(c: Constraint) -> str:
    if c.op == "any":
        return "any"
    value = list(c.value) if c.op == "in" else c.value
    return f"{c.op} {json.dumps(value)}"


def collapse_stars(pattern: str) -> str:
    """The same language with every run of "*" written as one "*"."""
    while "**" in pattern:
        pattern = pattern.replace("**", "*")
    return pattern


def is_prefix_shape(pattern: str) -> bool:
    return pattern.endswith("*") and "*" not in pattern[:-1]


def categorize(parent: Constraint, child: Constraint) -> str:
    """Why a truly safe pair was rejected. First matching rule wins, so exactly one."""
    if child.op != "glob":
        return "other"
    if "*" not in child.value:
        if parent.op in ("eq", "in"):
            return "child glob has no star (one literal string), parent is eq/in"
        if parent.op == "glob":
            return "child glob has no star (one literal string), parent glob is not P*"
        return "other"
    if parent.op != "glob":
        return "other"
    p, c = collapse_stars(parent.value), collapse_stars(child.value)
    if p == c:
        return "same language, spelled with repeated stars"
    if is_prefix_shape(p) and c.split("*")[0].startswith(p[:-1]):
        return "prefix rule would apply after collapsing repeated stars"
    p_parts, c_parts = p.split("*"), c.split("*")
    if len(p_parts) == 2 and not p_parts[0] and c_parts[-1].endswith(p_parts[1]):
        return "suffix containment (parent *S, child ends with S)"
    infix = len(p_parts) == 3 and p_parts[0] == "" and p_parts[-1] == ""
    if infix and any(p_parts[1] in part for part in c_parts):
        return "infix containment (parent *M*, child has M inside a literal piece)"
    ends = len(p_parts) == 2 and p_parts[0] and p_parts[1]
    if ends and c_parts[0].startswith(p_parts[0]) and c_parts[-1].endswith(p_parts[1]):
        return "both ends (parent P*S, child starts with P and ends with S)"
    return "other"


# Candidate rule extensions, measured but not implemented in src/. Each takes a
# rejected pair and says whether the extended checker would accept it.


def _ext_literal_child(parent: Constraint, child: Constraint) -> bool:
    """A child glob with no star accepts one string: check it like `eq`."""
    return child.op == "glob" and "*" not in child.value and parent.holds(child.value)


def _ext_collapse_stars(parent: Constraint, child: Constraint) -> bool:
    """Collapse runs of stars in both patterns, then apply today's glob rules."""
    if parent.op != "glob" or child.op != "glob":
        return False
    return at_least_as_strict(
        Constraint(ARG, "glob", collapse_stars(parent.value)),
        Constraint(ARG, "glob", collapse_stars(child.value)),
    )


def _ext_suffix(parent: Constraint, child: Constraint) -> bool:
    """Mirror image of the prefix rule: parent `*S`, child's literal tail ends with S."""
    if parent.op != "glob" or child.op != "glob":
        return False
    if not parent.value.startswith("*") or "*" in parent.value[1:]:
        return False
    return child.value.split("*")[-1].endswith(parent.value[1:])


EXTENSIONS: dict[str, Callable[[Constraint, Constraint], bool]] = {
    "A: treat a star-free child glob as eq": _ext_literal_child,
    "B: collapse repeated stars before the glob rules": _ext_collapse_stars,
    "C: suffix rule (parent *S, child tail ends with S)": _ext_suffix,
}
EXTENSION_SETS = (("A",), ("B",), ("C",), ("A", "B"), ("A", "C"), ("A", "B", "C"))


def section_exhaustive() -> dict[str, Any]:
    universe = build_universe()
    overall: Counter[str] = Counter()
    by_ops: dict[tuple[str, str], Counter[str]] = {(p, c): Counter() for p in OPS for c in OPS}
    categories: dict[str, list[tuple[Constraint, Constraint]]] = {}
    bugs: list[dict[str, str]] = []
    unconfirmed: list[dict[str, str]] = []
    rejected: list[tuple[Constraint, Constraint, bool]] = []

    for parent, child in product(universe, repeat=2):
        accepted = at_least_as_strict(parent, child)
        try:
            witness = ask(smt.find_escalation, parent, child)
        except smt.Inconclusive as why:
            kind = inconclusive(accepted)
            overall[kind] += 1
            by_ops[parent.op, child.op][kind] += 1
            if accepted:
                unconfirmed.append({"parent": show(parent), "child": show(child), "why": str(why)})
            continue
        safe = witness is smt.NO_WITNESS
        kind = outcome(accepted, safe)
        overall[kind] += 1
        by_ops[parent.op, child.op][kind] += 1
        if kind == "accepted_unsafe_BUG":
            bugs.append({"parent": show(parent), "child": show(child), "witness": repr(witness)})
        elif kind == "rejected_safe_gap":
            categories.setdefault(categorize(parent, child), []).append((parent, child))
        if not accepted:
            rejected.append((parent, child, safe))

    gap = overall["rejected_safe_gap"]
    what_if = []
    for names in EXTENSION_SETS:
        rules = [fn for label, fn in EXTENSIONS.items() if label[0] in names]
        closed = unsound = 0
        for parent, child, safe in rejected:
            if any(rule(parent, child) for rule in rules):
                closed += safe
                unsound += not safe
        what_if.append(
            {
                "extensions": [label for label in EXTENSIONS if label[0] in names],
                "gap_pairs_closed": closed,
                "gap_pairs_left": gap - closed,
                "unsafe_pairs_it_would_accept": unsound,
                "completeness_rate_with_it": round(
                    (overall["accepted_safe"] + closed) / (overall["accepted_safe"] + gap), 4
                ),
            }
        )

    ordered = sorted(categories.items(), key=lambda kv: (kv[0] == "other", -len(kv[1]), kv[0]))
    return {
        "universe": {
            "argument": ARG,
            "values_for_eq_and_in": list(VALUES),
            "in_set_sizes": list(IN_SET_SIZES),
            "max_ceilings": list(CEILINGS),
            "glob_alphabet": GLOB_ALPHABET,
            "glob_max_length": GLOB_MAX_LENGTH,
            "size": len(universe),
            "size_by_operator": {op: sum(c.op == op for c in universe) for op in OPS},
            "constraints": [show(c) for c in universe],
            "pairs": "every ordered (parent, child) pair, including a constraint with itself",
        },
        "outcomes": table(overall),
        "by_parent_and_child_operator": [
            {"parent": p, "child": c, **table(by_ops[p, c])} for p in OPS for c in OPS
        ],
        "gap_categories": [
            {
                "category": name,
                "count": len(pairs),
                "examples": [
                    {"parent": show(p), "child": show(c)} for p, c in pairs[:EXAMPLES_PER_CATEGORY]
                ],
            }
            for name, pairs in ordered
        ],
        "gap_pairs": [
            {"parent": show(p), "child": show(c), "category": name}
            for name, pairs in ordered
            for p, c in pairs
        ],
        "what_if_extensions": {
            "note": (
                "Analysis only, not implemented in src/. For each candidate rule set: how many "
                "gap pairs of this universe it would accept, and how many unsafe pairs (must be "
                "0 for the rule to be sound here; soundness in general would need its own proof)."
            ),
            "results": what_if,
        },
        "security_bugs": bugs,
        "accepted_but_inconclusive": unconfirmed,
    }


# ---------------------------------------------------------------------------
# Section 2: sampled capabilities and grants
# ---------------------------------------------------------------------------

EXPIRY = 10

CAT_CONSTRAINT = "constraint-level gap inherited (one child constraint is safe but rejected)"
CAT_UNION = "child capability covered only by a union of two or more parent capabilities"
CAT_UNSAT = "child capability can never allow a call (its constraints conjoin to nothing)"
CAT_CONJUNCTION = "child capability safe only through the conjunction of its own constraints"
CAT_SEVERAL = "several uncovered child capabilities with different reasons"
CAT_UNCLASSIFIED = "not classified (solver inconclusive while classifying)"
CAT_OTHER = "other"


def strip(cap: Capability) -> Capability:
    return Capability(cap.tool, cap.constraints, None)


def one(cap: Capability) -> Grant:
    return Grant((cap,), EXPIRY)


def exact_covers(parent: Capability, child: Capability) -> bool:
    """`covers` with the per-constraint test replaced by the solver's exact answer."""
    if parent.tool != child.tool or parent.arg_names != child.arg_names:
        return False
    return all(
        any(pc.arg == cc.arg and smt.constraint_included(pc, cc) for cc in child.constraints)
        for pc in parent.constraints
    )


def why_uncovered(parents: tuple[Capability, ...], child: Capability) -> str:
    """Classify one child capability that the checker did not cover but that is safe."""
    try:
        if smt.grant_included(Grant((), EXPIRY), one(child)):
            return CAT_UNSAT
        if any(exact_covers(p, child) for p in parents):
            return CAT_CONSTRAINT
        if any(smt.grant_included(one(p), one(child)) for p in parents):
            return CAT_CONJUNCTION
    except smt.Inconclusive:
        return CAT_UNCLASSIFIED
    return CAT_UNION


def show_capability(cap: Capability) -> str:
    return f"{cap.tool}({', '.join(f'{c.arg} {show(c)}' for c in cap.constraints)})"


def show_grant(grant: Grant) -> str:
    return "[" + "; ".join(show_capability(c) for c in grant.capabilities) + "]"


def sample(strategy: st.SearchStrategy[Any], count: int, seed_value: int) -> list[Any]:
    drawn: list[Any] = []

    @seed(seed_value)
    @settings(
        max_examples=count,
        deadline=None,
        database=None,
        phases=[Phase.generate],
        suppress_health_check=list(HealthCheck),
    )
    @given(strategy)
    def run(value: Any) -> None:
        drawn.append(value)

    run()
    return drawn


@st.composite
def capability_pairs(draw: st.DrawFn) -> tuple[Capability, Capability, str]:
    parent = pools._capability(draw)
    kind = draw(st.sampled_from(("narrowed", "narrowed", "faulty", "random")))
    if kind == "random":
        child = pools._capability(draw)
    else:
        fault = pools._pick(draw, pools._FAULTS) if kind == "faulty" else None
        child = pools._narrowed_capability(draw, parent, fault)
    return strip(parent), strip(child), kind


@st.composite
def grant_pairs(draw: st.DrawFn) -> tuple[Grant, Grant, str]:
    parent = pools._grant(draw)
    kind = draw(st.sampled_from(("narrowed", "narrowed", "faulty", "random")))
    if kind == "random":
        child = pools._grant(draw)
    else:
        child, _ = pools._narrowed(draw, parent, 1 if kind == "faulty" else 5)
    return (
        Grant(tuple(strip(c) for c in parent.capabilities), EXPIRY),
        Grant(tuple(strip(c) for c in child.capabilities), EXPIRY),
        kind,
    )


def summarize_gap(found: dict[str, list[dict[str, str]]]) -> list[dict[str, Any]]:
    order = (
        CAT_CONSTRAINT,
        CAT_UNION,
        CAT_UNSAT,
        CAT_CONJUNCTION,
        CAT_SEVERAL,
        CAT_UNCLASSIFIED,
        CAT_OTHER,
    )
    out = []
    for name in order:
        records = found.get(name, [])
        distinct = list({json.dumps(r, sort_keys=True): r for r in records}.values())
        out.append(
            {"category": name, "count": len(records), "examples": distinct[:EXAMPLES_PER_CATEGORY]}
        )
    return out


def classifier_self_check() -> list[dict[str, str]]:
    """Hand-built pairs, one per reason, to show the classifier can tell them apart.

    These are NOT sampled and are in no count. They exist because a category
    with a sampled count of 0 should mean "rare in this distribution", not
    "the classifier cannot see it".
    """

    def cap(*constraints: Constraint) -> Capability:
        return Capability("read", constraints)

    x = ARG
    cases = [
        (CAT_CONSTRAINT, (cap(Constraint(x, "glob", "*a")),), cap(Constraint(x, "glob", "*ba"))),
        (
            CAT_UNION,
            (cap(Constraint(x, "in", (1,))), cap(Constraint(x, "in", (2,)))),
            cap(Constraint(x, "in", (1, 2))),
        ),
        (
            CAT_UNSAT,
            (cap(Constraint(x, "eq", 1)),),
            cap(Constraint(x, "eq", "a"), Constraint(x, "max", 0)),
        ),
        (
            CAT_CONJUNCTION,
            (cap(Constraint(x, "in", (1, 2))),),
            cap(Constraint(x, "in", (1, 5)), Constraint(x, "max", 1)),
        ),
    ]
    out = []
    for expected, parents, child in cases:
        parent_grant, child_grant = Grant(parents, EXPIRY), one(child)
        assert not check_attenuation(parent_grant, child_grant).ok
        assert smt.grant_included(parent_grant, child_grant)
        got = why_uncovered(parents, child)
        assert got == expected, (expected, got)
        out.append(
            {"category": got, "parent": show_grant(parent_grant), "child": show_grant(child_grant)}
        )
    return out


def compare(
    levels: dict[str, Any],
    name: str,
    checker: str,
    truth: str,
    pairs: list[tuple[Any, Any, str]],
    accepts: Callable[[Any, Any], bool],
    as_grant: Callable[[Any], Grant],
    display: Callable[[Any], str],
    uncovered: Callable[[Any, Any], list[str]],
) -> None:
    counts: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    found: dict[str, list[dict[str, str]]] = {}
    bugs: list[dict[str, str]] = []
    unconfirmed: list[dict[str, str]] = []
    for parent, child, kind in pairs:
        kinds[kind] += 1
        accepted = accepts(parent, child)
        record = {"parent": display(parent), "child": display(child)}
        try:
            witness = ask(smt.find_grant_escalation, as_grant(parent), as_grant(child))
        except smt.Inconclusive as why:
            counts[inconclusive(accepted)] += 1
            if accepted:
                unconfirmed.append({**record, "why": str(why)})
            continue
        result = outcome(accepted, witness is None)
        counts[result] += 1
        if result == "accepted_unsafe_BUG":
            bugs.append({**record, "witness": repr(witness)})
        elif result == "rejected_safe_gap":
            reasons = set(uncovered(parent, child))
            reason = reasons.pop() if len(reasons) == 1 else CAT_SEVERAL if reasons else CAT_OTHER
            found.setdefault(reason, []).append(record)
    levels[name] = {
        "checker": checker,
        "truth": truth,
        "children_by_kind": dict(sorted(kinds.items())),
        "outcomes": table(counts),
        "gap_categories": summarize_gap(found),
        "security_bugs": bugs,
        "accepted_but_inconclusive": unconfirmed,
    }


def section_sampled(samples: int, seed_value: int) -> dict[str, Any]:
    out: dict[str, Any] = {}

    def capability_reasons(parent: Capability, child: Capability) -> list[str]:
        reason = why_uncovered((parent,), child)
        # With one parent capability there is no union to be covered by.
        return [CAT_OTHER if reason == CAT_UNION else reason]

    def grant_reasons(parent: Grant, child: Grant) -> list[str]:
        return [
            why_uncovered(parent.capabilities, cc)
            for cc in child.capabilities
            if not any(covers(pc, cc) for pc in parent.capabilities)
        ]

    compare(
        out,
        "capability_level",
        "covers(parent, child)",
        "smt.find_grant_escalation on the two one-capability grants",
        sample(capability_pairs(), samples, seed_value),
        covers,
        one,
        show_capability,
        capability_reasons,
    )
    compare(
        out,
        "grant_level",
        "check_attenuation(parent, child).ok",
        "smt.find_grant_escalation(parent, child)",
        sample(grant_pairs(), samples, seed_value + 1),
        lambda parent, child: check_attenuation(parent, child).ok,
        lambda grant: grant,
        show_grant,
        grant_reasons,
    )
    out["classifier_self_check"] = {
        "note": (
            "Hand-built gap pairs, one per reason, each rejected by the checker, proven safe by "
            "the solver and classified as expected. Not sampled and in no count: a sampled "
            "count of 0 means rare under this distribution, not invisible to the classifier."
        ),
        "pairs": classifier_self_check(),
    }
    out["sampling"] = {
        "seed": seed_value,
        "pairs_requested_per_level": samples,
        "generators": (
            "tests/strategies.py: parents from _capability / _grant. Half the children are "
            "'narrowed' from the parent (capability level: legal steps only; grant level: the "
            "test suite's default, one deliberate fault in one child out of five), a quarter "
            "are 'faulty' (always exactly one fault) and a quarter are fully 'random'"
        ),
        "budgets_and_expiry": (
            "max_calls removed from every capability and all expiries set equal before "
            "comparing, because the solver model covers the single-call question only"
        ),
    }
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "m0b_completeness.json")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--samples", type=int, default=5000, help="pairs per level in section 2")
    args = parser.parse_args()

    started = time.perf_counter()
    exhaustive = section_exhaustive()
    t_exhaustive = time.perf_counter() - started
    sampled = section_sampled(args.samples, args.seed)
    elapsed = time.perf_counter() - started

    sections = (exhaustive, sampled["capability_level"], sampled["grant_level"])
    bugs = sum(len(section["security_bugs"]) for section in sections)
    unknown = sum(
        section["outcomes"]["inconclusive_accepted"] + section["outcomes"]["inconclusive_rejected"]
        for section in sections
    )
    report = {
        "what_this_is": (
            "Checker verdict against solver truth for the attenuation check. "
            "rejected_safe_gap is the completeness gap; accepted_unsafe_BUG must be 0."
        ),
        "caveat": CAVEAT,
        "completeness_rate_definition": "accepted_safe / (accepted_safe + rejected_safe_gap)",
        "seed": args.seed,
        "accepted_unsafe_total": bugs,
        "inconclusive_total": unknown,
        "inconclusive_note": (
            "Pairs where smt raised Inconclusive. They are in no cell of the 2x2 tables and in "
            "no rate. Accepted ones are listed under accepted_but_inconclusive in each section."
        ),
        "solver_retries": {
            **RETRIES,
            "note": (
                "A question the solver did not answer is asked once more before the pair is "
                "counted as inconclusive. Z3's running time on these queries is erratic inside "
                "a long process, so these two counts can differ from run to run; the verdicts "
                "cannot, because any answer the solver gives is exact."
            ),
        },
        "exhaustive_constraints": exhaustive,
        "sampled": sampled,
        "z3_version": z3.get_version_string(),
        "hypothesis_version": hypothesis.__version__,
        "python_version": platform.python_version(),
        "seconds": {"exhaustive": round(t_exhaustive, 1), "total": round(elapsed, 1)},
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")

    def line(name: str, t: dict[str, Any]) -> None:
        print(
            f"{name:<22} pairs {t['pairs']:>6}  accepted+safe {t['accepted_safe']:>5}  "
            f"gap {t['rejected_safe_gap']:>4}  rejected+unsafe {t['rejected_unsafe']:>6}  "
            f"BUG {t['accepted_unsafe_BUG']}  completeness {t['completeness_rate']}  "
            f"inconclusive {t['inconclusive_accepted']}+{t['inconclusive_rejected']}"
        )

    line("exhaustive constraints", exhaustive["outcomes"])
    for entry in exhaustive["gap_categories"]:
        print(f"  {entry['count']:>4}  {entry['category']}")
    for entry in exhaustive["what_if_extensions"]["results"]:
        letters = "+".join(label[0] for label in entry["extensions"])
        print(
            f"  what if {letters:<6} closes {entry['gap_pairs_closed']:>4}, "
            f"unsafe accepted {entry['unsafe_pairs_it_would_accept']}"
        )
    for level in ("capability_level", "grant_level"):
        line(f"sampled {level.split('_')[0]}", sampled[level]["outcomes"])
        for entry in sampled[level]["gap_categories"]:
            print(f"  {entry['count']:>4}  {entry['category']}")
    print(f"inconclusive pairs (in no cell, in no rate): {unknown}; solver retries: {RETRIES}")
    print(f"wrote {args.out} in {elapsed:.1f}s")
    return 0 if bugs == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
