"""Measure the M0 security invariant and write results/m0_invariant.json.

Runs the same generators as tests/test_properties.py with a fixed seed and
counts what happened, so the README can state not just "the property passed"
but how many generated cases actually exercised it:

  * how many children the checker accepted and rejected
  * how many accepted children allowed the generated call (the non-vacuous
    cases, where "child allows implies parent allows" has something to prove)
  * how many violations were seen (must be 0)
  * which row of the attenuation table justified each accepted constraint
  * whether each deliberately broken checker (mutant) was caught, and the
    shrunk counterexample that caught it

Usage:  python scripts/m0_invariant.py [--cases 20000] [--seed 0] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import hypothesis
from hypothesis import HealthCheck, Phase, given, seed, settings

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from strategies import Scenario, scenarios  # noqa: E402
from test_properties import (  # noqa: E402
    MUTANT_BUDGET,
    MUTANTS,
    derivation_violation,
    grant_violation,
    kill,
)
from caveat import Capability, Grant, at_least_as_strict, check_attenuation  # noqa: E402


def show_capability(cap: Capability) -> str:
    parts = []
    for c in cap.constraints:
        parts.append(f"{c.arg} any" if c.op == "any" else f"{c.arg} {c.op} {c.value!r}")
    budget = "" if cap.max_calls is None else f" max_calls={cap.max_calls}"
    return f"{cap.tool}({', '.join(parts)}){budget}"


def show_grant(grant: Grant) -> str:
    caps = "; ".join(show_capability(c) for c in grant.capabilities)
    return f"[{caps}] expires_at={grant.expires_at!r}"


def show_scenario(s: Scenario) -> dict[str, Any]:
    return {
        "parent": show_grant(s.parent),
        "child": show_grant(s.child),
        "call": f"{s.call.tool}({dict(s.call.args)!r})",
        "now": repr(s.now),
    }


def rule_fired(parent_op: str, child_op: str, parent_value: Any, child_value: Any) -> str:
    """Name the attenuation-table row that accepted this constraint pair.

    The order follows at_least_as_strict: a parent `any` accepts before the
    child is looked at, then a star-free child glob is checked as the single
    string it accepts (like eq), and only a starred child reaches the two
    glob-under-glob rules.
    """
    if child_op == "glob" and parent_op != "any":
        if "*" not in child_value:
            child_op = "glob literal (star-free child)"
        elif parent_op == "glob":
            child_op = "glob (identical)" if parent_value == child_value else "glob (longer prefix)"
    return f"parent {parent_op} / child {child_op}"


def measure(cases: int, seed_value: int) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    violations: list[dict[str, Any]] = []

    @seed(seed_value)
    @settings(
        max_examples=cases,
        deadline=None,
        database=None,
        phases=[Phase.generate],
        suppress_health_check=list(HealthCheck),
    )
    @given(scenarios())
    def run(s: Scenario) -> None:
        counts["cases"] += 1
        counts[f"children_{s.child_kind}"] += 1
        result = check_attenuation(s.parent, s.child)
        if not result.ok:
            counts["rejected"] += 1
            return
        counts["accepted"] += 1
        counts[f"accepted_{s.child_kind}"] += 1
        if s.child.capabilities:
            counts["accepted_with_capabilities"] += 1
        for i, cc in enumerate(s.child.capabilities):
            pc = s.parent.capabilities[result.derivation[i]]
            for p in pc.constraints:
                c = next(c for c in cc.constraints if at_least_as_strict(p, c))
                rules[rule_fired(p.op, c.op, p.value, c.value)] += 1
        if s.child.allows(s.call, s.now):
            counts["non_vacuous"] += 1
            if s.parent.allows(s.call, s.now):
                counts["parent_also_allows"] += 1
        # Recorded, not raised, so the totals stay complete even if something is wrong.
        problem = grant_violation(
            check_attenuation, s.parent, s.child, s.call, s.now
        ) or derivation_violation(check_attenuation, s.parent, s.child, s.call)
        if problem is not None:
            violations.append({"problem": problem, **show_scenario(s)})

    run()
    return {"counts": counts, "rules": rules, "violations": violations}


def run_mutants(seed_value: int) -> list[dict[str, Any]]:
    out = []
    for name in sorted(MUTANTS):
        invariant, what = MUTANTS[name]
        found = kill(name, seed=seed_value, shrink=True)
        entry: dict[str, Any] = {
            "mutant": name,
            "fault": what,
            "invariant": invariant,
            "killed": found is not None,
        }
        if found is not None:
            entry["counterexample"] = show_scenario(found)
        out.append(entry)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", type=Path, default=Path("results/m0_invariant.json"))
    args = parser.parse_args()

    started = time.perf_counter()
    measured = measure(args.cases, args.seed)
    mutants = run_mutants(args.seed)
    elapsed = time.perf_counter() - started

    counts, rules = measured["counts"], measured["rules"]
    cases = counts["cases"]
    killed = sum(m["killed"] for m in mutants)
    report = {
        "seed": args.seed,
        "cases_requested": args.cases,
        "cases_generated": cases,
        "children_narrowed": counts["children_narrowed"],
        "children_random": counts["children_random"],
        "children_accepted": counts["accepted"],
        "children_accepted_narrowed": counts["accepted_narrowed"],
        "children_accepted_random": counts["accepted_random"],
        "children_accepted_with_at_least_one_capability": counts["accepted_with_capabilities"],
        "children_rejected": counts["rejected"],
        "calls_allowed_by_accepted_child": counts["non_vacuous"],
        "non_vacuous_fraction": round(counts["non_vacuous"] / cases, 4) if cases else 0.0,
        "parent_also_allowed": counts["parent_also_allows"],
        "violations": len(measured["violations"]),
        "violation_examples": measured["violations"][:10],
        "accepted_constraint_pairs_by_rule": dict(sorted(rules.items())),
        "mutants_tried": len(mutants),
        "mutants_killed": killed,
        "mutant_search_budget": MUTANT_BUDGET,
        "mutant_search_strategy": "scenarios(fault_one_in=1): every narrowed child has one fault",
        "mutants": mutants,
        "hypothesis_version": hypothesis.__version__,
        "python_version": platform.python_version(),
        "seconds": round(elapsed, 1),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"cases generated            {cases}")
    print(f"children accepted          {counts['accepted']}")
    print(f"children rejected          {counts['rejected']}")
    print(
        f"accepted child allows call {counts['non_vacuous']} "
        f"({report['non_vacuous_fraction']:.1%} of cases)"
    )
    print(f"violations                 {report['violations']}")
    print(f"mutants killed             {killed} of {len(mutants)}")
    for m in mutants:
        print(f"  {'killed  ' if m['killed'] else 'SURVIVED'} {m['mutant']}")
    print(f"wrote {args.out} in {elapsed:.1f}s")
    return 0 if not measured["violations"] and killed == len(mutants) else 1


if __name__ == "__main__":
    raise SystemExit(main())
