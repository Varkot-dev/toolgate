"""Prove the attenuation rules with Z3 and write results/m0b_rules.json.

Runs every lemma in caveat.proofs (each must be unsat), every wrong variant
(each must be sat, with the solver's counterexample recorded) and the premise
check of every lemma (each must be sat). Exits non-zero if any of them comes
back otherwise, including `unknown`.

Usage:  python scripts/m0b_prove_rules.py [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import asdict
from pathlib import Path

import z3

from caveat import proofs

ROOT = Path(__file__).resolve().parent.parent


def print_table(title: str, records: list[proofs.Lemma], expected: str) -> None:
    print(f"\n{title} (expected: {expected})")
    width = max(len(r.name) for r in records)
    for r in records:
        mark = "ok  " if r.result == expected else "FAIL"
        bound = "unbounded" if r.bound is None else f"bounded: {r.bound}"
        print(f"  {mark} {r.result:<7} {r.seconds:>7.3f}s  {r.name:<{width}}  [{r.table_row}]")
        print(f"       {bound}")
        if expected == "sat" and r.counterexample:
            print(f"       model: {r.counterexample}")
        elif r.result != expected and r.counterexample:
            print(f"       counterexample: {r.counterexample}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "m0b_rules.json")
    args = parser.parse_args()

    lemmas = proofs.all_lemmas()
    wrong = proofs.all_wrong_variants()
    premises = proofs.all_premise_checks()

    print(f"z3 {z3.get_version_string()}, python {platform.python_version()}")
    print_table("Lemmas", lemmas, "unsat")
    print_table("Wrong variants", wrong, "sat")
    bad_premises = [p.name for p in premises if p.result != "sat"]
    print(f"\nPremise checks: {len(premises) - len(bad_premises)}/{len(premises)} satisfiable")

    ok = (
        all(x.result == "unsat" for x in lemmas)
        and all(x.result == "sat" for x in wrong)
        and not bad_premises
    )
    report = {
        "z3_version": z3.get_version_string(),
        "python_version": platform.python_version(),
        "timeout_ms_per_query": proofs.TIMEOUT_MS,
        "all_as_expected": ok,
        "summary": {
            "lemmas": len(lemmas),
            "lemmas_unsat": sum(x.result == "unsat" for x in lemmas),
            "lemmas_bounded": sum(x.bound is not None for x in lemmas),
            "wrong_variants": len(wrong),
            "wrong_variants_sat": sum(x.result == "sat" for x in wrong),
            "premise_checks": len(premises),
            "premise_checks_sat": len(premises) - len(bad_premises),
        },
        "lemmas": [asdict(x) for x in lemmas],
        "wrong_variants": [asdict(x) for x in wrong],
        "premise_checks": [
            {"name": p.name, "result": p.result, "witness": p.counterexample, "seconds": p.seconds}
            for p in premises
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}")
    print("ALL AS EXPECTED" if ok else "SOMETHING IS NOT AS EXPECTED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
