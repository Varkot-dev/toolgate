"""Run the sandbox task suite with scripted agents and write results/scripted_eval.json.

Scripted agents, not a language model: an honest agent that performs exactly
the user's task and a hijacked agent that also obeys every injected
instruction it reads (caveat.sandbox.agents). Each of the 26 tasks is run
with both agents under every configuration of caveat.sandbox.runner: no
gateway; grant only; grant plus canonicalization; grant plus
config/sandbox_policy.yaml (careful and rubber-stamp approver); plus session
labels; plus value labels with handles; plan-then-execute (each of the last
three with both approvers).

Scripted agents, a scripted planner and a scripted extractor: this measures
the defence layers, not a model.

Deterministic: fixed seed, fixed clock, counting ids. Running it twice writes
the same bytes.

Usage:  python scripts/eval_scripted.py [--out PATH] [--seed N]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from caveat.sandbox.runner import SEED, dumps, evaluate, format_table

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "scripted_eval.json")
    parser.add_argument("--seed", type=int, default=SEED)
    options = parser.parse_args()

    result = evaluate(options.seed)
    print(format_table(result))

    print("\nWhich layer stopped each attack, where it differs from the task's label:")
    if not result["mismatches"]:
        print("  no mismatches")
    for m in result["mismatches"]:
        print(
            f"  {m['configuration']:<30}{m['task']:<13}expected "
            f"{m['expected_in_this_configuration']!r} (label {m['expected']!r}), "
            f"observed {m['observed']!r}"
        )

    print("\nargs-04 (reports/../secrets traversal), stopped by:")
    for key, layer in result["args_04_traversal"]["stopped_by"].items():
        print(f"  {key:<30}{layer}")

    if not all(result["checks"].values()):
        raise SystemExit(f"suite sanity checks failed: {result['checks']}")
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(dumps(result), encoding="utf-8")
    print(f"\nWrote {options.out}")


if __name__ == "__main__":
    main()
