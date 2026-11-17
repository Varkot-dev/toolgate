"""Run the sandbox task suite with scripted agents and write results/m5_scripted.json.

Scripted agents, not a language model: an honest agent that performs exactly
the user's task and a hijacked agent that also obeys every injected
instruction it reads (toolgate.sandbox.agents). Each of the 26 tasks is run
with both agents under four configurations: no gateway; gateway with the
task's grant and an allow-all policy; grant plus config/sandbox_policy.yaml
with a careful approver; the same with a rubber-stamp approver. The two
provenance configurations are listed as "not implemented".

Deterministic: fixed seed, fixed clock, counting ids. Running it twice writes
the same bytes.

Usage:  python scripts/m5_scripted_eval.py [--out PATH] [--seed N]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from toolgate.sandbox.runner import SEED, dumps, evaluate, format_table

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "m5_scripted.json")
    parser.add_argument("--seed", type=int, default=SEED)
    options = parser.parse_args()

    result = evaluate(options.seed)
    print(format_table(result))

    print("\nWhich layer stopped each attack, where it differs from the task's label:")
    if not result["mismatches"]:
        print("  no mismatches")
    for m in result["mismatches"]:
        print(
            f"  {m['configuration']:<24}{m['task']:<13}expected "
            f"{m['expected_in_this_configuration']!r} (label {m['expected']!r}), "
            f"observed {m['observed']!r}"
        )

    if not all(result["checks"].values()):
        raise SystemExit(f"suite sanity checks failed: {result['checks']}")
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(dumps(result), encoding="utf-8")
    print(f"\nWrote {options.out}")


if __name__ == "__main__":
    main()
