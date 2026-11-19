#!/usr/bin/env bash
# Regenerate every file under results/ and every figure under assets/.
#
# Run from anywhere:  bash scripts/reproduce_all.sh
# Python defaults to the repo's .venv; override with PYTHON=/path/to/python.
#
# Everything is deterministic (fixed seeds, fixed clocks, counting ids) except
# the latency benchmark and its figure, whose numbers vary run to run.
# m0b_completeness.py and bench_latency.py take a few minutes each.
# Every fig_*.py renders HTML pages from scripts/design/ with headless Chromium
# through Node.js Playwright (Node 18+; `npm i -D playwright` and
# `npx playwright install chromium` in the repo root, or set TOOLGATE_NODE_PATH;
# see node_path in scripts/design/render.py). fig_dashboard.py uses the Python
# playwright package instead if it is installed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-$ROOT/.venv/bin/python}"

run() {
    echo "==> $*"
    "$PY" "$@"
}

# M0: capability model and the security invariant
run scripts/m0_invariant.py --cases 20000 --seed 0     # results/m0_invariant.json
run scripts/fig_delegation_tree.py                       # results/m0_delegation_tree.json, assets/delegation_tree.png

# M0b: solver proofs and the completeness gap
run scripts/m0b_prove_rules.py                           # results/m0b_rules.json
run scripts/m0b_completeness.py --seed 0 --samples 5000  # results/m0b_completeness.json (minutes)
run scripts/fig_completeness_gap.py                      # assets/completeness_gap.* (reads the JSON above)

# M1, M1b, M2: tokens, offline chains, audit log
run scripts/m1_demo.py                                   # results/m1_demo.json
run scripts/fig_token_chain.py                           # results/m1b_token_chain.json, assets/token_chain.*
run scripts/fig_audit_tamper.py                          # results/m2_audit_tamper.json, assets/audit_tamper.*

# M3, M4: gateway service and MCP proxy
run scripts/demo_gateway.py                              # results/m3_demo.json
run scripts/demo_mcp_proxy.py                            # results/m4_demo.json

# M4b, M5: provenance and the scripted sandbox evaluation
run scripts/m5_scripted_eval.py                          # results/m5_scripted.json
run scripts/fig_label_creep.py                           # results/m4b_label_creep.json, assets/label_creep.*
run scripts/fig_provenance_graph.py                      # results/m4b_provenance_graph.json, assets/provenance_graph.*
run scripts/fig_real_model.py                            # assets/real_model.png (reads the committed real-model results; calls no model)

# M6: hero animation, latency, dashboard screenshots
run scripts/fig_hero.py                                  # results/m6_hero.json, assets/hero.gif, hero_poster.png
run scripts/bench_latency.py                             # results/m6_latency.json (minutes, varies run to run)
run scripts/fig_latency.py                               # assets/latency.* (reads the JSON above)
run scripts/fig_dashboard.py                             # assets/dashboard.png, assets/dashboard_tamper.png

echo "All results and figures regenerated."
