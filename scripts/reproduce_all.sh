#!/usr/bin/env bash
# Regenerate every file under results/ and every figure under assets/.
#
# Run from anywhere:  bash scripts/reproduce_all.sh
# Python defaults to the repo's .venv; override with PYTHON=/path/to/python.
#
# Everything is deterministic (fixed seeds, fixed clocks, counting ids) except
# the latency benchmark and its figure, whose numbers vary run to run.
# measure_completeness.py and bench_latency.py take a few minutes each.
# Every fig_*.py renders HTML pages from scripts/design/ with headless Chromium
# through Node.js Playwright (Node 18+; `npm i -D playwright` and
# `npx playwright install chromium` in the repo root, or set CAVEAT_NODE_PATH;
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

# Capability model and the security invariant
run scripts/check_invariant.py --cases 20000 --seed 0     # results/invariant.json
run scripts/fig_delegation_tree.py                       # results/delegation_tree.json, assets/delegation_tree.png

# Solver proofs and the completeness gap
run scripts/prove_rules.py                           # results/rules_proof.json
run scripts/measure_completeness.py --seed 0 --samples 5000  # results/completeness.json (minutes)
run scripts/fig_completeness_gap.py                      # assets/completeness_gap.* (reads the JSON above)

# Tokens, offline chains, audit log
run scripts/demo_tokens.py                                   # results/token_demo.json
run scripts/fig_token_chain.py                           # results/token_chain.json, assets/token_chain.*
run scripts/fig_audit_tamper.py                          # results/audit_tamper.json, assets/audit_tamper.*

# Gateway service and MCP proxy
run scripts/demo_gateway.py                              # results/gateway_demo.json
run scripts/demo_mcp_proxy.py                            # results/mcp_proxy_demo.json

# Provenance and the scripted sandbox evaluation
run scripts/eval_scripted.py                          # results/scripted_eval.json
run scripts/fig_label_creep.py                           # results/label_creep.json, assets/label_creep.*
run scripts/fig_provenance_graph.py                      # results/provenance_graph.json, assets/provenance_graph.*
run scripts/fig_real_model.py                            # assets/real_model.png (reads the committed real-model results; calls no model)

# Hero animation, latency, dashboard screenshots
run scripts/fig_hero.py                                  # results/hero.json, assets/hero.gif, hero_poster.png
run scripts/bench_latency.py                             # results/latency.json (minutes, varies run to run)
run scripts/fig_latency.py                               # assets/latency.* (reads the JSON above)
run scripts/fig_dashboard.py                             # assets/dashboard.png, assets/dashboard_tamper.png

echo "All results and figures regenerated."
