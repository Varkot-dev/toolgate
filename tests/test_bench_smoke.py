"""Smoke test for scripts/bench_latency.py: it runs end to end with tiny counts.

Only checks that the benchmark still works and writes the fields the figure
reads. The numbers of a --quick run mean nothing and are never compared.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bench_latency.py"
PERCENTILES = ("p50_us", "p90_us", "p99_us", "p99_9_us", "max_us", "mean_us")


def test_quick_benchmark_runs_and_writes_every_section(tmp_path: Path) -> None:
    out = tmp_path / "m6_latency.json"
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--quick", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    data = json.loads(out.read_text())
    assert data["mode"].startswith("quick")

    main = data["pipeline"]["memory_fsync_on"]
    for field in PERCENTILES:
        assert main["handle_call"][field] > 0
    assert len(main["added_samples_us"]) == main["added"]["n"]
    for name in (
        "memory_fsync_off",
        "sqlite_fsync_on",
        "sqlite_fsync_off",
        "memory_fsync_on_grant_denied",
        "memory_fsync_on_policy_denied",
    ):
        assert data["pipeline"][name]["handle_call"]["n"] > 0

    for key in ("token_verify", "policy_decide", "budget_charge", "audit_append_fsync"):
        assert data["stages"][key]["p50_us"] > 0
    assert [row["depth"] for row in data["depth"]] == [0, 1, 2, 3, 4]
    assert [row["ancestors_checked"] for row in data["depth"]] == [0, 1, 2, 3, 4]
    assert [row["rules"] for row in data["policy_size"]] == [10, 100, 1000]
    assert all(row["decision"]["effect"] == "allow" for row in data["policy_size"])
    assert [row["threads"] for row in data["throughput"]["in_process"]] == [1, 4, 16] * 2
    assert all(row["not_allowed"] == 0 for row in data["throughput"]["in_process"])

    http = data["throughput"]["http"]
    assert "runs" in http, http.get("reason")
    assert [row["clients"] for row in http["runs"]] == [1, 16]
    assert all(set(row["status_codes"]) == {"200"} for row in http["runs"])
    assert data["mcp_proxy"]["measured"], data["mcp_proxy"].get("reason")

    for field in ("cpu_model", "logical_cores", "python", "packages", "git_commit"):
        assert data["machine"][field]
