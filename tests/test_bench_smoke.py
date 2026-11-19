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
    out = tmp_path / "latency.json"
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

    assert "1.19 ms" in data["warm_vs_cold"]
    pipeline = data["pipeline"]
    for mode in ("warm", "cold"):
        main = pipeline[f"memory_fsync_on_{mode}"]
        assert main["token"] == mode
        for field in PERCENTILES:
            assert main["handle_call"][field] > 0
            assert field in main["added"]
        assert len(main["added_samples_us"]) == main["added"]["n"]
        assert pipeline[f"memory_fsync_off_{mode}"]["token"] == mode
        for fsync in ("on", "off"):
            checked = pipeline[f"memory_fsync_{fsync}_{mode}"]["signature_check_count"]
            assert checked["signature_checks"] == (checked["calls"] if mode == "cold" else 0)
    for name in (
        "memory_fsync_off_warm",
        "memory_fsync_off_cold",
        "sqlite_fsync_on_warm",
        "sqlite_fsync_off_warm",
        "memory_fsync_on_warm_grant_denied",
        "memory_fsync_on_warm_policy_denied",
        "memory_fsync_on_warm_server_options",
    ):
        assert pipeline[name]["handle_call"]["n"] > 0

    stages = data["stages"]
    for key in (
        "call_build",
        "verify_cold",
        "verify_warm",
        "recheck",
        "authorize",
        "budget_charge",
        "audit_append_fsync",
        "audit_append_no_fsync",
        "policy_decide",
        "grant_decide",
        "tool_run",
    ):
        assert stages[key]["p50_us"] > 0
    assert "re_verify" not in stages and "token_verify" not in stages
    assert [row["depth"] for row in data["depth"]] == [0, 1, 2, 3, 4]
    assert [row["ancestors_checked"] for row in data["depth"]] == [0, 1, 2, 3, 4]
    assert [row["rules"] for row in data["policy_size"]] == [10, 100, 1000]
    assert all(row["decision"]["effect"] == "allow" for row in data["policy_size"])
    for row in data["depth"]:
        assert row["signature_check_count_cold"]["signature_checks"] == row["cold_pool_size"]
        for label in ("added_warm_fsync_on", "added_cold_fsync_on", "verify_warm", "verify_cold"):
            assert row[label]["n"] > 0
    in_process = data["throughput"]["in_process"]
    assert [row["threads"] for row in in_process] == [1, 4, 16] * 4
    assert [row["token"] for row in in_process] == ["warm"] * 6 + ["cold"] * 6
    assert all(row["not_allowed"] == 0 for row in data["throughput"]["in_process"])

    http = data["throughput"]["http"]
    assert "runs" in http, http.get("reason")
    assert [row["clients"] for row in http["runs"]] == [1, 16]
    assert all(set(row["status_codes"]) == {"200"} for row in http["runs"])
    assert data["mcp_proxy"]["measured"], data["mcp_proxy"].get("reason")

    for field in ("cpu_model", "logical_cores", "python", "packages", "git_commit"):
        assert data["machine"][field]
