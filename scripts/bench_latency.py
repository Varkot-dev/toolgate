"""Measure what the gateway costs per tool call, and write results/m6_latency.json.

Sections (each timed with time.perf_counter_ns, after a warm-up, with the
garbage collector left on as it is in production and run once before each
timed loop):

  1. pipeline     `Gateway.handle_call` for an allowed call to a no-op tool,
                  minus the median cost of calling that tool directly. With
                  MemoryStore and SqliteStore (a file in a temp dir), audit
                  fsync on (the default) and, labeled separately, with the
                  audit log's os.fsync replaced by a no-op. Also a call the
                  grant denies and a call operator policy denies, and the
                  in-process configuration the HTTP server uses (tool on its
                  own thread with a timeout).
  2. stages       the public components of the pipeline timed one by one with
                  the same inputs: component timings, which need not sum to
                  the pipeline (the pipeline calls verify three times, and
                  caches, branches and the tool dispatch differ).
  3. depth        handle_call, verify and the budget charge for a token at the
                  end of a delegation chain of 0 to 4 exchanges.
  4. policy_size  Policy.decide for generated policies of 10, 100 and 1000
                  rules (seeded), on a call no deny rule matches, so every
                  rule is evaluated.
  5. throughput   calls per second for 1, 4 and 16 threads in-process (one
                  process, one GIL), and over HTTP against the real FastAPI
                  app on uvicorn (a separate process, localhost, keep-alive)
                  for 1 and 16 concurrent clients, each for a fixed duration.
  6. mcp          one tools/call through the MCP proxy in front of the example
                  MCP server, against the same call made to that server
                  directly. In-process ASGI transport, no socket.

Honest framing: one machine, a shared cloud container that is not isolated
from its neighbours, so the numbers are indicative only and vary run to run.
fsync cost depends entirely on the disk under the temp dir. Nothing here is
compared with any other system.

Usage:
    python scripts/bench_latency.py                 # full run, a few minutes
    python scripts/bench_latency.py --quick --out /tmp/x.json   # smoke test
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import gc
import hashlib
import itertools
import json
import math
import os
import platform
import random
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from toolgate.approvals import ApprovalQueue
from toolgate.audit import AuditLog, hash_args
from toolgate.capability import Call, Capability, Grant
from toolgate.gateway import Gateway, plain_args
from toolgate.policy import Policy
from toolgate.store import MemoryStore, SqliteStore
from toolgate.tokens import Authority

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = ROOT / "config" / "policy.example.yaml"
OUT = ROOT / "results" / "m6_latency.json"
SEED = 20261117
KEY_SEED = "toolgate m6 benchmark key, not a secret"
ADMIN_KEY = "bench-admin-key-not-a-secret"
ISSUER = "https://gateway.example"
AUDIENCE = "toolgate-bench"
BIG = 10**9  # a real budget that the benchmark never reaches

CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": BIG},
    {"tool": "list_files", "args": {"path": {"glob": "secrets/*"}}, "max_calls": BIG},
]
ALLOWED = ("read_file", {"path": "reports/q3/summary.txt"})
GRANT_DENIED = ("read_file", {"path": "notes/todo.txt"})  # outside reports/*
POLICY_DENIED = ("list_files", {"path": "secrets/keys"})  # granted, deny-secret-paths

# Iteration counts and durations: (full, quick).
COUNTS = {
    "warmup": (500, 20),
    "pipeline": (10_000, 60),
    "pipeline_sqlite": (5_000, 40),
    "pipeline_denied": (5_000, 40),
    "stage": (10_000, 60),
    "depth": (3_000, 30),
    "policy": (5_000, 40),
    "direct": (100_000, 200),
    "mcp": (300, 10),
    "mcp_warmup": (30, 3),
}
DURATIONS = {"threads": (3.0, 0.3), "http": (5.0, 0.5)}


def noop(path: str) -> None:
    """The tool: does nothing, so everything measured is the gateway."""
    return None


# ---------------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------------


def percentile(ordered: list[float], q: float) -> float:
    """Nearest-rank percentile of an already sorted list."""
    if not ordered:
        return math.nan
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def summarize(samples_us: list[float]) -> dict[str, Any]:
    ordered = sorted(samples_us)
    return {
        "n": len(ordered),
        "p50_us": round(percentile(ordered, 0.50), 2),
        "p90_us": round(percentile(ordered, 0.90), 2),
        "p99_us": round(percentile(ordered, 0.99), 2),
        "p99_9_us": round(percentile(ordered, 0.999), 2),
        "max_us": round(ordered[-1], 2),
        "mean_us": round(statistics.fmean(ordered), 2),
    }


def sample(fn: Callable[[], Any], n: int, warmup: int, check: Callable[[Any], bool] | None = None):
    """Time `fn` n times after `warmup` untimed calls. Returns microseconds."""
    for _ in range(warmup):
        result = fn()
        if check is not None and not check(result):
            raise SystemExit(f"benchmark precondition failed during warm-up: {result!r}")
    gc.collect()
    out: list[float] = []
    clock = time.perf_counter_ns
    bad = 0
    for _ in range(n):
        t0 = clock()
        result = fn()
        t1 = clock()
        out.append((t1 - t0) / 1000)
        if check is not None and not check(result):
            bad += 1
    if bad:
        raise SystemExit(f"{bad} of {n} timed calls did not have the expected outcome")
    return out


@contextlib.contextmanager
def audit_fsync(enabled: bool) -> Iterator[None]:
    """With enabled=False, os.fsync is a no-op (toolgate.audit calls os.fsync).

    SQLite syncs from C and is not affected: SqliteStore keeps its own syncs.
    """
    if enabled:
        yield
        return
    real = os.fsync
    os.fsync = lambda fd: None  # type: ignore[assignment]
    try:
        yield
    finally:
        os.fsync = real


# ---------------------------------------------------------------------------
# A gateway wired like scripts/demo_gateway.py, with the real clock
# ---------------------------------------------------------------------------


def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED.encode()).digest())


class Rig:
    """One Gateway with its own store and audit file, and a token `depth` exchanges deep."""

    def __init__(
        self,
        directory: Path,
        *,
        store: str = "memory",
        depth: int = 0,
        policy: Policy | None = None,
        **gateway_options: Any,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        if store == "memory":
            self.store: Any = MemoryStore()
        elif store == "sqlite":
            self.store = SqliteStore(str(directory / "store.db"))
        else:
            raise ValueError(store)
        ids = itertools.count(1)
        self.authority = Authority(
            signing_key(), ISSUER, AUDIENCE, self.store, new_id=lambda: f"tok-{next(ids)}"
        )
        self.audit = AuditLog(directory / "audit.jsonl")
        self.policy = policy if policy is not None else Policy.from_file(POLICY_FILE)
        self.gateway = Gateway(
            self.authority,
            self.policy,
            self.audit,
            ApprovalQueue(),
            {"read_file": noop, "list_files": noop},
            **gateway_options,
        )
        self.token = self.new_token(depth)

    def new_token(self, depth: int = 0) -> str:
        grant = Grant(tuple(Capability.from_dict(c) for c in CAPS), time.time() + 3600)
        token, _ = self.gateway.mint_token("user:bench", grant, "agent:bench", 900)
        for level in range(depth):
            token, _ = self.gateway.exchange_token(token, CAPS, f"agent:sub{level + 1}", 900)
        return token

    def close(self) -> None:
        self.audit.close()
        if isinstance(self.store, SqliteStore):
            self.store.close()


def is_allowed(outcome: Any) -> bool:
    return outcome.status == "allowed"


def denied_at(stage: str) -> Callable[[Any], bool]:
    return lambda outcome: outcome.status == "denied" and outcome.stage == stage


# ---------------------------------------------------------------------------
# 1. Pipeline
# ---------------------------------------------------------------------------


def direct_baseline(c: dict[str, int]) -> dict[str, Any]:
    tool, args = ALLOWED
    samples = sample(lambda: noop(**args), c["direct"], c["warmup"])
    return summarize(samples)


def bench_pipeline(scratch: Path, c: dict[str, int], direct_p50: float) -> dict[str, Any]:
    configs = [
        # name, store, fsync, call, check, count key, gateway options, note
        ("memory_fsync_on", "memory", True, ALLOWED, is_allowed, "pipeline", {}, "main"),
        ("memory_fsync_off", "memory", False, ALLOWED, is_allowed, "pipeline", {}, ""),
        ("sqlite_fsync_on", "sqlite", True, ALLOWED, is_allowed, "pipeline_sqlite", {}, ""),
        ("sqlite_fsync_off", "sqlite", False, ALLOWED, is_allowed, "pipeline_sqlite", {}, ""),
        (
            "memory_fsync_on_grant_denied",
            "memory",
            True,
            GRANT_DENIED,
            denied_at("grant"),
            "pipeline_denied",
            {},
            "",
        ),
        (
            "memory_fsync_on_policy_denied",
            "memory",
            True,
            POLICY_DENIED,
            denied_at("policy"),
            "pipeline_denied",
            {},
            "",
        ),
        (
            "memory_fsync_on_server_options",
            "memory",
            True,
            ALLOWED,
            is_allowed,
            "pipeline_denied",
            {"tool_timeout": 30, "max_in_flight_per_root": 8, "tool_error_detail": False},
            "",
        ),
    ]
    out: dict[str, Any] = {}
    keep_samples: list[float] = []
    for name, store, fsync, (tool, args), check, key, options, note in configs:
        rig = Rig(scratch / f"pipeline-{name}", store=store, **options)
        try:
            with audit_fsync(fsync):
                samples = sample(
                    lambda rig=rig, tool=tool, args=args: rig.gateway.handle_call(
                        rig.token, tool, args
                    ),
                    c[key],
                    c["warmup"],
                    check,
                )
        finally:
            rig.close()
        added = [s - direct_p50 for s in samples]
        out[name] = {
            "store": store,
            "audit_fsync": "on" if fsync else "off (os.fsync replaced by a no-op)",
            "call": {"tool": tool, "args": args},
            "gateway_options": options,
            "handle_call": summarize(samples),
            "added": summarize(added),
        }
        print(
            f"  {name:34} added p50 {out[name]['added']['p50_us']:9.1f} us   "
            f"p99 {out[name]['added']['p99_us']:9.1f} us"
        )
        if note == "main":
            keep_samples = added
    out["memory_fsync_on"]["added_samples_us"] = [round(s, 1) for s in keep_samples]
    return out


# ---------------------------------------------------------------------------
# 2. Stages
# ---------------------------------------------------------------------------


def bench_stages(scratch: Path, c: dict[str, int]) -> dict[str, Any]:
    rig = Rig(scratch / "stages")
    side_log = AuditLog(scratch / "stages" / "side-audit.jsonl")
    tool, args = ALLOWED
    call = Call(tool, args)
    verified = rig.authority.verify(rig.token)
    now = time.time()
    path = verified.budget_path(0)
    n, w = c["stage"], c["warmup"]

    def append() -> Any:
        return side_log.append(
            jti=verified.jti,
            actors=verified.actors,
            tool=tool,
            args=call.args,
            decision="allow",
            rule="allow-file-reads",
        )

    def run_tool() -> Any:
        value = noop(**plain_args(call.args))
        return json.loads(json.dumps(value, allow_nan=False, separators=(",", ":")))

    # The signature check on its own, to show how much of verify it is.
    head, payload, signature = rig.token.split(".")
    signed = f"{head}.{payload}".encode()
    raw_signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    public_key = rig.authority.public_key

    stages: list[tuple[str, str, Callable[[], Any], bool]] = [
        (
            "call_build",
            "Call(tool, args) + hash_args",
            lambda: hash_args(Call(tool, args).args),
            True,
        ),
        (
            "token_verify",
            "Authority.verify (step b)",
            lambda: rig.authority.verify(rig.token),
            True,
        ),
        ("grant_decide", "Grant.decide", lambda: verified.grant.decide(call, now), True),
        ("policy_decide", "Policy.decide (example policy)", lambda: rig.policy.decide(call), True),
        (
            "budget_charge",
            "Store.charge on the delegation path",
            lambda: rig.store.charge(path),
            True,
        ),
        (
            "authorize",
            "Authority.authorize (verify + decide + charge, step d)",
            lambda: rig.authority.authorize(rig.token, call),
            True,
        ),
        ("audit_append_fsync", "AuditLog.append, fsync on", append, True),
        ("audit_append_no_fsync", "AuditLog.append, os.fsync a no-op", append, False),
        (
            "re_verify",
            "Authority.verify again (step e)",
            lambda: rig.authority.verify(rig.token),
            True,
        ),
        ("tool_dispatch", "no-op tool + output JSON check", run_tool, True),
        (
            "ed25519_signature_only",
            "Ed25519 signature check alone (part of every verify)",
            lambda: public_key.verify(raw_signature, signed),
            True,
        ),
    ]
    out: dict[str, Any] = {}
    try:
        for key, label, fn, fsync in stages:
            with audit_fsync(fsync):
                out[key] = {"label": label, **summarize(sample(fn, n, w))}
            print(f"  {key:24} p50 {out[key]['p50_us']:9.1f} us   p99 {out[key]['p99_us']:9.1f} us")
    finally:
        side_log.close()
        rig.close()
    return out


# ---------------------------------------------------------------------------
# 3. Delegation depth
# ---------------------------------------------------------------------------


def bench_depth(scratch: Path, c: dict[str, int], direct_p50: float) -> list[dict[str, Any]]:
    tool, args = ALLOWED
    rows = []
    for depth in range(0, 5):
        rig = Rig(scratch / f"depth-{depth}", depth=depth)
        try:
            verified = rig.authority.verify(rig.token)
            path = verified.budget_path(0)
            row: dict[str, Any] = {
                "depth": depth,
                "ancestors_checked": len(verified.chain),
                "budget_entries_charged": len(path),
                "token_chars": len(rig.token),
            }
            for fsync in (True, False):
                with audit_fsync(fsync):
                    samples = sample(
                        lambda rig=rig: rig.gateway.handle_call(rig.token, tool, args),
                        c["depth"],
                        c["warmup"],
                        is_allowed,
                    )
                row["added_fsync_on" if fsync else "added_fsync_off"] = summarize(
                    [s - direct_p50 for s in samples]
                )
            row["verify"] = summarize(
                sample(lambda rig=rig: rig.authority.verify(rig.token), c["depth"], c["warmup"])
            )
            row["charge"] = summarize(
                sample(lambda rig=rig, path=path: rig.store.charge(path), c["depth"], c["warmup"])
            )
        finally:
            rig.close()
        rows.append(row)
        print(
            f"  depth {depth}: added p50 fsync on {row['added_fsync_on']['p50_us']:8.1f} us, "
            f"off {row['added_fsync_off']['p50_us']:8.1f} us, "
            f"verify p50 {row['verify']['p50_us']:.1f} us"
        )
    return rows


# ---------------------------------------------------------------------------
# 4. Policy size
# ---------------------------------------------------------------------------

SERVICES = [
    "crm", "billing", "hr", "wiki", "tickets", "chat", "calendar", "mail", "drive", "repo",
    "ci", "deploy", "metrics", "logs", "db", "search", "docs", "forms", "survey", "payroll",
    "expenses", "travel", "inventory", "orders", "shipping",
]  # fmt: skip
VERBS = ["read", "list", "search", "create", "update", "delete", "send", "export"]
RESTRICTED_DIRS = ["secrets", "private", "hr", "finance", "legal", "keys", "backups", "payroll"]


def generate_policy(size: int, rng: random.Random) -> dict[str, Any]:
    """`size` rules in realistic shapes. About 5% name read_file, none can deny our call.

    Every deny or approve rule on read_file has a `when: path glob <dir>/*` with a
    directory other than reports/, so it is proven FALSE for the measured call
    and evaluated in full; the last rule allows read_file under reports/.
    """
    rules: list[dict[str, Any]] = []
    for i in range(size - 1):
        roll = rng.random()
        effect = "allow" if roll < 0.55 else "approve" if roll < 0.8 else "deny"
        rule: dict[str, Any] = {"id": f"r{i:04d}-{effect}", "effect": effect}
        if rng.random() < 0.05:
            rule["tools"] = ["read_file", "list_files"][: rng.randint(1, 2)]
            if effect == "allow":
                rule["when"] = {"path": {"glob": f"{rng.choice(RESTRICTED_DIRS)}/public/*"}}
            else:
                rule["when"] = {"path": {"glob": f"{rng.choice(RESTRICTED_DIRS)}/*"}}
        else:
            service = rng.choice(SERVICES)
            if rng.random() < 0.2:
                rule["tools"] = [f"{service}_*"]
            else:
                rule["tools"] = sorted(
                    {f"{service}_{v}" for v in rng.sample(VERBS, rng.randint(1, 3))}
                )
            shape = rng.random()
            if shape < 0.3:
                rule["when"] = {"path": {"glob": f"{rng.choice(RESTRICTED_DIRS)}/*"}}
            elif shape < 0.5:
                rule["when"] = {"amount": {"max": rng.choice([100, 500, 1000, 5000])}}
            elif shape < 0.65:
                rule["unless"] = {"to": {"glob": "*@example.com"}}
            elif shape < 0.75:
                rule["when"] = {"region": {"in": ["eu", "us", "apac"][: rng.randint(1, 3)]}}
            elif shape < 0.85 and effect == "allow":
                rule["absent"] = ["cc", "bcc"]
            elif shape < 0.85:
                rule["when"] = {"bcc": {"any": True}}
            if effect != "allow":
                rule["reason"] = f"generated rule {i}"
        rules.append(rule)
    rules.append(
        {
            "id": f"r{size - 1:04d}-allow-reports",
            "effect": "allow",
            "tools": ["read_file"],
            "when": {"path": {"glob": "reports/*"}},
        }
    )
    return {"version": 1, "rules": rules}


def bench_policy(c: dict[str, int]) -> list[dict[str, Any]]:
    tool, args = ALLOWED
    call = Call(tool, args)
    rows = []
    for size in (10, 100, 1000):
        rng = random.Random(SEED + size)
        data = generate_policy(size, rng)
        policy = Policy.from_dict(data)
        decision = policy.decide(call)
        if decision.effect != "allow":
            raise SystemExit(f"generated policy of {size} rules does not allow the call")
        effects = {
            e: sum(1 for r in data["rules"] if r["effect"] == e)
            for e in ("allow", "approve", "deny")
        }
        stats = summarize(
            sample(lambda policy=policy: policy.decide(call), c["policy"], c["warmup"])
        )
        rows.append(
            {
                "rules": size,
                "effects": effects,
                "rules_naming_read_file": sum(
                    1 for r in data["rules"] if "read_file" in r["tools"]
                ),
                "decision": {"effect": decision.effect, "rule": decision.rule_id},
                "policy_sha256": hashlib.sha256(
                    json.dumps(data, sort_keys=True).encode()
                ).hexdigest(),
                "decide": stats,
            }
        )
        print(
            f"  {size:5} rules: decide p50 {stats['p50_us']:8.1f} us   "
            f"p99 {stats['p99_us']:8.1f} us"
        )
    return rows


# ---------------------------------------------------------------------------
# 5. Throughput
# ---------------------------------------------------------------------------


def run_workers(
    count: int, duration: float, prepare: Callable[[int], Callable[[float], None]]
) -> float:
    """Run `count` threads for `duration` seconds and return the measured span.

    Each thread first calls prepare(i) (warm-up, connection setup) and gets
    back a loop, which it runs with the shared deadline. The deadline is set
    only when every thread is ready, so set-up time never eats into it.
    """
    stop_at = [0.0]

    def set_deadline() -> None:
        stop_at[0] = time.perf_counter() + duration

    start = threading.Barrier(count + 1, action=set_deadline)

    def runner(i: int) -> None:
        loop = prepare(i)
        start.wait()
        loop(stop_at[0])

    pool = [threading.Thread(target=runner, args=(i,)) for i in range(count)]
    for t in pool:
        t.start()
    gc.collect()
    start.wait()
    began = stop_at[0] - duration
    for t in pool:
        t.join()
    return time.perf_counter() - began


def _in_process_worker(
    rig: Rig, tokens: list[str], counts: list[int], bad: list[int]
) -> Callable[[int], Callable[[float], None]]:
    tool, args = ALLOWED

    def prepare(i: int) -> Callable[[float], None]:
        handle, token = rig.gateway.handle_call, tokens[i]

        def loop(deadline: float) -> None:
            n = b = 0
            while time.perf_counter() < deadline:
                if handle(token, tool, args).status != "allowed":
                    b += 1
                n += 1
            counts[i], bad[i] = n, b

        return loop

    return prepare


def bench_threads(scratch: Path, duration: float) -> list[dict[str, Any]]:
    rows = []
    for fsync in (True, False):
        for threads in (1, 4, 16):
            rig = Rig(scratch / f"threads-{threads}-{fsync}")
            tokens = [rig.new_token() for _ in range(threads)]  # one agent per thread
            counts, bad = [0] * threads, [0] * threads
            try:
                with audit_fsync(fsync):
                    elapsed = run_workers(
                        threads, duration, _in_process_worker(rig, tokens, counts, bad)
                    )
            finally:
                rig.close()
            row = {
                "threads": threads,
                "audit_fsync": "on" if fsync else "off (os.fsync replaced by a no-op)",
                "duration_s": round(elapsed, 3),
                "calls": sum(counts),
                "not_allowed": sum(bad),
                "calls_per_second": round(sum(counts) / elapsed, 1),
            }
            rows.append(row)
            print(
                f"  in-process {threads:2} threads, fsync {'on ' if fsync else 'off'}: "
                f"{row['calls_per_second']:9.1f} calls/s"
            )
    return rows


def serve(port: int, directory: Path) -> None:
    """Child-process mode: the real FastAPI app on uvicorn, until killed."""
    import uvicorn

    from toolgate.server import create_app, hash_admin_key

    rig = Rig(
        directory,
        tool_timeout=30,
        max_in_flight_per_root=8,
        tool_error_detail=False,
    )
    app = create_app(rig.gateway, hash_admin_key(ADMIN_KEY))
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=port,
        server_header=False,
        proxy_headers=False,
        access_log=False,
        log_level="warning",
        limit_concurrency=256,
        timeout_keep_alive=5,
    )


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _http_worker(
    httpx: Any,
    base: str,
    tokens: list[str],
    latencies: list[list[float]],
    statuses: list[dict[int, int]],
) -> Callable[[int], Callable[[float], None]]:
    tool, args = ALLOWED
    body = {"tool": tool, "args": args}

    def prepare(i: int) -> Callable[[float], None]:
        headers = {"Authorization": f"Bearer {tokens[i]}"}
        client = httpx.Client(base_url=base, headers=headers, timeout=30)
        for _ in range(20):  # warm-up, and the keep-alive connection is opened
            client.post("/call", json=body)

        def loop(deadline: float) -> None:
            lat, seen = latencies[i], statuses[i]
            try:
                while time.perf_counter() < deadline:
                    t0 = time.perf_counter_ns()
                    response = client.post("/call", json=body)
                    lat.append((time.perf_counter_ns() - t0) / 1000)
                    seen[response.status_code] = seen.get(response.status_code, 0) + 1
            finally:
                client.close()

        return loop

    return prepare


def bench_http(scratch: Path, duration: float) -> dict[str, Any]:
    import httpx

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "src"), str(ROOT / "scripts"), env.get("PYTHONPATH", "")]
    )
    server = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--serve", str(port), "--serve-dir",
         str(scratch / "http")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if server.poll() is not None or time.monotonic() > deadline:
                err = server.stderr.read().decode(errors="replace") if server.stderr else ""
                raise RuntimeError(f"server did not start: {err[-500:]}")
            time.sleep(0.1)
        admin = {"Authorization": f"Bearer {ADMIN_KEY}"}

        def mint() -> str:
            body = {"sub": "user:bench", "actor": "agent:bench", "capabilities": CAPS,
                    "expires_in": 900}  # fmt: skip
            response = httpx.post(f"{base}/token", json=body, headers=admin, timeout=10)
            response.raise_for_status()
            return response.json()["token"]

        rows = []
        # The HTTP floor: an endpoint that does no gateway work at all.
        floor: dict[str, Any] = {}
        with httpx.Client(base_url=base) as client:
            for _ in range(50):
                client.get("/healthz")
            gc.collect()
            lat = []
            end = time.perf_counter() + duration / 2
            while time.perf_counter() < end:
                t0 = time.perf_counter_ns()
                client.get("/healthz")
                lat.append((time.perf_counter_ns() - t0) / 1000)
            floor = {"endpoint": "GET /healthz", "clients": 1, "latency": summarize(lat),
                     "requests_per_second": round(len(lat) / (duration / 2), 1)}  # fmt: skip
        print(f"  HTTP floor GET /healthz: p50 {floor['latency']['p50_us']:.1f} us")

        for clients in (1, 16):
            tokens = [mint() for _ in range(clients)]
            latencies: list[list[float]] = [[] for _ in range(clients)]
            statuses: list[dict[int, int]] = [{} for _ in range(clients)]
            cpu0 = time.process_time()
            elapsed = run_workers(
                clients, duration, _http_worker(httpx, base, tokens, latencies, statuses)
            )
            cpu = time.process_time() - cpu0
            every = [x for lat in latencies for x in lat]
            codes: dict[str, int] = {}
            for seen in statuses:
                for code, count in seen.items():
                    codes[str(code)] = codes.get(str(code), 0) + count
            row = {
                "clients": clients,
                "duration_s": round(elapsed, 3),
                "requests": len(every),
                "status_codes": codes,
                "calls_per_second": round(codes.get("200", 0) / elapsed, 1),
                "latency": summarize(every),
                "client_process_cpu_share": round(cpu / elapsed, 2),
            }
            rows.append(row)
            print(
                f"  HTTP {clients:2} clients: {row['calls_per_second']:8.1f} calls/s, "
                f"p50 {row['latency']['p50_us']:.1f} us, p99 {row['latency']['p99_us']:.1f} us"
            )
        return {
            "server": "toolgate.server.create_app on uvicorn "
            f"{version('uvicorn')}, 1 worker process, 127.0.0.1, HTTP/1.1 keep-alive",
            "gateway_options": {
                "tool_timeout": 30,
                "max_in_flight_per_root": 8,
                "tool_error_detail": False,
                "store": "memory",
                "audit_fsync": "on",
            },  # fmt: skip
            "client": f"httpx {version('httpx')}, one httpx.Client (one connection) per "
            "client thread, in a separate process from the server",
            "one_root_token_per_client": True,
            "floor": floor,
            "runs": rows,
        }
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


# ---------------------------------------------------------------------------
# 6. MCP proxy
# ---------------------------------------------------------------------------


async def _mcp(scratch: Path, n: int, warmup: int) -> dict[str, Any]:
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    sys.path.insert(0, str(ROOT / "examples"))
    sys.dont_write_bytecode, before = True, sys.dont_write_bytecode
    import mcp_upstream_server as upstream_example

    sys.dont_write_bytecode = before
    from toolgate.mcp_proxy import create_proxy

    proxy_url = "http://proxy.bench/mcp"
    upstream_url = "http://127.0.0.1:8765/mcp"  # a name for the in-memory transport
    upstream_app, _world = upstream_example.build_app()
    store = MemoryStore()
    ids = itertools.count(1)
    authority = Authority(
        signing_key(), ISSUER, proxy_url, store, new_id=lambda: f"tok-{next(ids)}"
    )
    audit = AuditLog(scratch / "mcp-audit.jsonl")

    def upstream_client() -> Client:
        http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=upstream_app))
        return Client(streamable_http_client(upstream_url, http_client=http), cache=None)

    @contextlib.asynccontextmanager
    async def connect(app: Any, url: str, token: str | None):
        headers = {} if token is None else {"Authorization": f"Bearer {token}"}
        async with (
            httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
            Client(streamable_http_client(url, http_client=http), cache=None) as client,
        ):
            yield client

    async def timed(client: Client) -> list[float]:
        arguments = {"path": "reports/q3.txt"}
        for _ in range(warmup):
            result = await client.call_tool("read_file", arguments)
            if result.is_error:
                raise RuntimeError("MCP warm-up call failed")
        gc.collect()
        out = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            result = await client.call_tool("read_file", arguments)
            out.append((time.perf_counter_ns() - t0) / 1000)
            if result.is_error:
                raise RuntimeError("MCP call failed")
        return out

    try:
        async with upstream_app.router.lifespan_context(upstream_app):
            async with connect(upstream_app, upstream_url, None) as direct:
                names = sorted(t.name for t in (await direct.list_tools()).tools)
                direct_samples = await timed(direct)
            proxy = create_proxy(
                authority,
                Policy.from_file(POLICY_FILE),
                audit,
                ApprovalQueue(),
                upstream_client,
                tool_names=names,
                resource_url=proxy_url,
            )
            async with proxy.app.router.lifespan_context(proxy.app):
                caps = (Capability.from_dict(
                    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": BIG}
                ),)  # fmt: skip
                token, _ = proxy.gateway.mint_token(
                    "user:bench", Grant(caps, time.time() + 3600), "agent:bench", 900
                )
                async with connect(proxy, proxy_url, token) as client:
                    proxied_samples = await timed(client)
    finally:
        audit.close()
    direct_stats, proxied_stats = summarize(direct_samples), summarize(proxied_samples)
    return {
        "measured": True,
        "transport": "in-process ASGI (httpx2.ASGITransport), no socket; the upstream is "
        "examples/mcp_upstream_server.py; MCP SDK client mcp.Client",
        "mcp_sdk": version("mcp"),
        "call": {"tool": "read_file", "arguments": {"path": "reports/q3.txt"}},
        "audit_fsync": "on",
        "direct_to_upstream": direct_stats,
        "through_proxy": proxied_stats,
        "added_p50_us": round(proxied_stats["p50_us"] - direct_stats["p50_us"], 2),
        "note": "added_p50_us is a difference of medians, not a distribution",
    }


def bench_mcp(scratch: Path, c: dict[str, int]) -> dict[str, Any]:
    try:
        result = asyncio.run(_mcp(scratch, c["mcp"], c["mcp_warmup"]))
    except Exception as exc:  # report, do not fail the whole benchmark
        return {"measured": False, "reason": f"{type(exc).__name__}: {exc}"[:300]}
    print(
        f"  MCP read_file: direct p50 {result['direct_to_upstream']['p50_us']:.1f} us, "
        f"through proxy p50 {result['through_proxy']['p50_us']:.1f} us"
    )
    return result


# ---------------------------------------------------------------------------
# Machine description
# ---------------------------------------------------------------------------


def cpu_model() -> str:
    with contextlib.suppress(OSError):
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "unknown"


def filesystem_of(path: Path) -> str:
    best, kind = "", "unknown"
    with contextlib.suppress(OSError):
        target = str(path.resolve())
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and target.startswith(parts[1]) and len(parts[1]) > len(best):
                best, kind = parts[1], parts[2]
    return kind


def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def packages() -> dict[str, str]:
    out = {}
    for name in ("toolgate", "PyJWT", "cryptography", "PyYAML", "fastapi", "starlette",
                 "uvicorn", "httpx", "httpx2", "pydantic", "anyio", "mcp"):  # fmt: skip
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = "not installed"
    return out


def machine(scratch: Path) -> dict[str, Any]:
    return {
        "cpu_model": cpu_model(),
        "logical_cores": os.cpu_count(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "temp_dir_filesystem": filesystem_of(scratch),
        "packages": packages(),
        "git_commit": git("rev-parse", "HEAD"),
        "git_worktree_dirty": git("status", "--porcelain") not in ("", "unknown"),
    }


FRAMING = (
    "Single machine: a shared cloud container (KVM guest), not isolated from other "
    "tenants, with no CPU pinning or frequency control. Numbers are indicative and vary "
    "run to run. Audit fsync cost depends entirely on the disk under the temp dir. "
    "Nothing here is compared with any other system. 'added' latency is handle_call time "
    "minus the median time of calling the no-op tool directly. Stage timings are the "
    "public components timed one by one with the same inputs; they need not sum to the "
    "pipeline. In-process threads share one GIL, so thread counts above 1 measure "
    "contention, not parallel speed-up."
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true", help="tiny counts, for the smoke test")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--serve", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--serve-dir", type=Path, help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    if options.serve:
        serve(options.serve, options.serve_dir)
        return 0

    pick = 1 if options.quick else 0
    c = {k: v[pick] for k, v in COUNTS.items()}
    durations = {k: v[pick] for k, v in DURATIONS.items()}
    random.seed(SEED)
    began = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="toolgate-bench-") as directory:
        scratch = Path(directory)
        print("direct call of the no-op tool")
        direct = direct_baseline(c)
        print(f"  p50 {direct['p50_us']} us")
        print("pipeline")
        pipeline = bench_pipeline(scratch, c, direct["p50_us"])
        print("stages")
        stages = bench_stages(scratch, c)
        print("delegation depth")
        depth = bench_depth(scratch, c, direct["p50_us"])
        print("policy size")
        policy = bench_policy(c)
        print("throughput")
        threads = bench_threads(scratch, durations["threads"])
        try:
            http = bench_http(scratch, durations["http"])
        except Exception as exc:
            http = {"measured": False, "reason": f"{type(exc).__name__}: {exc}"[:300]}
            print(f"  HTTP not measured: {http['reason']}")
        print("MCP proxy")
        mcp = bench_mcp(scratch, c)
        host = machine(scratch)
    runtime = time.perf_counter() - began

    result = {
        "description": "M6: latency and throughput the gateway adds to one tool call",
        "framing": FRAMING,
        "mode": "quick (smoke test, not a result)" if options.quick else "full",
        "created_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "runtime_seconds": round(runtime, 1),
        "seed": SEED,
        "machine": host,
        "method": {
            "timer": "time.perf_counter_ns around each call",
            "gc": "left on; gc.collect() before each timed loop",
            "percentiles": "nearest rank",
            "counts": c,
            "durations_s": durations,
            "tool": "no-op function noop(path) returning None",
            "policy": "config/policy.example.yaml unless stated",
            "policy_sha256": hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest(),
            "capabilities": CAPS,
            "allowed_call": {"tool": ALLOWED[0], "args": ALLOWED[1]},
            "fsync_off": "os.fsync replaced by a no-op for the audit log only; SQLite keeps "
            "its own syncs (default rollback journal, synchronous=FULL)",
            "clock": "real time.time for tokens and policy, time.time_ns for the audit log",
            "gateway_options": "library defaults (tool runs on the calling thread, no "
            "in-flight limit) unless stated; 'server_options' matches toolgate.server.build",
        },
        "direct_tool_call": direct,
        "pipeline": pipeline,
        "stages": stages,
        "depth": depth,
        "policy_size": policy,
        "throughput": {"in_process": threads, "http": http},
        "mcp_proxy": mcp,
    }
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(result, indent=1) + "\n")
    print(f"wrote {options.out} in {runtime:.0f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
