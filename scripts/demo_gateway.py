"""Run the M3 gateway story in-process and write results/m3_demo.json.

The same story as tests/test_server_e2e.py, told through the real HTTP app
(FastAPI over an in-process ASGI transport, no socket):

  1. the admin mints a token for the user's orchestrator
  2. the orchestrator tries to exchange it for MORE than it has (refused),
     then for a narrower child token (issued)
  3. the child makes a call that is allowed, one its grant denies, one that
     operator policy denies, and one that policy parks for a person
  4. the agent cannot approve its own request; the admin sees the arguments,
     approves, and the stored call runs exactly once; a second approval of
     the same id is refused
  5. the agent polls and gets the result
  6. the admin revokes the PARENT token and the child's next call is 401
  7. the audit log verifies and holds one entry per decision, minting,
     exchanging and revoking tokens included

The policy is the repo's config/policy.example.yaml. The run is deterministic:
the signing key comes from a fixed public string, the clock is fixed, token
ids are tok-1, tok-2, ... and approval ids are apr-1, ... (a real gateway uses
32 random bytes for those). The audit log is a throwaway file. The admin key
below is a demo value that protects nothing.

Usage:  python scripts/demo_gateway.py [--out PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import itertools
import json
import tempfile
from pathlib import Path
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from caveat.approvals import ApprovalQueue
from caveat.audit import AuditLog, verify
from caveat.gateway import Gateway
from caveat.policy import Policy
from caveat.server import create_app, hash_admin_key
from caveat.store import MemoryStore
from caveat.tokens import Authority

ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = ROOT / "config" / "policy.example.yaml"
KEY_SEED = "caveat m3 demo key, not a secret"
ADMIN_KEY = "demo-admin-key-not-a-secret"
START = 1_794_873_600  # 2026-11-17 00:00:00 UTC
ISSUER = "https://gateway.example"
AUDIENCE = "caveat-demo"

USER_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 5},
    {
        "tool": "send_email",
        "args": {"to": {"any": True}, "subject": {"any": True}, "body": {"any": True}},
        "max_calls": 2,
    },
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
]
CHILD_CAPS = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/q3/*"}}, "max_calls": 3},
    {
        "tool": "send_email",
        "args": {"to": {"any": True}, "subject": {"any": True}, "body": {"any": True}},
        "max_calls": 1,
    },
    {"tool": "delete_file", "args": {"path": {"any": True}}, "max_calls": 1},
]
MAIL = {"to": "partner@other.example", "subject": "Q3 summary", "body": "Revenue is up 4%."}
# (tool, decision) of every audit entry the story must leave, in order.
EXPECTED_DECISIONS = [
    ("token:mint", "allow"),
    ("token:exchange", "deny"),
    ("token:exchange", "allow"),
    ("read_file", "allow"),
    ("read_file", "deny"),
    ("delete_file", "deny"),
    ("send_email", "approve"),
    ("send_email", "approved"),
    ("token:revoke", "allow"),
    ("read_file", "deny"),
]


class Tools:
    """Stand-in tools that count how often they really ran."""

    def __init__(self) -> None:
        self.ran: dict[str, int] = {"read_file": 0, "send_email": 0, "delete_file": 0}

    def read_file(self, path: str) -> dict[str, Any]:
        self.ran["read_file"] += 1
        return {"path": path, "content": "Q3 revenue: up 4% on Q2."}

    def send_email(self, to: str, subject: str, body: str) -> dict[str, Any]:
        self.ran["send_email"] += 1
        return {"sent_to": to, "subject": subject}

    def delete_file(self, path: str) -> dict[str, Any]:
        self.ran["delete_file"] += 1
        return {"deleted": path}


def build(audit_path: Path) -> tuple[Any, Gateway, Tools]:
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED.encode()).digest())
    token_ids = (f"tok-{n}" for n in itertools.count(1))
    approval_ids = (f"apr-{n}" for n in itertools.count(1))
    ticks = itertools.count(START * 1_000_000_000, 1_000_000)  # audit time: 1 ms per entry
    authority = Authority(
        key,
        ISSUER,
        AUDIENCE,
        MemoryStore(),
        clock=lambda: START,
        new_id=lambda: next(token_ids),
    )
    tools = Tools()
    gateway = Gateway(
        authority,
        Policy.from_file(POLICY_FILE),
        AuditLog(audit_path, clock=lambda: next(ticks)),
        ApprovalQueue(new_id=lambda: next(approval_ids)),
        {
            "read_file": tools.read_file,
            "send_email": tools.send_email,
            "delete_file": tools.delete_file,
        },
        clock=lambda: START,
    )
    return create_app(gateway, hash_admin_key(ADMIN_KEY)), gateway, tools


async def story(app: Any, gateway: Gateway, tools: Tools) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    admin = {"Authorization": f"Bearer {ADMIN_KEY}"}

    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.demo"
    ) as http:

        async def step(
            who: str,
            summary: str,
            method: str,
            path: str,
            headers: dict[str, str],
            body: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            response = await http.request(method, path, headers=headers, json=body)
            data = response.json()
            outcome = data.get("outcome", data) if isinstance(data, dict) else {}
            record = {
                "step": len(steps) + 1,
                "who": who,
                "request": f"{method} {path}",
                "summary": summary,
                "http_status": response.status_code,
                "outcome": outcome.get("status")
                or data.get("state")
                or data.get("error")
                or ("ok" if response.status_code == 200 else "refused"),
                "reason": outcome.get("reason") or data.get("reason"),
                "rule": outcome.get("rule"),
                "audit_seq": outcome.get("audit_seq"),
            }
            steps.append(record)
            rule = f"  rule={record['rule']}" if record["rule"] else ""
            seq = "" if record["audit_seq"] is None else f"  audit#{record['audit_seq']}"
            print(f"{record['step']:>2}. [{who}] {summary}")
            print(f"      {method} {path} -> {response.status_code} {record['outcome']}{rule}{seq}")
            if record["reason"] and record["reason"] != "ok":
                print(f"      reason: {record['reason']}")
            return data

        parent = await step(
            "admin",
            "mint a root token for user:alice, held by agent:orchestrator (3 capabilities)",
            "POST",
            "/token",
            admin,
            {
                "sub": "user:alice",
                "actor": "agent:orchestrator",
                "capabilities": USER_CAPS,
                "expires_in": 600,
            },
        )
        await step(
            "orchestrator",
            "exchange for a WIDER child (read_file on any path): must be refused",
            "POST",
            "/token/exchange",
            bearer(parent["token"]),
            {
                "capabilities": [{"tool": "read_file", "args": {"path": {"glob": "*"}}}],
                "actor": "agent:researcher",
                "expires_in": 300,
            },
        )
        child = await step(
            "orchestrator",
            "exchange for a narrower child (reports/q3/* only, smaller budgets)",
            "POST",
            "/token/exchange",
            bearer(parent["token"]),
            {"capabilities": CHILD_CAPS, "actor": "agent:researcher", "expires_in": 300},
        )
        agent = bearer(child["token"])

        async def call(summary: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
            return await step(
                "agent", summary, "POST", "/call", agent, {"tool": tool, "args": args}
            )

        await call(
            "read_file reports/q3/summary.txt: inside the grant, allowed by policy",
            "read_file",
            {"path": "reports/q3/summary.txt"},
        )
        await call(
            "read_file reports/q2/summary.txt: outside the child's grant",
            "read_file",
            {"path": "reports/q2/summary.txt"},
        )
        await call(
            "delete_file reports/q3/summary.txt: granted, but operator policy denies",
            "delete_file",
            {"path": "reports/q3/summary.txt"},
        )
        pending = await call(
            "send_email to an outside address: policy asks for a person", "send_email", MAIL
        )
        approval = f"/approvals/{pending['approval_id']}"
        sent_before_approval = tools.ran["send_email"]
        await step(
            "agent", "poll the approval: still pending, nothing has run", "GET", approval, agent
        )
        await step(
            "agent",
            "try to approve its own request with its token: not an admin credential",
            "POST",
            approval,
            agent,
            {"decision": "approve", "approver": "agent:researcher"},
        )
        listing = await step(
            "admin",
            "list pending approvals: tool, actors and the arguments",
            "GET",
            "/approvals",
            admin,
        )
        shown = listing["pending"][0]
        print(f"      shown to the approver: {shown['tool']} {json.dumps(shown['args'])}")
        print(f"      for {shown['sub']} via {' <- '.join(shown['actors'])}")
        steps[-1]["shown_to_approver"] = {
            "tool": shown["tool"],
            "args": shown["args"],
            "sub": shown["sub"],
            "actors": shown["actors"],
            "args_hash": shown["args_hash"],
        }
        decision = {"decision": "approve", "approver": "alice@example.com"}
        await step(
            "admin",
            "approve: checks re-run, then the stored call runs",
            "POST",
            approval,
            admin,
            decision,
        )
        await step(
            "admin", "approve the same id again: single use", "POST", approval, admin, decision
        )
        result = await step(
            "agent", "poll the approval: approved, with the result", "GET", approval, agent
        )
        steps[-1]["result"] = result["outcome"]["result"]
        print(f"      result: {json.dumps(result['outcome']['result'])}")
        await step(
            "admin",
            f"revoke the PARENT token {parent['jti']}",
            "POST",
            "/token/revoke",
            admin,
            {"jti": parent["jti"]},
        )
        await call(
            "read_file again with the child token: its ancestor is revoked",
            "read_file",
            {"path": "reports/q3/summary.txt"},
        )
        report = await step(
            "admin", "replay the audit log's hash chain", "GET", "/audit/verify", admin
        )
        steps[-1]["verify"] = report
        print(f"      entries={report['entries']} head={report['head']['hash'][:16]}...")

    steps.append({"sent_before_approval": sent_before_approval})
    return steps


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "m3_demo.json")
    options = parser.parse_args()

    with tempfile.TemporaryDirectory() as directory:
        audit_path = Path(directory) / "audit.jsonl"
        app, gateway, tools = build(audit_path)
        steps = asyncio.run(story(app, gateway, tools))
        sent_before_approval = steps.pop()["sent_before_approval"]
        head = gateway.audit.head()
        gateway.audit.close()
        # Independent of the endpoint: the offline verifier against the head hash.
        offline = verify(audit_path, head.hash)
        entries = [json.loads(line) for line in audit_path.read_text().splitlines()]

    print("\nAudit log (arguments appear only as a hash):")
    for entry in entries:
        who = " <- ".join(entry["actors"]) or "-"
        approver = f"  approver={entry['approver']}" if entry["approver"] else ""
        print(
            f"  #{entry['seq']} {entry['decision']:<9} {entry['tool']:<14} "
            f"{entry['jti']:<6} {who:<36} {entry['rule']}{approver}"
        )
    print(f"\nOffline verify against the head hash: {'ok' if offline.ok else 'FAILED'}")
    print(f"Tools really ran: {tools.ran}")

    # Every decision of the story, in order: issuing and revoking tokens are
    # decisions too. The response no longer gives a caller whose token did not
    # verify an audit_seq (the last call), so the log is compared with the
    # story itself rather than with the seqs the responses reported.
    decisions = [(e["tool"], e["decision"]) for e in entries]
    # (A poll of a decided approval reports the seq of the decision it shows.)
    reported = {s["audit_seq"] for s in steps if s["audit_seq"] is not None}
    checks = {
        "audit_verifies": offline.ok,
        "one_entry_per_decision": decisions == EXPECTED_DECISIONS
        and offline.entries == len(EXPECTED_DECISIONS)
        and all(0 <= seq < offline.entries for seq in reported),
        "email_not_sent_before_approval": sent_before_approval == 0,
        "email_sent_exactly_once": tools.ran["send_email"] == 1,
        "file_read_exactly_once": tools.ran["read_file"] == 1,
        "nothing_deleted": tools.ran["delete_file"] == 0,
    }
    if not all(checks.values()):
        raise SystemExit(f"demo invariants failed: {checks}")

    result = {
        "description": "M3 gateway story: scripted, in-process HTTP, fixed clock and ids",
        "config": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "start_unix": START,
            "policy_file": str(POLICY_FILE.relative_to(ROOT)),
            "policy_sha256": hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest(),
            "key_seed": KEY_SEED,
            "user_capabilities": USER_CAPS,
            "child_capabilities": CHILD_CAPS,
            "approval_ttl_seconds": gateway.approvals.ttl,
        },
        "steps": steps,
        "audit_log": entries,
        "audit_verify": {
            "ok": offline.ok,
            "entries": offline.entries,
            "first_bad_index": offline.first_bad_index,
            "problem": offline.problem,
            "head_seq": head.seq,
            "head_hash": head.hash,
        },
        "tool_executions": tools.ran,
        "checks": checks,
    }
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nWrote {options.out}")


if __name__ == "__main__":
    main()
