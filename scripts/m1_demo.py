"""Run the M1 token scenario and write results/m1_demo.json.

One user grant, one orchestrator, two sub-agents, and everything the token
layer is supposed to stop:

  1. the user's grant is minted as a root token for the orchestrator
  2. the orchestrator exchanges it for two weaker sub-agent tokens
  3. escalation attempts on exchange are refused
  4. calls are allowed or denied, and the two sub-agents share the
     orchestrator's call budget instead of each getting all of it
  5. a tampered token and a short-lived token that ran out are refused
  6. revoking the orchestrator's token kills both sub-agent tokens

The run is deterministic: the signing key comes from a fixed seed, the clock
is a counter the script moves by hand, and token ids are tok-1, tok-2, ...
The key is derived from a public string and protects nothing.

Usage:  python scripts/m1_demo.py [--out PATH]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from toolgate import Call, Capability, Grant
from toolgate.store import MemoryStore
from toolgate.tokens import Authority, EscalationError, TokenError

ROOT = Path(__file__).resolve().parent.parent
KEY_SEED = "toolgate m1 demo key, not a secret"
START = 1_794_873_600  # 2026-11-17 00:00:00 UTC
ISSUER = "https://gateway.example"
AUDIENCE = "toolgate-demo"
USER = "user:alice"


class Clock:
    def __init__(self, now: int) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


def read(pattern: str, max_calls: int | None) -> Capability:
    return Capability.from_dict(
        {"tool": "read_file", "args": {"path": {"glob": pattern}}, "max_calls": max_calls}
    )


def send(recipients: list[str], ceiling: int) -> Capability:
    return Capability.from_dict(
        {"tool": "send_email", "args": {"to": {"in": recipients}, "amount": {"max": ceiling}}}
    )


def claims_of(token: str) -> dict[str, Any]:
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


class Demo:
    def __init__(self) -> None:
        self.clock = Clock(START)
        self.store = MemoryStore()
        self.count = 0
        key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED.encode()).digest())
        self.authority = Authority(
            key, ISSUER, AUDIENCE, self.store, clock=self.clock, new_id=self.new_id
        )
        self.steps: list[dict[str, Any]] = []
        self.tokens: dict[str, str] = {}

    def new_id(self) -> str:
        self.count += 1
        return f"tok-{self.count}"

    def record(self, action: str, who: str, what: str, outcome: str, reason: str) -> None:
        self.steps.append(
            {
                "step": len(self.steps) + 1,
                "t": self.clock.now - START,
                "action": action,
                "who": who,
                "what": what,
                "outcome": outcome,
                "reason": reason,
            }
        )

    def mint(self, name: str, grant: Grant, ttl: int) -> None:
        token = self.authority.mint(USER, grant, name, ttl)
        self.tokens[name] = token
        v = self.authority.verify(token)
        what = f"root token {v.jti} for {USER}, {len(grant.capabilities)} capabilities, ttl {ttl}s"
        self.record("mint", name, what, "issued", f"expires at t={v.exp - START}")

    def exchange(self, parent: str, name: str, caps: list[Capability], ttl: int, what: str) -> None:
        try:
            token = self.authority.exchange(self.tokens[parent], caps, name, ttl)
        except EscalationError as exc:
            self.record("exchange", parent, f"for {name}: {what}", "refused", exc.reason)
            return
        except TokenError as exc:
            self.record("exchange", parent, f"for {name}: {what}", "refused", exc.code)
            return
        self.tokens[name] = token
        v = self.authority.verify(token)
        reason = f"token {v.jti}, chain {list(v.chain)}, expires at t={v.exp - START}"
        self.record("exchange", parent, f"for {name}: {what}", "issued", reason)

    def call(self, name: str, tool: str, token: str | None = None, **args: Any) -> None:
        what = f"{tool}({', '.join(f'{k}={v!r}' for k, v in args.items())})"
        try:
            decision, _ = self.authority.authorize(token or self.tokens[name], Call(tool, args))
        except TokenError as exc:
            self.record("call", name, what, "token refused", exc.code)
            return
        self.record(
            "call", name, what, "allowed" if decision.allowed else "denied", decision.reason
        )

    def revoke(self, name: str) -> None:
        jti = claims_of(self.tokens[name])["jti"]
        self.authority.revoke(jti)
        self.record("revoke", "gateway operator", f"token {jti} ({name})", "revoked", "")

    def ledger(self) -> dict[str, Any]:
        out = {}
        for name, token in self.tokens.items():
            claims = claims_of(token)
            entries = []
            for index, cap in enumerate(claims["caps"]):
                used, limit = self.store.usage(claims["jti"], index)
                entries.append({"tool": cap["tool"], "used": used, "limit": limit})
            out[name] = {"jti": claims["jti"], "capabilities": entries}
        return out


def run() -> dict[str, Any]:
    d = Demo()

    # 1. Alice lets the orchestrator read reports (3 times) and email two people.
    user_grant = Grant(
        (read("reports/*", 3), send(["bob@corp.example", "carol@corp.example"], 100)),
        START + 3600,
    )
    d.mint("orchestrator", user_grant, ttl=600)

    # 2. Two sub-agents. Each is handed the orchestrator's whole read budget.
    d.exchange(
        "orchestrator", "researcher", [read("reports/q3/*", 3)], 300, "read reports/q3/*, 3 calls"
    )
    d.exchange("orchestrator", "summarizer", [read("reports/*", 3)], 300, "read reports/*, 3 calls")

    # 3. Escalation attempts.
    d.exchange("orchestrator", "rogue", [read("*", 3)], 300, "read *, 3 calls (wider pattern)")
    d.exchange(
        "orchestrator", "rogue", [read("reports/*", 50)], 300, "read reports/*, 50 calls (budget)"
    )
    d.exchange(
        "researcher",
        "rogue",
        [send(["bob@corp.example"], 10)],
        300,
        "send_email (a tool the researcher was never given)",
    )
    d.exchange(
        "researcher", "rogue", [read("reports/*", 1)], 300, "read reports/* (wider than its own)"
    )
    d.exchange("orchestrator", "long-lived", [read("reports/*", 1)], 10**6, "ttl of 1,000,000s")

    # 4. Calls. Denied calls cost nothing; allowed calls are charged to the
    #    caller and to the orchestrator, so three reads is all the family gets.
    d.call("researcher", "read_file", path="reports/q2/revenue.csv")
    d.call("researcher", "read_file", path="reports/q3/revenue.csv", mode="rw")
    d.call("researcher", "send_email", to="bob@corp.example", amount=5)
    d.call("researcher", "read_file", path="reports/q3/revenue.csv")
    d.call("summarizer", "read_file", path="reports/q2/revenue.csv")
    d.call("researcher", "read_file", path="reports/q3/costs.csv")
    d.call("summarizer", "read_file", path="reports/q3/revenue.csv")
    d.call("orchestrator", "read_file", path="reports/q1/revenue.csv")
    d.call("orchestrator", "send_email", to="bob@corp.example", amount=40)
    d.call("orchestrator", "send_email", to="bob@corp.example", amount=400)
    ledger_after_calls = d.ledger()

    # 5. A tampered token, and expiry. The long-lived request above was capped
    #    at the orchestrator's own expiry; a 30 second token is gone at t=30.
    head, payload, signature = d.tokens["summarizer"].split(".")
    forged_claims = claims_of(d.tokens["summarizer"])
    forged_claims["caps"][0]["args"]["path"]["glob"] = "*"
    forged_payload = base64.urlsafe_b64encode(json.dumps(forged_claims).encode()).rstrip(b"=")
    forged = f"{head}.{forged_payload.decode()}.{signature}"
    d.call("summarizer (payload edited)", "read_file", token=forged, path="secrets/key.pem")

    d.exchange("orchestrator", "scratch", [send(["bob@corp.example"], 1)], 30, "send, ttl 30s")
    d.call("scratch", "send_email", to="bob@corp.example", amount=1)
    d.clock.now = START + 30
    d.call("scratch", "send_email", to="bob@corp.example", amount=1)
    d.call("orchestrator", "send_email", to="carol@corp.example", amount=1)

    # 6. Revoke the orchestrator. Its descendants carry its id in `chain`.
    d.exchange("researcher", "intern", [read("reports/q3/public/*", 1)], 60, "depth 2 token")
    d.revoke("orchestrator")
    for name in ("orchestrator", "researcher", "summarizer", "intern"):
        d.call(name, "read_file", path="reports/q3/public/summary.txt")
    d.exchange("researcher", "late", [read("reports/q3/*", 1)], 60, "after the revocation")

    public = d.authority.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "description": "M1 token scenario: scripted, fixed clock, fixed key, no network",
        "config": {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "algorithm": "EdDSA (Ed25519)",
            "key_seed": KEY_SEED,
            "public_key_hex": public.hex(),
            "start_unix": START,
            "max_depth": d.authority.max_depth,
            "max_ttl_seconds": d.authority.max_ttl,
        },
        "steps": d.steps,
        "ledger_after_calls": ledger_after_calls,
        "tokens": {name: claims_of(token) for name, token in d.tokens.items()},
        "summary": {
            "steps": len(d.steps),
            "tokens_issued": len(d.tokens),
            "exchanges_refused": sum(
                s["action"] == "exchange" and s["outcome"] == "refused" for s in d.steps
            ),
            "calls_allowed": sum(s["outcome"] == "allowed" for s in d.steps),
            "calls_denied": sum(s["outcome"] == "denied" for s in d.steps),
            "calls_with_token_refused": sum(s["outcome"] == "token refused" for s in d.steps),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results" / "m1_demo.json")
    args = parser.parse_args()

    result = run()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    for s in result["steps"]:
        line = f"{s['step']:>2}  t={s['t']:<3} {s['action']:<8} {s['who']:<28} {s['what']}"
        print(line)
        print(f"      -> {s['outcome']}" + (f": {s['reason']}" if s["reason"] else ""))
    print(json.dumps(result["summary"], indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
