"""Run the M4 story in-process and write results/m4_demo.json.

A real MCP server (examples/mcp_upstream_server.py, six tools) sits behind the
toolgate MCP proxy. A real MCP client (the SDK's `mcp.Client`) connects three
ways and the script records what each one sees and what each call returns:

  1. straight to the upstream, with no proxy: every tool, no questions asked
  2. through the proxy with the orchestrator's token
  3. through the proxy with a narrower token the orchestrator exchanged for
     its sub-agent

then a request with no token, and the sub-agent's next request after the
orchestrator's token is revoked.

Everything runs in one process over in-memory HTTP (httpx2's ASGI transport):
the same ASGI apps and the same client code as over a socket, with no port.
The URLs below are names only. The run is deterministic: the signing key
comes from a fixed public string, the clock is fixed, token ids are tok-1,
tok-2, ... and approval ids apr-1, ... (a real deployment uses random ids).
The policy is the repo's config/policy.example.yaml. tests/test_mcp_proxy.py
runs this script twice and compares the output with the saved file; the same
tests drive the proxy over real sockets.

Usage:  python scripts/demo_mcp_proxy.py [--out PATH]
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import itertools
import json
import sys
import tempfile
from collections.abc import AsyncIterator
from importlib.metadata import version
from pathlib import Path
from typing import Any

import httpx2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, TextContent

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))

# examples/ is a folder people copy from; no __pycache__ is left in it.
_WRITE_BYTECODE, sys.dont_write_bytecode = sys.dont_write_bytecode, True
import mcp_upstream_server as upstream_example  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

from toolgate.approvals import ApprovalQueue  # noqa: E402
from toolgate.audit import AuditLog, verify  # noqa: E402
from toolgate.capability import Capability, Grant  # noqa: E402
from toolgate.mcp_proxy import APPROVAL_TOOL, McpProxy, create_proxy  # noqa: E402
from toolgate.policy import Policy  # noqa: E402
from toolgate.store import MemoryStore  # noqa: E402
from toolgate.tokens import Authority  # noqa: E402

POLICY_FILE = ROOT / "config" / "policy.example.yaml"
KEY_SEED = "toolgate m4 demo key, not a secret"
START = 1_794_873_600  # 2026-11-17 00:00:00 UTC
ISSUER = "https://gateway.example"
PROXY_URL = "http://proxy.demo/mcp"
UPSTREAM_URL = "http://127.0.0.1:8765/mcp"  # a name for the in-memory transport; nothing listens

ANY = {"any": True}
ORCHESTRATOR_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": ANY}},
    {"tool": "list_files", "args": {"path": ANY}},
    {"tool": "write_file", "args": {"path": ANY, "content": ANY}},
    {"tool": "delete_file", "args": {"path": ANY}},
    {"tool": "send_email", "args": {"to": ANY, "subject": ANY, "body": ANY}, "max_calls": 3},
    {"tool": "search_calendar", "args": {"query": ANY}},
]
SUB_AGENT_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}, "max_calls": 2},
    {"tool": "list_files", "args": {"path": {"glob": "reports/*"}}},
]
MAIL = {"to": "partner@other.example", "subject": "Q3 summary", "body": "Revenue is up 8%."}


class Counting:
    """ASGI wrapper around the upstream: counts requests and Authorization headers."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.methods: list[str] = []
        self.authorization_headers = 0

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            for key, value in scope["headers"]:
                if key == b"mcp-method":
                    self.methods.append(value.decode())
                if key == b"authorization":
                    self.authorization_headers += 1
        await self.app(scope, receive, send)


@contextlib.asynccontextmanager
async def connect(app: Any, url: str, token: str | None) -> AsyncIterator[Client]:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    async with (
        httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
        Client(streamable_http_client(url, http_client=http), cache=None) as client,
    ):
        yield client


def describe(result: CallToolResult) -> dict[str, Any]:
    text = " ".join(b.text for b in result.content if isinstance(b, TextContent))
    structured = result.structured_content or {}
    kind = structured.get("toolgate") if isinstance(structured.get("toolgate"), str) else None
    out: dict[str, Any] = {
        "mcp": "result",
        "is_error": bool(result.is_error),
        "outcome": kind or ("error" if result.is_error else "allowed"),
        "text": text,
    }
    if "approval_id" in structured:
        out["approval_id"] = structured["approval_id"]
    if structured.get("rule"):
        out["rule"] = structured["rule"]
    return out


async def attempt(client: Client, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return describe(await client.call_tool(tool, arguments))
    except MCPError as exc:
        return {"mcp": "protocol_error", "code": exc.code, "message": exc.message}


async def raw_status(app: Any, token: str | None) -> dict[str, Any]:
    """A bare tools/list POST, to show the HTTP-level answer for a bad credential."""
    headers = {
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": "tools/list",
    }
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    }
    async with httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app)) as http:
        response = await http.post(PROXY_URL, json=body, headers=headers)
    return {
        "http_status": response.status_code,
        "www_authenticate": response.headers.get("www-authenticate"),
    }


async def story(audit_path: Path) -> dict[str, Any]:
    upstream_app, world = upstream_example.build_app()
    upstream = Counting(upstream_app)

    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(KEY_SEED.encode()).digest())
    token_ids = (f"tok-{n}" for n in itertools.count(1))
    approval_ids = (f"apr-{n}" for n in itertools.count(1))
    ticks = itertools.count(START * 1_000_000_000, 1_000_000)  # audit time: 1 ms per entry
    authority = Authority(
        key, ISSUER, PROXY_URL, MemoryStore(), clock=lambda: START, new_id=lambda: next(token_ids)
    )
    audit = AuditLog(audit_path, clock=lambda: next(ticks))

    def upstream_client() -> Client:
        http = httpx2.AsyncClient(transport=httpx2.ASGITransport(app=upstream))
        return Client(streamable_http_client(UPSTREAM_URL, http_client=http), cache=None)

    steps: list[dict[str, Any]] = []
    seen: dict[str, list[str]] = {}

    async def do(who: str, client: Client, tool: str, arguments: dict[str, Any], note: str) -> Any:
        outcome = await attempt(client, tool, arguments)
        steps.append(
            {"who": who, "tool": tool, "arguments": arguments, "note": note, "answer": outcome}
        )
        return outcome

    try:
        async with upstream_app.router.lifespan_context(upstream_app):
            async with connect(upstream, UPSTREAM_URL, None) as direct:
                seen["without_proxy"] = sorted(t.name for t in (await direct.list_tools()).tools)
            proxy: McpProxy = create_proxy(
                authority,
                Policy.from_file(POLICY_FILE),
                audit,
                ApprovalQueue(new_id=lambda: next(approval_ids)),
                upstream_client,
                tool_names=seen["without_proxy"],
                resource_url=PROXY_URL,
                clock=lambda: START,
            )
            async with proxy.app.router.lifespan_context(proxy.app):
                grant = Grant(
                    tuple(Capability.from_dict(c) for c in ORCHESTRATOR_CAPS), START + 600
                )
                # Through the Gateway, so that issuing and revoking are in the audit log too.
                gateway = proxy.gateway
                orchestrator, _ = gateway.mint_token("user:varshith", grant, "orchestrator", 600)
                sub_agent, _ = gateway.exchange_token(
                    orchestrator, SUB_AGENT_CAPS, "sub-agent", 300
                )

                who = "orchestrator"
                async with connect(proxy, PROXY_URL, orchestrator) as client:
                    seen[who] = sorted(t.name for t in (await client.list_tools()).tools)
                    await do(who, client, "read_file", {"path": "reports/q3.txt"}, "granted")
                    await do(
                        who,
                        client,
                        "read_file",
                        {"path": "secrets/payroll.csv"},
                        "granted by the user, denied by operator policy",
                    )
                    await do(
                        who,
                        client,
                        "write_file",
                        {"path": "drafts/summary.txt", "content": "Q3 was up 8 percent."},
                        "granted; the file appears upstream",
                    )
                    for tool, arguments, note in (
                        (
                            "delete_file",
                            {"path": "reports/q3.txt"},
                            "the grant names it, policy denies it outright: not listed, unknown",
                        ),
                        (
                            "search_calendar",
                            {"query": "review"},
                            "the grant names it, no policy rule allows it: not listed, unknown",
                        ),
                        (
                            "no_such_tool",
                            {"path": "reports/q3.txt"},
                            "does not exist: the same answer as the two above",
                        ),
                    ):
                        await do(who, client, tool, arguments, note)
                    parked = await do(
                        who,
                        client,
                        "send_email",
                        MAIL,
                        "external mail: policy parks it for a person; nothing is sent",
                    )
                    sent_while_parked = len(world.outbox)
                    poll = {"approval_id": parked["approval_id"]}
                    await do(who, client, APPROVAL_TOOL, poll, "the agent polls: still waiting")
                    released = await proxy.resolve_approval(
                        parked["approval_id"], "approve", "varshith"
                    )
                    steps.append(
                        {
                            "who": "operator",
                            "action": "approve",
                            "approval_id": parked["approval_id"],
                            "answer": {"status": released.status, "rule": released.rule},
                        }
                    )
                    await do(
                        who, client, APPROVAL_TOOL, poll, "the agent polls again: the mail's result"
                    )

                who = "sub-agent"
                async with connect(proxy, PROXY_URL, sub_agent) as client:
                    seen[who] = sorted(t.name for t in (await client.list_tools()).tools)
                    await do(who, client, "read_file", {"path": "reports/q3.txt"}, "granted")
                    await do(
                        who,
                        client,
                        "read_file",
                        {"path": "notes/todo.txt"},
                        "the tool is granted, this path is not",
                    )
                    await do(
                        who,
                        client,
                        "send_email",
                        MAIL,
                        "the orchestrator may, the sub-agent's token does not name it: unknown",
                    )
                    await do(
                        who, client, "read_file", {"path": "reports/q4-draft.txt"}, "second read"
                    )
                    await do(
                        who,
                        client,
                        "read_file",
                        {"path": "reports/q3.txt"},
                        "third read: the token's budget for read_file was 2",
                    )

                no_token = await raw_status(proxy, None)
                gateway.revoke_token(authority.verify(orchestrator).jti)
                after_revoke = await raw_status(proxy, sub_agent)
    finally:
        audit.close()

    entries = [json.loads(line) for line in audit_path.read_text().splitlines()]
    return {
        "description": (
            "M4 MCP proxy story: real MCP SDK client, real MCP upstream server, in-process "
            "HTTP, fixed clock and ids"
        ),
        "config": {
            "mcp_sdk": version("mcp"),
            "protocol_version": "2026-07-28",
            "policy_file": "config/policy.example.yaml",
            "policy_sha256": hashlib.sha256(POLICY_FILE.read_bytes()).hexdigest(),
            "key_seed": KEY_SEED,
            "start_unix": START,
            "proxy_url": PROXY_URL,
            "orchestrator_capabilities": ORCHESTRATOR_CAPS,
            "sub_agent_capabilities": SUB_AGENT_CAPS,
        },
        "tools_seen": seen,
        "steps": steps,
        "http": {
            "no_token": no_token,
            "sub_agent_after_orchestrator_revoked": after_revoke,
        },
        "upstream": {
            "tool_calls_received": [name for name, _ in world.calls],
            "requests_by_method": {
                m: upstream.methods.count(m) for m in sorted(set(upstream.methods))
            },
            "authorization_headers_received": upstream.authorization_headers,
            "outbox": world.outbox,
            "outbox_size_while_parked": sent_while_parked,
            "files_added": sorted(set(world.files) - set(upstream_example.SEED_FILES)),
            "files_removed": sorted(set(upstream_example.SEED_FILES) - set(world.files)),
        },
        "audit": [
            {
                "seq": e["seq"],
                "actors": e["actors"],
                "tool": e["tool"],
                "decision": e["decision"],
                "rule": e["rule"],
            }
            for e in entries
        ],
        "checks": {
            "audit_log_verifies": bool(verify(audit_path).ok),
            "audit_entries": len(entries),
            "tools_hidden_from_orchestrator": sorted(
                set(seen["without_proxy"]) - set(seen["orchestrator"])
            ),
            "tools_hidden_from_sub_agent": sorted(
                set(seen["without_proxy"]) - set(seen["sub-agent"])
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(ROOT / "results" / "m4_demo.json"))
    options = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as scratch:
        result = asyncio.run(story(Path(scratch) / "audit.jsonl"))
    out = Path(options.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {out}")
    for who, names in result["tools_seen"].items():
        print(f"  {who:14} sees {len(names)} tools: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
