"""M4: the MCP proxy, driven by the real MCP SDK client over real sockets.

Layout of every test: the example upstream server (examples/mcp_upstream_server.py)
and the proxy each run under uvicorn on their own thread, bound to 127.0.0.1
port 0 on a socket that is opened before the server starts, so there is no
port to guess and no window in which another process can take it. The client
is `mcp.Client` over streamable HTTP. The upstream is wrapped in a recorder
that keeps every request it receives (headers and body).

Rule for every refusal test here: assert on the upstream's state and on the
requests it received (the observed absence of the effect), not only on the
error the client got.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import itertools
import json
import socket
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.shared.inbound import encode_header_value
from mcp.types import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
)
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    HEADER_MISMATCH,
    PROTOCOL_VERSION_META_KEY,
    UNSUPPORTED_PROTOCOL_VERSION,
    InputRequiredResult,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))
sys.path.insert(0, str(ROOT / "scripts"))

# examples/ is a folder people copy from; no __pycache__ is left in it.
_WRITE_BYTECODE, sys.dont_write_bytecode = sys.dont_write_bytecode, True
import mcp_upstream_server as upstream_example  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

from toolgate.approvals import ApprovalQueue  # noqa: E402
from toolgate.audit import AuditLog, verify  # noqa: E402
from toolgate.capability import Capability, Grant  # noqa: E402
from toolgate.gateway import CallOutcome  # noqa: E402
from toolgate.mcp_proxy import (  # noqa: E402
    APPROVAL_TOOL,
    McpProxy,
    create_proxy,
    discover_tool_names,
    policy_denies_outright,
)
from toolgate.policy import Policy  # noqa: E402
from toolgate.store import MemoryStore  # noqa: E402
from toolgate.tokens import Authority  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
T0 = 1_800_000_000
ISSUER = "https://issuer.example"
PROTOCOL = "2026-07-28"
UPSTREAM_TOOLS = [
    "delete_file",
    "list_files",
    "read_file",
    "search_calendar",
    "send_email",
    "write_file",
]

POLICY = """
version: 1
rules:
  - id: deny-delete
    effect: deny
    tools: ["delete_file"]
    reason: Agents never delete files.
  - id: deny-report-overwrite
    effect: deny
    tools: ["write_file"]
    when:
      path: {glob: "reports/*"}
    reason: Reports are read-only.
  - id: approve-external-email
    effect: approve
    tools: ["send_email"]
    unless:
      to: {glob: "*@example.com"}
    reason: External mail needs a person.
  - id: allow-tools
    effect: allow
    tools: ["read_file", "list_files", "write_file", "send_email"]
"""

ANY = {"any": True}
# The orchestrator's grant names all six upstream tools. Policy denies
# delete_file outright and has no rule at all for search_calendar, so the
# orchestrator should SEE four tools.
ORCH_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/*"}}},
    {"tool": "list_files", "args": {"path": ANY}, "max_calls": 2},
    {"tool": "write_file", "args": {"path": ANY, "content": ANY}},
    {"tool": "delete_file", "args": {"path": ANY}},
    {"tool": "send_email", "args": {"to": ANY, "subject": ANY, "body": ANY}},
    {"tool": "search_calendar", "args": {"query": ANY}},
]
ORCH_SEES = ["list_files", "read_file", "send_email", "write_file"]
SUB_CAPS: list[dict[str, Any]] = [
    {"tool": "read_file", "args": {"path": {"glob": "reports/q3*"}}},
]
SUB_SEES = ["read_file"]


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class Recorder:
    """ASGI wrapper that keeps every HTTP request the wrapped app receives."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.requests: list[dict[str, Any]] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        record: dict[str, Any] = {
            "method": scope["method"],
            "headers": [(k.decode("latin-1"), v.decode("latin-1")) for k, v in scope["headers"]],
            "body": b"",
        }
        self.requests.append(record)

        async def keep() -> Any:
            message = await receive()
            if message["type"] == "http.request":
                record["body"] += message.get("body", b"")
            return message

        await self.app(scope, keep, send)

    def mcp_methods(self) -> list[str]:
        return [v for r in self.requests for k, v in r["headers"] if k == "mcp-method"]

    def header_values(self, name: str) -> list[str]:
        return [v for r in self.requests for k, v in r["headers"] if k == name]

    def everything(self) -> str:
        """All headers and bodies as one string, to search for things that must not be there."""
        parts: list[str] = []
        for r in self.requests:
            parts.extend(f"{k}: {v}" for k, v in r["headers"])
            parts.append(r["body"].decode("utf-8", "replace"))
        return "\n".join(parts)


class Served:
    """An ASGI app under uvicorn on 127.0.0.1, on a socket bound before the server starts."""

    def __init__(self, make_app: Callable[[int], Any], port: int = 0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.port: int = self.sock.getsockname()[1]
        config = uvicorn.Config(make_app(self.port), log_level="error", lifespan="on")
        self.server = uvicorn.Server(config)
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, name="served", daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while not self.server.started:
            if self.error is not None or not self.thread.is_alive():
                raise RuntimeError(f"server did not start: {self.error!r}")
            if time.monotonic() > deadline:
                raise RuntimeError("server did not start in time")
            time.sleep(0.002)

    def _run(self) -> None:
        try:
            asyncio.run(self.server.serve(sockets=[self.sock]))
        except BaseException as exc:  # reported by the constructor or by stop()
            self.error = exc

    def stop(self) -> None:
        if not self.thread.is_alive():
            return
        self.server.should_exit = True
        self.thread.join(15)
        self.sock.close()
        assert not self.thread.is_alive(), "server thread did not stop"


class Env:
    """Upstream + proxy + everything needed to mint tokens and inspect what happened."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        policy: str = POLICY,
        upstream_app: Any = None,
        tool_names: list[str] | None = None,
        upstream_factory: Callable[[str], Callable[[], Client]] | None = None,
        **proxy_options: Any,
    ) -> None:
        self.clock = Clock()
        self.world: upstream_example.World | None = None
        if upstream_app is None:
            upstream_app, self.world = upstream_example.build_app()
        self.recorder = Recorder(upstream_app)
        self.upstream = Served(lambda port: self.recorder)
        self.upstream_url = f"http://127.0.0.1:{self.upstream.port}/mcp"
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = AuditLog(self.audit_path)
        ids = itertools.count(1)
        self.proxy: McpProxy

        def make(port: int) -> Any:
            self.url = f"http://127.0.0.1:{port}/mcp"
            self.base = f"http://127.0.0.1:{port}"
            self.store = MemoryStore()
            self.authority = Authority(
                KEY,
                ISSUER,
                self.url,
                self.store,
                clock=self.clock,
                new_id=lambda: f"tok-{next(ids)}",
            )
            self.proxy = create_proxy(
                self.authority,
                Policy.from_yaml(policy),
                self.audit,
                ApprovalQueue(),
                self.upstream_url
                if upstream_factory is None
                else upstream_factory(self.upstream_url),
                tool_names=UPSTREAM_TOOLS if tool_names is None else tool_names,
                resource_url=self.url,
                clock=self.clock,
                **proxy_options,
            )
            return self.proxy

        try:
            self.server = Served(make)
        except BaseException:
            self.upstream.stop()
            self.audit.close()
            raise
        # Startup listed the upstream's tools once; tests count from here.
        self.recorder.requests.clear()

    def close(self) -> None:
        self.server.stop()
        self.upstream.stop()
        self.audit.close()

    def mint(
        self, caps: list[dict[str, Any]], ttl: float = 600, actor: str = "orchestrator"
    ) -> str:
        grant = Grant(tuple(Capability.from_dict(c) for c in caps), self.clock() + ttl)
        return self.authority.mint("user-1", grant, actor, ttl)

    def jti(self, token: str) -> str:
        return self.authority.verify(token).jti

    def audit_entries(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]

    def raw(
        self,
        token: str | None,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        drop: tuple[str, ...] = (),
        meta: dict[str, Any] | None = None,
        extra_header_items: list[tuple[str, str]] | None = None,
    ) -> httpx2.Response:
        """One hand-built 2026-07-28 request, for things the SDK client will not send."""
        body_params = dict(params or {})
        body_params["_meta"] = {
            PROTOCOL_VERSION_META_KEY: PROTOCOL,
            CLIENT_CAPABILITIES_META_KEY: {},
            **(meta or {}),
        }
        head = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-protocol-version": PROTOCOL,
            "mcp-method": method,
        }
        if method == "tools/call" and isinstance(body_params.get("name"), str):
            head["mcp-name"] = encode_header_value(body_params["name"])
        if token is not None:
            head["authorization"] = f"Bearer {token}"
        head.update(headers or {})
        for name in drop:
            head.pop(name, None)
        items = list(head.items()) + list(extra_header_items or [])
        content = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": body_params})
        with httpx2.Client(timeout=15) as http:
            return http.post(self.url, content=content.encode(), headers=items)


@pytest.fixture
def make_env(tmp_path: Path) -> Iterator[Callable[..., Env]]:
    made: list[Env] = []

    def make(**options: Any) -> Env:
        env = Env(tmp_path, **options)
        made.append(env)
        return env

    yield make
    for env in made:
        env.close()


@pytest.fixture
def env(make_env: Callable[..., Env]) -> Env:
    return make_env()


@contextlib.asynccontextmanager
async def connect(url: str, token: str | None, **client_options: Any) -> AsyncIterator[Client]:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=15) as http,
        Client(streamable_http_client(url, http_client=http), **client_options) as client,
    ):
        yield client


def run(coroutine: Any) -> Any:
    return asyncio.run(coroutine)


async def names_seen(url: str, token: str) -> list[str]:
    async with connect(url, token) as client:
        return sorted(t.name for t in (await client.list_tools()).tools)


async def call(url: str, token: str, tool: str, arguments: dict[str, Any]) -> CallToolResult:
    async with connect(url, token) as client:
        return await client.call_tool(tool, arguments)


async def call_error(url: str, token: str, tool: str, arguments: dict[str, Any]) -> MCPError:
    async with connect(url, token) as client:
        with pytest.raises(MCPError) as caught:
            await client.call_tool(tool, arguments)
        return caught.value


def text(result: CallToolResult) -> str:
    return " ".join(block.text for block in result.content if isinstance(block, TextContent))


def leaves(group: BaseException) -> list[Any]:
    """The exceptions inside (possibly nested) exception groups."""
    if isinstance(group, BaseExceptionGroup):
        return [leaf for inner in group.exceptions for leaf in leaves(inner)]
    return [group]


def decisions(env: Env) -> list[tuple[str, str]]:
    return [(e["tool"], e["decision"]) for e in env.audit_entries()]


# ---------------------------------------------------------------------------
# tools/list
# ---------------------------------------------------------------------------


def test_each_grant_sees_only_its_own_tools(env: Env) -> None:
    orch = env.mint(ORCH_CAPS)
    sub = env.authority.exchange(orch, SUB_CAPS, "sub-agent", 300)

    async def scenario() -> None:
        # Without the proxy the upstream shows everything to anyone.
        async with connect(env.upstream_url, None) as direct:
            assert sorted(t.name for t in (await direct.list_tools()).tools) == UPSTREAM_TOOLS
        async with connect(env.url, orch) as client:
            listing = await client.list_tools()
            assert sorted(t.name for t in listing.tools) == sorted([*ORCH_SEES, APPROVAL_TOOL])
            # A filtered list is for this caller only, and not for long.
            assert listing.cache_scope == "private"
            assert listing.ttl_ms == 5000
            assert listing.next_cursor is None
            by_name = {t.name: t for t in listing.tools}
            assert by_name["read_file"].input_schema["properties"]["path"]["type"] == "string"
            assert by_name["read_file"].description == "Return the contents of one file."
            # Results of parked or refused calls could not satisfy an output schema.
            assert all(t.output_schema is None for t in listing.tools)
            assert client.server_info is not None
            assert client.server_info.name == "toolgate-mcp-proxy"
        assert await names_seen(env.url, sub) == sorted([*SUB_SEES, APPROVAL_TOOL])

    run(scenario())
    assert env.audit_entries() == []  # listing decides nothing


def test_a_token_with_no_usable_capability_sees_only_the_status_tool(env: Env) -> None:
    token = env.mint([{"tool": "not_upstream", "args": {}}, {"tool": "delete_file", "args": {}}])
    assert run(names_seen(env.url, token)) == [APPROVAL_TOOL]


def test_policy_denies_outright_is_sound_and_conservative() -> None:
    policy = Policy.from_yaml(POLICY)
    assert policy_denies_outright(policy, "delete_file")  # unconditional deny
    assert policy_denies_outright(policy, "search_calendar")  # no allow or approve rule
    assert policy_denies_outright(policy, "Read_File")  # exact names: no rule matches
    assert not policy_denies_outright(policy, "write_file")  # conditional deny: cannot tell
    assert not policy_denies_outright(policy, "send_email")  # approve is a path to running
    assert not policy_denies_outright(policy, "read_file")
    assert policy_denies_outright(Policy.from_yaml("version: 1\nrules: []"), "read_file")
    approve_all = Policy.from_yaml(
        'version: 1\nrules:\n  - {id: a, effect: approve, tools: ["*"]}\n'
        '  - {id: d, effect: deny, tools: ["x"], absent: [force]}\n'
    )
    assert not policy_denies_outright(approve_all, "anything")
    assert not policy_denies_outright(approve_all, "x")  # the deny depends on an argument


def test_changing_policy_changes_the_list(env: Env) -> None:
    token = env.mint(ORCH_CAPS)
    assert run(names_seen(env.url, token)) == sorted([*ORCH_SEES, APPROVAL_TOOL])
    env.proxy.set_policy(
        Policy.from_yaml('version: 1\nrules:\n  - {id: r, effect: allow, tools: ["read_file"]}\n')
    )
    assert run(names_seen(env.url, token)) == sorted(["read_file", APPROVAL_TOOL])


# ---------------------------------------------------------------------------
# tools/call
# ---------------------------------------------------------------------------


def test_permitted_call_runs_upstream_and_has_its_side_effect(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)
    result = run(call(env.url, token, "write_file", {"path": "notes/new.txt", "content": "hello"}))
    assert result.is_error is False
    assert text(result) == "wrote 5 characters to notes/new.txt"
    assert result.structured_content == {"result": "wrote 5 characters to notes/new.txt"}
    assert env.world.files["notes/new.txt"] == "hello"
    assert env.world.calls == [("write_file", {"path": "notes/new.txt", "content": "hello"})]
    assert decisions(env) == [("write_file", "allow")]
    # The result carries the proxy's identity, and nothing of the upstream's.
    dumped = result.model_dump_json(by_alias=True)
    assert "toolgate-mcp-proxy" in dumped
    assert upstream_example.SERVER_NAME not in dumped

    read = run(call(env.url, token, "read_file", {"path": "reports/q3.txt"}))
    assert text(read) == upstream_example.SEED_FILES["reports/q3.txt"]


@pytest.mark.parametrize(
    ("caps", "tool", "arguments"),
    [
        (SUB_CAPS, "delete_file", {"path": "reports/q3.txt"}),  # exists upstream, not granted
        (SUB_CAPS, "write_file", {"path": "x", "content": "y"}),  # exists upstream, not granted
        (ORCH_CAPS, "delete_file", {"path": "reports/q3.txt"}),  # granted, policy denies outright
        (ORCH_CAPS, "search_calendar", {"query": "review"}),  # granted, no policy rule at all
        (ORCH_CAPS, "no_such_tool", {"path": "reports/q3.txt"}),  # does not exist anywhere
    ],
)
def test_unlisted_tool_is_unknown_and_nothing_happens_upstream(
    env: Env, caps: list[dict[str, Any]], tool: str, arguments: dict[str, Any]
) -> None:
    assert env.world is not None
    token = env.mint(caps)
    before = env.world.snapshot()
    error = run(call_error(env.url, token, tool, arguments))
    # The same answer whether the tool exists upstream or not.
    assert error.code == INVALID_PARAMS
    assert error.message == f"Unknown tool: {tool}"
    assert env.world.snapshot() == before
    assert env.world.calls == []
    assert "tools/call" not in env.recorder.mcp_methods()
    # The attempt is still on the record.
    assert decisions(env) == [(tool, "deny")]


def test_argument_constraint_denial_is_readable_and_has_no_effect(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)
    result = run(call(env.url, token, "read_file", {"path": "secrets/payroll.csv"}))
    assert result.is_error is True
    assert "Denied by toolgate at the grant check (constraint_failed)" in text(result)
    assert "argument 'path' fails glob" in text(result)
    assert result.structured_content == {
        "toolgate": "denied",
        "stage": "grant",
        "reason": "argument 'path' fails glob",
        "rule": None,
        "code": "constraint_failed",
    }
    assert "salary" not in result.model_dump_json()
    # An argument the capability does not mention is refused too (closed world).
    extra = run(call(env.url, token, "read_file", {"path": "reports/q3.txt", "encoding": "x"}))
    assert extra.is_error is True
    assert "argument 'encoding' is not permitted" in text(extra)
    assert extra.structured_content is not None
    assert extra.structured_content["code"] == "argument_not_permitted"
    assert env.world.calls == []
    assert "tools/call" not in env.recorder.mcp_methods()
    assert decisions(env) == [("read_file", "deny"), ("read_file", "deny")]


def test_policy_denial_names_the_rule_and_has_no_effect(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)
    result = run(call(env.url, token, "write_file", {"path": "reports/q3.txt", "content": "0"}))
    assert result.is_error is True
    assert "policy rule deny-report-overwrite" in text(result)
    assert "Reports are read-only." in text(result)
    assert result.structured_content is not None
    assert result.structured_content["rule"] == "deny-report-overwrite"
    assert result.structured_content["stage"] == "policy"
    assert env.world.files["reports/q3.txt"] == upstream_example.SEED_FILES["reports/q3.txt"]
    assert env.world.calls == []
    entry = env.audit_entries()[0]
    assert (entry["decision"], entry["rule"]) == ("deny", "deny-report-overwrite")


def test_budget_runs_out_and_the_next_call_does_not_reach_upstream(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)  # list_files has max_calls 2

    async def scenario() -> list[CallToolResult]:
        async with connect(env.url, token) as client:
            return [await client.call_tool("list_files", {"path": "reports/"}) for _ in range(3)]

    first, second, third = run(scenario())
    assert first.is_error is False and second.is_error is False
    assert first.structured_content == {"result": ["reports/q3.txt", "reports/q4-draft.txt"]}
    assert third.is_error is True
    assert "budget" in text(third)
    assert third.structured_content is not None
    assert third.structured_content["stage"] == "budget"
    assert third.structured_content["code"] == "budget_exhausted"
    assert [name for name, _ in env.world.calls] == ["list_files", "list_files"]
    assert env.store.usage(env.jti(token), 1) == (2, 2)
    assert decisions(env) == [
        ("list_files", "allow"),
        ("list_files", "allow"),
        ("list_files", "deny"),
    ]


def test_upstream_tool_failure_is_a_bounded_error_result(env: Env) -> None:
    token = env.mint([{"tool": "read_file", "args": {"path": ANY}}])
    result = run(call(env.url, token, "read_file", {"path": "missing.txt"}))
    assert result.is_error is True
    assert text(result).startswith("The call was authorized and sent, but it failed: the tool")
    assert len(text(result)) < 2500
    # The decision was "allow" and it was logged before the tool ran.
    assert decisions(env) == [("read_file", "allow")]


@pytest.mark.parametrize("detail", [False, True])
def test_upstream_failure_reaches_the_agent_whatever_the_gateways_error_detail(
    make_env: Callable[..., Env], detail: bool
) -> None:
    # The gateway may withhold exception text from callers. Upstream failures
    # do not travel as exceptions, so the agent gets the same bounded message.
    env = make_env(tool_error_detail=detail)
    assert env.world is not None
    assert env.proxy.gateway.tool_error_detail is detail
    token = env.mint([{"tool": "read_file", "args": {"path": ANY}}])
    missing = run(call(env.url, token, "read_file", {"path": "missing.txt"}))
    assert missing.is_error is True
    assert text(missing).startswith(
        "The call was authorized and sent, but it failed: the tool reported an error: "
    )
    assert "no such file: missing.txt" in text(missing)
    assert "UpstreamError" not in text(missing) and "withheld" not in text(missing)
    assert missing.structured_content is not None
    assert missing.structured_content["toolgate"] == "error"
    # A long upstream message is cut, visibly.
    long_path = "p" * 20_000
    long = run(call(env.url, token, "read_file", {"path": long_path}))
    assert long.is_error is True
    assert "[truncated]" in text(long)
    assert len(text(long)) < 1300
    assert env.world.calls == [
        ("read_file", {"path": "missing.txt"}),
        ("read_file", {"path": long_path}),
    ]
    # Each was one "allow" decision: the call did go out.
    assert decisions(env) == [("read_file", "allow")] * 2


def test_upstream_down_is_an_error_result_that_does_not_name_the_upstream(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(upstream_timeout=3, tool_error_detail=False)
    assert env.world is not None
    token = env.mint([{"tool": "read_file", "args": {"path": ANY}}])
    port = env.upstream.port
    env.upstream.stop()
    for _ in range(2):
        result = run(call(env.url, token, "read_file", {"path": "reports/q3.txt"}))
        assert result.is_error is True
        assert "upstream" in text(result)
        assert str(port) not in result.model_dump_json()
    listing = env.raw(token, "tools/list")
    assert listing.status_code == 500 or "error" in listing.json()
    assert str(port) not in listing.text
    assert env.world.calls == []
    # The proxy itself is still up, and it reconnects when the upstream is back.
    assert env.raw(None, "tools/list").status_code == 401
    app, world = upstream_example.build_app()
    env.upstream = Served(lambda _: app, port=port)
    result = run(call(env.url, token, "read_file", {"path": "reports/q3.txt"}))
    assert result.is_error is False
    assert world.calls == [("read_file", {"path": "reports/q3.txt"})]


def test_output_over_the_limit_is_withheld(make_env: Callable[..., Env]) -> None:
    env = make_env(max_output_bytes=200)
    assert env.world is not None
    env.world.files["reports/big.txt"] = "x" * 1000
    token = env.mint(ORCH_CAPS)
    result = run(call(env.url, token, "read_file", {"path": "reports/big.txt"}))
    assert result.is_error is True
    assert "withheld" in text(result)
    assert "xxxx" not in result.model_dump_json()


def test_gateway_outcomes_that_need_a_failing_store_map_to_protocol_errors(env: Env) -> None:
    # These stages need a token revoked mid-request or a broken store or audit
    # file to occur, so the mapping is checked directly.
    for stage, code in (("token", INVALID_REQUEST), ("unavailable", -32603), ("audit", -32603)):
        with pytest.raises(MCPError) as caught:
            env.proxy._to_mcp(CallOutcome("denied", "revoked", stage=stage), "read_file", True)
        assert caught.value.code == code
        # Not visible wins: the caller learns nothing else.
        with pytest.raises(MCPError) as caught:
            env.proxy._to_mcp(CallOutcome("denied", "revoked", stage=stage), "read_file", False)
        assert caught.value.code == INVALID_PARAMS


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

EXTERNAL = {"to": "partner@other.org", "subject": "Q3", "body": "numbers attached"}


def test_approval_flow_end_to_end_through_the_status_tool(env: Env) -> None:
    assert env.world is not None
    world = env.world
    token = env.mint(ORCH_CAPS)
    other = env.mint(ORCH_CAPS, actor="someone-else")

    async def scenario() -> None:
        async with connect(env.url, token) as client:
            parked = await client.call_tool("send_email", EXTERNAL)
            assert parked.is_error is False
            assert "has NOT run" in text(parked)
            assert parked.structured_content is not None
            assert parked.structured_content["toolgate"] == "pending_approval"
            assert parked.structured_content["rule"] == "approve-external-email"
            approval_id = parked.structured_content["approval_id"]
            assert approval_id in text(parked)
            assert world.outbox == []  # parked means not sent

            waiting = await client.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})
            assert waiting.is_error is False
            assert "Still waiting" in text(waiting)
            assert world.outbox == []

            # Somebody else's token gets the same answer as a made-up id.
            async with connect(env.url, other) as stranger:
                theirs = await stranger.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})
                made_up = await stranger.call_tool(APPROVAL_TOOL, {"approval_id": "nope"})
            assert theirs.is_error is True and made_up.is_error is True
            assert (
                text(theirs) == text(made_up) == "No approval with that id belongs to this token."
            )
            for bad in ({}, {"approval_id": 7}, {"approval_id": approval_id, "x": 1}):
                refused = await client.call_tool(APPROVAL_TOOL, bad)
                assert refused.is_error is True

            outcome = await env.proxy.resolve_approval(approval_id, "approve", "varshith")
            assert outcome.status == "allowed"
            assert world.outbox == [EXTERNAL]

            done = await client.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})
            assert done.is_error is False
            assert text(done) == "email 1 sent to partner@other.org"
            assert upstream_example.SERVER_NAME not in done.model_dump_json(by_alias=True)
            # Polling again does not send again.
            await client.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})
            assert len(world.outbox) == 1

            # Internal mail needs no approval.
            internal = await client.call_tool(
                "send_email", {"to": "a@example.com", "subject": "s", "body": "b"}
            )
            assert internal.is_error is False
            assert len(world.outbox) == 2

    run(scenario())
    # One entry per decision. Polling the status tool is not a decision.
    assert decisions(env) == [
        ("send_email", "approve"),
        ("send_email", "approved"),
        ("send_email", "allow"),
    ]
    assert env.audit_entries()[1]["approver"] == "varshith"


def test_rejected_approval_never_runs_and_says_so(env: Env) -> None:
    assert env.world is not None
    world = env.world
    token = env.mint(ORCH_CAPS)

    async def scenario() -> None:
        async with connect(env.url, token) as client:
            parked = await client.call_tool("send_email", EXTERNAL)
            assert parked.structured_content is not None
            approval_id = parked.structured_content["approval_id"]
            await env.proxy.resolve_approval(approval_id, "reject", "varshith")
            result = await client.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})
            assert result.is_error is True
            assert "did not run" in text(result) and "rejected" in text(result)

    run(scenario())
    assert world.outbox == []
    assert world.calls == []
    assert decisions(env) == [("send_email", "approve"), ("send_email", "rejected")]


def test_approval_after_revocation_does_not_run(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)
    parked = run(call(env.url, token, "send_email", EXTERNAL))
    assert parked.structured_content is not None
    env.authority.revoke(env.jti(token))
    outcome = run(
        env.proxy.resolve_approval(parked.structured_content["approval_id"], "approve", "v")
    )
    assert outcome.status == "denied" and outcome.stage == "token"
    assert env.world.outbox == []


def test_admin_api_mounted_beside_the_proxy_can_approve(env: Env) -> None:
    assert env.world is not None
    # Imported here so that the rest of this file does not depend on the HTTP gateway module.
    from toolgate.server import create_app, hash_admin_key

    # What `main` does: the M3 admin API under /admin, on the same Gateway.
    env.proxy.app.mount("/admin", create_app(env.proxy.gateway, hash_admin_key("admin-key")))
    token = env.mint(ORCH_CAPS)
    parked = run(call(env.url, token, "send_email", EXTERNAL))
    assert parked.structured_content is not None
    approval_id = parked.structured_content["approval_id"]
    admin = {"Authorization": "Bearer admin-key", "Content-Type": "application/json"}
    with httpx2.Client(timeout=15) as http:
        # The agent's own token is not an admin key.
        refused = http.post(
            f"{env.base}/admin/approvals/{approval_id}",
            headers={**admin, "Authorization": f"Bearer {token}"},
            json={"decision": "approve", "approver": "agent"},
        )
        assert refused.status_code == 401
        assert env.world.outbox == []
        pending = http.get(f"{env.base}/admin/approvals", headers=admin).json()["pending"]
        assert [p["args"] for p in pending] == [EXTERNAL]
        approved = http.post(
            f"{env.base}/admin/approvals/{approval_id}",
            headers=admin,
            json={"decision": "approve", "approver": "varshith"},
        )
        assert approved.status_code == 200 and approved.json()["status"] == "allowed"
    assert env.world.outbox == [EXTERNAL]
    done = run(call(env.url, token, APPROVAL_TOOL, {"approval_id": approval_id}))
    assert text(done) == "email 1 sent to partner@other.org"


# ---------------------------------------------------------------------------
# Tokens: HTTP 401 before any handler runs
# ---------------------------------------------------------------------------


def assert_401(env: Env, response: httpx2.Response) -> None:
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert 'error="invalid_token"' in challenge
    metadata_url = f"{env.base}/.well-known/oauth-protected-resource/mcp"
    assert f'resource_metadata="{metadata_url}"' in challenge


def test_no_token_and_garbage_token_get_401_with_resource_metadata(env: Env) -> None:
    assert env.world is not None
    for token in (None, "garbage", "a.b.c", "Bearer x", "x" * 70_000):
        assert_401(env, env.raw(token, "tools/list"))
        assert_401(env, env.raw(token, "tools/call", {"name": "read_file", "arguments": {}}))
    # A non-bearer scheme is no credential either.
    assert_401(env, env.raw(None, "tools/list", headers={"authorization": "Basic dXNlcjpwdw=="}))
    assert_401(env, env.raw(None, "tools/list", headers={"authorization": "Bearer"}))
    # The metadata document the challenge points to (RFC 9728).
    with httpx2.Client() as http:
        metadata = http.get(f"{env.base}/.well-known/oauth-protected-resource/mcp")
    assert metadata.status_code == 200
    assert metadata.json()["resource"] == env.url
    assert metadata.json()["authorization_servers"] == [ISSUER + "/"]
    assert metadata.json()["bearer_methods_supported"] == ["header"]
    assert env.recorder.requests == []
    assert env.world.calls == []

    async def sdk_client() -> None:
        with pytest.raises(BaseExceptionGroup) as caught:
            async with connect(env.url, None) as client:
                await client.list_tools()
        assert [type(e) for e in leaves(caught.value)] == [MCPError]

    run(sdk_client())
    assert env.recorder.requests == []


def test_revoked_token_is_401_on_the_next_request(env: Env) -> None:
    assert env.world is not None
    orch = env.mint(ORCH_CAPS)
    sub = env.authority.exchange(orch, SUB_CAPS, "sub-agent", 300)
    assert env.raw(sub, "tools/list").status_code == 200
    ok = env.raw(sub, "tools/call", {"name": "read_file", "arguments": {"path": "reports/q3.txt"}})
    assert ok.status_code == 200 and ok.json()["result"]["isError"] is False
    # Revoking the PARENT stops the child as well.
    env.authority.revoke(env.jti(orch))
    calls_before = list(env.world.calls)
    assert_401(env, env.raw(sub, "tools/list"))
    assert_401(
        env,
        env.raw(sub, "tools/call", {"name": "read_file", "arguments": {"path": "reports/q3.txt"}}),
    )
    assert_401(env, env.raw(orch, "tools/list"))
    assert env.world.calls == calls_before


def test_expired_token_is_401(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS, ttl=60)
    assert env.raw(token, "tools/list").status_code == 200
    env.clock.now += 61
    assert_401(env, env.raw(token, "tools/list"))
    assert_401(
        env,
        env.raw(
            token, "tools/call", {"name": "read_file", "arguments": {"path": "reports/q3.txt"}}
        ),
    )
    assert env.world.calls == []


def test_token_for_another_audience_or_from_another_key_is_401(env: Env) -> None:
    grant = Grant(tuple(Capability.from_dict(c) for c in ORCH_CAPS), T0 + 600)
    # Same signing key and the same store, but minted for a different resource (RFC 8707).
    elsewhere = Authority(KEY, ISSUER, "https://other.example/mcp", env.store, clock=env.clock)
    assert_401(env, env.raw(elsewhere.mint("user-1", grant, "orchestrator", 600), "tools/list"))
    # Right audience, wrong key.
    forger = Authority(OTHER_KEY, ISSUER, env.url, env.store, clock=env.clock)
    assert_401(env, env.raw(forger.mint("user-1", grant, "orchestrator", 600), "tools/list"))
    # Right key and audience, wrong issuer.
    stranger = Authority(KEY, "https://evil.example", env.url, env.store, clock=env.clock)
    assert_401(env, env.raw(stranger.mint("user-1", grant, "orchestrator", 600), "tools/list"))
    assert env.recorder.requests == []


def test_two_authorization_headers_are_refused(env: Env) -> None:
    good = env.mint(ORCH_CAPS)
    response = env.raw(
        None, "tools/list", extra_header_items=[("authorization", f"Bearer {good}")] * 2
    )
    assert response.status_code == 400
    response = env.raw(
        None,
        "tools/list",
        extra_header_items=[("authorization", "Bearer junk"), ("authorization", f"Bearer {good}")],
    )
    assert response.status_code == 400


def test_proxy_refuses_an_authority_with_another_audience(tmp_path: Path) -> None:
    authority = Authority(KEY, ISSUER, "https://other.example/mcp", MemoryStore())
    with AuditLog(tmp_path / "a.jsonl") as audit:
        common: dict[str, Any] = {"tool_names": ["read_file"]}
        parts = (
            authority,
            Policy.from_yaml(POLICY),
            audit,
            ApprovalQueue(),
            "http://127.0.0.1:1/mcp",
        )
        with pytest.raises(ValueError, match="audience"):
            create_proxy(*parts, resource_url="https://proxy.example/mcp", **common)
        with pytest.raises(ValueError, match="path"):
            create_proxy(*parts, resource_url="https://other.example", **common)
        for bad in (APPROVAL_TOOL, "has space", "star*", ""):
            with pytest.raises(ValueError, match="cannot be put behind"):
                create_proxy(
                    *parts, resource_url="https://other.example/mcp", tool_names=["read_file", bad]
                )


# ---------------------------------------------------------------------------
# The caller's token never goes upstream
# ---------------------------------------------------------------------------


def test_the_callers_token_never_reaches_the_upstream(env: Env) -> None:
    orch = env.mint(ORCH_CAPS)
    sub = env.authority.exchange(orch, SUB_CAPS, "sub-agent", 300)

    async def scenario() -> None:
        for token in (orch, sub):
            async with connect(env.url, token) as client:
                await client.list_tools()
                await client.call_tool("read_file", {"path": "reports/q3.txt"})
        async with connect(env.url, orch) as client:
            await client.call_tool("write_file", {"path": "notes/a.txt", "content": "a"})
            parked = await client.call_tool("send_email", EXTERNAL)
            assert parked.structured_content is not None
            await env.proxy.resolve_approval(
                parked.structured_content["approval_id"], "approve", "v"
            )
            with pytest.raises(MCPError):
                await client.call_tool("delete_file", {"path": "notes/a.txt"})

    run(scenario())
    # A hand-built call that tries to push the token along in every other place.
    env.raw(
        orch,
        "tools/call",
        {"name": "read_file", "arguments": {"path": "reports/q3.txt"}},
        headers={"x-forwarded-authorization": f"Bearer {orch}", "cookie": f"t={orch}"},
        meta={"authorization": orch},
    )
    methods = env.recorder.mcp_methods()
    assert methods.count("tools/call") == 5  # the upstream was really used
    assert env.recorder.header_values("authorization") == []
    assert env.recorder.header_values("cookie") == []
    seen = env.recorder.everything()
    for token in (orch, sub):
        assert token not in seen
        # No part of it either: header, payload and signature are checked separately.
        for part in token.split("."):
            assert part not in seen


def test_the_proxys_own_static_credential_is_what_the_upstream_gets(
    make_env: Callable[..., Env],
) -> None:
    env = make_env(upstream_headers={"Authorization": "Bearer proxy-own-credential"})
    token = env.mint(ORCH_CAPS)
    run(call(env.url, token, "read_file", {"path": "reports/q3.txt"}))
    values = env.recorder.header_values("authorization")
    assert values and set(values) == {"Bearer proxy-own-credential"}
    assert token not in env.recorder.everything()


# ---------------------------------------------------------------------------
# Isolation and upstream request counts
# ---------------------------------------------------------------------------


def test_concurrent_callers_never_see_each_others_list(env: Env) -> None:
    orch = env.mint(ORCH_CAPS)
    sub = env.authority.exchange(orch, SUB_CAPS, "sub-agent", 300)
    mail = env.mint([{"tool": "send_email", "args": {"to": ANY, "subject": ANY, "body": ANY}}])
    expected = {
        orch: sorted([*ORCH_SEES, APPROVAL_TOOL]),
        sub: sorted([*SUB_SEES, APPROVAL_TOOL]),
        mail: sorted(["send_email", APPROVAL_TOOL]),
    }

    async def one_client(token: str) -> list[list[str]]:
        seen = []
        async with connect(env.url, token) as client:
            for _ in range(5):
                listing = await client.list_tools(cache_mode="refresh")
                seen.append(sorted(t.name for t in listing.tools))
                with contextlib.suppress(MCPError):
                    await client.call_tool("read_file", {"path": "reports/q3.txt"})
        return seen

    async def scenario() -> None:
        tokens = [orch, sub, mail] * 6
        results = await asyncio.gather(*(one_client(t) for t in tokens))
        for token, seen in zip(tokens, results, strict=True):
            assert seen == [expected[token]] * 5

    run(scenario())
    # The upstream was asked with the proxy's identity only, so it cannot have varied its answer.
    assert env.recorder.header_values("authorization") == []


def test_a_call_makes_exactly_one_upstream_request_and_no_list(env: Env) -> None:
    token = env.mint(ORCH_CAPS)
    # With arguments, the SDK looks up the input schema before dispatch. Without
    # get_tool_input_schema that lookup would run tools/list against the upstream.
    response = env.raw(
        token, "tools/call", {"name": "read_file", "arguments": {"path": "reports/q3.txt"}}
    )
    assert response.status_code == 200 and response.json()["result"]["isError"] is False
    assert env.recorder.mcp_methods() == ["tools/call"]
    assert len(env.recorder.requests) == 1
    # Refused calls make none at all.
    env.recorder.requests.clear()
    env.raw(token, "tools/call", {"name": "read_file", "arguments": {"path": "secrets/x"}})
    env.raw(token, "tools/call", {"name": "delete_file", "arguments": {"path": "reports/q3.txt"}})
    assert env.recorder.requests == []
    # And a list is one upstream list.
    env.raw(token, "tools/list")
    assert env.recorder.mcp_methods() == ["tools/list"]


# ---------------------------------------------------------------------------
# Everything that is not tools
# ---------------------------------------------------------------------------


def test_resources_prompts_and_subscriptions_are_refused(env: Env) -> None:
    token = env.mint(ORCH_CAPS)

    async def scenario() -> None:
        # The upstream really offers them.
        async with connect(env.upstream_url, None) as direct:
            assert (await direct.list_resources()).resources
            assert (await direct.list_prompts()).prompts
            assert direct.server_capabilities.resources is not None
        env.recorder.requests.clear()
        async with connect(env.url, token) as client:
            capabilities = client.server_capabilities
            assert capabilities.tools is not None
            assert capabilities.resources is None
            assert capabilities.prompts is None
            assert capabilities.completions is None
            assert capabilities.logging is None
            attempts = (
                client.list_resources(),
                client.list_resource_templates(),
                client.read_resource("world://outbox-size"),
                client.list_prompts(),
                client.get_prompt("summarize_reports"),
            )
            for attempt in attempts:
                with pytest.raises(MCPError) as caught:
                    await attempt
                assert caught.value.code == METHOD_NOT_FOUND

    run(scenario())
    for method, params in (
        ("subscriptions/listen", {"notifications": {"toolsListChanged": True}}),
        ("resources/subscribe", {"uri": "world://outbox-size"}),
        ("completion/complete", {}),
        ("logging/setLevel", {"level": "debug"}),
        ("sampling/createMessage", {}),
        ("tasks/list", {}),
    ):
        response = env.raw(token, method, params)
        assert response.status_code in (400, 404), method
        assert response.json()["error"]["code"] in (METHOD_NOT_FOUND, INVALID_PARAMS), method
    assert env.recorder.requests == []
    assert env.audit_entries() == []


def test_the_legacy_initialize_handshake_is_refused(env: Env) -> None:
    token = env.mint(ORCH_CAPS)
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "old-client", "version": "1"},
        },
    }
    head = {"accept": "application/json, text/event-stream", "authorization": f"Bearer {token}"}
    with httpx2.Client(timeout=15) as http:
        for version in (None, "2025-06-18", "2024-11-05"):
            extra = {} if version is None else {"mcp-protocol-version": version}
            response = http.post(env.url, json=initialize, headers={**head, **extra})
            assert response.status_code == 400
            assert response.json()["error"]["code"] == UNSUPPORTED_PROTOCOL_VERSION
            assert response.json()["error"]["data"] == {"supported": [PROTOCOL]}
            assert "mcp-session-id" not in response.headers
        # Authentication still comes first.
        assert http.post(env.url, json=initialize).status_code == 401
        # No session stream to open either.
        assert http.get(env.url, headers=head).status_code == 400

    async def legacy_client() -> None:
        with pytest.raises(BaseExceptionGroup) as caught:
            async with connect(env.url, token, mode="legacy") as client:
                await client.list_tools()
        errors = leaves(caught.value)
        assert [type(e) for e in errors] == [MCPError]
        assert errors[0].code == UNSUPPORTED_PROTOCOL_VERSION

    run(legacy_client())
    assert env.recorder.requests == []


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def test_audit_log_has_one_entry_per_decision_and_verifies(env: Env) -> None:
    orch = env.mint(ORCH_CAPS)
    sub = env.authority.exchange(orch, SUB_CAPS, "sub-agent", 300)

    async def scenario() -> None:
        async with connect(env.url, orch) as client:
            await client.list_tools()  # not a decision
            await client.call_tool("read_file", {"path": "reports/q3.txt"})  # allow
            await client.call_tool("read_file", {"path": "secrets/payroll.csv"})  # deny (grant)
            await client.call_tool(
                "write_file", {"path": "reports/x", "content": ""}
            )  # deny (policy)
            parked = await client.call_tool("send_email", EXTERNAL)  # approve
            assert parked.structured_content is not None
            approval_id = parked.structured_content["approval_id"]
            await client.call_tool(APPROVAL_TOOL, {"approval_id": approval_id})  # not a decision
            await env.proxy.resolve_approval(approval_id, "approve", "varshith")  # approved
            with pytest.raises(MCPError):
                await client.call_tool("delete_file", {"path": "reports/q3.txt"})  # deny (policy)
        async with connect(env.url, sub) as client:
            await client.call_tool("read_file", {"path": "reports/q3.txt"})  # allow
            with pytest.raises(MCPError):
                await client.call_tool("send_email", EXTERNAL)  # deny (grant)

    run(scenario())
    entries = env.audit_entries()
    assert [(e["tool"], e["decision"]) for e in entries] == [
        ("read_file", "allow"),
        ("read_file", "deny"),
        ("write_file", "deny"),
        ("send_email", "approve"),
        ("send_email", "approved"),
        ("delete_file", "deny"),
        ("read_file", "allow"),
        ("send_email", "deny"),
    ]
    assert [e["seq"] for e in entries] == list(range(len(entries)))
    assert entries[0]["actors"] == ["orchestrator"]
    assert entries[6]["actors"] == ["sub-agent", "orchestrator"]
    assert entries[5]["rule"] == "deny-delete"
    result = verify(env.audit_path, env.audit.head())
    assert result.ok and result.entries == len(entries)
    # Arguments are in the log only as a hash.
    assert "partner@other.org" not in env.audit_path.read_text()


# ---------------------------------------------------------------------------
# A paginating upstream with awkward tools
# ---------------------------------------------------------------------------

PAGE_SIZE = 2
REGION_SCHEMA = {
    "type": "object",
    "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
    "required": ["region"],
}
PLAIN_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}
PAGED_TOOLS = [
    Tool(name="alpha", input_schema=PLAIN_SCHEMA),
    Tool(name="alpha", description="a duplicate", input_schema=REGION_SCHEMA),
    Tool(name="bad name!", input_schema=PLAIN_SCHEMA),
    Tool(name="beta", input_schema=PLAIN_SCHEMA),
    Tool(name=APPROVAL_TOOL, description="an impostor", input_schema=PLAIN_SCHEMA),
    Tool(name="region_tool", input_schema=REGION_SCHEMA),
    Tool(name="gamma", input_schema=PLAIN_SCHEMA, output_schema={"type": "object"}),
    Tool(name="hidden_region", input_schema=REGION_SCHEMA),
    Tool(name="ns/delta.v2", input_schema=PLAIN_SCHEMA),
]
PAGED_NAMES = ["alpha", "beta", "gamma", "hidden_region", "ns/delta.v2", "region_tool"]
PAGED_POLICY = 'version: 1\nrules:\n  - {id: allow-all, effect: allow, tools: ["*"]}\n'


def paged_upstream() -> tuple[Any, list[tuple[str, dict[str, Any]]], list[str | None]]:
    calls: list[tuple[str, dict[str, Any]]] = []
    cursors: list[str | None] = []

    async def list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        cursor = None if params is None else params.cursor
        cursors.append(cursor)
        if cursor is not None and cursor not in {str(i) for i in range(len(PAGED_TOOLS))}:
            raise MCPError(INVALID_PARAMS, "Invalid cursor")
        start = 0 if cursor is None else int(cursor)
        end = start + PAGE_SIZE
        return ListToolsResult(
            tools=PAGED_TOOLS[start:end],
            next_cursor=str(end) if end < len(PAGED_TOOLS) else None,
            # Invites any client cache to keep the listing for a minute.
            ttl_ms=60_000,
            cache_scope="public",
        )

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> CallToolResult:
        calls.append((params.name, dict(params.arguments or {})))
        return CallToolResult(
            content=[
                TextContent(
                    type="text",
                    text=json.dumps(params.arguments, sort_keys=True),
                    _meta={"io.modelcontextprotocol/serverInfo": {"name": "block-identity"}},
                )
            ],
            _meta={"upstream-secret": "internal-build-7"},
        )

    server = Server("paged-upstream", version="9", on_list_tools=list_tools, on_call_tool=call_tool)
    return server.streamable_http_app(), calls, cursors


@pytest.fixture
def paged(make_env: Callable[..., Env]) -> tuple[Env, list[tuple[str, dict[str, Any]]], list[Any]]:
    app, calls, cursors = paged_upstream()
    env = make_env(upstream_app=app, tool_names=PAGED_NAMES, policy=PAGED_POLICY)
    cursors.clear()
    return env, calls, cursors


def test_discover_tool_names_skips_names_the_gateway_cannot_carry() -> None:
    app, _, _ = paged_upstream()
    served = Served(lambda port: app)
    try:
        names = run(discover_tool_names(f"http://127.0.0.1:{served.port}/mcp"))
    finally:
        served.stop()
    assert names == PAGED_NAMES


def test_pagination_cursors_are_forwarded_and_every_page_is_filtered(
    paged: tuple[Env, list[tuple[str, dict[str, Any]]], list[Any]],
) -> None:
    env, _, cursors = paged
    granted = ["alpha", "gamma", "ns/delta.v2", "region_tool"]
    token = env.mint(
        [{"tool": n, "args": {"x": ANY}} for n in granted[:3]]
        + [{"tool": "region_tool", "args": {"region": ANY}}]
        # Named by the grant, but never usable through the gateway.
        + [{"tool": "bad name!", "args": {}}]
    )

    async def scenario() -> None:
        async with connect(env.url, token) as client:
            pages: list[list[str]] = []
            cursor: str | None = None
            while True:
                page = await client.list_tools(cursor=cursor, cache_mode="refresh")
                assert page.cache_scope == "private"
                pages.append([t.name for t in page.tools])
                for tool in page.tools:
                    assert tool.output_schema is None
                    assert tool.description != "a duplicate"
                cursor = page.next_cursor
                if cursor is None:
                    break
            # The proxy's own tool is on the first page only; the impostor,
            # the unusable name and the ungranted tools are on none.
            assert pages == [
                [APPROVAL_TOOL, "alpha"],
                [],
                ["region_tool"],
                ["gamma"],
                ["ns/delta.v2"],
            ]
            listed = [name for page in pages for name in page]
            assert listed.count(APPROVAL_TOOL) == 1
            by_name = {t.name: t for t in (await client.list_tools(cache_mode="refresh")).tools}
            assert by_name[APPROVAL_TOOL].description != "an impostor"
            with pytest.raises(MCPError) as caught:
                await client.list_tools(cursor="not-a-cursor", cache_mode="refresh")
            assert (caught.value.code, caught.value.message) == (INVALID_PARAMS, "Invalid cursor")
            with pytest.raises(MCPError) as caught:
                await client.list_tools(cursor="9" * 5000, cache_mode="refresh")
            assert caught.value.code == INVALID_PARAMS

    run(scenario())
    assert cursors == [None, "2", "4", "6", "8", None, "not-a-cursor"]


def test_upstream_meta_is_stripped_from_results(
    paged: tuple[Env, list[tuple[str, dict[str, Any]]], list[Any]],
) -> None:
    env, calls, _ = paged
    token = env.mint([{"tool": "alpha", "args": {"x": ANY}}])
    response = env.raw(token, "tools/call", {"name": "alpha", "arguments": {"x": "1"}})
    assert response.status_code == 200
    assert calls == [("alpha", {"x": "1"})]
    assert "internal-build-7" not in response.text
    assert "paged-upstream" not in response.text
    # `_meta` on a content block is dropped too, not only the result's own.
    assert "block-identity" not in response.text
    assert response.json()["result"]["content"] == [{"type": "text", "text": '{"x": "1"}'}]


# ---------------------------------------------------------------------------
# A malicious agent with one valid, narrow token
# ---------------------------------------------------------------------------

TRICK_NAMES = [
    "Delete_File",
    "DELETE_FILE",
    " delete_file",
    "delete_file ",
    "delete_file\n",
    "delete_file\x00",
    "delete\u200b_file",  # zero-width space
    "d\u0435lete_file",  # Cyrillic e
    "\uff44elete_file",  # fullwidth d
    "delete_file/",
    "/delete_file",
    "./delete_file",
    "read_file/../delete_file",
    "*",
    "delete_*",
    "read_file*",
    "delete_file\u0000read_file",
    "read_file,delete_file",
    "tools/call",
    "",
    "x" * 300,
    "=?base64?ZGVsZXRlX2ZpbGU=?=",
]


def test_tool_name_tricks_reach_nothing(env: Env) -> None:
    assert env.world is not None
    token = env.mint(SUB_CAPS)  # read_file under reports/q3* and nothing else
    before = env.world.snapshot()
    for name in TRICK_NAMES:
        response = env.raw(
            token, "tools/call", {"name": name, "arguments": {"path": "reports/q3.txt"}}
        )
        assert response.status_code == 400, name
        error = response.json()["error"]
        # Either the SDK refuses the header/body pair, or the proxy says unknown.
        assert error["code"] in (INVALID_PARAMS, HEADER_MISMATCH), name
        if error["code"] == INVALID_PARAMS:
            assert error["message"] == f"Unknown tool: {name[:128]}", name
    # The same names with the Mcp-Name header base64-wrapped, as the spec allows.
    for name in ("delete_file", "Delete_File", "delete_file ", "d\u0435lete_file"):
        wrapped = "=?base64?" + base64.b64encode(name.encode()).decode() + "?="
        response = env.raw(
            token,
            "tools/call",
            {"name": name, "arguments": {"path": "reports/q3.txt"}},
            headers={"mcp-name": wrapped},
        )
        assert response.status_code == 400
        assert response.json()["error"]["message"] == f"Unknown tool: {name}"
    assert env.world.snapshot() == before
    assert env.recorder.requests == []


def test_mcp_name_header_cannot_disagree_with_the_body(env: Env) -> None:
    assert env.world is not None
    token = env.mint(SUB_CAPS)
    call_delete = {"name": "delete_file", "arguments": {"path": "reports/q3.txt"}}
    call_read = {"name": "read_file", "arguments": {"path": "reports/q3.txt"}}
    # Header says the permitted tool, body says the forbidden one, and the reverse.
    for params, header in ((call_delete, "read_file"), (call_read, "delete_file")):
        response = env.raw(token, "tools/call", params, headers={"mcp-name": header})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == HEADER_MISMATCH
    # No Mcp-Name at all, and a method header that lies.
    assert env.raw(token, "tools/call", call_read, drop=("mcp-name",)).status_code == 400
    lied = env.raw(token, "tools/call", call_delete, headers={"mcp-method": "tools/list"})
    assert lied.status_code == 400
    # Two Mcp-Name headers.
    doubled = env.raw(
        token, "tools/call", call_delete, extra_header_items=[("mcp-name", "read_file")]
    )
    assert doubled.status_code == 400
    assert env.world.calls == []
    assert env.recorder.requests == []
    assert "reports/q3.txt" in env.world.files


def test_mcp_param_headers_cannot_smuggle_or_probe(
    paged: tuple[Env, list[tuple[str, dict[str, Any]]], list[Any]],
) -> None:
    env, calls, _ = paged
    token = env.mint([{"tool": "region_tool", "args": {"region": {"eq": "eu"}}}])
    # Honest call: header and body agree, the grant allows "eu".
    ok = env.raw(
        token,
        "tools/call",
        {"name": "region_tool", "arguments": {"region": "eu"}},
        headers={"mcp-param-region": "eu"},
    )
    assert ok.status_code == 200 and ok.json()["result"].get("isError") is not True
    # Body says "eu" (allowed), header says "us": refused before anything is decided.
    lie = env.raw(
        token,
        "tools/call",
        {"name": "region_tool", "arguments": {"region": "eu"}},
        headers={"mcp-param-region": "us"},
    )
    assert lie.status_code == 400 and lie.json()["error"]["code"] == HEADER_MISMATCH
    # Body says "us" (not granted). A header that says "eu", or no header, is a
    # mismatch; a header that agrees gets the grant's refusal of the BODY value.
    for header in ({"mcp-param-region": "eu"}, {}):
        response = env.raw(
            token,
            "tools/call",
            {"name": "region_tool", "arguments": {"region": "us"}},
            headers=header,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == HEADER_MISMATCH
    honest_us = env.raw(
        token,
        "tools/call",
        {"name": "region_tool", "arguments": {"region": "us"}},
        headers={"mcp-param-region": "us"},
    )
    assert honest_us.status_code == 200 and honest_us.json()["result"]["isError"] is True
    assert "argument 'region' fails eq" in honest_us.json()["result"]["content"][0]["text"]
    # An argument given only as a header never becomes an argument.
    only_header = env.raw(
        token,
        "tools/call",
        {"name": "region_tool", "arguments": {}},
        headers={"mcp-param-region": "eu"},
    )
    assert only_header.status_code == 400
    assert only_header.json()["error"]["code"] == HEADER_MISMATCH
    # A header the schema does not declare is ignored and is not passed on.
    extra = env.raw(
        token,
        "tools/call",
        {"name": "region_tool", "arguments": {"region": "eu"}},
        headers={"mcp-param-region": "eu", "mcp-param-admin": "true"},
    )
    assert extra.status_code == 200
    assert calls == [("region_tool", {"region": "eu"})] * 2
    # What reached the upstream was built by the proxy from the checked body.
    assert env.recorder.header_values("mcp-param-region") == ["eu", "eu"]
    assert env.recorder.header_values("mcp-param-admin") == []

    # A tool the token cannot see answers "unknown" whatever the headers say. If
    # the schema lookup were not scoped to the caller, the first of these would
    # be a header mismatch and reveal that hidden_region exists with that schema.
    answers = set()
    for name in ("hidden_region", "no_such_tool"):
        for header in ({}, {"mcp-param-region": "us"}):
            response = env.raw(
                token, "tools/call", {"name": name, "arguments": {"region": "eu"}}, headers=header
            )
            error = response.json()["error"]
            answers.add((response.status_code, error["code"], error["message"].replace(name, "N")))
    assert answers == {(400, INVALID_PARAMS, "Unknown tool: N")}
    assert len(calls) == 2


def test_meta_and_extra_fields_change_nothing(env: Env) -> None:
    assert env.world is not None
    token = env.mint(SUB_CAPS)
    response = env.raw(
        token,
        "tools/call",
        {
            "name": "read_file",
            "arguments": {"path": "reports/q3.txt"},
            "requestState": "forged-state",
            "inputResponses": {"x": {"action": "accept"}},
        },
        meta={
            "progressToken": "p1",
            "io.modelcontextprotocol/serverInfo": {"name": "spoof"},
            "toolgate.verified": {"jti": "tok-0"},
            "name": "delete_file",
        },
    )
    assert response.status_code == 200
    assert response.json()["result"]["isError"] is False
    assert env.world.calls == [("read_file", {"path": "reports/q3.txt"})]
    upstream_body = env.recorder.requests[-1]["body"].decode()
    for smuggled in ("forged-state", "spoof", "p1", "tok-0", "delete_file"):
        assert smuggled not in upstream_body
    # `_meta` as an ARGUMENT is just an argument the grant does not name.
    response = env.raw(
        token,
        "tools/call",
        {"name": "read_file", "arguments": {"path": "reports/q3.txt", "_meta": {}}},
    )
    assert response.json()["result"]["isError"] is True
    # Arguments that are not an object never reach a decision.
    for arguments in ([], "reports/q3.txt", 7):
        response = env.raw(token, "tools/call", {"name": "read_file", "arguments": arguments})
        assert response.status_code == 400
    assert len(env.world.calls) == 1


def test_oversized_and_malformed_requests_are_refused_cheaply(env: Env) -> None:
    assert env.world is not None
    token = env.mint([{"tool": "read_file", "args": {"path": ANY}}])
    huge = env.raw(token, "tools/call", {"name": "read_file", "arguments": {"path": "a" * 70_000}})
    assert huge.status_code == 413
    # Under the body limit but more than one audit entry may describe: refused, not run.
    deep: Any = "x"
    for _ in range(200):
        deep = [deep]
    response = env.raw(token, "tools/call", {"name": "read_file", "arguments": {"path": deep}})
    assert response.status_code in (200, 400)
    if response.status_code == 200:
        assert response.json()["result"]["isError"] is True
    with httpx2.Client(timeout=15) as http:
        head = {
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            "mcp-protocol-version": PROTOCOL,
            "mcp-method": "tools/call",
            "mcp-name": "read_file",
        }
        assert http.post(env.url, content=b"{not json", headers=head).status_code == 400
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}] * 2
        assert http.post(env.url, json=batch, headers=head).status_code == 400
        # A browser page on another origin, and a rebinding Host.
        origin = http.post(env.url, json={}, headers={**head, "origin": "https://evil.example"})
        assert origin.status_code == 403
        host = http.post(env.url, json={}, headers={**head, "host": "evil.example"})
        assert host.status_code == 421
        assert http.post(env.url + "?token=" + token, json={}).status_code == 401
    assert env.world.calls == []
    assert env.recorder.requests == []


def test_request_shapes_that_must_not_run_anything(env: Env) -> None:
    assert env.world is not None
    token = env.mint(SUB_CAPS)
    meta = {PROTOCOL_VERSION_META_KEY: PROTOCOL, CLIENT_CAPABILITIES_META_KEY: {}}
    head = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "accept": "application/json, text/event-stream",
        "mcp-protocol-version": PROTOCOL,
        "mcp-method": "tools/call",
        "mcp-name": "read_file",
    }
    good = {"name": "read_file", "arguments": {"path": "reports/q3.txt"}, "_meta": meta}
    with httpx2.Client(timeout=15) as http:
        # A call without an id is a notification: acknowledged and dropped, not run.
        note = http.post(
            env.url, json={"jsonrpc": "2.0", "method": "tools/call", "params": good}, headers=head
        )
        assert note.status_code == 202 and note.content == b""
        # Duplicate keys: one parser, so the value that is checked is the value that is sent.
        duplicated = (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file",'
            '"arguments":{"path":"reports/q3.txt","path":"secrets/payroll.csv"},"_meta":'
            + json.dumps(meta)
            + "}}"
        )
        response = http.post(env.url, content=duplicated.encode(), headers=head)
        assert response.json()["result"]["isError"] is True
        not_a_number = duplicated.replace('"secrets/payroll.csv"', "NaN")
        response = http.post(env.url, content=not_a_number.encode(), headers=head)
        assert response.json()["result"]["isError"] is True
        assert "malformed call" in response.json()["result"]["content"][0]["text"]
        for method in ("GET", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            assert http.request(method, env.url, headers=head).status_code == 405, method
        for path in ("/mcp/", "//mcp", "/MCP", "/admin/approvals", "/docs", "/"):
            assert http.post(env.base + path, json={}, headers=head).status_code == 404, path
        listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta}}
        for scheme, status in (("bearer", 200), ("BEARER", 200), ("Token", 401), ("Bearer,", 401)):
            response = http.post(
                env.url,
                json=listing,
                headers={**head, "mcp-method": "tools/list", "authorization": f"{scheme} {token}"},
            )
            assert response.status_code == status, scheme
    # The status tool's name is exact too, and its argument is not a path.
    wrong_case = env.raw(token, "tools/call", {"name": "Toolgate_Approval_Status", "arguments": {}})
    assert wrong_case.json()["error"]["message"] == "Unknown tool: Toolgate_Approval_Status"
    odd = env.raw(
        token, "tools/call", {"name": APPROVAL_TOOL, "arguments": {"approval_id": "../x"}}
    )
    assert odd.json()["result"]["isError"] is True
    assert env.world.calls == []
    assert "tools/call" not in env.recorder.mcp_methods()


def test_many_parked_calls_hit_the_queue_limit(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)

    async def scenario() -> list[CallToolResult]:
        async with connect(env.url, token) as client:
            return [
                await client.call_tool("send_email", {**EXTERNAL, "subject": f"s{i}"})
                for i in range(7)
            ]

    results = run(scenario())
    assert [r.is_error for r in results] == [False] * 5 + [True] * 2
    assert "too many pending approvals" in text(results[-1])
    assert env.world.outbox == []


INPUT_TOOLS = ["asks_to_retry", "asks_to_sample", "asks_to_elicit"]


def input_required_upstream() -> tuple[Any, list[tuple[str, Any, Any]]]:
    """An upstream whose every tool answers "input required" instead of a result."""
    calls: list[tuple[str, Any, Any]] = []
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}

    async def list_tools(
        ctx: ServerRequestContext, params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        return ListToolsResult(tools=[Tool(name=n, input_schema=schema) for n in INPUT_TOOLS])

    async def call_tool(ctx: ServerRequestContext, params: CallToolRequestParams) -> Any:
        calls.append((params.name, params.request_state, params.input_responses))
        if params.name == "asks_to_retry":
            # State only: an SDK client retries this by itself, with backoff.
            return InputRequiredResult(request_state="again", result_type="input_required")
        if params.name == "asks_to_sample":
            request = {
                "method": "sampling/createMessage",
                "params": {
                    "messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}],
                    "maxTokens": 5,
                },
            }
        else:
            request = {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": "Your password?",
                    "requestedSchema": {"type": "object", "properties": {}},
                },
            }
        return InputRequiredResult(input_requests={"k": request}, result_type="input_required")

    server = Server(
        "asking-upstream", version="1", on_list_tools=list_tools, on_call_tool=call_tool
    )
    return server.streamable_http_app(), calls


def test_an_upstream_asking_for_input_gets_one_call_and_the_agent_an_error(
    make_env: Callable[..., Env],
) -> None:
    # Found in the attack pass: through `Client.call_tool`, a state-only answer
    # made the proxy send the same tools/call 11 times for ONE allow decision
    # and ONE budget charge. Now every decision is at most one upstream call.
    app, calls = input_required_upstream()
    env = make_env(upstream_app=app, tool_names=INPUT_TOOLS, policy=PAGED_POLICY)
    token = env.mint([{"tool": n, "args": {"x": ANY}, "max_calls": 1} for n in INPUT_TOOLS])

    async def scenario() -> None:
        samples: list[Any] = []

        async def sampling(*args: Any) -> Any:  # the AGENT's callback: must never run
            samples.append(args)
            raise AssertionError("the upstream reached the agent")

        async with connect(env.url, token, sampling_callback=sampling) as client:
            for name in INPUT_TOOLS:
                result = await client.call_tool(name, {"x": "1"})
                assert result.is_error is True, name
                assert "asked for more input" in text(result), name
                assert "was not repeated" in text(result), name
        assert samples == []

    started = time.monotonic()
    run(scenario())
    assert time.monotonic() - started < 10  # no retry backoff either
    assert [name for name, _, _ in calls] == INPUT_TOOLS
    assert all(state is None and responses is None for _, state, responses in calls)
    assert env.recorder.mcp_methods() == ["tools/call"] * 3
    # One decision each, charged once each.
    assert decisions(env) == [(n, "allow") for n in INPUT_TOOLS]
    assert [env.store.usage(env.jti(token), i) for i in range(3)] == [(1, 1)] * 3


def test_a_cache_on_a_supplied_upstream_client_is_never_used(
    make_env: Callable[..., Env],
) -> None:
    # A factory may hand the proxy a Client with the SDK's default response
    # cache, and this upstream says its listing may be cached for a minute.
    app, _, cursors = paged_upstream()
    env = make_env(
        upstream_app=app,
        tool_names=PAGED_NAMES,
        policy=PAGED_POLICY,
        upstream_factory=lambda url: lambda: Client(url),
    )
    cursors.clear()
    wide = env.mint([{"tool": n, "args": {"x": ANY}} for n in ("alpha", "beta")])
    narrow = env.mint([{"tool": "beta", "args": {"x": ANY}}])
    seen = [run(names_seen(env.url, token)) for token in (wide, narrow, wide, narrow, narrow, wide)]
    both = sorted(["alpha", APPROVAL_TOOL])
    # First pages only; beta is on the upstream's second page.
    assert seen == [both, [APPROVAL_TOOL], both, [APPROVAL_TOOL], [APPROVAL_TOOL], both]
    # Every listing went to the upstream: nothing was served from a cache.
    assert cursors == [None] * 6
    assert env.recorder.header_values("authorization") == []


def test_a_failing_token_store_is_503_and_nothing_runs(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("disk on fire")

    env.store.any_revoked = broken  # type: ignore[method-assign]
    for method, params in (
        ("tools/list", None),
        ("tools/call", {"name": "write_file", "arguments": {"path": "n/x", "content": "y"}}),
    ):
        response = env.raw(token, method, params)
        assert response.status_code == 503, method
        assert response.headers["retry-after"] == "1"
        assert "disk on fire" not in response.text
    assert env.recorder.requests == []
    assert env.world.calls == []
    assert "n/x" not in env.world.files


def test_parallel_calls_cannot_overspend_the_budget(env: Env) -> None:
    assert env.world is not None
    token = env.mint(ORCH_CAPS)  # list_files has max_calls 2

    async def one() -> bool:
        async with connect(env.url, token) as client:
            result = await client.call_tool("list_files", {"path": "reports/"})
            return bool(result.is_error)

    async def scenario() -> list[bool]:
        return await asyncio.gather(*(one() for _ in range(12)))

    errors = run(scenario())
    assert errors.count(False) == 2 and errors.count(True) == 10
    assert [name for name, _ in env.world.calls] == ["list_files"] * 2
    assert env.recorder.mcp_methods().count("tools/call") == 2
    assert sorted(decisions(env)) == sorted(
        [("list_files", "allow")] * 2 + [("list_files", "deny")] * 10
    )
    assert verify(env.audit_path, env.audit.head()).ok


def test_related_tokens_cannot_poll_each_others_approvals(env: Env) -> None:
    assert env.world is not None
    mail = {"tool": "send_email", "args": {"to": ANY, "subject": ANY, "body": ANY}}
    orch = env.mint([*ORCH_CAPS])
    sub = env.authority.exchange(orch, [mail], "sub-agent", 300)
    ids = {}
    for name, token in (("orch", orch), ("sub", sub)):
        parked = run(call(env.url, token, "send_email", EXTERNAL))
        assert parked.structured_content is not None
        ids[name] = parked.structured_content["approval_id"]
    for token, other in ((orch, ids["sub"]), (sub, ids["orch"])):
        # Parent and child, same user, same tool: still not each other's.
        result = run(call(env.url, token, APPROVAL_TOOL, {"approval_id": other}))
        assert result.is_error is True
        assert text(result) == "No approval with that id belongs to this token."
    run(env.proxy.resolve_approval(ids["orch"], "approve", "varshith"))
    leaked = run(call(env.url, sub, APPROVAL_TOOL, {"approval_id": ids["orch"]}))
    assert "email" not in text(leaked) and leaked.is_error is True
    assert len(env.world.outbox) == 1
    # Polling is not a decision: two parked, one approved.
    assert decisions(env) == [
        ("send_email", "approve"),
        ("send_email", "approve"),
        ("send_email", "approved"),
    ]


# ---------------------------------------------------------------------------
# The demo script
# ---------------------------------------------------------------------------


def test_demo_is_deterministic_and_matches_the_saved_result(tmp_path: Path) -> None:
    import demo_mcp_proxy

    first, second = tmp_path / "one.json", tmp_path / "two.json"
    assert demo_mcp_proxy.main(["--out", str(first)]) == 0
    assert demo_mcp_proxy.main(["--out", str(second)]) == 0
    assert first.read_text() == second.read_text()
    saved = ROOT / "results" / "m4_demo.json"
    assert json.loads(first.read_text()) == json.loads(saved.read_text()), (
        "results/m4_demo.json is stale: run python scripts/demo_mcp_proxy.py"
    )
    result = json.loads(first.read_text())
    assert result["tools_seen"]["without_proxy"] == UPSTREAM_TOOLS
    assert result["checks"]["audit_log_verifies"] is True
