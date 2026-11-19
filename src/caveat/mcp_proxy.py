"""MCP proxy mode: the gateway in front of a real MCP server (plan section 3.6).

An MCP client connects to this proxy instead of to the server, with a caveat
token as its bearer credential. The proxy reduces `tools/list` to what that
token can use, runs every `tools/call` through `Gateway.handle_call`, and only
then forwards the call to the upstream server over its own connection.

Written against MCP specification 2026-07-28 and the MCP Python SDK 2.3
(`mcp`, `mcp-types`). That revision is stateless: there is no `initialize`
handshake and no session id; every request is one self-contained POST that
carries its own bearer token, so every request is authenticated on its own.

Which tools a caller sees (the visibility rule)
-----------------------------------------------

A tool is VISIBLE to a token iff all of these hold:

  1. its name is one the proxy was started with (`tool_names`), which also
     means the name matches the gateway's tool-name alphabet
     [A-Za-z0-9_.:/-]{1,128} and is not the reserved `caveat_approval_status`;
  2. the token's grant has a capability whose tool is exactly that name, and
     the grant has not expired;
  3. operator policy does not deny the tool outright. "Outright" is decided
     from the rule list alone, with no arguments, and means one of
       (a) a deny rule with no `when`, no `unless` and no `absent` matches the
           name (such a rule matches every call, and deny beats everything);
       (b) no allow rule and no approve rule matches the name (so every call
           falls to an explicit deny or to the default deny).
     A tool whose every call is denied for a reason that depends on arguments
     (a deny rule with conditions that happen to cover everything) is not
     detected and stays listed. The rule only ever errs toward listing a tool
     the grant names; it never lists a tool the grant does not name.

`tools/list` returns the upstream page filtered to visible tools, plus the
proxy's own `caveat_approval_status` on the first page. Listing never
decides anything: a listed tool is still checked in full on every call.

What a call turns into
----------------------

Every `tools/call` (except the approval-status tool) goes through
`Gateway.handle_call`: token (signature, audience, expiry, revocation), grant
on the exact arguments, policy, approval, budget, audit entry, then the tool.

    gateway outcome                              what the MCP client gets
    allowed                                      the upstream result; every `_meta` removed,
                                                   at the top level and inside content blocks
    denied, tool not visible to this token       JSON-RPC -32602 "Unknown tool: <name>"
    denied, tool visible (arguments, policy,     result with isError=true; the text gives the
      budget, approval queue full, bad call)       stage, the reason and the policy rule id
                                                   (or, for a non-policy refusal, the gateway's
                                                   code such as constraint_failed)
    denied, stage token (revoked mid-request)    JSON-RPC -32600; the next request is HTTP 401
    denied, stage unavailable or audit           JSON-RPC -32603, nothing ran
    pending approval                             result with isError=false that says the call has
                                                   NOT run and carries the approval id
    allowed, but the upstream failed (refused,   result with isError=true and a bounded message
      unreachable, timed out, reported isError,    written by the proxy
      or asked for input)
    error (the gateway's own: tool timeout,      result with isError=true and the gateway's
      output over the limit)                       reason, in the detail the gateway allows

An upstream failure is not an exception inside the gateway: the forwarding
callable returns a small envelope built by the proxy ({"caveat_upstream":
"failed", "message": ...}), so the agent's message does not depend on the
gateway's `tool_error_detail` setting, and the proxy never parses gateway
text. The decision was "allow" and was logged before the call went out.

Each allowed decision is at most ONE upstream `tools/call`. The SDK client
would repeat a call by itself in two cases (an "input required" answer, and a
header mismatch after re-listing); the proxy calls through the client session
so that neither happens.

"Unknown tool" is the same answer for a tool that does not exist, a tool the
upstream has but the grant does not name, and a tool policy denies outright,
so a caller cannot use the proxy to find out what the upstream offers.

Missing, malformed, expired, revoked or wrong-audience tokens never reach a
handler: the SDK's bearer middleware asks `Authority.verify` (through the
`TokenVerifier` hook) and answers HTTP 401 with `WWW-Authenticate` naming the
RFC 9728 protected-resource metadata document, which this app also serves.
The token's audience must be this proxy's URL (RFC 8707), so `create_proxy`
refuses an Authority whose audience is anything else.

Approvals
---------

A parked call returns at once. The agent polls with the proxy's own tool
`caveat_approval_status(approval_id)`, which is visible to every valid
token. It is exempt from grant, policy and budget, and it writes no audit
entry: it runs nothing and releases nothing new. It only reads a record that
the caller's own token created (`Gateway.get_approval` compares the token),
and the result it hands over was audited when the person approved it. This is
the same choice the HTTP gateway makes for `GET /approvals/{id}`. A wrong id
and somebody else's id get the same "not found" answer.

A person approves through `McpProxy.resolve_approval` or through the admin
API mounted next to the proxy (see `main`).

The caller's token never goes upstream
--------------------------------------

The upstream connection is opened once, by the proxy, with the proxy's own
identity: no credential, or static headers the operator configures (`main`
reads one from an environment variable). Nothing from the caller's request is
forwarded except the tool name and the arguments the gateway checked: not the
Authorization header, not `_meta`, not `Mcp-Param-*` headers, not progress
tokens. The MCP specification forbids token passthrough for the same reason
this project does: the upstream would be trusting a token minted for someone
else's audience.

Per-caller isolation
--------------------

The upstream client's response cache is switched off (`cache=None`), every
upstream listing is made with `cache_mode="bypass"` (so a client supplied by
an upstream factory cannot serve one from a cache either), and the proxy
keeps exactly one piece of shared state about tools: the upstream's
unfiltered tool definitions, fetched with the proxy's identity. Filtering
happens per request from the caller's verified grant and is never stored. The
filtered list is returned with `cacheScope: "private"` and a short `ttlMs`.

`get_tool_input_schema`
-----------------------

On every `tools/call` with arguments the SDK validates `Mcp-Param-*` headers
against the tool's input schema, and without this hook it would run the whole
`tools/list` handler (one upstream round trip) to find that schema. The hook
answers from the shared definitions instead. The SDK calls it before
dispatch, so the hook itself checks visibility for the calling token and
answers None for a tool the caller cannot see; otherwise a header-mismatch
error could be used to probe for hidden tools. The proxy never decides
anything from `Mcp-Param-*` headers: the arguments in the body are what is
checked and what is forwarded.

Everything except tools is refused
----------------------------------

Only `tools/list`, `tools/call` and `server/discover` are served.
Resources, prompts, completion, logging and `subscriptions/listen` are not
advertised and answer JSON-RPC -32601 (HTTP 404), whatever the upstream
offers: a grant says nothing about them, so there is no rule to check them
against, and default deny is the only safe reading. In the other direction
the upstream cannot reach the agent: the proxy's upstream client has no
sampling, elicitation or roots callbacks, and upstream notifications are
dropped. An upstream that answers a call with "input required" (a sampling,
elicitation or roots request, or only a request to retry) gets nothing back:
the agent gets an error result and the call is not sent again.
Tool definitions are passed on without `outputSchema`, because a parked or
refused call returns a result that could not satisfy it.

The legacy handshake is refused
-------------------------------

The SDK's HTTP app still serves the pre-2026 `initialize` handshake with
server-side sessions. This proxy answers such requests (no
`MCP-Protocol-Version` header, or a handshake-era version) with HTTP 400 and
JSON-RPC -32022, after authentication. Sessions are state that outlives a
request, they bring a long-lived GET stream and server-to-client requests,
and none of that is needed to list and call tools.

Limits, stated plainly
----------------------

  * The set of tools is fixed when the proxy starts. A tool the upstream adds
    later is not reachable until the proxy is restarted with its name.
  * Tool descriptions and results are passed through as the upstream wrote
    them. The proxy controls which calls happen, not what the text says.
  * Requests refused with HTTP 401 are logged (with a fingerprint, never the
    token) but are not in the audit log, which records decisions on calls.
  * caveat is not an OAuth authorization server. The metadata document
    names the token issuer, but there is no OAuth discovery or client
    registration behind it; tokens come from the gateway's own endpoints.
  * `Gateway.handle_call` is synchronous, so each call occupies a worker
    thread until the upstream answers or `upstream_timeout` passes.
"""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import json
import logging
import os
import re
import sys
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
import httpx2
from mcp import Client, MCPError
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server, ServerRequestContext
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware, get_access_token
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp, StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    CallToolRequestParams,
    CallToolResult,
    Implementation,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT, UNSUPPORTED_PROTOCOL_VERSION
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.authentication import AuthenticationError
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from caveat.approvals import PENDING as APPROVAL_PENDING
from caveat.approvals import ApprovalError, ApprovalQueue
from caveat.audit import AuditLog
from caveat.constraints import glob_match
from caveat.gateway import (
    ALLOWED,
    DENIED,
    ERROR,
    INVALID_TOOL,
    PENDING,
    CallOutcome,
    Gateway,
    bounded,
    loggable_tool,
    token_fingerprint,
)
from caveat.policy import ALLOW, APPROVE, DENY, Policy
from caveat.tokens import Authority, TokenError, Verified

logger = logging.getLogger(__name__)

PROXY_NAME = "caveat-mcp-proxy"
PROXY_VERSION = "0.0.1"
APPROVAL_TOOL = "caveat_approval_status"

DEFAULT_LIST_TTL_MS = 5_000
DEFAULT_UPSTREAM_TIMEOUT = 30.0
DEFAULT_MAX_REQUEST_BYTES = 64 * 1024
MAX_CURSOR_CHARS = 4096
MAX_LIST_PAGES = 100
MAX_ECHOED_NAME_CHARS = 128
MAX_UPSTREAM_MESSAGE_CHARS = 1024
MAX_FAILURE_CHARS = 2048

# The envelope the forwarder hands the gateway (see `_upstream_result`).
OUTCOME_KEY, OK, FAILED = "caveat_upstream", "ok", "failed"

_APPROVAL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_VERIFIED_CLAIM = "caveat.verified"

Upstream = str | Callable[[], Client]
"""Where the real MCP server is: a streamable-HTTP URL, or a function that
returns a new, not yet entered `mcp.Client` (for other transports and tests)."""


class UpstreamError(Exception):
    """The upstream server could not be reached, refused the call or failed it.

    The message is written by the proxy and is safe to show to the agent.
    """


class _AuthUnavailable(AuthenticationError):
    """The token could not be checked because the store or the clock failed."""


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------


def policy_denies_outright(policy: Policy, tool: str) -> bool:
    """True if `policy` denies every possible call to `tool`, judged from rules alone.

    Sound, not complete: True means no call to `tool` can ever be allowed or
    parked. False means "cannot tell without the arguments".
    """
    reachable = False
    for rule in policy.rules:
        if not any(glob_match(pattern, tool) for pattern in rule.tools):
            continue
        if rule.effect == DENY:
            if not rule.when and not rule.unless and not rule.absent:
                return True
        elif rule.effect in (ALLOW, APPROVE):
            reachable = True
    return not reachable


def grant_names(verified: Verified, tool: str, now: float) -> bool:
    """True if the token's unexpired grant has a capability for exactly `tool`."""
    grant = verified.grant
    return now < grant.expires_at and any(cap.tool == tool for cap in grant.capabilities)


def _text_result(
    text: str, *, is_error: bool, structured: dict[str, Any] | None = None
) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        structured_content=structured,
        is_error=is_error,
    )


def _approval_tool() -> Tool:
    return Tool(
        name=APPROVAL_TOOL,
        title="Approval status",
        description=(
            "Check a tool call that caveat parked for human approval. Give the approval id "
            "from the parked call. While a person has not decided, this says so; once they "
            "approve, it returns the result of the original call."
        ),
        input_schema={
            "type": "object",
            "properties": {"approval_id": {"type": "string"}},
            "required": ["approval_id"],
            "additionalProperties": False,
        },
        annotations=ToolAnnotations(read_only_hint=True),
    )


def _public_tool(tool: Tool) -> Tool:
    """The definition passed on to callers. See the module docstring for what is dropped."""
    return Tool(
        name=tool.name,
        title=tool.title,
        description=tool.description,
        input_schema=tool.input_schema,
        annotations=tool.annotations,
    )


def usable_tool_name(name: Any) -> bool:
    """True if an upstream tool of this name can be put behind the gateway."""
    return loggable_tool(name) != INVALID_TOOL and name != APPROVAL_TOOL


# ---------------------------------------------------------------------------
# HTTP layers around the SDK's handler
# ---------------------------------------------------------------------------


class _OneCredential:
    """Refuse a request that carries more than one Authorization header.

    The SDK's bearer backend reads the first one. A request with two is
    ambiguous by construction, and ambiguity about the credential is refused.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            count = sum(1 for key, _ in scope.get("headers", []) if key == b"authorization")
            if count > 1:
                response = JSONResponse(
                    {"error": "invalid_request"},
                    status_code=400,
                    headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class _ModernOnly:
    """Refuse the legacy handshake era. Runs after authentication."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            version = next(
                (v.decode("latin-1") for k, v in scope["headers"] if k == b"mcp-protocol-version"),
                None,
            )
            if version is None or version in HANDSHAKE_PROTOCOL_VERSIONS:
                body = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": UNSUPPORTED_PROTOCOL_VERSION,
                        "message": (
                            "This server only speaks the stateless protocol: send the "
                            "MCP-Protocol-Version header with a supported version. The "
                            "initialize handshake is not served."
                        ),
                        "data": {"supported": list(MODERN_PROTOCOL_VERSIONS)},
                    },
                }
                await JSONResponse(body, status_code=400)(scope, receive, send)
                return
        await self.app(scope, receive, send)


def _auth_unavailable(conn: HTTPConnection, exc: AuthenticationError) -> Response:
    return JSONResponse({"error": "unavailable"}, status_code=503, headers={"Retry-After": "1"})


class _Verifier(TokenVerifier):
    """The SDK's token hook, answered by `Authority.verify`."""

    def __init__(self, authority: Authority, resource_url: str) -> None:
        self._authority = authority
        self._resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            verified = await anyio.to_thread.run_sync(
                self._authority.verify, token, self._resource_url
            )
        except TokenError as exc:
            if exc.code == "unavailable":
                raise _AuthUnavailable("token state is unavailable") from None
            logger.warning("refused bearer token %s: %s", token_fingerprint(token), exc.code)
            return None
        except Exception:  # anything unexpected is a refusal, never a pass
            logger.exception("token verification failed unexpectedly")
            raise _AuthUnavailable("token check failed") from None
        # `expires_at` is left unset on purpose: the SDK would compare it with
        # the system clock, and expiry was just checked against the Authority's
        # own clock, which is the one every other check uses.
        return AccessToken(
            token=token,
            client_id=verified.jti,
            scopes=[],
            resource=self._resource_url,
            subject=verified.sub,
            claims={_VERIFIED_CLAIM: verified},
        )


# ---------------------------------------------------------------------------
# The proxy
# ---------------------------------------------------------------------------


class McpProxy:
    """The proxy: an ASGI app, the `Gateway` behind it and the upstream connection.

    Build one with `create_proxy`. The object is itself an ASGI application;
    `app` is the same thing as a Starlette instance (for mounting more routes).
    """

    def __init__(
        self,
        authority: Authority,
        policy: Policy,
        audit: AuditLog,
        approvals: ApprovalQueue,
        upstream: Upstream,
        *,
        tool_names: Iterable[str],
        resource_url: str,
        authorization_server: str | None = None,
        upstream_headers: Mapping[str, str] | None = None,
        clock: Callable[[], float] = time.time,
        list_ttl_ms: int = DEFAULT_LIST_TTL_MS,
        upstream_timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        allowed_hosts: Iterable[str] = (),
        **gateway_options: Any,
    ) -> None:
        parts = urlsplit(resource_url) if type(resource_url) is str else None
        if parts is None or parts.scheme not in ("http", "https") or not parts.netloc:
            raise ValueError("resource_url must be the proxy's own http(s) URL")
        if parts.path in ("", "/") or parts.query or parts.fragment:
            raise ValueError("resource_url must have a path such as /mcp and no query or fragment")
        if authority.audience != resource_url:
            # RFC 8707: a token is for one resource. Tokens are minted with the
            # Authority's audience, so that audience has to be this proxy.
            raise ValueError(
                "the Authority's audience must equal resource_url, so that only tokens "
                "minted for this proxy are accepted here"
            )
        issuer = authority.issuer if authorization_server is None else authorization_server
        if urlsplit(issuer).scheme not in ("http", "https"):
            raise ValueError(
                "authorization_server must be an http(s) URL (the Authority's issuer is not one)"
            )
        if type(upstream) is not str and not callable(upstream):
            raise ValueError("upstream must be a URL or a function returning an mcp.Client")
        if type(list_ttl_ms) is not int or list_ttl_ms < 0:
            raise ValueError("list_ttl_ms must be a non-negative integer")
        if type(upstream_timeout) not in (int, float) or not upstream_timeout > 0:
            raise ValueError("upstream_timeout must be a positive number of seconds")
        names = list(tool_names)
        bad = [name for name in names if not usable_tool_name(name)]
        if bad:
            raise ValueError(f"tool name {bad[0]!r} cannot be put behind the gateway")

        self.authority = authority
        self.resource_url = resource_url
        self.list_ttl_ms = list_ttl_ms
        self.upstream_timeout = float(upstream_timeout)
        self._upstream = upstream
        self._upstream_headers = dict(upstream_headers or {})
        self._clock = clock
        self._names = frozenset(names)
        self._definitions: dict[str, Tool] = {}
        self._client: Client | None = None
        self._tasks: Any = None  # the task group that holds upstream connections
        self._connecting: asyncio.Lock | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: int | None = None
        self.gateway = Gateway(
            authority,
            policy,
            audit,
            approvals,
            {name: self._forwarder(name) for name in sorted(self._names)},
            clock=clock,
            **gateway_options,
        )

        self._server: Server[None] = Server(
            PROXY_NAME,
            version=PROXY_VERSION,
            instructions=(
                "Tool calls are authorized by caveat. A refused call says why; do not repeat "
                f"it unchanged. A call waiting for human approval is polled with {APPROVAL_TOOL}."
            ),
            lifespan=self._lifespan,
            get_tool_input_schema=self._input_schema,
            on_list_tools=self._list_tools,
            on_call_tool=self._call_tool,
        )
        manager = StreamableHTTPSessionManager(
            app=self._server,
            stateless=True,
            security_settings=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=[parts.netloc, *allowed_hosts],
                allowed_origins=[],
            ),
            max_request_body_size=max_request_bytes,
        )
        resource = AnyHttpUrl(resource_url)
        endpoint = _OneCredential(
            AuthenticationMiddleware(
                AuthContextMiddleware(
                    RequireAuthMiddleware(
                        _ModernOnly(StreamableHTTPASGIApp(manager)),
                        [],
                        build_resource_metadata_url(resource),
                    )
                ),
                backend=BearerAuthBackend(
                    _Verifier(authority, resource_url), resource_server_url=resource
                ),
                on_error=_auth_unavailable,
            )
        )
        self.path = parts.path
        self.app = Starlette(
            routes=[
                Route(parts.path, endpoint=endpoint),
                *create_protected_resource_routes(
                    resource_url=resource,
                    authorization_servers=[AnyHttpUrl(issuer)],
                    resource_name=PROXY_NAME,
                ),
            ],
            lifespan=lambda app: manager.run(),
        )
        self.app.router.redirect_slashes = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)

    # -- for the operator ---------------------------------------------------

    @property
    def tool_names(self) -> tuple[str, ...]:
        """The upstream tools this proxy can forward to, fixed at construction."""
        return tuple(sorted(self._names))

    def set_policy(self, policy: Policy) -> None:
        """Swap the operator policy. Takes effect on the next list or call."""
        self.gateway.set_policy(policy)

    async def resolve_approval(self, approval_id: str, decision: str, approver: str) -> CallOutcome:
        """A person approves or rejects a parked call. See `Gateway.resolve_approval`.

        Runs on a worker thread, because an approved call is forwarded to the
        upstream from inside the gateway and that must not block an event loop.
        """
        return await anyio.to_thread.run_sync(
            self.gateway.resolve_approval, approval_id, decision, approver
        )

    # -- upstream -----------------------------------------------------------

    @asynccontextmanager
    async def _open_upstream(self) -> AsyncIterator[Client]:
        async with AsyncExitStack() as stack:
            if type(self._upstream) is str:
                # The proxy's own identity: only the configured static headers.
                http = await stack.enter_async_context(
                    httpx2.AsyncClient(
                        headers=self._upstream_headers,
                        timeout=httpx2.Timeout(self.upstream_timeout),
                        follow_redirects=False,
                    )
                )
                client = Client(
                    streamable_http_client(self._upstream, http_client=http),
                    cache=None,
                    client_info=Implementation(name=PROXY_NAME, version=PROXY_VERSION),
                    read_timeout_seconds=self.upstream_timeout,
                )
            else:
                client = self._upstream()
                if not isinstance(client, Client):
                    raise TypeError("the upstream factory must return an mcp.Client")
            yield await stack.enter_async_context(client)

    @asynccontextmanager
    async def _lifespan(self, server: Server[None]) -> AsyncIterator[None]:
        self._connecting = asyncio.Lock()
        async with anyio.create_task_group() as tasks:
            self._tasks = tasks
            self._loop = asyncio.get_running_loop()
            self._loop_thread = threading.get_ident()
            try:
                # Startup fails loudly if the upstream cannot be reached or listed.
                await self._connected()
                missing = sorted(self._names - set(self._definitions))
                if missing:
                    logger.warning("the upstream does not list these configured tools: %s", missing)
                yield None
            finally:
                self._tasks = None
                self._loop = None
                self._loop_thread = None
                tasks.cancel_scope.cancel()

    async def _connected(self) -> Client:
        """The live upstream client, reconnecting first if the last one died.

        The SDK's HTTP client ends for good when a request cannot be sent (the
        upstream restarted, the network dropped). It is therefore held by a
        task of its own, so that its failure ends that task and not the proxy,
        and the next request connects again. A call that was in flight when
        the connection died is NOT retried: the proxy cannot know whether the
        upstream ran it, and running a tool twice is worse than reporting an
        error.
        """
        client = self._client
        if client is not None:
            return client
        tasks, lock = self._tasks, self._connecting
        if tasks is None or lock is None:
            raise UpstreamError("the proxy is not running")
        async with lock:
            if self._client is None:
                ready = anyio.Event()
                tasks.start_soon(self._hold_upstream, ready)
                await ready.wait()
            client = self._client
        if client is None:
            raise UpstreamError("the upstream cannot be reached")
        return client

    async def _hold_upstream(self, ready: anyio.Event) -> None:
        """Own one upstream connection for as long as it lives."""
        client: Client | None = None
        try:
            async with self._open_upstream() as client:
                # Listing with this client also teaches it each tool's schema,
                # which is what lets a later call go out as a single request.
                self._definitions.update(await _walk_definitions(client, self._names))
                self._client = client
                ready.set()
                await anyio.sleep_forever()
        except Exception as exc:  # the connection died or never came up
            logger.warning("upstream connection ended: %r", exc)
        finally:
            if client is not None and self._client is client:
                self._client = None
            ready.set()

    def _forwarder(self, name: str) -> Callable[..., Any]:
        """The callable registered in the gateway for one upstream tool."""

        def forward(**arguments: Any) -> Any:
            # An upstream failure is a RESULT the proxy builds, not an
            # exception: the gateway may withhold exception text from callers
            # (`tool_error_detail=False`), and the message below is written by
            # the proxy for the agent. Only an unexpected exception (a bug in
            # the proxy) reaches the gateway as one.
            try:
                return self._on_loop(self._forward(name, arguments))
            except UpstreamError as exc:
                return {OUTCOME_KEY: FAILED, "message": bounded(str(exc), MAX_FAILURE_CHARS)}

        forward.__name__ = f"forward_{name}"
        return forward

    def _on_loop(self, coroutine: Any) -> Any:
        """Run `coroutine` on the proxy's event loop from a worker thread and wait."""
        loop = self._loop
        if loop is None or loop.is_closed():
            coroutine.close()
            raise UpstreamError("the proxy is not running")
        if threading.get_ident() == self._loop_thread:
            coroutine.close()
            raise UpstreamError(
                "a tool was run on the proxy's own event loop; call the gateway from a "
                "worker thread (McpProxy.resolve_approval does)"
            )
        future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        try:
            return future.result(self.upstream_timeout + 5)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise UpstreamError("the upstream did not answer in time") from None

    async def _forward(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """One upstream `tools/call`, with the proxy's identity.

        Returns the success envelope (plain JSON data, see `_upstream_result`);
        raises UpstreamError with a message for the agent on any failure.
        """
        client = await self._connected()
        try:
            with anyio.fail_after(self.upstream_timeout):
                # The session, not `Client.call_tool`: the Client re-sends the
                # call by itself when the upstream answers "input required"
                # (up to 10 more times for a state-only answer) or "header
                # mismatch" (after an extra tools/list). One gateway decision
                # must be at most one upstream tools/call, so neither loop runs.
                result = await client.session.call_tool(
                    name,
                    arguments,
                    read_timeout_seconds=self.upstream_timeout,
                    allow_input_required=True,
                )
        except TimeoutError:
            raise UpstreamError("the upstream did not answer in time") from None
        except MCPError as exc:
            if exc.code == CONNECTION_CLOSED:
                raise UpstreamError("the connection to the upstream failed") from None
            if exc.code == REQUEST_TIMEOUT:
                raise UpstreamError("the upstream did not answer in time") from None
            message = bounded(str(exc.message), MAX_UPSTREAM_MESSAGE_CHARS)
            raise UpstreamError(f"the upstream refused the call ({exc.code}): {message}") from None
        except Exception as exc:
            # Only the type: the text of a transport error can name the
            # upstream's address, which is not the agent's business.
            logger.warning("upstream call to %s failed: %r", name, exc)
            raise UpstreamError(f"the upstream call failed ({type(exc).__name__})") from None
        if not isinstance(result, CallToolResult):
            # Sampling, elicitation, roots or a bare retry request. The agent
            # never sees it and the call is not repeated: answering would let
            # the upstream reach the agent, and retrying would run the tool
            # again on one decision and one charge.
            raise UpstreamError(
                "the upstream asked for more input (sampling, elicitation or a retry), which "
                "the proxy does not forward; the call was not repeated"
            )
        data = result.model_dump(mode="json", by_alias=True, exclude_none=True)
        if result.is_error:
            texts = [block.text for block in result.content if isinstance(block, TextContent)]
            message = bounded(" ".join(texts) or "no message", MAX_UPSTREAM_MESSAGE_CHARS)
            raise UpstreamError(f"the tool reported an error: {message}")
        # Only the payload is kept. The upstream's `_meta` (which carries its
        # server identity) and anything else at the top level stay behind, and
        # so does every `_meta` inside the content blocks (protocol metadata
        # can ride on any block). `structuredContent` is the tool's own data
        # and is passed on as it is.
        kept: dict[str, Any] = {
            OUTCOME_KEY: OK,
            "content": _without_meta(data.get("content", [])),
        }
        if "structuredContent" in data:
            kept["structuredContent"] = data["structuredContent"]
        return kept

    # -- who is calling -----------------------------------------------------

    def _caller(self) -> tuple[str, Verified]:
        """The bearer token of this request and what the auth layer verified it to say."""
        access = get_access_token()
        claims = None if access is None else access.claims
        verified = None if claims is None else claims.get(_VERIFIED_CLAIM)
        if access is None or type(verified) is not Verified:
            # Unreachable behind the HTTP app, where every request is
            # authenticated first; this is the fail-closed answer otherwise.
            raise MCPError(INVALID_REQUEST, "Authentication required")
        return access.token, verified

    def _visible(self, verified: Verified, name: Any) -> bool:
        """The visibility rule of the module docstring, minus "the upstream lists it"."""
        return (
            type(name) is str
            and name in self._names
            and grant_names(verified, name, self._clock())
            and not policy_denies_outright(self.gateway.policy, name)
        )

    def _input_schema(self, name: str) -> Mapping[str, Any] | None:
        """The SDK's `get_tool_input_schema` hook, scoped to the caller."""
        try:
            _, verified = self._caller()
        except MCPError:
            return None
        if name == APPROVAL_TOOL:
            return _approval_tool().input_schema
        definition = self._definitions.get(name) if type(name) is str else None
        if definition is None or not self._visible(verified, name):
            return None
        return definition.input_schema

    # -- tools/list ---------------------------------------------------------

    async def _list_tools(
        self, ctx: ServerRequestContext[None], params: PaginatedRequestParams | None
    ) -> ListToolsResult:
        _, verified = self._caller()
        try:
            client = await self._connected()
        except UpstreamError:
            raise MCPError(INTERNAL_ERROR, "The upstream could not list its tools") from None
        cursor = None if params is None else params.cursor
        if cursor is not None and len(cursor) > MAX_CURSOR_CHARS:
            raise MCPError(INVALID_PARAMS, "Invalid cursor")
        try:
            with anyio.fail_after(self.upstream_timeout):
                page = await client.list_tools(cursor=cursor, cache_mode="bypass")
        except MCPError as exc:
            if cursor is not None and exc.code == INVALID_PARAMS:
                raise MCPError(INVALID_PARAMS, "Invalid cursor") from None
            raise MCPError(INTERNAL_ERROR, "The upstream could not list its tools") from None
        except Exception as exc:
            logger.warning("upstream tools/list failed: %r", exc)
            raise MCPError(INTERNAL_ERROR, "The upstream could not list its tools") from None

        tools: list[Tool] = [] if cursor is not None else [_approval_tool()]
        seen: set[str] = set()
        for tool in page.tools:
            if tool.name in seen or tool.name not in self._names:
                continue
            seen.add(tool.name)
            public = _public_tool(tool)
            self._definitions[tool.name] = public  # unfiltered and shared: not per caller
            if self._visible(verified, tool.name):
                tools.append(public)
        return ListToolsResult(
            tools=tools,
            next_cursor=page.next_cursor,
            ttl_ms=self.list_ttl_ms,
            cache_scope="private",
        )

    # -- tools/call ---------------------------------------------------------

    async def _call_tool(
        self, ctx: ServerRequestContext[None], params: CallToolRequestParams
    ) -> CallToolResult:
        token, verified = self._caller()
        name = params.name
        arguments = {} if params.arguments is None else params.arguments
        if name == APPROVAL_TOOL:
            return await self._approval_status(token, arguments)
        visible = self._visible(verified, name)
        outcome = await anyio.to_thread.run_sync(self.gateway.handle_call, token, name, arguments)
        return self._to_mcp(outcome, name, visible)

    def _to_mcp(self, outcome: CallOutcome, name: str, visible: bool) -> CallToolResult:
        """The outcome table of the module docstring."""
        if outcome.status == ALLOWED:
            return _upstream_result(outcome.result, "The call was authorized and sent")
        if outcome.status == PENDING:
            return _text_result(
                "This call has NOT run. Operator policy requires a person to approve it "
                f"(rule {outcome.rule}: {outcome.reason.rstrip('.')}). "
                f"Approval id: {outcome.approval_id}. "
                f"Call {APPROVAL_TOOL} with that approval_id to see the decision and collect "
                "the result. Do not repeat the original call.",
                is_error=False,
                structured={
                    "caveat": "pending_approval",
                    "approval_id": outcome.approval_id,
                    "rule": outcome.rule,
                    "poll_with": APPROVAL_TOOL,
                },
            )
        if outcome.status == ERROR:
            # The gateway's own error (timeout, output over the limit, a
            # proxy bug), in whatever detail the gateway chose to give.
            reason = bounded(outcome.reason, MAX_FAILURE_CHARS)
            return _text_result(
                f"The call was authorized and sent, but it failed: {reason}",
                is_error=True,
                structured={"caveat": "error", "reason": reason},
            )
        if outcome.status != DENIED:  # no such status exists; refuse rather than guess
            raise MCPError(INTERNAL_ERROR, "Unexpected gateway outcome")
        if not visible:
            shown = name if type(name) is str else ""
            raise MCPError(INVALID_PARAMS, f"Unknown tool: {shown[:MAX_ECHOED_NAME_CHARS]}")
        if outcome.stage == "token":
            raise MCPError(INVALID_REQUEST, "The access token is no longer valid")
        if outcome.stage in ("unavailable", "audit"):
            raise MCPError(INTERNAL_ERROR, "caveat could not authorize the call; nothing was run")
        # A policy refusal is identified by its rule id; any other refusal by
        # the gateway's code (a capability decision code, "budget_exhausted",
        # "in_flight_limit"), when it gave one.
        if outcome.rule:
            which = f" (policy rule {outcome.rule})"
        elif outcome.code:
            which = f" ({outcome.code})"
        else:
            which = ""
        return _text_result(
            f"Denied by caveat at the {outcome.stage} check{which}: "
            f"{outcome.reason.rstrip('.')}. "
            "The call did not run. Repeating it unchanged will be denied again.",
            is_error=True,
            structured={
                "caveat": "denied",
                "stage": outcome.stage,
                "reason": outcome.reason,
                "rule": outcome.rule,
                "code": outcome.code or None,
            },
        )

    async def _approval_status(self, token: str, arguments: Mapping[str, Any]) -> CallToolResult:
        approval_id = arguments.get("approval_id")
        if (
            set(arguments) != {"approval_id"}
            or type(approval_id) is not str
            or not _APPROVAL_ID.fullmatch(approval_id)
        ):
            return _text_result(
                f"{APPROVAL_TOOL} takes exactly one argument, approval_id (a string).",
                is_error=True,
            )
        try:
            record = await anyio.to_thread.run_sync(self.gateway.get_approval, approval_id, token)
        except TokenError as exc:
            if exc.code == "unavailable":
                raise MCPError(INTERNAL_ERROR, "caveat could not check the token") from None
            raise MCPError(INVALID_REQUEST, "The access token is no longer valid") from None
        except ApprovalError:
            # One answer for "no such id" and "not yours".
            return _text_result(
                "No approval with that id belongs to this token.",
                is_error=True,
                structured={"caveat": "approval_not_found"},
            )
        outcome = record.outcome
        if record.state == APPROVAL_PENDING:
            return _text_result(
                "Still waiting for a person to decide. The call has not run. Check again later.",
                is_error=False,
                structured={"caveat": "pending_approval", "approval_id": record.id},
            )
        if type(outcome) is CallOutcome and outcome.status == ALLOWED:
            return _upstream_result(outcome.result, "The call was approved and sent")
        if type(outcome) is CallOutcome and outcome.status == ERROR:
            reason = bounded(outcome.reason, MAX_FAILURE_CHARS)
            return _text_result(
                f"The call was approved and sent, but it failed: {reason}",
                is_error=True,
                structured={"caveat": "error", "state": record.state, "reason": reason},
            )
        reason = outcome.reason if type(outcome) is CallOutcome else record.state
        return _text_result(
            f"The call did not run. Approval state: {record.state} ({reason}).",
            is_error=True,
            structured={"caveat": "denied", "state": record.state, "reason": reason},
        )


def _without_meta(value: Any) -> Any:
    """A copy of plain JSON data with every `_meta` member removed, at any depth."""
    if type(value) is dict:
        return {k: _without_meta(v) for k, v in value.items() if k != "_meta"}
    if type(value) is list:
        return [_without_meta(v) for v in value]
    return value


def _upstream_result(data: Any, sent: str) -> CallToolResult:
    """Rebuild what the forwarder returned. Never carries upstream `_meta`.

    The forwarder returns one of two envelopes, both built by the proxy (the
    upstream's data only ever sits inside `content` and `structuredContent`):

        {"caveat_upstream": "ok", "content": [...], "structuredContent": ...}
        {"caveat_upstream": "failed", "message": "<bounded text by the proxy>"}

    Anything else is withheld. `sent` starts the sentence for a failure.
    """
    try:
        if type(data) is not dict:
            raise ValueError("unexpected shape")
        if data.get(OUTCOME_KEY) == FAILED and set(data) == {OUTCOME_KEY, "message"}:
            message = data["message"]
            if type(message) is not str:
                raise ValueError("unexpected shape")
            reason = bounded(message, MAX_FAILURE_CHARS)
            return _text_result(
                f"{sent}, but it failed: {reason}",
                is_error=True,
                structured={"caveat": "error", "reason": reason},
            )
        if data.get(OUTCOME_KEY) != OK or set(data) - {OUTCOME_KEY, "content", "structuredContent"}:
            raise ValueError("unexpected shape")
        return CallToolResult(
            content=CallToolResult.model_validate({"content": data["content"]}).content,
            structured_content=data.get("structuredContent"),
            is_error=False,
        )
    except Exception:
        return _text_result(
            "The upstream returned a result the proxy could not read; it was withheld.",
            is_error=True,
        )


async def _walk_definitions(client: Client, names: frozenset[str] | None) -> dict[str, Tool]:
    """Every page of the upstream's tool list, as public definitions keyed by name.

    With `names` given, only those are kept; otherwise every usable name is.
    The first definition of a duplicated name wins.
    """
    found: dict[str, Tool] = {}
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(MAX_LIST_PAGES):
        page = await client.list_tools(cursor=cursor, cache_mode="bypass")
        for tool in page.tools:
            wanted = usable_tool_name(tool.name) if names is None else tool.name in names
            if wanted and tool.name not in found:
                found[tool.name] = _public_tool(tool)
        cursor = page.next_cursor
        if cursor is None:
            return found
        if cursor in seen_cursors:
            raise UpstreamError("the upstream's tool list repeats a cursor")
        seen_cursors.add(cursor)
    raise UpstreamError(f"the upstream's tool list did not end within {MAX_LIST_PAGES} pages")


async def discover_tool_names(
    upstream: Upstream, *, upstream_headers: Mapping[str, str] | None = None
) -> list[str]:
    """Ask the upstream which tools it has: the names `create_proxy` can be given.

    Names the gateway cannot carry (outside [A-Za-z0-9_.:/-]{1,128}, or the
    reserved approval-status name) are left out and logged.
    """
    async with AsyncExitStack() as stack:
        if type(upstream) is str:
            http = await stack.enter_async_context(
                httpx2.AsyncClient(headers=dict(upstream_headers or {}), follow_redirects=False)
            )
            client = Client(streamable_http_client(upstream, http_client=http), cache=None)
        else:
            client = upstream()
        await stack.enter_async_context(client)
        skipped: list[str] = []
        cursor: str | None = None
        names: list[str] = []
        for _ in range(MAX_LIST_PAGES):
            page = await client.list_tools(cursor=cursor, cache_mode="bypass")
            for tool in page.tools:
                if not usable_tool_name(tool.name):
                    skipped.append(tool.name)
                elif tool.name not in names:
                    names.append(tool.name)
            cursor = page.next_cursor
            if cursor is None:
                break
        else:
            raise UpstreamError(f"the upstream's tool list did not end in {MAX_LIST_PAGES} pages")
        if skipped:
            logger.warning("upstream tools with unusable names are not exposed: %r", skipped[:20])
        return sorted(names)


def create_proxy(
    authority: Authority,
    policy: Policy,
    audit: AuditLog,
    approvals: ApprovalQueue,
    upstream: Upstream,
    *,
    tool_names: Iterable[str],
    resource_url: str,
    authorization_server: str | None = None,
    upstream_headers: Mapping[str, str] | None = None,
    clock: Callable[[], float] = time.time,
    list_ttl_ms: int = DEFAULT_LIST_TTL_MS,
    upstream_timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    allowed_hosts: Iterable[str] = (),
    **gateway_options: Any,
) -> McpProxy:
    """Build the proxy: an ASGI app in front of `upstream`.

    authority, policy, audit, approvals
        The parts of a `Gateway`. The proxy builds the Gateway itself, with
        one registered tool per name in `tool_names` that forwards to the
        upstream. `proxy.gateway` is that Gateway.
    upstream
        The real MCP server: a streamable-HTTP URL, or a function returning a
        new `mcp.Client`. It is connected when the app starts (ASGI lifespan).
    tool_names
        The upstream tools the proxy may forward to (`discover_tool_names`
        lists what an upstream has). Fixed for the life of the proxy.
    resource_url
        The public URL of this proxy's MCP endpoint, for example
        https://tools.example/mcp. It is the token audience, the RFC 9728
        resource, and its path is where the endpoint is served.
    authorization_server
        URL named in the protected-resource metadata. Defaults to the
        Authority's issuer, which must then be an http(s) URL.
    upstream_headers
        Static headers sent upstream with every request: the proxy's own
        credential, if the upstream wants one. Used only with a URL upstream.
    allowed_hosts
        Extra values accepted in the Host header, besides resource_url's own.
    gateway_options
        Passed to `Gateway` (max_output_bytes, max_error_chars).
    """
    return McpProxy(
        authority,
        policy,
        audit,
        approvals,
        upstream,
        tool_names=tool_names,
        resource_url=resource_url,
        authorization_server=authorization_server,
        upstream_headers=upstream_headers,
        clock=clock,
        list_ttl_ms=list_ttl_ms,
        upstream_timeout=upstream_timeout,
        max_request_bytes=max_request_bytes,
        allowed_hosts=allowed_hosts,
        **gateway_options,
    )


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Run the proxy from a gateway config file.

    The config is the one `caveat.server` reads. Its `audience` must be the
    proxy's public MCP URL, and its `tools` section is ignored: the tools are
    the upstream's. The admin API (approvals, revocation, minting, audit
    verification) is served under /admin on the same port, backed by the same
    Gateway, so a person can approve a parked call.
    """
    from caveat.server import ConfigError, build, create_app, load_config

    parser = argparse.ArgumentParser(prog="python -m caveat.mcp_proxy")
    parser.add_argument("--config", default="config/gateway.example.yaml")
    parser.add_argument("--upstream", required=True, help="URL of the upstream MCP endpoint")
    parser.add_argument(
        "--upstream-auth-env",
        default="CAVEAT_UPSTREAM_AUTHORIZATION",
        help="environment variable holding the Authorization header value the PROXY sends "
        "upstream (its own credential); unset means none",
    )
    parser.add_argument(
        "--tools",
        default="",
        help="comma-separated upstream tool names to expose; default: all the upstream lists now",
    )
    options = parser.parse_args(argv)
    config_path = Path(options.config).resolve()
    headers: dict[str, str] = {}
    credential = os.environ.get(options.upstream_auth_env, "")
    if credential:
        headers["Authorization"] = credential
    try:
        config = dict(load_config(config_path))
        config["tools"] = {}
        _, base, settings = build(config, os.environ, config_path.parent)
        admin_hash = os.environ[config["admin_key_hash_env"]].strip()
    except ConfigError as exc:
        print(f"caveat: cannot start: {exc}", file=sys.stderr)
        return 2
    try:
        names = [n for n in options.tools.split(",") if n] or asyncio.run(
            discover_tool_names(options.upstream, upstream_headers=headers)
        )
        proxy = create_proxy(
            base.authority,
            base.policy,
            base.audit,
            base.approvals,
            options.upstream,
            tool_names=names,
            resource_url=config["audience"],
            upstream_headers=headers,
            max_output_bytes=base.max_output_bytes,
        )
    except Exception as exc:
        print(f"caveat: cannot start: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    proxy.app.mount("/admin", create_app(proxy.gateway, admin_hash))
    print(
        f"caveat: proxying {len(names)} tools at {proxy.resource_url}: {json.dumps(names)}",
        file=sys.stderr,
    )
    import uvicorn

    uvicorn.run(
        proxy.app,
        host=settings["host"],
        port=settings["port"],
        server_header=False,
        proxy_headers=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
