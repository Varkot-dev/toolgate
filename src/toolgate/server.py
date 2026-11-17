"""HTTP front of the gateway: a thin FastAPI layer over `toolgate.gateway.Gateway`.

Every decision is made by `Gateway`; this module only authenticates the
caller, parses the request strictly and turns a `CallOutcome` into a status
code.

    POST /token            admin   mint a root token
    POST /token/exchange   bearer  parent token -> narrower child token
    POST /token/revoke     admin   revoke a token id (and its descendants)
    POST /call             bearer  make a tool call
    GET  /approvals        admin   pending approvals, WITH arguments
    POST /approvals/{id}   admin   approve or reject
    GET  /approvals/{id}   bearer  status and result, for the creating token
    GET  /audit/verify     admin   replay the audit log's hash chain
    GET  /audit/head       admin   seq and hash of the last entry
    GET  /healthz          none

Two kinds of credential, never mixed up. Both travel as
`Authorization: Bearer <value>`, but an admin endpoint only ever hashes the
value and compares it with the stored SHA-256 of the admin key (constant
time), and an agent endpoint only ever verifies it as a signed token. A token
on an admin endpoint is a wrong key; the admin key on an agent endpoint is
refused before it reaches the token verifier or the audit log.

Strictness at the boundary:

  * exactly one Authorization header, scheme "Bearer" (any letter case, as
    RFC 9110 requires), one space, no other whitespace
  * request bodies are read with a hard size limit before anything parses them
  * bodies must be `application/json`, valid UTF-8, with no duplicate keys,
    no NaN or Infinity, and a bounded nesting depth
  * unknown fields are refused (Pydantic `extra="forbid"`, strict types)
  * query strings are refused: no endpoint takes one
  * no CORS headers are ever sent, and the interactive docs are off by default
  * tokens, keys and request bodies never appear in error bodies

Endpoints that touch the store, the audit file or a tool are plain `def`
functions, which FastAPI runs on a worker thread, so nothing blocks the event
loop. Only header checks and JSON parsing of an already bounded body run on
the loop.

GET /approvals is the one place call arguments are shown, and only to the
operator: a person cannot approve what they cannot see. Everywhere else the
arguments exist only as a hash.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import importlib
import json
import math
import os
import re
import sys
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from toolgate.approvals import PENDING, Approval, ApprovalError, ApprovalQueue, valid_name
from toolgate.audit import AuditLog, verify
from toolgate.capability import Capability, Grant
from toolgate.gateway import (
    ALLOWED,
    ERROR,
    CallOutcome,
    Gateway,
    bounded,
    plain_args,
)
from toolgate.gateway import PENDING as CALL_PENDING
from toolgate.policy import Policy
from toolgate.store import MemoryStore, SqliteStore
from toolgate.tokens import Authority, EscalationError, TokenError

DEFAULT_MAX_BODY_BYTES = 64 * 1024
MAX_JSON_DEPTH = 64
MAX_EXPIRES_IN = 366 * 24 * 3600  # sanity bound; the authority's max_ttl is the real cap
_HEX64 = re.compile(r"[0-9a-f]{64}")
# RFC 6750 token68 characters. No whitespace, no commas, no control characters.
_BEARER = re.compile(r"[Bb][Ee][Aa][Rr][Ee][Rr] ([A-Za-z0-9._~+/=-]{1,65536})")
_APPROVAL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_JSON_TYPE = re.compile(r"application/json(\s*;\s*charset=utf-8)?", re.IGNORECASE)


class ApiError(Exception):
    """An error response. `reason` must never contain a credential."""

    def __init__(
        self,
        status: int,
        error: str,
        reason: str = "",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.reason = reason
        self.headers = dict(headers or {})

    def response(self) -> JSONResponse:
        body = {"error": self.error}
        if self.reason:
            body["reason"] = self.reason
        return JSONResponse(body, status_code=self.status, headers=self.headers)


def _unauthorized(error: str = "", description: str = "") -> ApiError:
    """401 with the challenge RFC 6750 asks for. `description` is a fixed code."""
    challenge = 'Bearer realm="toolgate"'
    if error:
        challenge += f', error="{error}"'
    if description:
        challenge += f', error_description="{description}"'
    return ApiError(401, "unauthorized", description or "", headers={"WWW-Authenticate": challenge})


# ---------------------------------------------------------------------------
# Strict JSON
# ---------------------------------------------------------------------------


def _unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError("NaN and Infinity are not JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("number out of range")
    return value


def _too_deep(raw: bytes) -> bool:
    """True if brackets nest deeper than MAX_JSON_DEPTH. Brackets inside strings count
    too, which only errs toward refusing."""
    depth = 0
    for byte in raw:
        if byte in (0x5B, 0x7B):  # [ {
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return True
        elif byte in (0x5D, 0x7D):  # ] }
            depth -= 1
    return False


def strict_json(raw: bytes) -> Any:
    """Parse a request body. Raises ApiError(400) for anything questionable."""
    if _too_deep(raw):
        raise ApiError(400, "invalid_json", "nested too deeply")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_keys,
            parse_constant=_no_constant,
            parse_float=_finite_float,
        )
    except UnicodeDecodeError:
        raise ApiError(400, "invalid_json", "body is not UTF-8") from None
    except RecursionError:
        raise ApiError(400, "invalid_json", "nested too deeply") from None
    except ValueError as exc:
        known = ("duplicate key", "NaN and Infinity are not JSON", "number out of range")
        reason = str(exc) if str(exc) in known else "body is not valid JSON"
        raise ApiError(400, "invalid_json", reason) from None


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _name(value: str) -> str:
    if not valid_name(value):
        raise ValueError("must be 1 to 256 printable characters with no surrounding whitespace")
    return value


class TokenRequest(_Model):
    sub: str
    actor: str
    capabilities: list[dict[str, Any]] = Field(max_length=256)
    expires_in: int | float = Field(gt=0, le=MAX_EXPIRES_IN, allow_inf_nan=False)

    _names = field_validator("sub", "actor")(_name)


class ExchangeRequest(_Model):
    capabilities: list[dict[str, Any]] = Field(max_length=256)
    actor: str
    expires_in: int | float = Field(gt=0, le=MAX_EXPIRES_IN, allow_inf_nan=False)

    _names = field_validator("actor")(_name)


class RevokeRequest(_Model):
    jti: str = Field(min_length=1, max_length=256)


class CallRequest(_Model):
    tool: str = Field(min_length=1, max_length=128)
    args: dict[str, Any] = Field(default_factory=dict)


class ResolveRequest(_Model):
    decision: Literal["approve", "reject"]
    approver: str

    _names = field_validator("approver")(_name)


def _body(model: type[_Model]) -> Callable[[Request], Awaitable[Any]]:
    """Dependency: the request body, strictly parsed and validated as `model`."""

    async def read(request: Request) -> Any:
        data = strict_json(await request.body())
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            # Field names and messages only; never the submitted values.
            problems = [
                f"{bounded('.'.join(str(p) for p in e['loc']), 80) or 'body'}: {e['msg']}"
                for e in exc.errors(include_input=False, include_url=False)[:5]
            ]
            raise ApiError(422, "invalid_request", "; ".join(problems)) from None

    return read


# ---------------------------------------------------------------------------
# Body size limit and request shape, before FastAPI sees anything
# ---------------------------------------------------------------------------


class _Guard:
    """ASGI middleware: no query strings, JSON only, and a hard body size limit.

    The body is read here, counted as it arrives, and replayed to the app, so
    the limit holds for chunked uploads that declare no Content-Length too.
    """

    def __init__(self, app: Any, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                await self.app(scope, receive, send)
            return  # websockets and anything else: not served
        error = self._check(scope)
        body = b""
        if error is None and scope["method"] in ("POST", "PUT", "PATCH"):
            more = True
            while more:
                message = await receive()
                if message["type"] != "http.request":
                    return  # client went away
                body += message.get("body", b"")
                more = message.get("more_body", False)
                if len(body) > self.max_body_bytes:
                    error = ApiError(413, "body_too_large")
                    break
        if error is not None:
            await error.response()(scope, receive, send)
            return

        sent = False

        async def replay() -> Any:
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    def _check(self, scope: Any) -> ApiError | None:
        if scope.get("query_string"):
            return ApiError(400, "invalid_request", "query strings are not accepted")
        if scope["method"] not in ("POST", "PUT", "PATCH"):
            return None
        headers = scope.get("headers", [])
        types = [v for k, v in headers if k == b"content-type"]
        if len(types) != 1 or not _JSON_TYPE.fullmatch(types[0].decode("latin-1").strip()):
            return ApiError(415, "unsupported_media_type", "send application/json")
        if any(k == b"content-encoding" for k, _ in headers):
            return ApiError(415, "unsupported_media_type", "compressed bodies are not accepted")
        lengths = [v for k, v in headers if k == b"content-length"]
        if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
            return ApiError(400, "invalid_request", "bad Content-Length")
        if lengths and int(lengths[0]) > self.max_body_bytes:
            return ApiError(413, "body_too_large")
        return None


# ---------------------------------------------------------------------------
# The app
# ---------------------------------------------------------------------------


def hash_admin_key(key: str) -> str:
    """SHA-256 (hex) of an admin key: the value `create_app` is given.

    A plain hash is only safe for a long random key (32 random bytes or
    more). It is not a password hash and must not be used for one.
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _outcome_body(outcome: CallOutcome, *, with_result: bool = True) -> dict[str, Any]:
    body: dict[str, Any] = {"status": outcome.status, "reason": outcome.reason}
    if outcome.stage:
        body["stage"] = outcome.stage
    if outcome.rule is not None:
        body["rule"] = outcome.rule
    if outcome.approval_id is not None:
        body["approval_id"] = outcome.approval_id
    if outcome.audit_seq is not None:
        body["audit_seq"] = outcome.audit_seq
    if with_result and outcome.status == ALLOWED:
        body["result"] = outcome.result
    return body


def _token_error(exc: TokenError) -> ApiError:
    if exc.code == "unavailable":
        return ApiError(503, "unavailable", "token state is unavailable")
    return _unauthorized("invalid_token", exc.code)


def _issuing_error(exc: TokenError) -> ApiError:
    """A TokenError from mint or exchange. Not every one is about the credential."""
    if isinstance(exc, ValueError):  # the request was too large to consider
        return ApiError(422, "invalid_request", bounded(exc.detail or exc.code, 200))
    if exc.code in ("depth_exceeded", "too_many_children"):
        # The parent token is valid; it has simply run out of delegation.
        return ApiError(403, exc.code, bounded(exc.detail, 200))
    return _token_error(exc)


def create_app(
    gateway: Gateway,
    admin_key_hash: str,
    *,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    docs: bool = False,
) -> FastAPI:
    """Build the HTTP app around a gateway.

    `admin_key_hash` is the lowercase hex SHA-256 of the admin key (see
    `hash_admin_key`); the key itself is never held by the server.
    """
    if type(admin_key_hash) is not str or not _HEX64.fullmatch(admin_key_hash):
        raise ValueError("admin_key_hash must be 64 lowercase hex characters (a SHA-256)")
    if type(max_body_bytes) is not int or max_body_bytes < 1:
        raise ValueError("max_body_bytes must be a positive integer")
    stored = admin_key_hash.encode("ascii")
    authority = gateway.authority

    app = FastAPI(
        title="toolgate",
        redirect_slashes=False,
        docs_url="/docs" if docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.add_middleware(_Guard, max_body_bytes=max_body_bytes)

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return exc.response()

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"error": "internal"}, status_code=500)

    # -- who is calling -----------------------------------------------------

    def is_admin_key(value: str) -> bool:
        presented = hashlib.sha256(value.encode("utf-8")).hexdigest().encode("ascii")
        return hmac.compare_digest(presented, stored)

    def credential(request: Request) -> str:
        values = request.headers.getlist("authorization")
        if len(values) != 1:
            raise _unauthorized()
        match = _BEARER.fullmatch(values[0])
        if match is None:
            raise _unauthorized()
        return match.group(1)

    async def admin(request: Request) -> None:
        if not is_admin_key(credential(request)):
            raise _unauthorized("invalid_token")

    async def bearer(request: Request) -> str:
        value = credential(request)
        if is_admin_key(value):
            # The admin key is not an agent credential. Stop here, so it is
            # never handed to the token verifier or fingerprinted in the log.
            raise _unauthorized("invalid_token")
        return value

    Admin = Depends(admin)
    Bearer = Annotated[str, Depends(bearer)]

    def issued(token: str) -> dict[str, Any]:
        verified = authority.verify(token)
        return {"token": token, "jti": verified.jti, "expires_at": verified.exp}

    # -- tokens -------------------------------------------------------------

    @app.post("/token", dependencies=[Admin])
    def mint(body: Annotated[TokenRequest, Depends(_body(TokenRequest))]) -> dict[str, Any]:
        try:
            capabilities = tuple(Capability.from_dict(c) for c in body.capabilities)
            grant = Grant(capabilities, gateway.now() + body.expires_in)
            return issued(authority.mint(body.sub, grant, body.actor, body.expires_in))
        except TokenError as exc:
            raise _issuing_error(exc) from None
        except (ValueError, TypeError) as exc:
            raise ApiError(422, "invalid_request", bounded(str(exc), 200)) from None

    @app.post("/token/exchange")
    def exchange(
        parent: Bearer, body: Annotated[ExchangeRequest, Depends(_body(ExchangeRequest))]
    ) -> dict[str, Any]:
        try:
            return issued(
                authority.exchange(parent, body.capabilities, body.actor, body.expires_in)
            )
        except TokenError as exc:
            raise _issuing_error(exc) from None
        except EscalationError as exc:
            raise ApiError(403, "escalation", bounded(exc.reason, 200)) from None
        except (ValueError, TypeError) as exc:
            raise ApiError(422, "invalid_request", bounded(str(exc), 200)) from None

    @app.post("/token/revoke", dependencies=[Admin])
    def revoke(body: Annotated[RevokeRequest, Depends(_body(RevokeRequest))]) -> dict[str, Any]:
        try:
            authority.revoke(body.jti)
        except TokenError as exc:
            raise _token_error(exc) from None
        except ValueError as exc:
            raise ApiError(422, "invalid_request", bounded(str(exc), 200)) from None
        return {"revoked": body.jti}

    # -- calls --------------------------------------------------------------

    @app.post("/call")
    def call(
        token: Bearer, body: Annotated[CallRequest, Depends(_body(CallRequest))]
    ) -> JSONResponse:
        outcome = gateway.handle_call(token, body.tool, body.args)
        content = _outcome_body(outcome)
        if outcome.status == ALLOWED:
            return JSONResponse(content, status_code=200)
        if outcome.status == CALL_PENDING:
            return JSONResponse(content, status_code=202)
        if outcome.status == ERROR:
            return JSONResponse(content, status_code=502)
        if outcome.stage == "token":
            challenge = _unauthorized("invalid_token", outcome.reason)
            return JSONResponse(content, status_code=401, headers=challenge.headers)
        if outcome.stage in ("unavailable", "audit"):
            return JSONResponse(content, status_code=503)
        return JSONResponse(content, status_code=403)

    # -- approvals ----------------------------------------------------------

    def approval_id_or_404(approval_id: str) -> str:
        if not _APPROVAL_ID.fullmatch(approval_id):
            raise ApiError(404, "not_found")
        return approval_id

    def approval_error(exc: ApprovalError) -> ApiError:
        status = {"not_found": 404, "not_pending": 409, "expired": 410}.get(exc.code, 409)
        return ApiError(status, exc.code, exc.detail)

    @app.get("/approvals", dependencies=[Admin])
    def list_approvals() -> dict[str, Any]:
        now = gateway.now()

        def row(record: Approval) -> dict[str, Any]:
            return {
                "id": record.id,
                "tool": record.call.tool,
                "sub": record.sub,
                "actors": list(record.actors),
                "jti": record.jti,
                "args_hash": record.args_hash,
                "args": plain_args(record.call.args),
                "rule": record.rule,
                "reason": record.reason,
                "age_seconds": max(0, now - record.created_at),
                "expires_in_seconds": max(0, record.expires_at - now),
            }

        return {"pending": [row(r) for r in gateway.list_pending()]}

    @app.post("/approvals/{approval_id}", dependencies=[Admin])
    def resolve(
        approval_id: str, body: Annotated[ResolveRequest, Depends(_body(ResolveRequest))]
    ) -> dict[str, Any]:
        approval_id = approval_id_or_404(approval_id)
        try:
            outcome = gateway.resolve_approval(approval_id, body.decision, body.approver)
        except ApprovalError as exc:
            raise approval_error(exc) from None
        except ValueError as exc:
            raise ApiError(422, "invalid_request", bounded(str(exc), 200)) from None
        record = gateway.approvals.get(approval_id)
        content = _outcome_body(outcome, with_result=False)
        content["state"] = record.state if record is not None else body.decision
        return content

    @app.get("/approvals/{approval_id}")
    def read_approval(approval_id: str, token: Bearer) -> dict[str, Any]:
        approval_id = approval_id_or_404(approval_id)
        try:
            record = gateway.get_approval(approval_id, token)
        except TokenError as exc:
            raise _token_error(exc) from None
        except ApprovalError as exc:
            raise approval_error(exc) from None
        content: dict[str, Any] = {
            "id": record.id,
            "state": record.state,
            "tool": record.call.tool,
            "args_hash": record.args_hash,
            "rule": record.rule,
        }
        if record.state != PENDING and type(record.outcome) is CallOutcome:
            content["outcome"] = _outcome_body(record.outcome)
            content["outcome"].pop("approval_id", None)
        return content

    # -- audit --------------------------------------------------------------

    @app.get("/audit/head", dependencies=[Admin])
    def audit_head() -> dict[str, Any]:
        head = gateway.audit.head()
        return {"seq": head.seq, "hash": head.hash}

    @app.get("/audit/verify", dependencies=[Admin])
    def audit_verify() -> dict[str, Any]:
        # Verify against the head this process holds in memory, which also
        # catches a file truncated or rebuilt behind the gateway's back. If
        # entries were appended while the file was being read, read it again.
        for _ in range(3):
            head = gateway.audit.head()
            result = verify(gateway.audit.path, head)
            if result.ok or gateway.audit.head() == head:
                break
        else:
            result = verify(gateway.audit.path)
            head = gateway.audit.head()
        return {
            "ok": result.ok,
            "entries": result.entries,
            "first_bad_index": result.first_bad_index,
            "problem": result.problem,
            "head": {"seq": head.seq, "hash": head.hash},
        }

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# Configuration and the command line
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """The gateway configuration cannot be used."""


_CONFIG_KEYS = {
    "issuer",
    "audience",
    "signing_key_env",
    "admin_key_hash_env",
    "policy_file",
    "audit_log",
    "store",
    "tokens",
    "approvals",
    "limits",
    "server",
    "tools",
}


def echo(**arguments: Any) -> dict[str, Any]:
    """Example tool: returns its arguments. Only for trying the gateway out."""
    return {"echo": arguments}


def _section(config: Mapping[str, Any], name: str, allowed: set[str]) -> dict[str, Any]:
    value = config.get(name, {})
    if type(value) is not dict:
        raise ConfigError(f"`{name}` must be a mapping")
    unknown = sorted(str(k) for k in set(value) - allowed)
    if unknown:
        raise ConfigError(f"`{name}`: unknown key {unknown[0]!r}")
    return value


def _env(config: Mapping[str, Any], key: str, environ: Mapping[str, str]) -> str:
    name = config.get(key)
    if type(name) is not str or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
        raise ConfigError(f"`{key}` must name an environment variable (the secret is not in files)")
    value = environ.get(name, "")
    if not value:
        raise ConfigError(f"environment variable {name} is not set")
    return value


def _load_tool(spec: Any) -> Callable[..., Any]:
    if type(spec) is not str or spec.count(":") != 1:
        raise ConfigError("a tool is written as 'package.module:function'")
    module_name, attribute = spec.split(":")
    try:
        function = getattr(importlib.import_module(module_name), attribute)
    except (ImportError, AttributeError) as exc:
        raise ConfigError(f"cannot load tool {spec!r}: {type(exc).__name__}") from None
    if not callable(function):
        raise ConfigError(f"tool {spec!r} is not callable")
    return function


def load_config(path: str | Path) -> dict[str, Any]:
    """Read and shape-check a gateway config file. No secrets are read here."""
    try:
        with open(path, "rb") as handle:
            config = yaml.safe_load(handle.read(1_000_001).decode("utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read config: {type(exc).__name__}") from None
    if type(config) is not dict:
        raise ConfigError("config must be a mapping")
    unknown = sorted(str(k) for k in set(config) - _CONFIG_KEYS)
    if unknown:
        raise ConfigError(f"unknown key {unknown[0]!r}")
    return config


def build(
    config: Mapping[str, Any], environ: Mapping[str, str], base: Path
) -> tuple[FastAPI, Gateway, dict[str, Any]]:
    """Assemble store, authority, policy, audit log, queue, gateway and app.

    Relative paths in the config are resolved against `base` (the config
    file's directory). Returns (app, gateway, server settings).
    """
    try:
        seed = base64.b64decode(_env(config, "signing_key_env", environ), validate=True)
    except (binascii.Error, ValueError):
        raise ConfigError("the signing key must be base64 of 32 bytes") from None
    if len(seed) != 32:
        raise ConfigError("the signing key must be base64 of 32 bytes")
    admin_hash = _env(config, "admin_key_hash_env", environ).strip()
    if not _HEX64.fullmatch(admin_hash):
        raise ConfigError("the admin key hash must be 64 lowercase hex characters")

    def path(key: str) -> Path:
        value = config.get(key)
        if type(value) is not str or not value:
            raise ConfigError(f"`{key}` must be a file path")
        return (base / value).resolve()

    store_cfg = _section(config, "store", {"kind", "path"})
    tokens = _section(config, "tokens", {"max_ttl_seconds", "max_depth", "max_children"})
    approvals = _section(
        config,
        "approvals",
        {"ttl_seconds", "max_pending_per_token", "max_pending", "retention_seconds"},
    )
    limits = _section(config, "limits", {"max_body_bytes", "max_output_bytes"})
    server = _section(config, "server", {"host", "port"})
    tools_cfg = config.get("tools", {})
    if type(tools_cfg) is not dict:
        raise ConfigError("`tools` must map a tool name to 'package.module:function'")

    settings = {"host": server.get("host", "127.0.0.1"), "port": server.get("port", 8000)}
    if type(settings["host"]) is not str or type(settings["port"]) is not int:
        raise ConfigError("`server.host` must be a string and `server.port` an integer")

    # Everything that can be checked without opening a file for writing is
    # checked first; the store and the audit log (which takes a lock) come last
    # and are closed again if anything after them fails.
    opened: list[Any] = []
    try:
        tools = {name: _load_tool(spec) for name, spec in tools_cfg.items()}
        policy = Policy.from_file(path("policy_file"))
        queue = ApprovalQueue(
            ttl=approvals.get("ttl_seconds", 300),
            max_pending_per_token=approvals.get("max_pending_per_token", 5),
            max_pending=approvals.get("max_pending", 100),
            retention=approvals.get("retention_seconds", 3600),
        )
        audit_path = path("audit_log")
        kind = store_cfg.get("kind", "memory")
        if kind == "sqlite":
            if type(store_cfg.get("path")) is not str:
                raise ConfigError("`store.path` is required for a sqlite store")
            store: Any = SqliteStore(str((base / store_cfg["path"]).resolve()))
            opened.append(store)
        elif kind == "memory":
            store = MemoryStore()
        else:
            raise ConfigError("`store.kind` must be memory or sqlite")
        authority = Authority(
            Ed25519PrivateKey.from_private_bytes(seed),
            config.get("issuer"),
            config.get("audience"),
            store,
            max_depth=tokens.get("max_depth", 4),
            max_ttl=tokens.get("max_ttl_seconds", 900),
            max_children=tokens.get("max_children", 64),
        )
        audit = AuditLog(audit_path)
        opened.append(audit)
        gateway = Gateway(
            authority,
            policy,
            audit,
            queue,
            tools,
            max_output_bytes=limits.get("max_output_bytes", 64 * 1024),
        )
        app = create_app(
            gateway,
            admin_hash,
            max_body_bytes=limits.get("max_body_bytes", DEFAULT_MAX_BODY_BYTES),
        )
    except Exception as exc:  # PolicyError, AuditError, sqlite3.Error, ValueError, ...
        for resource in opened:
            resource.close()
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"{type(exc).__name__}: {exc}") from None
    return app, gateway, settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m toolgate.server")
    parser.add_argument("--config", default="config/gateway.example.yaml")
    options = parser.parse_args(argv)
    config_path = Path(options.config).resolve()
    try:
        app, gateway, settings = build(load_config(config_path), os.environ, config_path.parent)
    except ConfigError as exc:
        print(f"toolgate: cannot start: {exc}", file=sys.stderr)
        return 2
    for warning in getattr(gateway.policy, "warnings", ()):
        print(f"toolgate: policy warning: {warning}", file=sys.stderr)
    import uvicorn

    # The access log prints the request line only, never headers, so no
    # credential reaches it. No Server header, no proxy header trust.
    uvicorn.run(
        app,
        host=settings["host"],
        port=settings["port"],
        server_header=False,
        proxy_headers=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
