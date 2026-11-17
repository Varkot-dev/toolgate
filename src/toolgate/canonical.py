"""Argument canonicalization: one spelling per meaning, before any decision.

Why. Capabilities and policy compare strings (decision log M0.2). A file tool
that resolves "reports/../secrets/key" after the gateway has matched the raw
string against `reports/*` runs something the gateway never checked. The fix
is not a smarter glob but a rule: the gateway rewrites each argument it knows
how to read into its canonical form, then decides on that form AND passes that
form to the tool. What was checked is what runs.

The rule for ambiguity. A canonicalizer may only rewrite a value into another
spelling of the same meaning (resolve dot segments the way the tool would,
lowercase a DNS domain, which is case-insensitive). Anything whose meaning is
unclear is REFUSED, never repaired: a path that escapes the root, a recipient
string holding two addresses, a URL with credentials in it, a host in
non-ASCII characters. Repairing such input means guessing which reading the
tool will pick, and a wrong guess is exactly the gap this module closes.

Configuration. The operator names, per tool, the kind of each argument:

    Canonicalizer({"read_file": {"path": "path"},
                   "send_email": {"to": "email"},
                   "create_event": {"attendees": "email_list"},
                   "web_fetch": {"url": "url"}})

Kinds:

    path        posixpath.normpath, then refused if it is empty, ".", starts
                with ".." or "/", contains NUL, a backslash or a control
                character, or has a segment made only of dots ("...")
    email       exactly one address local@domain; the domain is lowercased;
                refused if it holds whitespace, a comma, semicolon, angle
                bracket, quote, a second "@", a control character or any
                non-ASCII character
    email_list  a list of `email` values (each canonicalized the same way)
    url         http or https only; scheme and host lowercased; refused if it
                has user info ("a@b" before the host), a non-ASCII or empty
                host, whitespace, control characters, a backslash, or "." or
                ".." path segments (encoded or not)

Every tool name is NFC-normalized and refused unless it is 1 to 128
characters from [A-Za-z0-9_.:/-]; that is the gateway's own rule for
registered tools, applied before anything else looks at the name.

Arguments the configuration does not mention pass through unchanged (the grant
is closed-world and decides about them). Tools it does not mention get only the
tool-name check.

Errors are `CanonicalError` with a fixed code from `CODES`, so the gateway can
log the code and never the caller's text.
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

KINDS: frozenset[str] = frozenset({"path", "email", "email_list", "url"})
CODES: frozenset[str] = frozenset(
    {
        "bad_tool_name",
        "not_a_string",
        "not_a_list",
        "bad_path",
        "path_escapes_root",
        "bad_email",
        "bad_url",
        "not_a_mapping",
    }
)

_TOOL = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_LOCAL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}")
_DOMAIN = re.compile(
    r"(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_HOST = re.compile(r"[a-z0-9.-]{1,253}")


class CanonicalError(ValueError):
    """An argument was refused. `code` is one of CODES; it never quotes the input."""

    def __init__(self, code: str, arg: str = "") -> None:
        assert code in CODES
        self.code = code
        self.arg = arg
        super().__init__(f"{code}" + (f" (argument {arg!r})" if arg else ""))


def _control(text: str) -> bool:
    return any(unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp") for ch in text)


def canonical_tool(name: Any) -> str:
    """NFC-normalize a tool name and refuse it unless it is in the safe set."""
    if type(name) is not str:
        raise CanonicalError("bad_tool_name")
    name = unicodedata.normalize("NFC", name)
    if not _TOOL.fullmatch(name):
        raise CanonicalError("bad_tool_name")
    return name


def canonical_path(value: Any, arg: str = "path") -> str:
    """Resolve dot segments; refuse what would leave the tree or is unclear."""
    if type(value) is not str:
        raise CanonicalError("not_a_string", arg)
    if not value or "\x00" in value or "\\" in value or _control(value):
        raise CanonicalError("bad_path", arg)
    clean = posixpath.normpath(value)
    if clean in (".", "..") or clean.startswith(("/", "../")):
        raise CanonicalError("path_escapes_root", arg)
    if any(set(segment) == {"."} for segment in clean.split("/")):
        # "..." and longer: a plain name to POSIX, but not to every file system.
        raise CanonicalError("bad_path", arg)
    return clean


def canonical_email(value: Any, arg: str = "to") -> str:
    """Exactly one address; the domain lowercased, the local part kept as written."""
    if type(value) is not str:
        raise CanonicalError("not_a_string", arg)
    if not value.isascii() or _control(value) or value.count("@") != 1:
        raise CanonicalError("bad_email", arg)
    local, domain = value.split("@")
    if not _LOCAL.fullmatch(local) or not _DOMAIN.fullmatch(domain):
        raise CanonicalError("bad_email", arg)
    if local.startswith(".") or local.endswith(".") or ".." in local:
        raise CanonicalError("bad_email", arg)
    return f"{local}@{domain.lower()}"


def canonical_url(value: Any, arg: str = "url") -> str:
    """http(s) URLs with a plain ASCII host and no credentials or dot segments."""
    if type(value) is not str:
        raise CanonicalError("not_a_string", arg)
    if not value.isascii() or _control(value) or "\\" in value or any(c.isspace() for c in value):
        raise CanonicalError("bad_url", arg)
    try:
        parts = urlsplit(value)
        port = parts.port  # raises ValueError for a port that is not a number
    except ValueError:
        raise CanonicalError("bad_url", arg) from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https") or "@" in parts.netloc:
        raise CanonicalError("bad_url", arg)
    host = (parts.hostname or "").lower()
    if not host or not _HOST.fullmatch(host) or "%" in parts.netloc:
        raise CanonicalError("bad_url", arg)
    segments = unquote(parts.path).split("/")
    if any(s in (".", "..") for s in segments):
        raise CanonicalError("bad_url", arg)
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


_BY_KIND = {"path": canonical_path, "email": canonical_email, "url": canonical_url}


class Canonicalizer:
    """Per-tool, operator-configured canonicalization. Call it as `c(tool, args)`.

    Returns `(tool, args)` in canonical form, as a fresh dict, or raises
    CanonicalError. The input is never modified.
    """

    def __init__(self, rules: Mapping[str, Mapping[str, str]]) -> None:
        table: dict[str, dict[str, str]] = {}
        for tool, kinds in dict(rules).items():
            canonical_tool(tool)
            if not isinstance(kinds, Mapping):
                raise ValueError(f"rules for tool {tool!r} must be a mapping")
            for arg, kind in kinds.items():
                if type(arg) is not str or not arg:
                    raise ValueError(f"tool {tool!r}: argument names must be non-empty strings")
                if kind not in KINDS:
                    raise ValueError(f"tool {tool!r} argument {arg!r}: unknown kind {kind!r}")
            table[tool] = dict(kinds)
        self.rules: Mapping[str, Mapping[str, str]] = table

    def __call__(self, tool: Any, args: Any) -> tuple[str, dict[str, Any]]:
        name = canonical_tool(tool)
        if args is None:
            args = {}
        if type(args) is not dict:
            raise CanonicalError("not_a_mapping")
        out = dict(args)
        for arg, kind in self.rules.get(name, {}).items():
            if arg not in out:
                continue  # a missing argument is the grant's business
            value = out[arg]
            if kind == "email_list":
                if type(value) is not list:
                    raise CanonicalError("not_a_list", arg)
                out[arg] = [canonical_email(v, arg) for v in value]
            else:
                out[arg] = _BY_KIND[kind](value, arg)
        return name, out
