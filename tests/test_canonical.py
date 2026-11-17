"""Argument canonicalization: refuse what is ambiguous, and run what was checked.

Every refusal test through the gateway asserts that the tool was never called.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from toolgate.approvals import ApprovalQueue
from toolgate.audit import AuditLog, verify
from toolgate.canonical import (
    CODES,
    CanonicalError,
    Canonicalizer,
    canonical_email,
    canonical_path,
    canonical_tool,
    canonical_url,
)
from toolgate.capability import Capability, Grant
from toolgate.gateway import ALLOWED, DENIED, PENDING, Gateway
from toolgate.policy import Policy
from toolgate.sandbox.agents import HijackedAgent
from toolgate.sandbox.runner import configuration, run_task
from toolgate.sandbox.tasks import GRANT_ARGS, attack_tasks
from toolgate.store import MemoryStore
from toolgate.tokens import Authority

T0 = 1_800_000_000
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


# -- the kinds, one by one -------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("reports/q3.txt", "reports/q3.txt"),
        ("reports/../secrets/key", "secrets/key"),
        ("reports/./q3.txt", "reports/q3.txt"),
        ("reports//q3.txt", "reports/q3.txt"),
        ("a/b/../../c", "c"),
    ],
)
def test_paths_resolve_dot_segments_like_the_file_tool(raw, clean):
    assert canonical_path(raw) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "..",
        "../x",
        "a/../..",
        "/etc/passwd",
        "a\x00b",
        "a\\..\\b",
        "a\nb",
        "a/.../b",
        3,
        None,
    ],
)
def test_ambiguous_or_escaping_paths_are_refused(raw):
    with pytest.raises(CanonicalError) as info:
        canonical_path(raw)
    assert info.value.code in CODES


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("Bob@NorthWind.Example", "Bob@northwind.example"),
        ("bob@northwind.example", "bob@northwind.example"),
    ],
)
def test_email_domain_is_lowercased_local_part_kept(raw, clean):
    assert canonical_email(raw) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "a@x.example, b@northwind.example",
        "a@x.example b@y.example",
        "a@b@c.example",
        "<a@x.example>",
        '"a"@x.example',
        "a@x.example;b@y.example",
        "a@xn--bcher.exampleа",  # a Cyrillic letter in the domain
        "аlice@northwind.example",
        "a..b@x.example",
        ".a@x.example",
        "no-at-sign",
        "a@localhost",
        "",
        ["a@x.example"],
    ],
)
def test_anything_but_one_plain_address_is_refused(raw):
    with pytest.raises(CanonicalError):
        canonical_email(raw)


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("HTTPS://Vendor.Example/pricing", "https://vendor.example/pricing"),
        ("https://vendor.example/quote?ctx=a%20b", "https://vendor.example/quote?ctx=a%20b"),
        ("http://vendor.example:8080/x", "http://vendor.example:8080/x"),
    ],
)
def test_urls_lowercase_scheme_and_host_only(raw, clean):
    assert canonical_url(raw) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "https://vendor.example@evil.example/x",  # user info: which host is meant?
        "https://user:pw@vendor.example/",
        "https://vendor.example/a/../secret",
        "https://vendor.example/a/%2e%2e/secret",
        "https://vendor.example\\@evil.example/",
        "https://vеndor.example/",  # a Cyrillic e
        "https://vendor.example/a b",
        "https://%76endor.example/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https:///nohost",
        "https://vendor.example:notaport/",
        42,
    ],
)
def test_ambiguous_urls_are_refused(raw):
    with pytest.raises(CanonicalError):
        canonical_url(raw)


def test_tool_names_are_normalized_then_checked():
    assert canonical_tool("read_file") == "read_file"
    for bad in ("read file", "read_fıle", "", "x" * 129, "réad", None):
        with pytest.raises(CanonicalError):
            canonical_tool(bad)


def test_refusal_never_quotes_the_input():
    secret = "SECRET-TEXT@x.example, y@z.example"
    with pytest.raises(CanonicalError) as info:
        canonical_email(secret)
    assert "SECRET" not in str(info.value)


@settings(max_examples=500, deadline=None)
@given(st.text(alphabet="ab./\\\x00", max_size=12))
def test_a_path_is_either_refused_or_a_fixed_point(raw):
    """Never "fixed" into something the next pass would change again."""
    try:
        clean = canonical_path(raw)
    except CanonicalError:
        return
    assert canonical_path(clean) == clean
    assert not clean.startswith("/") and "\\" not in clean and "\x00" not in clean
    assert all(segment and set(segment) != {"."} for segment in clean.split("/"))


def test_canonicalizer_is_per_tool_and_leaves_other_arguments_alone():
    canon = Canonicalizer({"read_file": {"path": "path"}, "send_email": {"to": "email"}})
    args = {"path": "a/./b", "extra": "a/./b"}
    assert canon("read_file", args) == ("read_file", {"path": "a/b", "extra": "a/./b"})
    assert args == {"path": "a/./b", "extra": "a/./b"}, "the input is not modified"
    assert canon("other", {"path": "a/./b"}) == ("other", {"path": "a/./b"})
    assert canon("read_file", {}) == ("read_file", {})
    with pytest.raises(ValueError):
        Canonicalizer({"read_file": {"path": "regex"}})
    with pytest.raises(CanonicalError):
        canon("read_file", ["path"])


# -- through the gateway: decide and execute on the canonical form -----------------


def build(rules: dict[str, dict[str, str]] | None, policy: str | None = None):
    calls: list[tuple[str, dict[str, Any]]] = []

    def tool(name):
        def run(**kwargs):
            calls.append((name, kwargs))
            return {"ok": True}

        return run

    authority = Authority(KEY, "https://gw.example", "gw", MemoryStore(), clock=lambda: T0)
    directory = tempfile.TemporaryDirectory()
    log = Path(directory.name) / "audit.jsonl"
    gateway = Gateway(
        authority,
        Policy.from_yaml(
            policy or "version: 1\nrules:\n  - {id: allow-all, effect: allow, tools: ['*']}\n"
        ),
        AuditLog(log),
        ApprovalQueue(),
        {"read_file": tool("read_file"), "send_email": tool("send_email")},
        clock=lambda: T0,
        canonicalizer=None if rules is None else Canonicalizer(rules),
    )
    grant = Grant(
        (
            Capability.from_dict({"tool": "read_file", "args": {"path": {"glob": "reports/*"}}}),
            Capability.from_dict(
                {"tool": "send_email", "args": {"to": {"glob": "*@northwind.example"}}}
            ),
        ),
        T0 + 600,
    )
    token = authority.mint("user:alice", grant, "agent:test", 600)
    return gateway, token, calls, directory, log


RULES = {"read_file": {"path": "path"}, "send_email": {"to": "email"}}


def test_without_a_canonicalizer_the_traversal_passes_the_glob():
    """The M0.2 gap, kept visible: the raw string matches reports/*."""
    gateway, token, calls, directory, _ = build(None)
    with directory:
        out = gateway.handle_call(token, "read_file", {"path": "reports/../secrets/key"})
        assert out.status == ALLOWED
        assert calls == [("read_file", {"path": "reports/../secrets/key"})]


def test_canonicalized_traversal_is_refused_by_the_grant_and_never_runs():
    gateway, token, calls, directory, log = build(RULES)
    with directory:
        out = gateway.handle_call(token, "read_file", {"path": "reports/../secrets/key"})
        assert out.status == DENIED and out.stage == "grant"
        assert calls == []
        assert verify(log).ok


def test_the_tool_receives_the_canonical_argument():
    gateway, token, calls, directory, _ = build(RULES)
    with directory:
        assert gateway.handle_call(token, "read_file", {"path": "reports/./q3.txt"}).allowed
        out = gateway.handle_call(token, "send_email", {"to": "Bob@NorthWind.EXAMPLE"})
        assert out.allowed
        assert calls == [
            ("read_file", {"path": "reports/q3.txt"}),
            ("send_email", {"to": "Bob@northwind.example"}),
        ]


def test_ambiguous_input_is_refused_at_the_canonical_stage_and_logged_by_code():
    gateway, token, calls, directory, log = build(RULES)
    with directory:
        out = gateway.handle_call(
            token, "send_email", {"to": "evil@x.example, a@northwind.example"}
        )
        assert out.status == DENIED and out.stage == "canonical" and out.code == "bad_email"
        assert calls == []
        text = log.read_text(encoding="utf-8")
        assert "canonical: bad_email" in text and "evil@x.example" not in text


def test_an_approval_stores_and_releases_the_canonical_call():
    policy = (
        "version: 1\nrules:\n"
        "  - {id: approve-mail, effect: approve, tools: [send_email]}\n"
        "  - {id: allow-all, effect: allow, tools: ['*']}\n"
    )
    gateway, token, calls, directory, _ = build(RULES, policy)
    with directory:
        out = gateway.handle_call(token, "send_email", {"to": "bob@NORTHWIND.example"})
        assert out.status == PENDING and calls == []
        held = gateway.approvals.get(out.approval_id)
        assert held.call.args["to"] == "bob@northwind.example"
        done = gateway.resolve_approval(out.approval_id, "approve", "alice")
        assert done.allowed and calls == [("send_email", {"to": "bob@northwind.example"})]


# -- in the sandbox --------------------------------------------------------------------


def test_args_04_is_stopped_by_the_grant_once_arguments_are_canonical():
    task = next(t for t in attack_tasks() if t.id == "args-04")
    for key in ("1c-grant-canonical", "3-session-labels", "4-value-labels"):
        run = run_task(task, HijackedAgent(), configuration(key))
        assert run.stopped_by == GRANT_ARGS == task.expected, key
        assert not run.attack_succeeded
        assert not any(run.world.canary["api_key"] in e.get("body", "") for e in run.world.effects)
