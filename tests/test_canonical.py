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

from caveat.approvals import ApprovalQueue
from caveat.audit import AuditLog, verify
from caveat.canonical import (
    CODES,
    CanonicalError,
    Canonicalizer,
    canonical_email,
    canonical_path,
    canonical_tool,
    canonical_url,
)
from caveat.capability import Capability, Grant
from caveat.gateway import ALLOWED, DENIED, PENDING, Gateway
from caveat.policy import Policy
from caveat.sandbox.agents import HijackedAgent
from caveat.sandbox.runner import configuration, run_task
from caveat.sandbox.tasks import GRANT_ARGS, attack_tasks
from caveat.store import MemoryStore
from caveat.tokens import Authority

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
    """The glob gap from the decision log, kept visible: the raw string matches reports/*."""
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


# -- lead L3 to L5: spellings two programs read differently -----------------------


@pytest.mark.parametrize(
    "raw",
    [
        "http://2130706433/",  # 127.0.0.1 as one decimal number
        "http://0x7f000001/",  # ... as hex
        "http://0x7f.0.0.1/",
        "http://0177.0.0.1/",  # ... with an octal part
        "http://127.1/",  # ... shortened
        "http://127.0.0.01/",
        "http://256.0.0.1/",
        "http://1.2.3.4.5/",
        "http://vendor.0x1/",  # a numeric top label is parsed as IPv4 by browsers
        "http://vendor.123/",
        "http://localhost/",  # one label: depends on the resolver's search list
        "http://intranet/x",
        "https://vendor.example./x",  # trailing dot: same name, another Host and string
        "https://vendor.example../x",
        "https://-vendor.example/",
        "https://vendor-.example/",
        "https://vendor..example/",
    ],
)
def test_numeric_dotted_and_single_label_hosts_are_refused(raw):
    with pytest.raises(CanonicalError) as info:
        canonical_url(raw)
    assert info.value.code == "bad_url"


@pytest.mark.parametrize(
    ("raw", "clean"),
    [
        ("https://vendor.example:443/x", "https://vendor.example/x"),
        ("http://vendor.example:80/", "http://vendor.example/"),
        ("HTTP://Vendor.Example:80/a?b=1", "http://vendor.example/a?b=1"),
        ("https://vendor.example:80/", "https://vendor.example:80/"),  # not https's default
        ("http://vendor.example:443/", "http://vendor.example:443/"),
        ("http://127.0.0.1:8080/x", "http://127.0.0.1:8080/x"),  # the strict dotted quad
        ("https://shop.xn--p1ai/", "https://shop.xn--p1ai/"),  # an ASCII (punycode) top label
    ],
)
def test_a_default_port_is_removed_and_nothing_else_changes(raw, clean):
    assert canonical_url(raw) == clean
    assert canonical_url(clean) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "https://vendor.example:0443/",  # leading zero
        "https://vendor.example:/",  # empty port
        "https://vendor.example:0/",
        "https://vendor.example:65536/",
    ],
)
def test_ports_not_written_as_plain_decimal_are_refused(raw):
    with pytest.raises(CanonicalError):
        canonical_url(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "https://vendor.example/%252e%252e/secret",  # ".." to a server that decodes twice
        "https://vendor.example/a/%252E%252E/b",
        "https://vendor.example/%25%32%65%25%32%65/x",  # "%2e%2e" after one decoding
        "https://vendor.example/a%5c..%5cb",  # an encoded backslash
        "https://vendor.example/a%00b",
    ],
)
def test_escapes_that_survive_one_decoding_are_refused(raw):
    with pytest.raises(CanonicalError):
        canonical_url(raw)


def test_a_literal_percent_sign_is_still_allowed():
    assert canonical_url("https://vendor.example/100%25off") == "https://vendor.example/100%25off"


@settings(max_examples=500, deadline=None)
@given(
    st.text(alphabet="0123456789abcdefx.-", min_size=1, max_size=16),
    st.sampled_from(["", ":80", ":443", ":8080", ":0443", ":"]),
)
def test_an_accepted_url_has_one_reading_and_is_a_fixed_point(host, port):
    try:
        clean = canonical_url(f"https://{host}{port}/p")
    except CanonicalError:
        return
    netloc = clean.split("/")[2]
    name = netloc.split(":")[0]
    labels = name.split(".")
    is_quad = len(labels) == 4 and all(x.isdigit() for x in labels)
    if is_quad:
        assert all(x == str(int(x)) and int(x) <= 255 for x in labels)
    else:
        assert len(labels) >= 2 and labels[-1].isalpha() and not name.endswith(".")
    assert ":443" not in netloc
    assert canonical_url(clean) == clean


@pytest.mark.parametrize(
    "raw",
    [
        "*@northwind.example",  # the whole-domain reader principal of provenance
        "a*@northwind.example",
        "?@northwind.example",
        "bob%evil.example@northwind.example",  # source routing through a relay
        "evil.example!bob@northwind.example",
    ],
)
def test_wildcard_and_routing_characters_are_refused_in_addresses(raw):
    with pytest.raises(CanonicalError) as info:
        canonical_email(raw)
    assert info.value.code == "bad_email"


def test_a_wildcard_recipient_cannot_reach_a_canonicalized_tool():
    canon = Canonicalizer(
        {"send_email": {"to": "email"}, "create_event": {"attendees": "email_list"}}
    )
    with pytest.raises(CanonicalError):
        canon("send_email", {"to": "*@northwind.example"})
    with pytest.raises(CanonicalError):
        canon("create_event", {"attendees": ["bob@northwind.example", "*@northwind.example"]})
    assert canonical_email("o'brien+tag@northwind.example") == "o'brien+tag@northwind.example"


@pytest.mark.parametrize("raw", ["reports/", "notes/todo.txt/", "a//", "reports/./"])
def test_a_trailing_slash_is_refused_not_dropped(raw):
    with pytest.raises(CanonicalError) as info:
        canonical_path(raw)
    assert info.value.code == "bad_path"


def test_path_resolution_is_lexical_and_says_so():
    """normpath cannot see links: the documented limit, pinned so it cannot drift silently."""
    assert canonical_path("a/link/../b") == "a/b"
    import caveat.canonical as module

    assert "symlink" in (module.__doc__ or "")
