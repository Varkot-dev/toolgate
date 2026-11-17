"""Where labels come from in the sandbox, and how its arguments are canonicalized.

Written once, from the organization's point of view, before any provenance
run, the way config/sandbox_policy.yaml was: it knows the directory layout and
what each tool returns, not which tasks attack what.

Initial labels (see toolgate.provenance for the rules that combine them)

    the user's request              sources {user}, readers ANY
    read_inbox                      {tool:read_inbox, untrusted}; readers: the
                                    user and, per email, its sender,
                                    intersected over the listed emails
    read_email                      {tool:read_email, untrusted}; readers: the
                                    user and the sender
    search_contacts                 {tool:search_contacts}; readers: the user
                                    (it is the user's address book)
    search_calendar                 {tool:search_calendar}; readers: the user
                                    plus the attendees common to every
                                    returned event (an event is readable by
                                    its attendees; a list by those who may
                                    read every entry)
    read_file, list_files           {tool:read_file} or {tool:list_files}, plus
                                    untrusted under downloads/ (world
                                    metadata); readers by directory:
                                      public/   ANY
                                      reports/  the user and *@northwind.example
                                      anything else (notes/, finance/, hr/,
                                      secrets/, drafts/, downloads/): the user
    web_fetch                       {tool:web_fetch, untrusted}; readers ANY
                                    (a public page)
    send_email, create_event,       receipts: {tool:<name>} joined with the
    write_file, delete_file         labels of the call's own arguments (a
                                    receipt echoes what was sent)

The user's own address is the principal for "the user".
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from toolgate.canonical import Canonicalizer
from toolgate.policy import Policy
from toolgate.provenance import Label, join_all, tool_source
from toolgate.sandbox.world import TOOLS, USER, result_is_untrusted

ROOT = Path(__file__).resolve().parents[3]
SESSION_POLICY_FILE = ROOT / "config" / "sandbox_policy_session.yaml"
VALUE_POLICY_FILE = ROOT / "config" / "sandbox_policy_values.yaml"
ORG = "*@northwind.example"

CANONICAL_RULES: dict[str, dict[str, str]] = {
    "read_file": {"path": "path"},
    "list_files": {"path": "path"},
    "write_file": {"path": "path"},
    "delete_file": {"path": "path"},
    "send_email": {"to": "email"},
    "create_event": {"attendees": "email_list"},
    "web_fetch": {"url": "url"},
}


def canonicalizer() -> Canonicalizer:
    return Canonicalizer(CANONICAL_RULES)


def file_readers(path: str) -> frozenset[str] | None:
    """Readers of a file or directory, by its top directory. None is ANY."""
    top = posixpath.normpath(path).split("/")[0]
    if top == "public":
        return None
    if top == "reports":
        return frozenset({USER, ORG})
    return frozenset({USER})


def _meet(sets: list[frozenset[str]]) -> frozenset[str]:
    out = frozenset({USER})
    if sets:
        common = sets[0]
        for s in sets[1:]:
            common &= s
        out |= common
    return out


def declare(
    tool: str, args: Mapping[str, Any], result: Any, arg_labels: Mapping[str, Label]
) -> Label:
    """The label of one tool result. Fails closed: an unknown shape gets readers {user}."""
    sources = {tool_source(tool)}
    if tool in TOOLS and result_is_untrusted(tool, dict(args)):
        sources.add("untrusted")
    readers: frozenset[str] | None
    if tool == "read_inbox":
        emails = result.get("emails", []) if isinstance(result, dict) else []
        readers = _meet([frozenset({str(e.get("sender", ""))}) for e in emails])
    elif tool == "read_email":
        sender = result.get("sender") if isinstance(result, dict) else None
        readers = frozenset({USER} | ({sender} if isinstance(sender, str) and sender else set()))
    elif tool == "search_contacts":
        readers = frozenset({USER})
    elif tool == "search_calendar":
        found = result.get("events", []) if isinstance(result, dict) else []
        readers = _meet([frozenset(e.get("attendees", [])) for e in found])
    elif tool in ("read_file", "list_files"):
        readers = file_readers(str(args.get("path", "")))
    elif tool == "web_fetch":
        readers = None
    elif tool in TOOLS and TOOLS[tool].side_effect:
        receipt = join_all(arg_labels.values())
        return Label(frozenset(sources) | receipt.sources, receipt.readers)
    else:
        readers = frozenset({USER})
    return Label(frozenset(sources), readers)


def policy(base: Policy, overlay: Path) -> Policy:
    """The base sandbox policy followed by an overlay's rules (rule order: base first)."""
    return Policy(base.rules + Policy.from_file(overlay).rules)
