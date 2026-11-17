"""Audit log: every kind of tampering is reported at the first bad index."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unicodedata
from itertools import count
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolgate.audit import (
    FIELDS,
    GENESIS,
    MAX_LINE_BYTES,
    AuditError,
    AuditLog,
    Head,
    VerifyResult,
    canonical_json,
    entry_hash,
    hash_args,
    loggable,
    main,
    verify,
)
from toolgate.capability import Call

T0 = 1_800_000_000_000_000_000
SAMPLES = [
    ("read_file", {"path": "reports/q3.txt"}, "allow", "allow-file-reads", None),
    ("send_email", {"to": "x@evil.com", "body": "hi"}, "approve", "approve-external-email", None),
    ("send_email", {"to": "x@evil.com", "body": "hi"}, "approved", "approve-external-email", "ana"),
    ("delete_file", {"path": "a"}, "deny", "deny-file-delete", None),
    ("write_file", {"path": "b", "content": "c"}, "rejected", "approve-writes", "ben"),
]


def fixed_clock() -> Any:
    ticks = count(T0, 1_000_000_000)
    return lambda: next(ticks)


def add(log: AuditLog, i: int) -> None:
    tool, args, decision, rule, approver = SAMPLES[i % len(SAMPLES)]
    log.append(
        jti=f"tok-{i % 3}",
        actors=["orchestrator", "mailer"][: 1 + i % 2],
        tool=tool,
        args=args,
        decision=decision,
        rule=rule,
        approver=approver,
    )


def build(path: Path, n: int) -> Head:
    with AuditLog(path, clock=fixed_clock()) as log:
        for i in range(n):
            add(log, i)
        return log.head()


def lines_of(path: Path) -> list[bytes]:
    return path.read_bytes().splitlines(keepends=True)


def parse(line: bytes) -> dict[str, Any]:
    return json.loads(line)


def dump(entry: dict[str, Any]) -> bytes:
    return canonical_json(entry) + b"\n"


def rewrite(path: Path, lines: list[bytes]) -> Path:
    path.write_bytes(b"".join(lines))
    return path


def flip(hex_text: str) -> str:
    return ("0" if hex_text[0] != "0" else "1") + hex_text[1:]


def mutate(entry: dict[str, Any], field: str) -> dict[str, Any]:
    """Change one field to a different, plausible value. The hash is left alone."""
    out = dict(entry)
    value = entry[field]
    if field in ("seq", "time"):
        out[field] = value + 1
    elif field in ("jti", "tool", "rule"):
        out[field] = value + "x"
    elif field == "actors":
        out[field] = [*value, "mallory"]
    elif field in ("args_hash", "prev", "hash"):
        out[field] = flip(value)
    elif field == "decision":
        swap = {"allow": "deny", "deny": "allow", "approve": "allow"}
        out[field] = swap.get(value) or ("rejected" if value == "approved" else "approved")
    elif field == "approver":
        out[field] = "mallory" if value is None else value + "x"
    assert out != entry
    return out


@pytest.fixture(scope="module")
def log50(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Head]:
    path = tmp_path_factory.mktemp("log50") / "audit.jsonl"
    return path, build(path, 50)


# ------------------------------------------------------------------- the basics


def test_entries_have_exactly_the_documented_fields(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    head = build(path, 5)
    lines = lines_of(path)
    assert len(lines) == 5 and path.read_bytes().endswith(b"\n")
    prev = GENESIS
    for i, line in enumerate(lines):
        entry = parse(line)
        assert tuple(entry) == tuple(sorted(FIELDS))  # canonical: keys are sorted
        assert entry["seq"] == i and entry["prev"] == prev
        assert entry["time"] == T0 + i * 1_000_000_000
        assert entry["hash"] == entry_hash(entry)
        assert dump(entry) == line
        prev = entry["hash"]
    assert head == Head(4, prev)
    assert parse(lines[2])["approver"] == "ana" and parse(lines[0])["approver"] is None
    assert verify(path) == VerifyResult(True, 5, None, None)
    assert verify(path, head.hash).ok and verify(path, head).ok
    assert AuditLog.verify(path, head).ok


def test_arguments_are_hashed_not_stored(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    secret = "hunter2-very-secret"
    with AuditLog(path) as log:
        entry = log.append(
            jti="j",
            actors=["a"],
            tool="send_email",
            args={"body": secret},
            decision="allow",
            rule="r",
        )
    assert secret.encode() not in path.read_bytes()
    assert entry.args_hash == hashlib.sha256(b'{"body":"hunter2-very-secret"}').hexdigest()
    assert entry.to_dict() == parse(lines_of(path)[0])
    assert entry.time > 1_600_000_000 * 10**9  # default clock is integer nanoseconds


def test_canonical_json_and_hash_args() -> None:
    assert canonical_json({"b": 1, "a": [True, None, "é"]}) == (
        b'{"a":[true,null,"\\u00e9"],"b":1}'
    )
    assert hash_args({}) == hashlib.sha256(b"{}").hexdigest()
    assert hash_args({"a": 1, "b": 2}) == hash_args({"b": 2, "a": 1})
    call = Call("t", {"to": ["a", "b"], "opts": {"n": 1}})
    assert hash_args(call.args) == hash_args({"to": ["a", "b"], "opts": {"n": 1}})
    assert hash_args({"x": 1}) != hash_args({"x": 1.0})  # documented: 1 and 1.0 differ
    assert hash_args({"x": 0.1}) == hashlib.sha256(b'{"x":0.1}').hexdigest()
    nfc, nfd = "café", unicodedata.normalize("NFD", "café")
    assert hash_args({"x": nfc}) != hash_args({"x": nfd})  # no normalization, on purpose
    for bad in (
        {"x": float("nan")},
        {"x": float("inf")},
        {"x": {1, 2}},
        {"x": b"bytes"},
        {1: "x"},
        {"x": "\ud800"},
        {"\ud800": 1},
        [1],
    ):
        with pytest.raises(ValueError):
            hash_args(bad)  # type: ignore[arg-type]
    deep: Any = "x"
    for _ in range(40):
        deep = [deep]
    with pytest.raises(ValueError):
        hash_args({"x": deep})


def test_empty_and_missing_files(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_bytes(b"")
    assert verify(path) == VerifyResult(True, 0, None, None)
    assert verify(path, GENESIS).ok
    with AuditLog(path) as log:
        assert log.head() == Head(-1, GENESIS)
    missing = verify(tmp_path / "nope.jsonl")
    assert not missing.ok and missing.first_bad_index is None and "cannot read" in missing.problem
    for bad_head in ("abc", "A" * 64, 5, Head(0, "zz")):
        with pytest.raises(ValueError):
            verify(path, bad_head)  # type: ignore[arg-type]


# ------------------------------------------------------- the plan's "done when"


def test_editing_any_field_of_any_line_is_detected_at_that_line(
    log50: tuple[Path, Head], tmp_path: Path
) -> None:
    original = lines_of(log50[0])
    assert len(original) == 50
    target = tmp_path / "edited.jsonl"
    checked = 0
    for i, line in enumerate(original):
        for field in FIELDS:
            edited = list(original)
            edited[i] = dump(mutate(parse(line), field))
            result = verify(rewrite(target, edited))
            assert (result.ok, result.first_bad_index, result.entries) == (False, i, i), (i, field)
            assert result.problem
            checked += 1
    assert checked == 50 * 11
    assert verify(rewrite(target, original)).ok


def test_every_byte_of_a_small_log(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 3)
    data = path.read_bytes()
    target = tmp_path / "edited.jsonl"
    for pos, old in enumerate(data):
        line = data.count(b"\n", 0, pos)
        for new in {old ^ 1, ord("\n"), ord('"'), ord(" "), ord("0"), ord("}"), 0xC3} - {old}:
            target.write_bytes(data[:pos] + bytes([new]) + data[pos + 1 :])
            result = verify(target)
            assert (result.ok, result.first_bad_index) == (False, line), (pos, new)


@settings(max_examples=3000, deadline=None)
@given(data=st.data())
def test_random_single_byte_edit_is_reported_at_the_edited_line(
    log50: tuple[Path, Head], tmp_path_factory: pytest.TempPathFactory, data: st.DataObject
) -> None:
    original = log50[0].read_bytes()
    pos = data.draw(st.integers(0, len(original) - 1), label="position")
    new = data.draw(st.integers(0, 255).filter(lambda b: b != original[pos]), label="byte")
    target = tmp_path_factory.getbasetemp() / "byte-edit.jsonl"
    target.write_bytes(original[:pos] + bytes([new]) + original[pos + 1 :])
    result = verify(target)
    assert not result.ok
    assert result.first_bad_index == original.count(b"\n", 0, pos)
    assert not verify(target, log50[1]).ok


# ------------------------------------------------------------ each tamper type


@pytest.fixture
def ten(tmp_path: Path) -> tuple[Path, list[bytes], Head]:
    path = tmp_path / "a.jsonl"
    head = build(path, 10)
    return path, lines_of(path), head


def bad_index(path: Path, lines: list[bytes]) -> int | None:
    result = verify(rewrite(path, lines))
    assert not result.ok and result.problem
    return result.first_bad_index


def test_deleted_line(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    for i in range(9):
        assert bad_index(path, lines[:i] + lines[i + 1 :]) == i
    assert "seq" in verify(path).problem


def test_inserted_line(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    forged = parse(lines[4])
    forged["tool"] = "forged"
    forged["hash"] = entry_hash(forged)
    for i in range(11):
        # At i == 4 the forgery sits where its seq and prev fit, so it passes and the
        # displaced original is the first bad line.
        expected = 5 if i == 4 else i
        assert bad_index(path, lines[:i] + [dump(forged)] + lines[i:]) == expected
    # a perfectly formed entry spliced in with the right seq and prev still breaks the next link
    forged = {**parse(lines[4]), "seq": 5, "prev": parse(lines[4])["hash"], "tool": "forged"}
    forged["hash"] = entry_hash(forged)
    assert bad_index(path, lines[:5] + [dump(forged)] + lines[5:]) == 6


def test_reordered_lines(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    swapped = list(lines)
    swapped[3], swapped[7] = swapped[7], swapped[3]
    assert bad_index(path, swapped) == 3
    assert bad_index(path, lines[::-1]) == 0


def test_duplicated_line(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    assert bad_index(path, lines[:5] + [lines[4]] + lines[5:]) == 5
    assert bad_index(path, [*lines, lines[-1]]) == 10


def test_invalid_json_and_blank_lines(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    for junk in (b"not json\n", b"\n", b"{}\n", b"[]\n", b"null\n", b"{\n", b"[" * 5000 + b"\n"):
        assert bad_index(path, lines[:6] + [junk] + lines[7:]) == 6
    assert bad_index(path, [*lines, b"\n"]) == 10
    assert bad_index(path, [b"\n", *lines]) == 0
    assert bad_index(path, lines[:2] + [lines[2][:-1] + b"\r\n"] + lines[3:]) == 2
    assert bad_index(path, lines[:2] + [b" " + lines[2]] + lines[3:]) == 2
    assert bad_index(path, lines[:2] + [b"x" * (MAX_LINE_BYTES + 10) + b"\n"] + lines[3:]) == 2
    assert bad_index(path, [b"\xef\xbb\xbf" + lines[0], *lines[1:]]) == 0  # UTF-8 BOM


def test_duplicate_json_keys(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    # Without the check, json keeps the LAST value, so this line would still hash correctly
    # while a first-key-wins reader would see a different tool.
    doubled = lines[4].replace(b'{"actors"', b'{"tool":"harmless","actors"', 1)
    assert json.loads(doubled) == json.loads(lines[4])
    assert bad_index(path, lines[:4] + [doubled] + lines[5:]) == 4
    assert "duplicate" in verify(path).problem


def test_unknown_and_missing_fields(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    for field in FIELDS:
        entry = parse(lines[4])
        del entry[field]
        if field != "hash":
            entry["hash"] = entry_hash(entry)
        assert bad_index(path, lines[:4] + [dump(entry)] + lines[5:]) == 4
        assert "missing" in verify(path).problem
    entry = parse(lines[4])
    entry["note"] = "extra"
    entry["hash"] = entry_hash(entry)
    assert bad_index(path, lines[:4] + [dump(entry)] + lines[5:]) == 4
    assert "unknown field" in verify(path).problem


WRONG_TYPES = {
    "seq": [True, "4", 4.0, -1, None],
    "time": [True, "1", 1.5, -5],
    "jti": [1, None, ["j"]],
    "actors": ["a", [1], None, {"a": 1}],
    "tool": ["", 1, None],
    "args_hash": ["abc", "G" * 64, "A" * 64, 5],
    "decision": ["ALLOW", "maybe", ["allow"], None, 1],
    "rule": [None, 1],
    "approver": [1, ["x"], "someone"],  # entry 4 is a `rejected` with approver "ben"
    "prev": ["", None],
    "hash": ["0" * 63, None],
}


@pytest.mark.parametrize("field", FIELDS)
def test_wrong_field_types_even_with_a_matching_hash(
    ten: tuple[Path, list[bytes], Head], field: str
) -> None:
    path, lines, _ = ten
    for index, value in ((3, v) for v in WRONG_TYPES[field]):
        entry = parse(lines[index])
        entry[field] = value
        if field != "hash":
            entry["hash"] = entry_hash(entry)
        raw = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        assert bad_index(path, lines[:index] + [raw] + lines[index + 1 :]) == index
    # approver rules: approved/rejected need one, the others must not have one
    entry = parse(lines[4])
    assert entry["decision"] == "rejected"
    entry["approver"] = None
    entry["hash"] = entry_hash(entry)
    assert bad_index(path, lines[:4] + [dump(entry)] + lines[5:]) == 4


def test_non_canonical_but_equal_json_is_rejected(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    entry = parse(lines[5])
    variants = [
        json.dumps(entry).encode() + b"\n",  # spaces, insertion order
        json.dumps(entry, sort_keys=True, separators=(",", ":"), indent=None).encode()[:-1]
        + b" }\n",
        lines[5].replace(b'"seq":5', b'"seq":05'),
        lines[5].replace(b'"seq":5', b'"seq":5.0'),
        lines[5].replace(b'"seq":5', b'"seq":5e0'),
        lines[5].replace(b'"seq":5', b'"seq":NaN'),
        lines[5].replace(b'"tool":"read_file"', b'"tool":"read\\u005ffile"'),
    ]
    for raw in variants:
        assert bad_index(path, lines[:5] + [raw] + lines[6:]) == 5


def test_unicode_is_escaped_and_not_normalized(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    nfc = "café"
    nfd = unicodedata.normalize("NFD", nfc)
    with AuditLog(path, clock=fixed_clock()) as log:
        for tool in (nfc, nfd, "emoji-\U0001f600", "line\nbreak", 'tab\tquote"back\\slash'):
            log.append(jti="j", actors=[tool], tool=tool, args={}, decision="allow", rule="r")
        with pytest.raises(ValueError):
            log.append(jti="j", actors=[], tool="\ud800", args={}, decision="allow", rule="r")
    data = path.read_bytes()
    assert data.isascii() and data.count(b"\n") == 5
    lines = lines_of(path)
    assert parse(lines[0])["tool"] == nfc and parse(lines[1])["tool"] == nfd
    assert parse(lines[0])["tool"] != parse(lines[1])["tool"]
    assert verify(path).ok
    # the same text written as raw UTF-8, or with different escape spelling, is an edit
    for raw in (
        lines[0].replace(b"\\u00e9", "é".encode()),
        lines[0].replace(b"\\u00e9", b"\\u00E9"),
        lines[0].replace(b"caf\\u00e9", b"cafe\\u0301"),
    ):
        assert raw != lines[0]
        assert bad_index(path, [raw, *lines[1:]]) == 0


# -------------------------------------------- what needs a trusted head, and why


def rebuild_from(lines: list[bytes], start: int, edit: dict[str, Any]) -> list[bytes]:
    """What an attacker with write access does: edit one entry, recompute every hash after it."""
    out = list(lines[:start])
    prev = parse(lines[start])["prev"]
    for i in range(start, len(lines)):
        entry = parse(lines[i])
        if i == start:
            entry.update(edit)
        entry["prev"] = prev
        entry["hash"] = prev = entry_hash(entry)
        out.append(dump(entry))
    return out


def test_edit_with_recomputed_hash_breaks_at_the_next_entry(
    ten: tuple[Path, list[bytes], Head],
) -> None:
    path, lines, head = ten
    entry = {**parse(lines[4]), "tool": "something_else"}
    entry["hash"] = entry_hash(entry)
    assert bad_index(path, lines[:4] + [dump(entry)] + lines[5:]) == 5
    assert "prev" in verify(path).problem
    # on the LAST entry there is no next link: only the trusted head notices
    last = {**parse(lines[9]), "tool": "something_else"}
    last["hash"] = entry_hash(last)
    rewrite(path, lines[:9] + [dump(last)])
    assert verify(path).ok
    assert not verify(path, head.hash).ok


def test_full_rebuild_passes_without_head_and_fails_with_it(
    ten: tuple[Path, list[bytes], Head],
) -> None:
    path, lines, head = ten
    for start in (0, 2, 9):
        rewrite(path, rebuild_from(lines, start, {"jti": "forged"}))
        assert verify(path) == VerifyResult(True, 10, None, None)
        for expected in (head.hash, head):
            result = verify(path, expected)
            assert (result.ok, result.entries, result.first_bad_index) == (False, 10, None)
            assert "rebuilt" in result.problem


def test_truncation_passes_without_head_and_fails_with_it(
    ten: tuple[Path, list[bytes], Head],
) -> None:
    path, lines, head = ten
    for keep in (0, 1, 7, 9):
        rewrite(path, lines[:keep])
        assert verify(path) == VerifyResult(True, keep, None, None)
        by_hash = verify(path, head.hash)
        assert (by_hash.ok, by_hash.first_bad_index) == (False, None)
        assert "truncated" in by_hash.problem
        by_head = verify(path, head)
        assert not by_head.ok and "removed from the end" in by_head.problem
        with pytest.raises(AuditError, match="does not verify"):
            AuditLog(path, expected_head=head)
    # a stale head: the log has grown since it was recorded
    rewrite(path, lines)
    old = Head(6, parse(lines[6])["hash"])
    assert not verify(path, old).ok and "added" in verify(path, old).problem


def test_partial_last_line_after_a_crash(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    for cut in (1, len(lines[9]) // 2, len(lines[9]) - 1):  # the last one lacks only "\n"
        rewrite(path, lines[:9] + [lines[9][:cut]])
        result = verify(path)
        assert (result.ok, result.entries, result.first_bad_index) == (False, 9, 9)
        assert "incomplete last line" in result.problem
        with pytest.raises(AuditError, match="entry 9"):
            AuditLog(path)
    assert path.read_bytes() == b"".join(lines[:9]) + lines[9][:-1]  # nothing was "repaired"


# ---------------------------------------------------------------------- writer


def test_refuses_to_append_to_a_tampered_log(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, _ = ten
    rewrite(path, lines[:3] + [dump(mutate(parse(lines[3]), "tool"))] + lines[4:])
    before = path.read_bytes()
    with pytest.raises(AuditError, match="entry 3"):
        AuditLog(path)
    assert path.read_bytes() == before


def test_reopen_and_continue(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    head = build(path, 4)
    # A5: the writer refuses a clock that restarts below the last entry, so this one continues.
    with AuditLog(path, clock=count(T0 + 10**12).__next__, expected_head=head) as log:
        assert log.head() == head
        add(log, 4)
        add(log, 5)
        new_head = log.head()
    assert new_head.seq == 5
    assert parse(lines_of(path)[4])["prev"] == head.hash
    assert verify(path, new_head) == VerifyResult(True, 6, None, None)
    # one continuous build gives the same chain apart from the restarted clock
    assert [parse(x)["seq"] for x in lines_of(path)] == list(range(6))


def test_one_writer_at_a_time(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    first = AuditLog(path)
    with pytest.raises(AuditError, match="already open"):
        AuditLog(path)
    first.close()
    first.close()  # idempotent
    with pytest.raises(AuditError, match="closed"):
        first.append(jti="j", actors=[], tool="t", args={}, decision="allow", rule="r")
    AuditLog(path).close()
    with pytest.raises(AuditError, match="cannot open"):
        AuditLog(tmp_path / "no-such-dir" / "a.jsonl")


BAD_APPENDS = [
    {"decision": "maybe"},
    {"decision": "approved"},  # no approver
    {"decision": "allow", "approver": "ana"},
    {"decision": "rejected", "approver": ""},
    {"tool": ""},
    {"tool": 5},
    {"jti": None},
    {"rule": None},
    {"actors": "orchestrator"},
    {"actors": [1]},
    {"args": [1, 2]},
    {"args": {"x": float("nan")}},
    {"args": {"x": object()}},
    {"rule": "x" * MAX_LINE_BYTES},
]


@pytest.mark.parametrize("override", BAD_APPENDS)
def test_malformed_appends_write_nothing(tmp_path: Path, override: dict[str, Any]) -> None:
    path = tmp_path / "a.jsonl"
    good = {"jti": "j", "actors": ["a"], "tool": "t", "args": {}, "decision": "allow", "rule": "r"}
    with AuditLog(path, clock=fixed_clock()) as log:
        log.append(**good)
        before, head = path.read_bytes(), log.head()
        with pytest.raises(ValueError):
            log.append(**{**good, **override})
        assert path.read_bytes() == before and log.head() == head
        log.append(**good)
    assert verify(path).entries == 2


def test_bad_clock_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    with AuditLog(path, clock=lambda: 1.5) as log, pytest.raises(ValueError):  # type: ignore[arg-type,return-value]
        log.append(jti="j", actors=[], tool="t", args={}, decision="allow", rule="r")
    assert path.read_bytes() == b""


def test_concurrent_appends_make_one_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    threads, each = 8, 60
    errors: list[BaseException] = []
    with AuditLog(path) as log:
        start = threading.Barrier(threads)

        def worker(n: int) -> None:
            try:
                start.wait()
                for i in range(each):
                    log.append(
                        jti=f"tok-{n}",
                        actors=[f"agent-{n}"],
                        tool="read_file",
                        args={"i": i},
                        decision="allow",
                        rule="r",
                    )
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        pool = [threading.Thread(target=worker, args=(n,)) for n in range(threads)]
        for t in pool:
            t.start()
        for t in pool:
            t.join()
        head = log.head()
    assert not errors
    assert verify(path, head) == VerifyResult(True, threads * each, None, None)
    entries = [parse(x) for x in lines_of(path)]
    assert [e["seq"] for e in entries] == list(range(threads * each))
    for n in range(threads):  # each thread's own entries stay in its own order
        mine = [e["args_hash"] for e in entries if e["jti"] == f"tok-{n}"]
        assert mine == [hash_args({"i": i}) for i in range(each)]


# ------------------------------------------------------------------------- CLI


def test_cli_exit_codes(ten: tuple[Path, list[bytes], Head], capsys: pytest.CaptureFixture) -> None:
    path, lines, head = ten
    assert main(["verify", str(path)]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ok: 10 entries") and head.hash in out and "no --head" in out
    assert main(["verify", str(path), "--head", head.hash]) == 0
    assert "no --head" not in capsys.readouterr().out
    assert main(["verify", str(path), "--head", GENESIS]) == 1
    assert capsys.readouterr().out.startswith("FAILED: ")
    assert main(["verify", str(path.with_name("missing.jsonl"))]) == 1
    capsys.readouterr()
    rewrite(path, lines[:6] + [dump(mutate(parse(lines[6]), "decision"))] + lines[7:])
    assert main(["verify", str(path)]) == 1
    assert capsys.readouterr().out.startswith("FAILED at entry 6: ")
    for bad in (["verify", str(path), "--head", "xyz"], ["verify"], []):
        with pytest.raises(SystemExit) as exit_info:
            main(bad)
        assert exit_info.value.code == 2


def test_cli_as_a_module(ten: tuple[Path, list[bytes], Head]) -> None:
    path, lines, head = ten

    def run(*args: str) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "toolgate.audit", "verify", str(path), *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    good = run("--head", head.hash)
    assert good.returncode == 0 and good.stdout.startswith("ok: 10 entries")
    rewrite(path, lines[:2] + lines[3:])
    bad = run()
    assert bad.returncode == 1 and bad.stdout.startswith("FAILED at entry 2: ")


# ------------------------------------------------------- security review findings

GOOD_APPEND = {
    "jti": "j",
    "actors": ["a"],
    "tool": "t",
    "args": {},
    "decision": "allow",
    "rule": "r",
}


@pytest.fixture(autouse=True)
def _private_umask() -> Any:
    """Files the tests create must not be group-writable, whatever the developer's umask."""
    old = os.umask(0o077)
    yield
    os.umask(old)


def test_a1_a_forked_child_cannot_append(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    with AuditLog(path, clock=fixed_clock()) as log:
        add(log, 0)
        read_end, write_end = os.pipe()
        pid = os.fork()
        if pid == 0:  # the child holds a copy of the lock and of the head
            try:
                try:
                    add(log, 1)
                    report = b"appended"
                except AuditError as exc:
                    report = b"AuditError: " + str(exc).encode()
                except BaseException as exc:  # noqa: BLE001
                    report = repr(exc).encode()
                os.write(write_end, report)
            finally:
                os._exit(0)
        os.close(write_end)
        report = os.read(read_end, 4096)
        os.close(read_end)
        os.waitpid(pid, 0)
        assert report.startswith(b"AuditError: ") and b"fork" in report
        assert len(lines_of(path)) == 1  # the child wrote nothing
        add(log, 1)  # the process that opened the log carries on
        head = log.head()
    assert verify(path, head) == VerifyResult(True, 2, None, None)


def test_a2_interrupt_between_write_and_head_update_breaks_the_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a.jsonl"
    real_fsync, calls = os.fsync, []

    def interrupted_once(fd: int) -> None:
        calls.append(fd)
        if len(calls) == 1:
            raise KeyboardInterrupt
        real_fsync(fd)

    clock = fixed_clock()
    with AuditLog(path, clock=clock) as log:
        add(log, 0)
        monkeypatch.setattr(os, "fsync", interrupted_once)
        with pytest.raises(KeyboardInterrupt):
            add(log, 1)
        assert len(lines_of(path)) == 2  # the entry reached the file
        for _ in range(2):  # and the stale head is never used again
            with pytest.raises(AuditError, match="unusable.*KeyboardInterrupt"):
                add(log, 2)
        assert len(lines_of(path)) == 2
    with AuditLog(path, clock=clock) as log:  # reopening re-verifies and recovers the head
        assert log.head().seq == 1
        add(log, 2)
        head = log.head()
    assert verify(path, head) == VerifyResult(True, 3, None, None)
    assert [parse(x)["seq"] for x in lines_of(path)] == [0, 1, 2]


def test_a3_symlinks_are_refused(tmp_path: Path) -> None:
    real = tmp_path / "real.jsonl"
    build(real, 2)
    before = real.read_bytes()
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    with pytest.raises(AuditError, match="symbolic link"):
        AuditLog(link)
    assert real.read_bytes() == before
    dangling = tmp_path / "dangling.jsonl"
    target = tmp_path / "elsewhere.jsonl"
    dangling.symlink_to(target)
    with pytest.raises(AuditError, match="symbolic link"):
        AuditLog(dangling)
    assert not target.exists()  # nothing was created through the link
    AuditLog(real).close()


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_a3_modes_that_only_the_owner_can_write_are_accepted(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 2)
    path.chmod(mode)
    with AuditLog(path) as log:
        assert log.head().seq == 1


@pytest.mark.parametrize("mode", [0o660, 0o620, 0o602, 0o666, 0o606])
def test_a3_group_or_world_writable_logs_are_refused(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 2)
    before = path.read_bytes()
    path.chmod(mode)
    with pytest.raises(AuditError, match=f"writable.*{mode:#o}"):
        AuditLog(path)
    assert path.read_bytes() == before
    path.chmod(0o600)
    AuditLog(path).close()


def test_a3_new_logs_are_created_private(tmp_path: Path) -> None:
    path = tmp_path / "new.jsonl"
    os.umask(0)
    AuditLog(path).close()
    assert path.stat().st_mode & 0o777 == 0o600


def test_a4_an_old_head_keeps_working_as_a_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    old = build(path, 4)
    with AuditLog(path, clock=count(T0 + 10**12).__next__) as log:
        for i in range(4, 9):
            add(log, i)
        new = log.head()
    assert not verify(path, old).ok  # expected_head keeps its exact meaning
    assert "entries were added" in verify(path, old).problem
    assert verify(path, expected_at=(old.seq, old.hash)) == VerifyResult(True, 9, None, None)
    assert verify(path, new, expected_at=(old.seq, old.hash)).ok
    assert verify(path, expected_at=(new.seq, new.hash)).ok
    assert verify(path, expected_at=(-1, GENESIS)).ok
    assert AuditLog.verify(path, expected_at=(old.seq, old.hash)).ok
    # the right hash at the wrong position is not the checkpoint
    wrong = verify(path, expected_at=(old.seq + 1, old.hash))
    assert (wrong.ok, wrong.entries, wrong.first_bad_index) == (False, 9, None)


def test_a4_a_rebuilt_prefix_fails_the_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 9)
    lines = lines_of(path)
    checkpoint = (3, parse(lines[3])["hash"])
    assert verify(path, expected_at=checkpoint).ok
    for start in (0, 2, 3):
        rewrite(path, rebuild_from(lines, start, {"jti": "forged"}))
        assert verify(path) == VerifyResult(True, 9, None, None)  # consistent on its own
        result = verify(path, expected_at=checkpoint)
        assert (result.ok, result.entries, result.first_bad_index) == (False, 9, None)
        assert "rebuilt" in result.problem and "entry 3" in result.problem
    # a rebuild that starts after the checkpoint leaves the checkpoint intact
    rewrite(path, rebuild_from(lines, 4, {"jti": "forged"}))
    assert verify(path, expected_at=checkpoint).ok


def test_a4_checkpoint_beyond_the_end_fails(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    head = build(path, 9)
    lines = lines_of(path)
    for seq in (9, 10, 500):
        result = verify(path, expected_at=(seq, head.hash))
        assert (result.ok, result.entries, result.first_bad_index) == (False, 9, None)
        assert "removed from the end" in result.problem
    rewrite(path, lines[:5])  # truncation below a checkpoint
    assert verify(path).ok
    assert not verify(path, expected_at=(head.seq, head.hash)).ok
    rewrite(path, [])
    assert not verify(path, expected_at=(0, parse(lines[0])["hash"])).ok
    for bad in ((0, "abc"), (-2, GENESIS), ("0", GENESIS), (True, GENESIS), [0, GENESIS], (0,), 5):
        with pytest.raises(ValueError):
            verify(path, expected_at=bad)  # type: ignore[arg-type]


def test_a4_cli_checkpoint(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    path = tmp_path / "a.jsonl"
    old = build(path, 4)
    with AuditLog(path, clock=count(T0 + 10**12).__next__) as log:
        add(log, 4)
        new = log.head()
    assert main(["verify", str(path), "--checkpoint", f"3:{old.hash}"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("ok: 5 entries") and "checkpoint" in out and "no --head" in out
    assert main(["verify", str(path), "--checkpoint", f"3:{old.hash}", "--head", new.hash]) == 0
    assert "no --head" not in capsys.readouterr().out
    assert main(["verify", str(path), "--head", old.hash]) == 1
    assert main(["verify", str(path), "--checkpoint", f"2:{old.hash}"]) == 1
    assert main(["verify", str(path), "--checkpoint", f"7:{old.hash}"]) == 1
    assert "FAILED: " in capsys.readouterr().out
    for bad in ("3", f"x:{old.hash}", "3:abc", f"{old.hash}", f"3:{old.hash}:1", f"-1:{old.hash}"):
        with pytest.raises(SystemExit) as exit_info:
            main(["verify", str(path), f"--checkpoint={bad}"])
        assert exit_info.value.code == 2


def test_a5_verify_reports_the_first_entry_whose_time_goes_backwards(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 9)
    lines = lines_of(path)
    earlier = parse(lines[2])["time"]
    rewrite(path, rebuild_from(lines, 5, {"time": earlier}))  # consistent hashes, bad order
    result = verify(path)
    assert (result.ok, result.entries, result.first_bad_index) == (False, 5, 5)
    assert "time goes backwards" in result.problem
    assert verify(path, monotonic_time=False) == VerifyResult(True, 9, None, None)
    assert AuditLog.verify(path, monotonic_time=False).ok and not AuditLog.verify(path).ok
    with pytest.raises(AuditError, match="entry 5"):
        AuditLog(path)
    # equal times are fine: the clock only has to never go back
    rewrite(path, rebuild_from(lines, 5, {"time": parse(lines[4])["time"]}))
    assert verify(path).ok


def test_a5_writer_refuses_a_clock_that_goes_backwards(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    times = iter([T0 + 10, T0 + 5, T0 + 10, T0 + 11])
    with AuditLog(path, clock=lambda: next(times)) as log:
        log.append(**GOOD_APPEND)
        before, head = path.read_bytes(), log.head()
        with pytest.raises(AuditError, match="clock went backwards"):
            log.append(**GOOD_APPEND)
        assert path.read_bytes() == before and log.head() == head
        log.append(**GOOD_APPEND)  # not broken: nothing was written, and an equal time is fine
        log.append(**GOOD_APPEND)
    assert verify(path) == VerifyResult(True, 3, None, None)
    # the last time is recovered from the file when the log is reopened
    with AuditLog(path, clock=lambda: T0) as log, pytest.raises(AuditError, match="backwards"):
        log.append(**GOOD_APPEND)
    assert verify(path).entries == 3


def test_a5_cli_empty_log_message(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    path = tmp_path / "a.jsonl"
    path.write_bytes(b"")
    assert main(["verify", str(path)]) == 0
    assert capsys.readouterr().out == (
        "ok: 0 entries (empty log; truncation to empty is only detectable with "
        "--head or --checkpoint)\n"
    )
    assert main(["verify", str(path), "--head", GENESIS]) == 0
    assert capsys.readouterr().out.startswith(f"ok: 0 entries, head {GENESIS}")


@pytest.mark.parametrize(("damage", "code"), [(False, 0), (True, 1)])
def test_a5_cli_survives_a_closed_pipe(tmp_path: Path, damage: bool, code: int) -> None:
    path = tmp_path / "a.jsonl"
    build(path, 3)
    if damage:
        rewrite(path, lines_of(path)[1:])
    cmd = [sys.executable, "-m", "toolgate.audit", "verify", str(path)]
    # `verify log | true`: the reader is gone before anything is printed
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.close()
    stderr = proc.stderr.read()
    proc.stderr.close()
    assert proc.wait(timeout=60) == code
    assert stderr == b""


# A6: loggable and append agree.


def _power_of_ten(digits: int) -> int:
    """Built inside the strategy: Hypothesis cannot print a 5000-digit integer."""
    return 10 ** abs(digits) * (1 if digits > 0 else -1)


_SURROGATE = "\ud800"
_TEXTS = st.sampled_from(
    ["", "t", "read_file", "caf\u00e9", "\U0001f600", _SURROGATE, "a" + _SURROGATE]
)
_BIG_TEXTS = st.sampled_from(["x" * 70_000, "\u00e9" * 6_000, "t" * 32_000, "t" * 33_000])
_LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(),  # includes NaN and both infinities
    st.sampled_from([float("nan"), float("inf"), -float("inf")]),
    st.sampled_from([4000, 5000, -5000]).map(_power_of_ten),  # 5000-digit integers
    st.text(max_size=5),
    _TEXTS,
    st.sampled_from(["x" * 70_000, b"bytes", (1, 2), {1, 2}]),
)
_VALUES = st.recursive(
    _LEAVES,
    lambda inner: st.lists(inner, max_size=3) | st.dictionaries(_TEXTS, inner, max_size=3),
    max_leaves=6,
)
_ARGS = st.one_of(
    st.dictionaries(st.text(max_size=4) | _TEXTS, _VALUES, max_size=3),
    st.dictionaries(st.sampled_from([1, None, "k"]), _VALUES, max_size=2),
    st.sampled_from([None, [1, 2], "x", 5]),
)
_TOOLS = st.one_of(_TEXTS, _BIG_TEXTS, st.text(max_size=8), st.sampled_from([None, 5, b"t", ["t"]]))
_ACTORS = st.one_of(
    st.lists(st.text(max_size=6) | _TEXTS, max_size=4),
    st.lists(_BIG_TEXTS | _TEXTS, max_size=3),
    st.lists(st.sampled_from(["a", 1, None]), max_size=3).map(tuple),
    st.sampled_from([None, "orchestrator", {"a"}, 7]),
)


@settings(max_examples=600, deadline=None)
@given(tool=_TOOLS, args=_ARGS, actors=_ACTORS)
def test_a6_loggable_is_none_exactly_when_append_succeeds(
    tool: Any, args: Any, actors: Any
) -> None:
    reason = loggable(tool, args, actors)
    assert reason is None or (type(reason) is str and 0 < len(reason) < 300)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "a.jsonl"
        with AuditLog(path, clock=fixed_clock()) as log:
            try:
                log.append(
                    jti="tok-1", actors=actors, tool=tool, args=args, decision="allow", rule="r"
                )
                appended = True
            except ValueError:
                appended = False
        assert appended == (reason is None), reason
        assert verify(path) == VerifyResult(True, int(appended), None, None)


def test_a6_loggable_examples_and_no_side_effects(tmp_path: Path) -> None:
    assert loggable("read_file", {"path": "a"}, ["orchestrator", "mailer"]) is None
    assert loggable("t", Call("t", {"x": [1, "a", None]}).args, ()) is None
    assert loggable("t", {"x": "y" * 70_000}, ["a"]) is None  # arguments are hashed, not stored
    for tool, args, actors in [
        ("", {}, []),
        (5, {}, []),
        (_SURROGATE, {}, []),
        ("t", {"x": float("nan")}, []),
        ("t", {"x": float("inf")}, []),
        ("t", {"x": _SURROGATE}, []),
        ("t", {"x": 10**5000}, []),
        ("t", [1], []),
        ("t", {}, "orchestrator"),
        ("t", {}, [_SURROGATE]),
        ("t", {}, [1]),
        ("t" * 70_000, {}, []),
        ("t", {}, ["a" * 40_000]),
    ]:
        reason = loggable(tool, args, actors)
        assert type(reason) is str and reason
    assert list(tmp_path.iterdir()) == []
