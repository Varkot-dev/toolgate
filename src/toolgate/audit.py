"""Hash-chained, append-only audit log of every gateway decision.

The file is JSON Lines: one entry per line, each line ending in "\\n". Every
entry has exactly these fields:

    seq        position in the log, starting at 0
    time       integer nanoseconds since the Unix epoch
    jti        id of the token the call was made with
    actors     the actor chain, a list of strings
    tool       tool name
    args_hash  SHA-256 of the canonical JSON of the call arguments
    decision   allow | deny | approve | approved | rejected
    rule       the policy rule id, or a reason string
    approver   who approved or rejected (required for approved and rejected,
               null otherwise)
    prev       `hash` of the previous entry; a fixed genesis value for seq 0
    hash       SHA-256 of the canonical JSON of all the fields above

Why the arguments are hashed, not stored. A log outlives the tokens it
describes, and arguments can hold secrets or personal data (an email body, a
file's contents). Storing them would turn the audit log into the most
sensitive file in the system, kept the longest. The hash still lets someone
who holds the original arguments prove they are the ones that were decided
on. A hash of a small, guessable argument set can be found by trying
candidates, so the hash hides content, it does not encrypt it.

Canonical JSON means `json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=True, allow_nan=False)`. One value has exactly one byte string,
so "the hash of an entry" is well defined. Entries contain no floats (time is
an integer) so no float formatting question arises in the chain itself.
Argument hashes can cover floats; those use Python's shortest round-trip
float text, and 1 and 1.0 hash differently. Strings are hashed exactly as
given, with no Unicode normalization: two spellings of the same visible text
are different arguments to a tool, so they are different in the log.

Why the chain reveals tampering. Each hash covers the entry's content and the
previous hash, so entry n commits to every entry before it. The verifier
replays the file from the top and reports the FIRST line that is wrong: not
valid JSON, not in canonical form, unknown or missing fields, wrong seq, a
`prev` that is not the previous hash, or a `hash` that does not match the
content. It checks the bytes of each line, not just the parsed values, so a
changed space or escape is caught as well.

What it does not do, stated plainly. A hash chain has no secret in it. It is
tamper-EVIDENT only relative to a trusted copy of the head hash kept
somewhere the attacker cannot write.

  * Without `expected_head`, `verify` proves internal consistency only.
    Someone with write access can delete entries from the END of the file, or
    edit any entry and recompute every hash from there on (a full rebuild),
    and the result verifies.
  * An attacker who edits entry i and recomputes only that entry's hash moves
    the visible break to entry i + 1, whose `prev` no longer matches. If i is
    the last entry there is no break to see.
  * With `expected_head` (the value `AuditLog.head()` returned, published
    outside the machine) truncation and rebuild are both detected, because
    the last hash can no longer be the published one. The verifier then knows
    that the log changed, not where: `first_bad_index` is None.

Crash behaviour. Each append is one write followed by fsync. A crash in the
middle can leave a last line with no newline. Verification reports that line,
and `AuditLog` refuses to open the file, because cutting the partial line off
automatically would also be how an attacker hides a truncation. Repair is a
deliberate act by an operator.

One writer per file: appends are serialized by a lock inside the process, and
on POSIX an exclusive `flock` stops a second process or a second `AuditLog`
on the same file from forking the chain. `os.fork` copies both the lock and
the in-memory head into the child, so the log remembers the process that
opened it and refuses to append from any other. An append that is interrupted
between the write and the head update (an OS error, or Ctrl-C) leaves the log
object refusing further appends until the file is reopened and re-verified.

The file itself: the path must not be a symbolic link (it is opened with
O_NOFOLLOW), and an existing log that is group- or world-writable is refused.

Time. `time` never decreases along the log. The writer refuses an append whose
clock value is lower than the previous entry's, and the verifier reports the
first entry that goes backwards (`monotonic_time=False` turns that check off
for logs written before the rule existed). A wall clock that steps backwards
therefore stops appends until it catches up; that is deliberate.

Checkpoints. `expected_head` means "the log ends exactly here", so a published
head stops being usable the moment the log grows. `expected_at=(seq, hash)`
means "the entry at this seq has this hash" and keeps working as the log
grows: because each hash commits to everything before it, an old published
head still proves that the prefix up to it was not rewritten. It says nothing
about entries after it.

Command line:

    python -m toolgate.audit verify <path> [--head HASH] [--checkpoint SEQ:HASH]

prints `ok` or the first bad index, and exits nonzero on failure.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import json
import math
import os
import stat
import sys
import threading
import time as _time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO

try:  # POSIX only; on other systems the in-process lock is the only guard
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

GENESIS: str = hashlib.sha256(b"toolgate audit log v1").hexdigest()
DECISIONS: frozenset[str] = frozenset({"allow", "deny", "approve", "approved", "rejected"})
FIELDS: tuple[str, ...] = (
    "seq",
    "time",
    "jti",
    "actors",
    "tool",
    "args_hash",
    "decision",
    "rule",
    "approver",
    "prev",
    "hash",
)
MAX_LINE_BYTES = 65_536
# Canonical JSON of [tool, actors] may take at most half a line, which leaves the other half
# for jti, rule and approver. `loggable` and `append` both enforce it.
MAX_CALL_BYTES = MAX_LINE_BYTES // 2
_MAX_DEPTH = 32
_HEX = frozenset("0123456789abcdef")


class AuditError(Exception):
    """The log cannot be opened or appended to."""


@dataclass(frozen=True)
class Head:
    """The last entry's seq and hash. An empty log has seq -1 and the genesis hash."""

    seq: int
    hash: str


@dataclass(frozen=True)
class VerifyResult:
    """`entries` counts the valid entries before the first bad one (all of them if ok)."""

    ok: bool
    entries: int
    first_bad_index: int | None
    problem: str | None

    def __bool__(self) -> bool:
        return self.ok


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    time: int
    jti: str
    actors: tuple[str, ...]
    tool: str
    args_hash: str
    decision: str
    rule: str
    approver: str | None
    prev: str
    hash: str

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["actors"] = list(self.actors)
        return out


# ----------------------------------------------------------------- canonical JSON


def _jsonable(value: Any, depth: int = 0) -> Any:
    """Copy plain data into dicts and lists, rejecting anything JSON cannot carry exactly."""
    if depth > _MAX_DEPTH:
        raise ValueError("value is nested too deeply")
    t = type(value)
    if value is None or t in (bool, int):
        return value
    if t is float:
        if not math.isfinite(value):
            raise ValueError("NaN and infinity cannot be hashed")
        return value
    if t is str:
        value.encode("utf-8")  # raises on lone surrogates
        return value
    if t in (list, tuple):
        return [_jsonable(v, depth + 1) for v in value]
    if t in (dict, MappingProxyType):
        out = {}
        for k, v in value.items():
            if type(k) is not str:
                raise ValueError("object keys must be strings")
            k.encode("utf-8")
            out[k] = _jsonable(v, depth + 1)
        return out
    raise ValueError(f"unsupported type {t.__name__}")


def canonical_json(value: Any) -> bytes:
    """The one byte string for a JSON value: sorted keys, no spaces, ASCII only, no NaN."""
    return json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def hash_args(args: Mapping[str, Any]) -> str:
    """SHA-256 (hex) of the canonical JSON of a call's arguments. Accepts `Call.args`."""
    if type(args) not in (dict, MappingProxyType):
        raise ValueError("arguments must be a dict")
    return hashlib.sha256(canonical_json(args)).hexdigest()


def entry_hash(fields: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON of every field except `hash`."""
    return hashlib.sha256(
        canonical_json({k: v for k, v in fields.items() if k != "hash"})
    ).hexdigest()


# --------------------------------------------------------------------- validation


def _is_hash(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _HEX


def _is_text(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _field_problem(entry: Mapping[str, Any]) -> str | None:
    """Why this dict is not a well-formed entry, or None if it is. Chain links are not checked."""
    missing = [f for f in FIELDS if f not in entry]
    if missing:
        return f"missing field {missing[0]!r}"
    unknown = sorted(k for k in entry if k not in FIELDS)
    if unknown:
        return f"unknown field {unknown[0]!r}"
    for name in ("seq", "time"):
        if type(entry[name]) is not int or entry[name] < 0:
            return f"{name} must be a non-negative integer"
    for name in ("jti", "tool", "rule"):
        if not _is_text(entry[name]):
            return f"{name} must be a string"
    if not entry["tool"]:
        return "tool must not be empty"
    actors = entry["actors"]
    if type(actors) is not list or not all(_is_text(a) for a in actors):
        return "actors must be a list of strings"
    if type(entry["decision"]) is not str or entry["decision"] not in DECISIONS:
        return f"unknown decision {entry['decision']!r}"
    approver = entry["approver"]
    if entry["decision"] in ("approved", "rejected"):
        if not _is_text(approver) or not approver:
            return f"decision {entry['decision']!r} needs an approver"
    elif approver is not None:
        return f"decision {entry['decision']!r} must not have an approver"
    for name in ("args_hash", "prev", "hash"):
        if not _is_hash(entry[name]):
            return f"{name} must be 64 lowercase hex characters"
    return None


class _Bad(Exception):
    """Internal: this line is the first bad one, and why."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _Bad(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _no_float(text: str) -> Any:
    raise _Bad(f"number {text[:20]!r} is not an integer")


def _check_line(raw: bytes, index: int, prev: str) -> str:
    """Return the hash of the entry on this line, or raise _Bad with the first problem."""
    return _check_entry(raw, index, prev)[0]


def _check_entry(raw: bytes, index: int, prev: str) -> tuple[str, int]:
    """Like `_check_line`, but also returns the entry's time."""
    if not raw.endswith(b"\n"):
        if len(raw) > MAX_LINE_BYTES:
            raise _Bad(f"line is longer than {MAX_LINE_BYTES} bytes")
        raise _Bad("incomplete last line (no newline): a crash during a write, or truncation")
    body = raw[:-1]
    try:
        text = body.decode("ascii")
    except UnicodeDecodeError:
        raise _Bad("line is not ASCII") from None
    try:
        entry = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_float=_no_float, parse_constant=_no_float
        )
    except (ValueError, RecursionError) as exc:
        raise _Bad(f"line is not valid JSON ({str(exc)[:80]})") from None
    if type(entry) is not dict:
        raise _Bad("line is not a JSON object")
    problem = _field_problem(entry)
    if problem:
        raise _Bad(problem)
    if canonical_json(entry) != body:
        raise _Bad("line is not in canonical form (key order, spacing or escapes differ)")
    if entry["seq"] != index:
        raise _Bad(
            f"seq is {entry['seq']} but this is line {index}: an entry was removed, added or moved"
        )
    if entry["prev"] != prev:
        raise _Bad(f"prev is {entry['prev'][:12]} but the previous entry's hash is {prev[:12]}")
    expected = entry_hash(entry)
    if entry["hash"] != expected:
        raise _Bad(
            f"stored hash {entry['hash'][:12]} does not match the entry's content "
            f"(recomputed {expected[:12]})"
        )
    return expected, entry["time"]


def _scan(stream: BinaryIO) -> tuple[VerifyResult, Head]:
    """Replay the chain. Returns the result and the head of the valid prefix."""
    result, head, _, _ = _replay(stream)
    return result, head


def _replay(
    stream: BinaryIO, *, monotonic_time: bool = True, at: int | None = None
) -> tuple[VerifyResult, Head, int, str | None]:
    """Replay the chain: the result, the head and last time of the valid prefix, and the
    hash of entry `at` if the valid prefix reaches it."""
    prev, index, last_time = GENESIS, 0, 0
    found = GENESIS if at == -1 else None
    while True:
        raw = stream.readline(MAX_LINE_BYTES + 1)
        if not raw:
            return VerifyResult(True, index, None, None), Head(index - 1, prev), last_time, found
        try:
            digest, when = _check_entry(raw, index, prev)
            if monotonic_time and when < last_time:
                raise _Bad(
                    f"time goes backwards: {when} is earlier than the previous entry's {last_time}"
                )
        except _Bad as bad:
            result = VerifyResult(False, index, index, str(bad))
            return result, Head(index - 1, prev), last_time, found
        prev, last_time = digest, when
        if index == at:
            found = digest
        index += 1


def _expected(expected_head: str | Head | None) -> tuple[int | None, str | None]:
    if expected_head is None:
        return None, None
    if type(expected_head) is Head:
        seq, digest = expected_head.seq, expected_head.hash
    else:
        seq, digest = None, expected_head
    if not _is_hash(digest):
        raise ValueError("expected_head must be a 64 character lowercase hex hash or a Head")
    return seq, digest


def _check_head(result: VerifyResult, head: Head, expected_head: str | Head | None) -> VerifyResult:
    seq, digest = _expected(expected_head)
    if not result.ok or digest is None:
        return result
    if seq is not None and head.seq != seq:
        what = "entries were removed from the end" if head.seq < seq else "entries were added"
        return VerifyResult(
            False,
            result.entries,
            None,
            f"the log ends at entry {head.seq} but the expected head is entry {seq}: {what}",
        )
    if head.hash != digest:
        return VerifyResult(
            False,
            result.entries,
            None,
            f"every entry is consistent, but the last hash is {head.hash[:12]} and the expected "
            f"head is {digest[:12]}: the log was truncated, extended or rebuilt",
        )
    return result


def _checkpoint(expected_at: tuple[int, str] | Head | None) -> tuple[int, str] | None:
    if expected_at is None:
        return None
    if type(expected_at) is Head:
        expected_at = (expected_at.seq, expected_at.hash)
    if type(expected_at) is not tuple or len(expected_at) != 2:
        raise ValueError("expected_at must be a (seq, hash) pair")
    seq, digest = expected_at
    if type(seq) is not int or seq < -1 or not _is_hash(digest):
        raise ValueError("expected_at must be (seq, 64 character lowercase hex hash)")
    return seq, digest


def _check_at(
    result: VerifyResult, head: Head, checkpoint: tuple[int, str] | None, found: str | None
) -> VerifyResult:
    if not result.ok or checkpoint is None:
        return result
    seq, digest = checkpoint
    if seq > head.seq or found is None:
        problem = (
            f"the checkpoint is entry {seq} but the log ends at entry {head.seq}: "
            "entries were removed from the end"
        )
    elif found != digest:
        problem = (
            f"every entry is consistent, but entry {seq} has hash {found[:12]} and the "
            f"checkpoint says {digest[:12]}: the log was rebuilt at or before entry {seq}"
        )
    else:
        return result
    return VerifyResult(False, result.entries, None, problem)


def verify(
    path: str | Path,
    expected_head: str | Head | None = None,
    *,
    expected_at: tuple[int, str] | None = None,
    monotonic_time: bool = True,
) -> VerifyResult:
    """Replay the log at `path` and report the first bad entry.

    Without `expected_head` this proves internal consistency only: truncation
    of the tail and a full rebuild of the chain both pass. Pass the head hash
    (or `Head`) that was recorded somewhere trusted to detect those too.

    `expected_head` must be the log's LAST entry. `expected_at=(seq, hash)` is
    a checkpoint instead: the entry at `seq` must have that hash, and the log
    may have grown past it. An old published head used this way keeps proving
    that the prefix up to it was not rewritten. `monotonic_time` also reports
    the first entry whose `time` is lower than the entry before it.
    """
    return _verify(path, expected_head, expected_at, monotonic_time)[0]


def _verify(
    path: str | Path,
    expected_head: str | Head | None,
    expected_at: tuple[int, str] | None = None,
    monotonic_time: bool = True,
) -> tuple[VerifyResult, Head]:
    _expected(expected_head)  # reject a malformed head before touching the file
    checkpoint = _checkpoint(expected_at)
    try:
        with open(path, "rb") as stream:
            result, head, _, found = _replay(
                stream,
                monotonic_time=monotonic_time,
                at=None if checkpoint is None else checkpoint[0],
            )
    except OSError as exc:
        problem = f"cannot read the log: {exc.strerror or exc}"
        return VerifyResult(False, 0, None, problem), Head(-1, GENESIS)
    result = _check_head(result, head, expected_head)
    return _check_at(result, head, checkpoint, found), head


# ------------------------------------------------------------------- loggability


def _call_size_problem(tool: str, actors: Sequence[str]) -> str | None:
    size = len(canonical_json([tool, list(actors)]))
    if size > MAX_CALL_BYTES:
        return f"tool and actors take {size} bytes as JSON, more than {MAX_CALL_BYTES}"
    return None


def loggable(tool: Any, args: Any, actors: Any) -> str | None:
    """None if `AuditLog.append` would accept this tool, arguments and actor chain,
    otherwise a short reason. Writes nothing and needs no log.

    A gateway calls this before any side effect, so a call that could not be
    recorded is denied instead of being run and then failing to log. It covers
    the three values a caller controls. The other fields (jti, rule, approver)
    come from the gateway itself; the answer holds as long as their canonical
    JSON together stays under 32,000 bytes, because `tool` and `actors` are
    limited to `MAX_CALL_BYTES` and a whole line to `MAX_LINE_BYTES`.
    """
    if type(actors) not in (list, tuple):
        return "actors must be a list of strings"
    try:
        hash_args(args)
    except ValueError as exc:
        return f"arguments cannot be hashed: {str(exc)[:120]}"
    if not _is_text(tool):
        return "tool must be a string"
    if not tool:
        return "tool must not be empty"
    if not all(_is_text(a) for a in actors):
        return "actors must be a list of strings"
    return _call_size_problem(tool, actors)


# ------------------------------------------------------------------------ writer


class AuditLog:
    """The single writer of one audit log file.

    Opening verifies the whole file and recovers the head from it. A file
    that does not verify is never appended to: `AuditError` is raised instead.
    `clock` returns integer nanoseconds and exists so tests and figures can
    fix the time.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], int] = _time.time_ns,
        expected_head: str | Head | None = None,
    ) -> None:
        self._path = Path(path)
        self._clock = clock
        self._lock = threading.Lock()
        self._broken: str | None = None
        self._fd: int | None = None
        self._pid = os.getpid()
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self._path, flags, 0o600)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise AuditError(
                    "cannot open the log: the path is a symbolic link, which is refused"
                ) from exc
            raise AuditError(f"cannot open the log: {exc.strerror or exc}") from exc
        try:
            mode = stat.S_IMODE(os.fstat(fd).st_mode)
            if mode & 0o022:
                raise AuditError(
                    f"refusing to open a log that is group- or world-writable (mode {mode:#o}); "
                    "remove those permissions, for example chmod 600"
                )
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    raise AuditError("the log is already open for writing elsewhere") from None
            # Read through the locked descriptor, so the file checked is the file written.
            with os.fdopen(os.dup(fd), "rb") as stream:
                result, head, last_time, _ = _replay(stream)
            result = _check_head(result, head, expected_head)
            if not result.ok:
                at = "" if result.first_bad_index is None else f"entry {result.first_bad_index}: "
                raise AuditError(
                    f"refusing to append to a log that does not verify: {at}{result.problem}"
                )
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        self._head = head
        self._last_time = last_time

    @property
    def path(self) -> Path:
        return self._path

    def head(self) -> Head:
        """Seq and hash of the last entry: the value to publish somewhere external."""
        with self._lock:
            return self._head

    def append(
        self,
        *,
        jti: str,
        actors: Sequence[str],
        tool: str,
        args: Mapping[str, Any],
        decision: str,
        rule: str,
        approver: str | None = None,
    ) -> AuditEntry:
        """Write one entry, flushed and fsynced before returning.

        Raises ValueError for a malformed entry (nothing is written) and
        AuditError if the write fails. After a failed or interrupted write the
        log object refuses further appends, because the state of the file is
        unknown. AuditError is also raised, with nothing written, in a process
        other than the one that opened the log (after a fork) and when the
        clock returns a time earlier than the previous entry's.
        """
        if type(actors) not in (list, tuple):
            raise ValueError("actors must be a list of strings")
        args_hash = hash_args(args)
        with self._lock:
            if self._fd is None:
                raise AuditError("the log is closed")
            if os.getpid() != self._pid:
                raise AuditError(
                    f"the log was opened by process {self._pid} and this is process "
                    f"{os.getpid()} (a fork); two processes appending would fork the chain, "
                    "so open the log again in the process that should write"
                )
            if self._broken:
                raise AuditError(f"the log is unusable after a failed write: {self._broken}")
            fields: dict[str, Any] = {
                "seq": self._head.seq + 1,
                "time": self._clock(),
                "jti": jti,
                "actors": list(actors),
                "tool": tool,
                "args_hash": args_hash,
                "decision": decision,
                "rule": rule,
                "approver": approver,
                "prev": self._head.hash,
                "hash": GENESIS,  # placeholder so the shape can be validated
            }
            problem = _field_problem(fields)
            if problem:
                raise ValueError(problem)
            problem = _call_size_problem(tool, fields["actors"])
            if problem:
                raise ValueError(problem)
            if fields["time"] < self._last_time:
                raise AuditError(
                    f"the clock went backwards: it returned {fields['time']} and the previous "
                    f"entry's time is {self._last_time}; nothing was written"
                )
            fields["hash"] = entry_hash(fields)
            line = canonical_json(fields) + b"\n"
            if len(line) > MAX_LINE_BYTES:
                raise ValueError(f"entry is longer than {MAX_LINE_BYTES} bytes")
            try:
                written = os.write(self._fd, line)
                if written != len(line):
                    raise OSError(f"short write ({written} of {len(line)} bytes)")
                os.fsync(self._fd)
            except OSError as exc:
                self._broken = str(exc)
                raise AuditError(f"could not write the entry: {exc}") from exc
            except BaseException as exc:
                # Interrupted between the write and the head update: the entry may be on
                # disk while the head here is stale. Appending again would repeat a seq.
                self._broken = f"interrupted by {type(exc).__name__}; reopen the log"
                raise
            self._head = Head(fields["seq"], fields["hash"])
            self._last_time = fields["time"]
            fields["actors"] = tuple(fields["actors"])
            return AuditEntry(**fields)

    @staticmethod
    def verify(
        path: str | Path,
        expected_head: str | Head | None = None,
        *,
        expected_at: tuple[int, str] | None = None,
        monotonic_time: bool = True,
    ) -> VerifyResult:
        """Same as the module-level `verify`."""
        return verify(path, expected_head, expected_at=expected_at, monotonic_time=monotonic_time)

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)  # also releases the flock
                self._fd = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        fd = getattr(self, "_fd", None)
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
            self._fd = None


# --------------------------------------------------------------------------- CLI


def _say(text: str) -> None:
    """Print one line; a reader that has gone away (`| true`, `| head`) is not an error."""
    try:
        print(text, flush=True)
    except BrokenPipeError:
        # Point stdout at /dev/null so the interpreter's final flush stays quiet too.
        with contextlib.suppress(OSError, ValueError):
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
            os.close(devnull)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m toolgate.audit")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "verify", help="replay the hash chain and report the first bad entry"
    )
    check.add_argument("path")
    check.add_argument("--head", help="trusted head hash; also detects truncation and rebuild")
    check.add_argument(
        "--checkpoint",
        metavar="SEQ:HASH",
        help="trusted hash of the entry at SEQ; the log may have grown since, but a rewrite "
        "of anything up to SEQ is detected",
    )
    options = parser.parse_args(argv)
    if options.head is not None and not _is_hash(options.head):
        parser.error("--head must be 64 lowercase hex characters")
    checkpoint = None
    if options.checkpoint is not None:
        seq, _, digest = options.checkpoint.partition(":")
        if not (seq.isascii() and seq.isdigit() and len(seq) <= 18 and _is_hash(digest)):
            parser.error("--checkpoint must be SEQ:HASH, a number and 64 lowercase hex characters")
        checkpoint = (int(seq), digest)
    result, head = _verify(options.path, options.head, checkpoint)
    if result.ok:
        if result.entries == 0 and not options.head and checkpoint is None:
            _say(
                "ok: 0 entries (empty log; truncation to empty is only detectable with "
                "--head or --checkpoint)"
            )
            return 0
        if options.head:
            note = ""
        elif checkpoint is not None:
            note = (
                f" (entry {checkpoint[0]} matches the checkpoint; entries after it are "
                "checked for internal consistency only: no --head given)"
            )
        else:
            note = " (internal consistency only: no --head given)"
        _say(f"ok: {result.entries} entries, head {head.hash}{note}")
        return 0
    if result.first_bad_index is None:
        _say(f"FAILED: {result.problem}")
    else:
        _say(f"FAILED at entry {result.first_bad_index}: {result.problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
