"""Shared state for the token layer: revoked token ids and the call-budget ledger.

Everything else about a token is carried inside its signed bytes. Two things
cannot be: whether somebody revoked it after it was signed, and how many calls
have already been made against a budget. Both live here.

The ledger is keyed by (token id, capability index). Each entry has a limit
(None means unlimited) and a usage counter. The one operation that matters is
`charge(path)`: `path` lists the entry of the token making the call and the
entry of every ancestor it was derived from. The charge succeeds only if every
entry exists, no token on the path is revoked and every entry with a limit has
room; then every counter goes up by one. All or nothing, under one lock (in
memory) or one transaction (SQLite). That is what stops two sibling sub-agents
from each spending their parent's whole budget.

Fail closed: an entry the store has never heard of is a refusal, not
"unlimited". A store that lost its data therefore denies budgeted calls instead
of forgetting every budget.

Growth is bounded in two ways. `add_child` counts the tokens exchanged from one
parent and refuses past a limit, and `prune(now)` forgets tokens whose expiry
has passed. Pruning is never run by the store itself; the owner decides when.
"""

from __future__ import annotations

import contextlib
import math
import sqlite3
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Protocol, TypeVar, runtime_checkable

Entry = tuple[str, int]  # (token id, capability index)

_MAX_INDEX = 2**31 - 1
_T = TypeVar("_T")


@dataclass(frozen=True)
class ChargeResult:
    """Outcome of `Store.charge`. Truthy only when every counter was incremented."""

    ok: bool
    reason: str  # "ok", "exhausted", "revoked" or "unknown"

    def __bool__(self) -> bool:
        return self.ok


_OK = ChargeResult(True, "ok")
_EXHAUSTED = ChargeResult(False, "exhausted")
_REVOKED = ChargeResult(False, "revoked")
_UNKNOWN = ChargeResult(False, "unknown")


@runtime_checkable
class Store(Protocol):
    """What the token service needs from its state. Every method is thread safe."""

    def revoke(self, jti: str) -> None:
        """Mark a token id as revoked. Revoking twice is harmless."""
        ...

    def any_revoked(self, jtis: Iterable[str]) -> bool:
        """True if at least one of the given token ids is revoked."""
        ...

    def register(
        self, jti: str, limits: Sequence[int | None], exp: int | float | None = None
    ) -> None:
        """Create the ledger entries (jti, 0..n-1) with the given limits.

        `exp` is the token's expiry in seconds since the epoch. It is only
        used by `prune`; a token registered without one is never pruned.
        Raises ValueError if the token id was registered before.
        """
        ...

    def add_child(self, parent_jti: str, max_children: int) -> bool:
        """Count one more child token exchanged from `parent_jti`.

        Atomic test and increment: True if the parent is registered and had
        fewer than `max_children` children, in which case its counter went up
        by one. False otherwise, and nothing changed.
        """
        ...

    def prune(self, now: int | float) -> int:
        """Forget every token registered with exp <= now. Returns how many.

        Removes the token's ledger entries, its child counter and its
        revocation entry.
        """
        ...

    def charge(self, path: Sequence[Entry]) -> ChargeResult:
        """Atomically add one call to every entry on `path`, or to none."""
        ...

    def usage(self, jti: str, index: int) -> tuple[int, int | None] | None:
        """(calls used, limit) for one entry, or None if it does not exist."""
        ...

    def is_registered(self, jti: str) -> bool:
        """True if `register` was ever called for this token id."""
        ...


def _check_id(jti: object) -> str:
    if type(jti) is not str or not jti:
        raise ValueError("token id must be a non-empty string")
    return jti


def _check_limits(limits: Sequence[int | None]) -> list[int | None]:
    out = list(limits)
    for limit in out:
        if limit is not None and (type(limit) is not int or not 1 <= limit <= _MAX_INDEX):
            raise ValueError("a limit must be a positive integer or None")
    return out


def _check_time(value: object, what: str) -> int | float:
    """An int or a finite float; bool is refused."""
    if type(value) is int or (type(value) is float and math.isfinite(value)):
        return value
    raise ValueError(f"{what} must be a finite number")


def _check_exp(exp: object) -> int | float | None:
    return None if exp is None else _check_time(exp, "exp")


def _check_max_children(max_children: object) -> int:
    if type(max_children) is not int or not 0 <= max_children <= _MAX_INDEX:
        raise ValueError("max_children must be a non-negative integer")
    return max_children


# Why `prune` may forget an expired token completely:
#
#   * The token itself. verify compares the signed `exp` with the clock before
#     it asks the store anything, so an expired token is refused with or
#     without its rows. Once the rows are gone it is also an unknown token,
#     which still refuses it if the clock is ever set backwards.
#   * Its revocation entry. A revocation only has to outlive the tokens it
#     blocks. Those are the revoked token and its descendants, and exchange
#     never signs a child with a later exp than its parent, so by induction
#     every descendant has exp <= the revoked token's exp. When the revoked
#     token has expired they all have, and the entry no longer blocks
#     anything that would otherwise pass.
#   * An ancestor's ledger entries and child counter. Same argument: every
#     descendant that charges along this ancestor expires no later than it
#     does, so no live token still needs the ancestor's rows. And if one
#     somehow did, a missing entry is a refusal ("unknown"), never "unlimited".
#
# What prune cannot forget: a token registered without an exp, and a
# revocation of an id that was never registered here (its expiry is unknown).


def _count_path(path: Sequence[Entry]) -> Counter[Entry] | None:
    """Entries of a well-formed path with how often each occurs, else None."""
    try:
        entries = list(path)
    except TypeError:
        return None
    if not entries:
        return None
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 2:
            return None
        jti, index = entry
        if type(jti) is not str or not jti:
            return None
        if type(index) is not int or not 0 <= index <= _MAX_INDEX:
            return None
    return Counter(entries)


class MemoryStore:
    """In-process store. State is lost on restart; use SqliteStore to keep it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked: set[str] = set()
        self._registered: set[str] = set()
        self._limits: dict[Entry, int | None] = {}
        self._used: dict[Entry, int] = {}
        self._exp: dict[str, int | float] = {}  # only tokens registered with an exp
        self._size: dict[str, int] = {}  # number of ledger entries per token
        self._children: dict[str, int] = {}

    def revoke(self, jti: str) -> None:
        _check_id(jti)
        with self._lock:
            self._revoked.add(jti)

    def any_revoked(self, jtis: Iterable[str]) -> bool:
        wanted = [_check_id(j) for j in jtis]
        with self._lock:
            return any(j in self._revoked for j in wanted)

    def register(
        self, jti: str, limits: Sequence[int | None], exp: int | float | None = None
    ) -> None:
        _check_id(jti)
        checked = _check_limits(limits)
        expiry = _check_exp(exp)
        with self._lock:
            if jti in self._registered:
                raise ValueError(f"token id {jti!r} is already registered")
            self._registered.add(jti)
            self._size[jti] = len(checked)
            if expiry is not None:
                self._exp[jti] = expiry
            for index, limit in enumerate(checked):
                self._limits[(jti, index)] = limit
                self._used[(jti, index)] = 0

    def add_child(self, parent_jti: str, max_children: int) -> bool:
        _check_id(parent_jti)
        _check_max_children(max_children)
        with self._lock:
            if parent_jti not in self._registered:
                return False
            count = self._children.get(parent_jti, 0)
            if count >= max_children:
                return False
            self._children[parent_jti] = count + 1
            return True

    def prune(self, now: int | float) -> int:
        _check_time(now, "now")
        with self._lock:
            expired = [jti for jti, exp in self._exp.items() if exp <= now]
            for jti in expired:
                for index in range(self._size.pop(jti)):
                    del self._limits[(jti, index)]
                    del self._used[(jti, index)]
                del self._exp[jti]
                self._registered.discard(jti)
                self._children.pop(jti, None)
                self._revoked.discard(jti)
            return len(expired)

    def charge(self, path: Sequence[Entry]) -> ChargeResult:
        counts = _count_path(path)
        if counts is None:
            return _UNKNOWN
        with self._lock:
            # Phase 1: look, change nothing.
            if any(jti in self._revoked for jti, _ in counts):
                return _REVOKED
            if any(entry not in self._used for entry in counts):
                return _UNKNOWN
            for entry, n in counts.items():
                limit = self._limits[entry]
                if limit is not None and self._used[entry] + n > limit:
                    return _EXHAUSTED
            # Phase 2: nothing below can fail, so the update is all or nothing.
            for entry, n in counts.items():
                self._used[entry] += n
            return _OK

    def usage(self, jti: str, index: int) -> tuple[int, int | None] | None:
        with self._lock:
            entry = (jti, index)
            if entry not in self._used:
                return None
            return self._used[entry], self._limits[entry]

    def is_registered(self, jti: str) -> bool:
        with self._lock:
            return jti in self._registered


_SCHEMA = """
CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS registered (
    jti       TEXT    PRIMARY KEY,
    exp,
    children  INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS budget (
    jti   TEXT    NOT NULL,
    idx   INTEGER NOT NULL,
    lim   INTEGER,
    used  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (jti, idx)
) WITHOUT ROWID;
"""


def _to_sql(value: int | float | None) -> int | float | None:
    """SQLite integers are 64 bit; a larger int is stored as a float instead."""
    if type(value) is int and not -(2**63) <= value < 2**63:
        return float(value)
    return value


class SqliteStore:
    """SQLite-backed store. `path` is a file name or ":memory:".

    One connection guarded by a lock serves all threads of this process. Every
    write runs inside BEGIN IMMEDIATE, which takes SQLite's write lock up
    front, so several processes (or several SqliteStore objects) on the same
    file also see each charge as one atomic step.
    """

    def __init__(self, path: str, timeout: float = 30.0) -> None:
        self._lock = threading.Lock()
        # isolation_level=None: no implicit transactions, we write BEGIN/COMMIT.
        self._db = sqlite3.connect(
            str(path), timeout=timeout, isolation_level=None, check_same_thread=False
        )
        with self._lock:
            self._db.executescript(_SCHEMA)
        self._write(self._migrate)

    @staticmethod
    def _migrate(db: sqlite3.Connection) -> None:
        """Add the columns a database file from before pruning does not have."""
        columns = {row[1] for row in db.execute("PRAGMA table_info(registered)")}
        if "exp" not in columns:
            db.execute("ALTER TABLE registered ADD COLUMN exp")
        if "children" not in columns:
            db.execute("ALTER TABLE registered ADD COLUMN children INTEGER NOT NULL DEFAULT 0")
        db.execute("CREATE INDEX IF NOT EXISTS registered_exp ON registered (exp)")

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._db.close()

    def _write(self, work: Callable[[sqlite3.Connection], _T]) -> _T:
        """Run `work(db)` in one write transaction; roll back if anything fails.

        "Anything" includes COMMIT itself. COMMIT can fail with "database is
        locked" when another connection still holds a read lock, and SQLite
        then leaves the transaction open. Without the rollback every later
        BEGIN on this connection would fail, so no revocation could be
        recorded while reads (and so verify) kept working.
        """
        with self._lock:
            if self._db.in_transaction:  # left over from a rollback that failed
                self._rollback()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = work(self._db)
                self._db.execute("COMMIT")
            except BaseException:
                self._rollback()
                raise
            return result

    def _rollback(self) -> None:
        """Roll back, without hiding the error that led here behind a new one."""
        # If this fails there was nothing to roll back, or the next _write retries.
        with contextlib.suppress(sqlite3.Error):
            self._db.execute("ROLLBACK")

    def revoke(self, jti: str) -> None:
        _check_id(jti)
        self._write(lambda db: db.execute("INSERT OR IGNORE INTO revoked (jti) VALUES (?)", (jti,)))

    def any_revoked(self, jtis: Iterable[str]) -> bool:
        wanted = [_check_id(j) for j in jtis]
        with self._lock:
            return any(self._is_revoked(self._db, j) for j in wanted)

    @staticmethod
    def _is_revoked(db: sqlite3.Connection, jti: str) -> bool:
        return db.execute("SELECT 1 FROM revoked WHERE jti = ?", (jti,)).fetchone() is not None

    def register(
        self, jti: str, limits: Sequence[int | None], exp: int | float | None = None
    ) -> None:
        _check_id(jti)
        checked = _check_limits(limits)
        expiry = _to_sql(_check_exp(exp))

        def work(db: sqlite3.Connection) -> None:
            try:
                db.execute("INSERT INTO registered (jti, exp) VALUES (?, ?)", (jti, expiry))
            except sqlite3.IntegrityError:
                raise ValueError(f"token id {jti!r} is already registered") from None
            db.executemany(
                "INSERT INTO budget (jti, idx, lim, used) VALUES (?, ?, ?, 0)",
                [(jti, index, limit) for index, limit in enumerate(checked)],
            )

        self._write(work)

    def add_child(self, parent_jti: str, max_children: int) -> bool:
        _check_id(parent_jti)
        _check_max_children(max_children)
        # One statement inside one write transaction: the test and the
        # increment cannot be separated by another thread or process.
        done = self._write(
            lambda db: (
                db.execute(
                    "UPDATE registered SET children = children + 1 WHERE jti = ? AND children < ?",
                    (parent_jti, max_children),
                ).rowcount
            )
        )
        return done == 1

    def prune(self, now: int | float) -> int:
        cutoff = _to_sql(_check_time(now, "now"))
        expired = "SELECT jti FROM registered WHERE exp IS NOT NULL AND exp <= ?"

        def work(db: sqlite3.Connection) -> int:
            db.execute(f"DELETE FROM budget WHERE jti IN ({expired})", (cutoff,))
            db.execute(f"DELETE FROM revoked WHERE jti IN ({expired})", (cutoff,))
            return db.execute(
                "DELETE FROM registered WHERE exp IS NOT NULL AND exp <= ?", (cutoff,)
            ).rowcount

        return self._write(work)

    def charge(self, path: Sequence[Entry]) -> ChargeResult:
        counts = _count_path(path)
        if counts is None:
            return _UNKNOWN

        def work(db: sqlite3.Connection) -> ChargeResult:
            if any(self._is_revoked(db, jti) for jti, _ in counts):
                return _REVOKED
            rows = [
                db.execute(
                    "SELECT lim, used FROM budget WHERE jti = ? AND idx = ?", entry
                ).fetchone()
                for entry in counts
            ]
            if any(row is None for row in rows):
                return _UNKNOWN
            for (limit, used), n in zip(rows, counts.values(), strict=True):
                if limit is not None and used + n > limit:
                    return _EXHAUSTED
            # Every entry was checked inside this same transaction, so the
            # updates below either all commit or (on an error) all roll back.
            for (jti, index), n in counts.items():
                db.execute(
                    "UPDATE budget SET used = used + ? WHERE jti = ? AND idx = ?", (n, jti, index)
                )
            return _OK

        return self._write(work)

    def usage(self, jti: str, index: int) -> tuple[int, int | None] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT used, lim FROM budget WHERE jti = ? AND idx = ?", (jti, index)
            ).fetchone()
        return None if row is None else (row[0], row[1])

    def is_registered(self, jti: str) -> bool:
        with self._lock:
            row = self._db.execute("SELECT 1 FROM registered WHERE jti = ?", (jti,)).fetchone()
        return row is not None
