"""The revocation list and the budget ledger, for both store implementations."""

from __future__ import annotations

import threading

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolgate.store import ChargeResult, MemoryStore, SqliteStore, Store


@pytest.fixture(params=["memory", "sqlite-memory", "sqlite-file"])
def store(request, tmp_path):
    if request.param == "memory":
        yield MemoryStore()
        return
    path = ":memory:" if request.param == "sqlite-memory" else str(tmp_path / "store.db")
    s = SqliteStore(path)
    yield s
    s.close()


def test_implementations_satisfy_the_protocol(store):
    assert isinstance(store, Store)


# -- revocation ---------------------------------------------------------------


def test_revoke_and_lookup(store):
    assert not store.any_revoked(["a", "b"])
    store.revoke("b")
    store.revoke("b")  # twice is harmless
    assert store.any_revoked(["b"])
    assert store.any_revoked(["a", "b", "c"])
    assert not store.any_revoked(["a", "c"])
    assert not store.any_revoked([])


@pytest.mark.parametrize("bad", ["", None, 7, b"a", ["a"]])
def test_revoke_rejects_non_string_ids(store, bad):
    with pytest.raises(ValueError):
        store.revoke(bad)
    with pytest.raises(ValueError):
        store.any_revoked([bad])


# -- registration -------------------------------------------------------------


def test_register_creates_one_entry_per_capability(store):
    assert not store.is_registered("t")
    store.register("t", [3, None])
    assert store.is_registered("t")
    assert store.usage("t", 0) == (0, 3)
    assert store.usage("t", 1) == (0, None)
    assert store.usage("t", 2) is None
    assert store.usage("other", 0) is None


def test_register_with_no_capabilities_still_records_the_token(store):
    store.register("empty", [])
    assert store.is_registered("empty")
    assert store.usage("empty", 0) is None


def test_register_twice_is_refused_and_changes_nothing(store):
    store.register("t", [2])
    assert store.charge([("t", 0)])
    with pytest.raises(ValueError, match="already registered"):
        store.register("t", [99, 99])
    assert store.usage("t", 0) == (1, 2)
    assert store.usage("t", 1) is None


@pytest.mark.parametrize("limits", [[0], [-1], [True], [1.5], ["3"], [2**40]])
def test_register_rejects_bad_limits(store, limits):
    with pytest.raises(ValueError):
        store.register("t", limits)
    assert not store.is_registered("t")


# -- charge ---------------------------------------------------------------------


def test_charge_counts_up_to_the_limit_and_stops(store):
    store.register("t", [2])
    assert store.charge([("t", 0)]) == ChargeResult(True, "ok")
    assert store.charge([("t", 0)])
    refused = store.charge([("t", 0)])
    assert not refused and refused.reason == "exhausted"
    assert store.usage("t", 0) == (2, 2)


def test_unlimited_entries_are_counted_but_never_refuse(store):
    store.register("t", [None])
    for _ in range(50):
        assert store.charge([("t", 0)])
    assert store.usage("t", 0) == (50, None)


def test_charge_increments_every_entry_on_the_path(store):
    store.register("root", [10])
    store.register("mid", [None, 5])
    store.register("leaf", [3])
    assert store.charge([("leaf", 0), ("mid", 1), ("root", 0)])
    assert store.usage("leaf", 0) == (1, 3)
    assert store.usage("mid", 1) == (1, 5)
    assert store.usage("mid", 0) == (0, None)
    assert store.usage("root", 0) == (1, 10)


@pytest.mark.parametrize("exhausted", ["leaf", "mid", "root"])
def test_one_exhausted_entry_anywhere_fails_the_charge_and_changes_nothing(store, exhausted):
    limits = {"leaf": 5, "mid": 5, "root": 5}
    limits[exhausted] = 1
    for name, limit in limits.items():
        store.register(name, [limit])
    path = [("leaf", 0), ("mid", 0), ("root", 0)]
    assert store.charge(path)
    refused = store.charge(path)
    assert not refused and refused.reason == "exhausted"
    assert [store.usage(n, 0)[0] for n in ("leaf", "mid", "root")] == [1, 1, 1]


def test_siblings_share_the_parent_budget(store):
    store.register("parent", [3])
    store.register("a", [3])
    store.register("b", [3])
    results = [
        bool(store.charge([(child, 0), ("parent", 0)])) for child in ("a", "b", "a", "b", "a", "b")
    ]
    assert results == [True, True, True, False, False, False]
    assert store.usage("parent", 0) == (3, 3)
    assert store.usage("a", 0) == (2, 3)
    assert store.usage("b", 0) == (1, 3)


def test_unknown_entry_fails_closed_and_changes_nothing(store):
    store.register("leaf", [5])
    for path in (
        [("leaf", 0), ("ghost", 0)],
        [("leaf", 0), ("leaf", 7)],
        [("ghost", 0)],
    ):
        refused = store.charge(path)
        assert not refused and refused.reason == "unknown"
    assert store.usage("leaf", 0) == (0, 5)


def test_revoked_token_on_the_path_fails_the_charge(store):
    store.register("parent", [5])
    store.register("child", [5])
    store.revoke("parent")
    refused = store.charge([("child", 0), ("parent", 0)])
    assert not refused and refused.reason == "revoked"
    assert store.usage("child", 0) == (0, 5)
    assert store.usage("parent", 0) == (0, 5)


def test_an_entry_listed_twice_is_charged_twice_or_not_at_all(store):
    store.register("t", [3])
    assert store.charge([("t", 0), ("t", 0)])
    assert store.usage("t", 0) == (2, 3)
    assert not store.charge([("t", 0), ("t", 0)])  # 2 + 2 > 3
    assert store.usage("t", 0) == (2, 3)


@pytest.mark.parametrize(
    "path",
    [
        [],
        None,
        "t",
        [("t",)],
        [("t", 0, 0)],
        [["t", 0]],
        [("t", -1)],
        [("t", True)],
        [("t", 0.0)],
        [("t", "0")],
        [(None, 0)],
        [("", 0)],
        [("t", 2**70)],
    ],
)
def test_malformed_paths_are_refused(store, path):
    store.register("t", [5])
    refused = store.charge(path)
    assert not refused and refused.reason == "unknown"
    assert store.usage("t", 0) == (0, 5)


def test_charge_result_of_a_refusal_is_falsy():
    # A refusal must never be mistaken for success by a plain `if`.
    assert not ChargeResult(False, "exhausted")
    assert ChargeResult(True, "ok")


# -- persistence and concurrency ------------------------------------------------


def test_sqlite_state_survives_reopening(tmp_path):
    path = str(tmp_path / "store.db")
    first = SqliteStore(path)
    first.register("t", [2])
    first.revoke("gone")
    assert first.charge([("t", 0)])
    first.close()

    second = SqliteStore(path)
    assert second.is_registered("t")
    assert second.usage("t", 0) == (1, 2)
    assert second.any_revoked(["gone"])
    assert second.charge([("t", 0)])
    assert not second.charge([("t", 0)])
    second.close()


def test_sqlite_rolls_back_when_the_transaction_fails_midway(tmp_path):
    s = SqliteStore(str(tmp_path / "store.db"))
    s.register("ok", [1])

    def work(db):
        db.execute("UPDATE budget SET used = used + 1 WHERE jti = 'ok'")
        raise RuntimeError("crash after the first update")

    with pytest.raises(RuntimeError):
        s._write(work)
    assert s.usage("ok", 0) == (0, 1)
    assert s.charge([("ok", 0)])  # the store is still usable
    s.close()


THREADS = 8
ATTEMPTS = 40
LIMIT = 100  # fewer than THREADS * ATTEMPTS, so the threads must fight over it


def _hammer(stores: list[Store]) -> list[int]:
    """Each thread charges its own child plus the shared parent, many times."""
    wins = [0] * THREADS
    start = threading.Barrier(THREADS)

    def worker(n: int) -> None:
        store = stores[n % len(stores)]
        start.wait()
        for _ in range(ATTEMPTS):
            if store.charge([(f"child{n}", 0), ("parent", 0)]):
                wins[n] += 1

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return wins


def _check_hammered(store: Store, wins: list[int]) -> None:
    assert sum(wins) == LIMIT  # not one call more than the parent allows
    assert store.usage("parent", 0) == (LIMIT, LIMIT)
    for n in range(THREADS):
        # A refused charge left the child's own counter alone.
        assert store.usage(f"child{n}", 0) == (wins[n], None)


def _prepare(store: Store) -> None:
    store.register("parent", [LIMIT])
    for n in range(THREADS):
        store.register(f"child{n}", [None])


def test_concurrent_charges_never_overspend_memory():
    store = MemoryStore()
    _prepare(store)
    _check_hammered(store, _hammer([store]))


def test_concurrent_charges_never_overspend_sqlite_file(tmp_path):
    store = SqliteStore(str(tmp_path / "store.db"))
    _prepare(store)
    _check_hammered(store, _hammer([store]))
    store.close()


def test_concurrent_charges_through_separate_sqlite_connections(tmp_path):
    # Two store objects on one file stand in for two gateway processes.
    path = str(tmp_path / "store.db")
    stores = [SqliteStore(path), SqliteStore(path), SqliteStore(path)]
    _prepare(stores[0])
    _check_hammered(stores[1], _hammer(stores))
    for s in stores:
        s.close()


# -- the two implementations agree ----------------------------------------------

_IDS = ("a", "b", "c", "d")
_entry = st.tuples(st.sampled_from(_IDS), st.integers(0, 2))
_op = st.one_of(
    st.tuples(
        st.just("register"),
        st.sampled_from(_IDS),
        st.lists(st.sampled_from([None, 1, 2, 3]), max_size=3),
    ),
    st.tuples(st.just("revoke"), st.sampled_from(_IDS)),
    st.tuples(st.just("charge"), st.lists(_entry, max_size=4)),
)


@settings(max_examples=150, deadline=None)
@given(st.lists(_op, max_size=30))
def test_memory_and_sqlite_agree_and_never_exceed_a_limit(ops):
    memory, sqlite = MemoryStore(), SqliteStore(":memory:")
    for op in ops:
        outcomes = []
        for store in (memory, sqlite):
            try:
                if op[0] == "register":
                    outcomes.append(store.register(op[1], op[2]))
                elif op[0] == "revoke":
                    outcomes.append(store.revoke(op[1]))
                else:
                    before = {e: store.usage(*e) for e in op[1]}
                    result = store.charge(op[1])
                    after = {e: store.usage(*e) for e in op[1]}
                    if not result:
                        assert after == before  # a refusal changes nothing
                    outcomes.append(result)
            except ValueError:
                outcomes.append("ValueError")
        assert outcomes[0] == outcomes[1]
    for jti in _IDS:
        for index in range(3):
            assert memory.usage(jti, index) == sqlite.usage(jti, index)
            usage = memory.usage(jti, index)
            if usage is not None and usage[1] is not None:
                assert usage[0] <= usage[1]
    sqlite.close()
