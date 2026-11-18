"""M0b: the solver proofs of the attenuation rules (PLAN.md 3.2 and 3.9).

Every lemma must be `unsat` (no escalation exists under the rule), every wrong
variant must be `sat` with a counterexample (the queries can find an escalation
when the rule is broken), and every lemma's premises must be satisfiable on
their own (no `unsat` comes from a contradictory side condition).
"""

import pytest

from toolgate import proofs

TABLE_ROWS = ("eq", "in", "max", "glob")


@pytest.fixture(scope="module")
def lemmas() -> list[proofs.Lemma]:
    return proofs.all_lemmas()


@pytest.fixture(scope="module")
def wrong_variants() -> list[proofs.Lemma]:
    return proofs.all_wrong_variants()


@pytest.mark.parametrize("build", proofs.LEMMAS, ids=lambda f: f.__name__)
def test_lemma_is_unsat(build):
    lemma = build()
    assert lemma.result == "unsat", f"{lemma.name}: {lemma.result} {lemma.counterexample}"
    assert lemma.counterexample is None


@pytest.mark.parametrize("build", proofs.WRONG_VARIANTS, ids=lambda f: f.__name__)
def test_wrong_variant_is_sat(build):
    variant = build()
    assert variant.result == "sat", f"{variant.name}: {variant.result}"
    assert variant.counterexample


def test_premises_of_every_lemma_are_satisfiable():
    checks = proofs.all_premise_checks()
    assert len(checks) == len(proofs.LEMMAS)
    assert [c.name for c in checks if c.result != "sat"] == []


def test_premise_check_switches_itself_off(lemmas):
    proofs.all_premise_checks()
    assert proofs.enumeration_rule().result == "unsat"


def test_lemmas_cover_every_table_row(lemmas):
    for row in TABLE_ROWS:
        own = [x for x in lemmas if x.table_row == row]
        assert own, f"no lemma is filed under table row {row!r}"
    general = lemmas[0]
    assert general.name.startswith("L1 ")
    assert all(row in general.table_row.split(", ") for row in TABLE_ROWS)


def test_every_requested_lemma_and_variant_is_present(lemmas, wrong_variants):
    prefixes = {x.name.split()[0] for x in lemmas}
    assert {"L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8"} <= prefixes
    rows = {x.table_row for x in wrong_variants}
    assert {"in", "max", "glob", "capability", "grant", "budget"} <= rows


def test_rule_a_has_a_lemma_and_a_wrong_variant(lemmas, wrong_variants):
    # Rule A: a child glob with no star is the single string of its pattern.
    assert "L1e" in {x.name.split()[0] for x in lemmas}
    assert "W12" in {x.name.split()[0] for x in wrong_variants}
    assert proofs.star_free_glob_is_literal in proofs.LEMMAS
    assert proofs.wrong_starred_glob_as_literal in proofs.WRONG_VARIANTS
    assert "" in proofs.STAR_FREE_PATTERNS
    assert all("*" not in g for g in proofs.STAR_FREE_PATTERNS)


def test_names_are_unique(lemmas, wrong_variants):
    names = [x.name for x in lemmas + wrong_variants]
    assert len(names) == len(set(names))


def test_bounded_lemmas_say_so(lemmas):
    bounded = {x.name.split()[0] for x in lemmas if x.bound is not None}
    assert bounded == {"L1e", "L4", "L4c", "L6", "L7", "L8a"}


def test_unknown_is_never_reported_as_proved(monkeypatch):
    monkeypatch.setattr(proofs, "_solve", lambda formulas: ("unknown", None))
    assert proofs.max_under_max().result == "unknown"
    assert proofs.glob_prefix_bounded().result == "unknown"
    assert proofs.wrong_max_reversed().result == "unknown"
