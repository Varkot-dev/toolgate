"""The attenuation check: may this child grant be derived from this parent?

The security requirement is one sentence: every call the child grant allows,
the parent grant must also allow. The check below is SOUND for that (it never
accepts a child that allows more) and deliberately NOT COMPLETE (it rejects
some children that are in fact safe). See docs/PLAN.md section 3.2.
"""

from __future__ import annotations

from dataclasses import dataclass

from toolgate.capability import Capability, Grant
from toolgate.constraints import Constraint


def _prefix_extends(parent: str, child: str) -> bool:
    """Parent is `P*` with P literal, and the child's literal head starts with P.

    Every string the child matches begins with the child's literal head (the
    text before its first "*"), hence with P, hence matches `P*`.
    """
    if not parent.endswith("*") or "*" in parent[:-1]:
        return False
    return child.split("*")[0].startswith(parent[:-1])


def at_least_as_strict(parent: Constraint, child: Constraint) -> bool:
    """True only if every value `child` accepts, `parent` accepts too.

    Both constraints must be on the same argument.
    """
    if parent.arg != child.arg:
        return False
    if parent.op == "any":
        return True
    values = child.finite_values()
    if values is not None:
        # eq / in / glob with no star: the child accepts a finite list, so test
        # each value directly.
        return all(parent.holds(v) for v in values)
    if parent.op == "max" and child.op == "max":
        return child.value <= parent.value
    if parent.op == "glob" and child.op == "glob":
        return child.value == parent.value or _prefix_extends(parent.value, child.value)
    return False


def covers(parent: Capability, child: Capability) -> bool:
    """True only if every call `child` permits, `parent` permits too,
    and the child's call budget is no larger than the parent's."""
    if parent.tool != child.tool:
        return False
    if parent.arg_names != child.arg_names:
        return False
    for pc in parent.constraints:
        if not any(at_least_as_strict(pc, cc) for cc in child.constraints):
            return False
    if parent.max_calls is not None:
        return child.max_calls is not None and child.max_calls <= parent.max_calls
    return True


@dataclass(frozen=True)
class AttenuationResult:
    ok: bool
    reason: str
    # derivation[i] is the index of the parent capability that covers child
    # capability i. The token layer charges call budgets along this mapping.
    derivation: tuple[int, ...] = ()

    def __bool__(self) -> bool:
        return self.ok


def check_attenuation(parent: Grant, child: Grant) -> AttenuationResult:
    """Accept `child` only if it can allow nothing that `parent` does not."""
    if not child.expires_at <= parent.expires_at:
        return AttenuationResult(False, "child expires later than parent")
    derivation: list[int] = []
    for i, cc in enumerate(child.capabilities):
        for j, pc in enumerate(parent.capabilities):
            if covers(pc, cc):
                derivation.append(j)
                break
        else:
            return AttenuationResult(
                False, f"child capability {i} ({cc.tool}) is not covered by any parent capability"
            )
    return AttenuationResult(True, "ok", tuple(derivation))
