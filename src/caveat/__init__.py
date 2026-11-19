"""caveat: an authorization gateway for LLM agents."""

from caveat.attenuation import AttenuationResult, at_least_as_strict, check_attenuation, covers
from caveat.capability import Call, Capability, Decision, Grant
from caveat.constraints import Constraint, glob_match, same_value

__all__ = [
    "AttenuationResult",
    "Call",
    "Capability",
    "Constraint",
    "Decision",
    "Grant",
    "at_least_as_strict",
    "check_attenuation",
    "covers",
    "glob_match",
    "same_value",
]
