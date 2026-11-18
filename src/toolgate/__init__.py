"""toolgate: an authorization gateway for LLM agents."""

from toolgate.attenuation import AttenuationResult, at_least_as_strict, check_attenuation, covers
from toolgate.capability import Call, Capability, Decision, Grant
from toolgate.constraints import Constraint, glob_match, same_value

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
