"""Token chain figure for M1b: a token gains restrictions offline, and none can be dropped.

Issues one HMAC chain token with the real library and a fixed demo root key,
appends three caveats with caveat.chain.attenuate (no key, no authority),
asks the real verifier about four sample calls at every step, then removes
the last caveat the way an attacker would and records the verifier's error.
Writes

    results/m1b_token_chain.json
    assets/token_chain.png    2x, drawn from scripts/design/token_chain.html

The figure is an HTML page on the shared design system in scripts/design/,
captured with headless Chromium (see scripts/design/render.py), and drawn
only from the record above.

Run from the repo root: .venv/bin/python scripts/fig_token_chain.py
"""

from __future__ import annotations

import json
from dataclasses import replace

import style
from design.render import Shot, render
from caveat import Call, Capability, Constraint, Grant
from caveat.chain import (
    ArgCaveat,
    ChainError,
    HmacAuthority,
    HmacToken,
    ToolsCaveat,
    attenuate,
    encode_caveat,
)

T0 = 1_800_000_000  # fixed "now" in epoch seconds, so the output never changes
# A demo key, published here on purpose so the figure is reproducible. Never a real key.
ROOT_KEY = bytes.fromhex("636176656174206d316220666967757265206b65792c20612064656d6f212121")
IDENTIFIER = "demo-token-1"

GRANT = Grant(
    (
        Capability.from_dict({"tool": "read_file", "args": {"path": {"glob": "reports/*"}}}),
        Capability.from_dict(
            {
                "tool": "send_email",
                "args": {"to": {"in": ["ana@x.com", "ben@x.com"]}, "body": {"any": True}},
            }
        ),
    ),
    T0 + 3600,
)
CAVEATS = (
    ArgCaveat("send_email", Constraint("to", "eq", "ana@x.com")),
    ToolsCaveat(("read_file",)),
    ArgCaveat("read_file", Constraint("path", "glob", "reports/q3/*")),
)

# (call, first header line, second header line)
SAMPLES = (
    (Call("read_file", {"path": "reports/q3/a"}), "read_file", "reports/q3/a"),
    (Call("read_file", {"path": "reports/q1/b"}), "read_file", "reports/q1/b"),
    (Call("send_email", {"to": "ana@x.com", "body": "hi"}), "send_email", "to ana@x.com"),
    (Call("send_email", {"to": "ben@x.com", "body": "hi"}), "send_email", "to ben@x.com"),
)


def decide_all(authority: HmacAuthority, token: HmacToken | str) -> list[dict]:
    out = []
    for call, _, _ in SAMPLES:
        d = authority.authorize(token, call, T0)
        out.append(
            {
                "tool": call.tool,
                "args": dict(call.args),
                "allowed": d.allowed,
                "reason": d.reason,
            }
        )
    return out


def build() -> dict:
    """Everything the figure shows, from real library calls."""
    authority = HmacAuthority(ROOT_KEY)
    token = authority.issue(IDENTIFIER, GRANT)
    steps = [
        {
            "step": 0,
            "added": None,
            "signature_rule": "sig0 = HMAC-SHA256(root key, tag + canonical(identifier, grant))",
        }
    ]
    tokens = [token]
    for n, caveat in enumerate(CAVEATS, start=1):
        # The holder's step: only the serialized token goes in, no authority is used.
        token = attenuate(HmacToken.parse(token.serialize()), caveat)
        tokens.append(token)
        steps.append(
            {
                "step": n,
                "added": json.loads(encode_caveat(caveat)),
                "signature_rule": f"sig{n} = HMAC-SHA256(sig{n - 1}, tag + canonical(caveat {n}))",
            }
        )
    for step, tok in zip(steps, tokens, strict=True):
        authority.verify(tok)  # raises if the chain is broken
        text = tok.serialize()
        step.update(
            {
                "caveats": [json.loads(encode_caveat(c)) for c in tok.caveats],
                "signature_hex": tok.signature.hex(),
                "token": text,
                "token_chars": len(text),
                "sample_calls": decide_all(authority, text),
            }
        )

    # The attack: drop the last caveat, keep the only signature the holder has.
    last = tokens[-1]
    forged = replace(last, caveats=last.caveats[:-1]).serialize()
    try:
        authority.verify(forged)
    except ChainError as exc:
        error = str(exc)
    else:
        raise AssertionError("the forged token must not verify")
    return {
        "construction": "HMAC chain (construction 1)",
        "now": T0,
        "identifier": IDENTIFIER,
        "root_key_hex_demo_only": ROOT_KEY.hex(),
        "grant": GRANT.to_dict(),
        "steps": steps,
        "forged": {
            "what": "the last token with caveat 3 removed and its signature (sig3) kept",
            "caveats": [json.loads(encode_caveat(c)) for c in last.caveats[:-1]],
            "signature_hex": last.signature.hex(),
            "signature_needed_hex": tokens[-2].signature.hex(),
            "token": forged,
            "verifier_error": error,
            "sample_calls": decide_all(authority, forged),
        },
    }


# --- the page ----------------------------------------------------------------

VERB = {"read_file": "read", "send_email": "email"}
NOUN = {"read_file": "file reads", "send_email": "email"}
SIG_CHARS = 8  # hex characters of each signature shown on a card


def who(value: str) -> str:
    return value.split("@")[0] if "@" in value else value


def value_text(constraint: dict) -> str:
    """A constraint's allowed values in plain words: "ana or ben", "reports/q3/*"."""
    op, value = constraint["op"], constraint.get("value")
    if op == "in":
        return " or ".join(who(v) for v in value)
    if op in ("eq", "glob"):
        return who(value)
    raise ValueError(f"no plain wording for op {op!r}")


def describe_grant(grant: dict) -> str:
    """The issued grant as one phrase: "read reports/*, email ana or ben"."""
    parts = []
    for cap in grant["capabilities"]:
        main = next(iter(cap["args"].items()))  # the first argument names the target
        arg, rule = main
        op, value = next(iter(rule.items()))
        parts.append(f"{VERB[cap['tool']]} {value_text({'op': op, 'value': value})}")
    return ", ".join(parts)


def describe_caveat(caveat: dict) -> str:
    """One caveat as a plain restriction: "email only ana", "file reads only"."""
    if caveat["type"] == "tools":
        return " and ".join(NOUN[t] for t in caveat["tools"]).capitalize() + " only"
    if caveat["type"] == "arg":
        return f"{VERB[caveat['tool']].capitalize()} only {value_text(caveat['constraint'])}"
    raise ValueError(f"no plain wording for caveat {caveat!r}")


def view(record: dict) -> dict:
    steps = record["steps"]
    cards = [
        {
            "name": "Issued" if s["step"] == 0 else f"Caveat {s['step']}",
            "text": describe_grant(record["grant"])
            if s["step"] == 0
            else describe_caveat(s["added"]),
            "sig": s["signature_hex"][:SIG_CHARS],
        }
        for s in steps
    ]
    cards[0]["text"] = cards[0]["text"].capitalize()
    forged = record["forged"]
    dropped = steps[-1]["added"]
    assert forged["verifier_error"].startswith("signature mismatch")
    return {
        "title": "Anyone can narrow a token. No one can widen it.",
        "cards": cards,
        "step_label": "holder adds, no key",
        "forged": {
            "name": "Forged",
            "dropped": describe_caveat(dropped),
            "sig": forged["signature_hex"][:SIG_CHARS],
            "verdict": "signature does not match",
            "label": f"drop caveat {len(steps) - 1}, keep its sig",
        },
    }


def main() -> None:
    record = build()
    # The figure's story must match what the verifier said.
    allowed = [[c["allowed"] for c in s["sample_calls"]] for s in record["steps"]]
    assert allowed == [
        [True, True, True, True],
        [True, True, True, False],
        [True, True, False, False],
        [True, False, False, False],
    ], allowed
    assert not any(c["allowed"] for c in record["forged"]["sample_calls"])
    assert len({s["signature_hex"] for s in record["steps"]}) == len(record["steps"])

    style.RESULTS.mkdir(exist_ok=True)
    out = style.RESULTS / "m1b_token_chain.json"
    out.write_text(json.dumps(record, indent=2) + "\n")

    style.ASSETS.mkdir(exist_ok=True)
    png = style.ASSETS / "token_chain.png"
    render("token_chain.html", view(record), [Shot(str(png), scale=2)])
    for path in (png, out):
        print(path.relative_to(style.ROOT))
    for step in record["steps"]:
        print(f"sig{step['step']} {step['signature_hex'][:16]}  {step['token_chars']} chars")
    print(f"forged: {record['forged']['verifier_error']}")


if __name__ == "__main__":
    main()
