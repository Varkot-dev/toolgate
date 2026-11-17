"""Token chain figure for M1b: a token gains restrictions offline, and none can be dropped.

Issues one HMAC chain token with the real library and a fixed demo root key,
appends three caveats with toolgate.chain.attenuate (no key, no authority),
asks the real verifier about four sample calls at every step, then removes
the last caveat the way an attacker would and records the verifier's error.
Writes

    assets/token_chain.png
    assets/token_chain.svg
    results/m1b_token_chain.json

Run from the repo root: .venv/bin/python scripts/fig_token_chain.py
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import replace

import matplotlib.pyplot as plt
from matplotlib.axes import Axes
from matplotlib.patches import FancyBboxPatch

import style
from toolgate import Call, Capability, Constraint, Grant
from toolgate.chain import (
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
ROOT_KEY = bytes.fromhex("746f6f6c67617465206d316220666967757265206b65792c2064656d6f212121")
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
GRANT_LINES = (
    "read_file(path ~ reports/*)",
    "send_email(to in {ana@x.com, ben@x.com}, body: any)",
)

# (caveat, how the figure writes it)
CAVEATS = (
    (ArgCaveat("send_email", Constraint("to", "eq", "ana@x.com")), "send_email: to = ana@x.com"),
    (ToolsCaveat(("read_file",)), "tool in {read_file}"),
    (
        ArgCaveat("read_file", Constraint("path", "glob", "reports/q3/*")),
        "read_file: path ~ reports/q3/*",
    ),
)

# (call, first header line, second header line)
SAMPLES = (
    (Call("read_file", {"path": "reports/q3/a"}), "read_file", "reports/q3/a"),
    (Call("read_file", {"path": "reports/q1/b"}), "read_file", "reports/q1/b"),
    (Call("send_email", {"to": "ana@x.com", "body": "hi"}), "send_email", "to ana@x.com"),
    (Call("send_email", {"to": "ben@x.com", "body": "hi"}), "send_email", "to ben@x.com"),
)


def short(signature: bytes) -> str:
    """First 8 bytes as hex, in groups of four, with a mark that more follows."""
    h = signature.hex()[:16]
    return " ".join(h[i : i + 4] for i in range(0, 16, 4)) + " …"


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
    for n, (caveat, _) in enumerate(CAVEATS, start=1):
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


# --- drawing ---------------------------------------------------------------

LEFT, RIGHT = 40, 1560
SIG_X = 690  # left edge of the signature column
CELL_X = (1090, 1224, 1358, 1492)  # centers of the four sample-call columns
PAD = 22


def card(ax: Axes, top: float, height: float, rejected: bool = False) -> None:
    ax.add_patch(
        FancyBboxPatch(
            (LEFT, top),
            RIGHT - LEFT,
            height,
            boxstyle="round,pad=0,rounding_size=12",
            facecolor=style.SURFACE if rejected else style.PANEL,
            edgecolor=style.DENY if rejected else style.RULE,
            linewidth=2 if rejected else 1.2,
            linestyle=(0, (5, 4)) if rejected else "solid",
        )
    )


def cells(ax: Axes, y: float, decisions: list[dict]) -> None:
    for x, d in zip(CELL_X, decisions, strict=True):
        ok = d["allowed"]
        ax.text(
            x,
            y,
            "✓ allow" if ok else "✕ deny",
            fontsize=15,
            fontweight="bold",
            color=style.ALLOW if ok else style.DENY,
            ha="center",
            va="center",
        )


def signature(ax: Axes, y: float, rule: str, hex_text: str) -> None:
    ax.text(SIG_X, y - 17, rule, fontsize=13, color=style.MUTED, va="center")
    ax.text(
        SIG_X,
        y + 13,
        hex_text,
        fontsize=16,
        fontweight="bold",
        family=style.MONO,
        color=style.ACCENT,
        va="center",
    )


def arrow(ax: Axes, y0: float, y1: float, label: str, ok: bool = True) -> None:
    color = style.MUTED if ok else style.DENY
    dash = "solid" if ok else (0, (5, 4))
    ax.annotate(
        "",
        xy=(92, y1 - 3),
        xytext=(92, y0 + 3),
        arrowprops={
            "arrowstyle": "-|>",
            "color": color,
            "linewidth": 2,
            "linestyle": dash,
            "mutation_scale": 16,
            "shrinkA": 0,
            "shrinkB": 0,
        },
    )
    ax.text(
        112,
        (y0 + y1) / 2,
        label,
        fontsize=13,
        fontweight="bold" if not ok else "normal",
        color=color,
        va="center",
    )


def draw(record: dict) -> plt.Figure:
    style.apply()
    fig = plt.figure(figsize=style.SIZE)
    ax = fig.add_axes((0, 0, 1, 1))
    ax.set_xlim(0, 1600)
    ax.set_ylim(900, 0)
    ax.axis("off")

    ax.text(
        40,
        50,
        "A token its holder can narrow offline, and nobody can widen",
        fontsize=26,
        fontweight="bold",
    )
    ax.text(
        40,
        88,
        "Each restriction is chained into the signature. Every row is a real token, "
        "checked by the real verifier against four sample calls.",
        fontsize=14,
        color=style.MUTED,
    )

    # Column heads.
    ax.text(LEFT + PAD, 150, "token", fontsize=13, color=style.MUTED, va="center")
    ax.text(
        SIG_X,
        150,
        "signature (first 8 of 32 bytes)",
        fontsize=13,
        color=style.MUTED,
        va="center",
    )
    for x, (_, tool, detail) in zip(CELL_X, SAMPLES, strict=True):
        ax.text(x, 138, tool, fontsize=13, fontweight="bold", ha="center", va="center")
        ax.text(x, 160, detail, fontsize=11.5, family=style.MONO, ha="center", va="center")

    steps = record["steps"]
    rules = [
        "sig0 = HMAC(root key, id + grant)",
        "sig1 = HMAC(sig0, caveat 1)",
        "sig2 = HMAC(sig1, caveat 2)",
        "sig3 = HMAC(sig2, caveat 3)",
    ]
    top = 180
    heights = [112, 88, 88, 88]
    gap = 36
    for n, step in enumerate(steps):
        h = heights[n]
        if n:
            arrow(
                ax,
                top - gap,
                top,
                f"holder appends caveat {n} by itself: no root key, no network call",
            )
        card(ax, top, h)
        mid = top + h / 2
        if n == 0:
            ax.text(
                LEFT + PAD,
                top + 28,
                "issued by the gateway",
                fontsize=16,
                fontweight="bold",
                va="center",
            )
            for k, line in enumerate(GRANT_LINES):
                ax.text(
                    LEFT + PAD,
                    top + 60 + 26 * k,
                    line,
                    fontsize=14,
                    family=style.MONO,
                    va="center",
                )
        else:
            ax.text(
                LEFT + PAD, mid - 15, f"+ caveat {n}", fontsize=16, fontweight="bold", va="center"
            )
            ax.text(
                LEFT + PAD,
                mid + 15,
                CAVEATS[n - 1][1],
                fontsize=14,
                family=style.MONO,
                va="center",
            )
        signature(ax, mid, rules[n], short(bytes.fromhex(step["signature_hex"])))
        cells(ax, mid, step["sample_calls"])
        top += h + gap

    # The failed attempt.
    forged = record["forged"]
    top += 6
    arrow(ax, top - gap - 6, top, "✕ attacker removes caveat 3 and keeps sig3", ok=False)
    h = 900 - top - 48
    card(ax, top, h, rejected=True)
    ax.text(
        LEFT + PAD,
        top + 28,
        "grant + caveat 1 + caveat 2, signed sig3",
        fontsize=16,
        fontweight="bold",
        va="center",
    )
    ax.text(LEFT + PAD, top + 60, "verifier says:", fontsize=13, color=style.MUTED, va="center")
    for k, line in enumerate(textwrap.wrap(forged["verifier_error"], 56)):
        ax.text(
            LEFT + PAD + 124, top + 60 + 24 * k, line, fontsize=13, color=style.DENY, va="center"
        )
    mid = top + h / 2
    signature(
        ax,
        mid - 12,
        "needs sig2, holds only sig3",
        short(bytes.fromhex(forged["signature_hex"])),
    )
    ax.text(
        SIG_X,
        mid + 34,
        "HMAC cannot be run backwards",
        fontsize=13,
        color=style.MUTED,
        va="center",
    )
    cells(ax, mid, forged["sample_calls"])

    ax.text(
        40,
        882,
        "Notation:   ~ glob pattern    = exact value    in {..} allow-list    "
        "A call must pass the grant AND every caveat.        "
        "Data: results/m1b_token_chain.json",
        fontsize=12.5,
        color=style.MUTED,
    )
    return fig


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

    fig = draw(record)
    png, svg = style.save(fig, "token_chain")
    for path in (png, svg, out):
        print(path.relative_to(style.ROOT))
    for step in record["steps"]:
        print(f"sig{step['step']} {step['signature_hex'][:16]}  {step['token_chars']} chars")
    print(f"forged: {record['forged']['verifier_error']}")


if __name__ == "__main__":
    main()
