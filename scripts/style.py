"""The visual system for every figure in this repo.

New figures draw on a `Canvas`: one axes in logical pixels (origin top left,
y pointing down) laid on a white rounded card. A figure is designed at its
README display width (about 800 px), so a size given here in px is the size
a reader sees; files are rendered at 2x for sharp screens.

    canvas = style.Canvas(800, 460)
    canvas.title("Authority only shrinks down the chain")
    canvas.node(32, 96, 240, 120)
    canvas.chip(48, 150, "read reports/*", tone="allow")
    canvas.arrow((152, 216), (152, 260), tone="allow")
    canvas.save("delegation_tree")

Design rules the helpers encode:
  * Palette: one ink, one muted gray, allow, deny, and one highlight.
    Allow and deny always come with a drawn check or cross mark (and deny
    with a dashed line), so meaning never rests on color alone. The
    colors pass the dataviz validator for protan, deutan and tritan
    separation and are at least 4.5:1 against the card as text.
  * Background: a white card with rounded corners and a hairline border,
    transparent outside. It reads as a deliberate panel on GitHub's light
    theme and on its dark theme, without a second set of colors.
  * Type: Inter (DejaVu Sans if Inter is missing), three sizes and two
    weights; JetBrains Mono only for real code tokens such as tool names.

Figures not yet ported still use `apply()`, `save()` and the legacy color
names at the bottom of this file, which keep their old values.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Literal

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib import font_manager  # noqa: E402
from matplotlib.artist import Artist  # noqa: E402
from matplotlib.axes import Axes  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402
from matplotlib.font_manager import FontProperties  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Circle, FancyBboxPatch, Polygon  # noqa: E402
from matplotlib.textpath import TextPath  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"
RESULTS = ROOT / "results"

# ---------------------------------------------------------------- palette

INK = "#1A1F2B"  # primary text and strong marks, 16.5:1 on the card
GRAY = "#5B6472"  # secondary text, 6.0:1 on the card
LINE = "#B4BBC6"  # neutral connectors
HAIRLINE = "#E3E6EB"  # card border, dividers
NODE = "#F3F5F8"  # fill of a node on the card
CARD = "#FFFFFF"  # the card itself

GOOD = "#0E7356"  # allowed / accepted, 5.6:1 on the card
GOOD_TINT = "#E4F2EC"
BAD = "#BD3D1A"  # denied / rejected, 5.4:1 on the card
BAD_TINT = "#FBE9E3"
HIGHLIGHT = "#2F6FDB"  # the one thing in motion or in focus
HIGHLIGHT_TINT = "#E6EEFB"

Tone = Literal["neutral", "good", "bad", "highlight", "plain"]
TONES: dict[str, tuple[str, str]] = {  # tone -> (fill, ink)
    "neutral": (NODE, INK),
    "plain": (CARD, INK),
    "good": (GOOD_TINT, GOOD),
    "bad": (BAD_TINT, BAD),
    "highlight": (HIGHLIGHT_TINT, HIGHLIGHT),
}
STROKE = {"neutral": LINE, "plain": LINE, "good": GOOD, "bad": BAD, "highlight": HIGHLIGHT}

# ---------------------------------------------------------------- type and spacing


def _pick(*families: str) -> str:
    for family in families:
        try:
            font_manager.findfont(FontProperties(family=family), fallback_to_default=False)
            return family
        except ValueError:
            continue
    return "DejaVu Sans"


SANS = _pick("Inter", "DejaVu Sans")
CODE = _pick("JetBrains Mono", "DejaVu Sans Mono")

# Sizes in display px at the design width. Nothing smaller than SMALL.
TITLE = 26
LABEL = 18  # node names, the big words of a diagram
BODY = 16  # chips, edge labels
SMALL = 15  # secondary notes
REGULAR, STRONG = "regular", "semibold"

UNIT = 8  # spacing grid: every gap and padding is a multiple of this
MARGIN = 32  # card edge to content
RADIUS = 12  # node corners
CHIP_H = 30  # height of a chip
SCALE = 2  # render factor for PNG files

PX_PER_INCH = 100
PT = 72 / PX_PER_INCH  # points per logical pixel


def text_width(text: str, size: float = BODY, weight: str = REGULAR, code: bool = False) -> float:
    """Advance width of `text` in logical px, measured from the real font outlines."""
    if not text:
        return 0.0
    prop = FontProperties(family=CODE if code else SANS, weight=weight)
    path = TextPath((0, 0), text, size=size, prop=prop)
    return float(path.get_extents().x1)


# ---------------------------------------------------------------- canvas


class Canvas:
    """One figure: a white rounded card, an axes in logical px, y pointing down."""

    def __init__(self, width: int, height: int, card: bool = True) -> None:
        self.width, self.height = width, height
        plt.rcParams.update(
            {
                "font.family": [SANS, "DejaVu Sans"],
                "text.color": INK,
                "svg.hashsalt": "toolgate",
                "svg.fonttype": "path",  # glyphs as outlines: identical on every viewer
                "path.simplify": False,
            }
        )
        self.fig = plt.figure(figsize=(width / PX_PER_INCH, height / PX_PER_INCH))
        self.fig.patch.set_alpha(0)
        ax = self.fig.add_axes((0, 0, 1, 1))
        ax.set_xlim(0, width)
        ax.set_ylim(height, 0)
        ax.axis("off")
        ax.patch.set_alpha(0)
        self.ax: Axes = ax
        if card:
            self.box(0.75, 0.75, width - 1.5, height - 1.5, fill=CARD, edge=HAIRLINE, r=16, z=0)

    # -- primitives ------------------------------------------------------------------

    def box(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: str = NODE,
        edge: str | None = None,
        lw: float = 1.5,
        r: float = RADIUS,
        dashed: bool = False,
        z: float = 1,
    ) -> Artist:
        """A rounded rectangle. Fill carries the shape; an edge is the exception."""
        patch = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad=0,rounding_size={r}",
            facecolor=fill,
            edgecolor=edge or "none",
            linewidth=lw * PT if edge else 0,
            linestyle=(0, (4, 3)) if dashed else "solid",
            zorder=z,
        )
        return self.ax.add_patch(patch)

    def text(
        self,
        x: float,
        y: float,
        s: str,
        size: float = BODY,
        color: str = INK,
        weight: str = REGULAR,
        code: bool = False,
        ha: str = "left",
        va: str = "center",
        z: float = 5,
    ) -> Artist:
        if chr(0x2014) in s:  # the em-dash
            raise ValueError("no em-dashes in figure text")
        return self.ax.text(
            x,
            y,
            s,
            fontsize=size * PT,
            color=color,
            fontweight=weight,
            family=CODE if code else SANS,
            ha=ha,
            va=va,
            zorder=z,
        )

    def title(self, s: str) -> Artist:
        """The takeaway, top left. At most about eight words; no subtitle."""
        return self.text(MARGIN, MARGIN + TITLE / 2 + 2, s, size=TITLE, weight=STRONG)

    def line(
        self,
        points: list[tuple[float, float]],
        tone: Tone = "neutral",
        lw: float = 2,
        dashed: bool = False,
        z: float = 2,
    ) -> Artist:
        xs, ys = zip(*points, strict=True)
        artist = Line2D(
            xs,
            ys,
            color=STROKE[tone],
            linewidth=lw * PT,
            linestyle=(0, (4, 3)) if dashed else "solid",
            solid_capstyle="round",
            solid_joinstyle="round",
            dash_capstyle="round",
            zorder=z,
        )
        self.ax.add_line(artist)
        return artist

    def arrow(
        self,
        a: tuple[float, float],
        b: tuple[float, float],
        tone: Tone = "neutral",
        lw: float = 2,
        dashed: bool = False,
        z: float = 2,
    ) -> list[Artist]:
        """A thin straight connector from a to b with a small solid arrowhead at b."""
        return self.path_arrow([a, b], tone, lw, dashed, z)

    def path_arrow(
        self,
        points: list[tuple[float, float]],
        tone: Tone = "neutral",
        lw: float = 2,
        dashed: bool = False,
        z: float = 2,
        head: float = 9,
    ) -> list[Artist]:
        """A polyline whose last segment ends in an arrowhead `head` px long."""
        (x0, y0), (x1, y1) = points[-2], points[-1]
        angle = math.atan2(y1 - y0, x1 - x0)
        ux, uy = math.cos(angle), math.sin(angle)
        base = (x1 - ux * head, y1 - uy * head)
        shaft = self.line([*points[:-1], base], tone, lw, dashed, z)
        half = head * 0.55
        tip = Polygon(
            [
                (x1, y1),
                (base[0] - uy * half, base[1] + ux * half),
                (base[0] + uy * half, base[1] - ux * half),
            ],
            closed=True,
            facecolor=STROKE[tone],
            edgecolor=STROKE[tone],
            linewidth=0.8 * PT,
            joinstyle="round",
            zorder=z,
        )
        self.ax.add_patch(tip)
        return [shaft, tip]

    def chip(
        self,
        x: float,
        y: float,
        s: str,
        tone: Tone = "neutral",
        code: bool = False,
        size: float = BODY,
        weight: str = REGULAR,
        mark: Literal["good", "bad"] | None = None,
        anchor: Literal["left", "center", "right"] = "left",
        h: float = CHIP_H,
        z: float = 4,
    ) -> tuple[list[Artist], float]:
        """A pill with a label (y is its vertical center). Returns (artists, width)."""
        fill, ink = TONES[tone]
        pad = 12
        mark_w = 18 if mark else 0
        w = pad * 2 + mark_w + text_width(s, size, weight, code)
        left = {"left": x, "center": x - w / 2, "right": x - w}[anchor]
        artists = [self.box(left, y - h / 2, w, h, fill=fill, r=h / 2, z=z)]
        tx = left + pad
        if mark:
            artists += self.mark(tx + 6, y, mark, size=12, z=z + 1)
            tx += mark_w
        artists.append(self.text(tx, y, s, size, ink, weight, code, z=z + 1))
        return artists, w

    def mark(
        self, x: float, y: float, kind: Literal["good", "bad"], size: float = 20, z: float = 6
    ) -> list[Artist]:
        """A drawn check or cross centered on (x, y); `size` is its box in px."""
        s = size / 2
        lw = max(2, size / 7)
        if kind == "good":
            pts = [(x - s * 0.8, y + s * 0.05), (x - s * 0.25, y + s * 0.6)]
            pts.append((x + s * 0.8, y - s * 0.6))
            return [self.line(pts, "good", lw=lw, z=z)]
        a = s * 0.62
        return [
            self.line([(x - a, y - a), (x + a, y + a)], "bad", lw=lw, z=z),
            self.line([(x - a, y + a), (x + a, y - a)], "bad", lw=lw, z=z),
        ]

    def badge(
        self, x: float, y: float, kind: Literal["good", "bad"], r: float = 13, z: float = 6
    ) -> list[Artist]:
        """A tinted disc with a check or cross: the verdict on a connector or node."""
        fill = GOOD_TINT if kind == "good" else BAD_TINT
        disc = self.ax.add_patch(Circle((x, y), r, facecolor=fill, edgecolor="none", zorder=z))
        return [disc, *self.mark(x, y, kind, size=r * 1.15, z=z + 1)]

    def clock(self, x: float, y: float, r: float = 7, color: str = GRAY, z: float = 5) -> None:
        """A small clock icon centered on (x, y), for expiry times."""
        self.ax.add_patch(
            Circle((x, y), r, facecolor="none", edgecolor=color, linewidth=1.6 * PT, zorder=z)
        )
        kw = {"color": color, "linewidth": 1.6 * PT, "solid_capstyle": "round", "zorder": z}
        self.ax.add_line(Line2D([x, x], [y, y - r * 0.6], **kw))
        self.ax.add_line(Line2D([x, x + r * 0.45], [y, y], **kw))

    # -- output ----------------------------------------------------------------------

    def save(self, stem: str, svg: bool = True) -> list[Path]:
        """Write assets/<stem>.png at 2x (and .svg) with no timestamps in the metadata."""
        return save_figure(self.fig, stem, svg=svg)


def save_figure(fig: Figure, stem: str, svg: bool = True, scale: float = SCALE) -> list[Path]:
    ASSETS.mkdir(exist_ok=True)
    png = ASSETS / f"{stem}.png"
    fig.savefig(png, dpi=PX_PER_INCH * scale, metadata={"Software": None}, transparent=True)
    out = [png]
    if svg:
        target = ASSETS / f"{stem}.svg"
        fig.savefig(target, metadata={"Date": None, "Creator": None}, transparent=True)
        out.append(target)
    return out


# ---------------------------------------------------------------- legacy, for unported figures
# The scripts not yet redrawn import these names. Values are unchanged from the
# previous style so their output stays the same until each one is ported.

MUTED = "#52514e"
ALLOW = "#008300"
DENY = "#d03b3a"
ACCENT = "#2a78d6"
PANEL = "#f1f0ec"
RULE = "#d6d4cc"
SURFACE = "#fcfcfb"
FONT = "DejaVu Sans"
MONO = "DejaVu Sans Mono"
DPI = 100
SIZE = (16, 9)


def apply() -> None:
    """Legacy: the rcParams of the old look, used by figures not yet ported."""
    plt.rcParams.update(
        {
            "font.family": FONT,
            "font.size": 13,
            "text.color": "#0b0b0b",
            "axes.edgecolor": RULE,
            "axes.labelcolor": MUTED,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "figure.dpi": DPI,
            "savefig.dpi": DPI,
            "svg.hashsalt": "toolgate",
        }
    )


def save(fig: Figure, stem: str) -> tuple[Path, Path]:
    """Legacy: write assets/<stem>.png and .svg at 1x with no timestamps in the metadata."""
    ASSETS.mkdir(exist_ok=True)
    png, svg = ASSETS / f"{stem}.png", ASSETS / f"{stem}.svg"
    fig.savefig(png, metadata={"Software": None})
    fig.savefig(svg, metadata={"Date": None, "Creator": None})
    return png, svg
