#!/usr/bin/env python3
"""Render the two integrated-review conceptual figures for manuscript v3.5.

This release-only utility contains no empirical inputs.  It does not import the
APHFS package, read a protected role, or call any scientific execution entry
point.  The same drawing objects are exported as PDF, SVG, and publication PNG.
"""

from __future__ import annotations

import argparse
import copy
import shutil
import subprocess
from itertools import pairwise
from pathlib import Path

from reportlab import rl_config
from reportlab.graphics import renderPDF, renderSVG
from reportlab.graphics.shapes import Drawing, Line, Rect, String
from reportlab.graphics.shapes import Path as ShapePath
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

rl_config.invariant = 1

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "figures"
FONT_DIR = ROOT / "assets/fonts"
FONT_REGULAR = FONT_DIR / "LiberationSans-Regular.ttf"
FONT_BOLD = FONT_DIR / "LiberationSans-Bold.ttf"
PDF_FONT_REGULAR = "APHFS-LiberationSans"
PDF_FONT_BOLD = "APHFS-LiberationSans-Bold"

NAVY = colors.HexColor("#142337")
BLUE = colors.HexColor("#315A7D")
PALE_BLUE = colors.HexColor("#EAF0F5")
GREEN = colors.HexColor("#2F6B4F")
PALE_GREEN = colors.HexColor("#EDF6F0")
AMBER = colors.HexColor("#9A6200")
PALE_AMBER = colors.HexColor("#FFF5DD")
GRAY = colors.HexColor("#4C566A")
GRID = colors.HexColor("#CFD8E3")
WHITE = colors.white


def _register_pdf_fonts() -> None:
    for path in (FONT_REGULAR, FONT_BOLD):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"embedded PDF font is missing: {path}")
    pdfmetrics.registerFont(TTFont(PDF_FONT_REGULAR, str(FONT_REGULAR)))
    pdfmetrics.registerFont(TTFont(PDF_FONT_BOLD, str(FONT_BOLD)))
    # ReportLab may otherwise emit an unused, unembedded Times-Roman resource.
    pdfmetrics.registerFont(TTFont("Times-Roman", str(FONT_REGULAR)))


def _pdf_font_clone(drawing: Drawing) -> Drawing:
    clone = copy.deepcopy(drawing)

    def visit(node: object) -> None:
        if isinstance(node, String):
            node.fontName = (
                PDF_FONT_BOLD if node.fontName == "Helvetica-Bold" else PDF_FONT_REGULAR
            )
        for child in getattr(node, "contents", ()):
            visit(child)

    visit(clone)
    return clone


def _text(
    drawing: Drawing,
    x: float,
    y: float,
    value: str,
    *,
    size: float = 9,
    color: colors.Color = NAVY,
    bold: bool = False,
    anchor: str = "start",
) -> None:
    drawing.add(
        String(
            x,
            y,
            value,
            fontName="Helvetica-Bold" if bold else "Helvetica",
            fontSize=size,
            fillColor=color,
            textAnchor=anchor,
        )
    )


def _multiline(
    drawing: Drawing,
    x: float,
    y: float,
    lines: tuple[str, ...],
    *,
    size: float = 8,
    leading: float = 10,
    color: colors.Color = NAVY,
    bold_first: bool = False,
    anchor: str = "middle",
) -> None:
    for index, line in enumerate(lines):
        _text(
            drawing,
            x,
            y - index * leading,
            line,
            size=size,
            color=color,
            bold=bold_first and index == 0,
            anchor=anchor,
        )


def _arrow(
    drawing: Drawing,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    color: colors.Color,
) -> None:
    drawing.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=1.4))
    angle = 4.5
    if abs(x2 - x1) >= abs(y2 - y1):
        sign = 1 if x2 >= x1 else -1
        head = ShapePath()
        head.moveTo(x2, y2)
        head.lineTo(x2 - sign * 7, y2 + angle)
        head.lineTo(x2 - sign * 7, y2 - angle)
    else:
        sign = 1 if y2 >= y1 else -1
        head = ShapePath()
        head.moveTo(x2, y2)
        head.lineTo(x2 + angle, y2 - sign * 7)
        head.lineTo(x2 - angle, y2 - sign * 7)
    head.lineTo(x2, y2)
    head.fillColor = color
    head.strokeColor = color
    drawing.add(head)


def _box(
    drawing: Drawing,
    x: float,
    y: float,
    width: float,
    height: float,
    lines: tuple[str, ...],
    *,
    fill: colors.Color = PALE_BLUE,
    stroke: colors.Color = BLUE,
    font_size: float = 8.2,
) -> None:
    drawing.add(
        Rect(
            x,
            y,
            width,
            height,
            rx=6,
            ry=6,
            fillColor=fill,
            strokeColor=stroke,
            strokeWidth=1,
        )
    )
    total = (len(lines) - 1) * (font_size + 1.8)
    _multiline(
        drawing,
        x + width / 2,
        y + height / 2 + total / 2 - font_size * 0.35,
        lines,
        size=font_size,
        leading=font_size + 1.8,
        anchor="middle",
    )


def _panel_title(drawing: Drawing, letter: str, title: str, y: float) -> None:
    drawing.add(Rect(14, y - 1, 20, 18, rx=4, ry=4, fillColor=NAVY, strokeColor=NAVY))
    _text(drawing, 24, y + 4, letter, size=9, color=WHITE, bold=True, anchor="middle")
    _text(drawing, 42, y + 4, title, size=10, color=NAVY, bold=True)


def _stage_box(
    drawing: Drawing,
    number: str,
    y: float,
    lines: tuple[str, ...],
    *,
    biological: bool,
) -> None:
    x, width, height = 30, 250, 28
    fill = PALE_GREEN if biological else PALE_BLUE
    stroke = GREEN if biological else BLUE
    drawing.add(
        Rect(
            x,
            y,
            width,
            height,
            rx=5,
            ry=5,
            fillColor=fill,
            strokeColor=stroke,
            strokeWidth=1,
        )
    )
    drawing.add(
        Rect(
            x + 7,
            y + 5,
            18,
            18,
            rx=4,
            ry=4,
            fillColor=NAVY,
            strokeColor=NAVY,
        )
    )
    _text(
        drawing,
        x + 16,
        y + 10.4,
        number,
        size=8.2,
        color=WHITE,
        bold=True,
        anchor="middle",
    )
    total = (len(lines) - 1) * 8.9
    _multiline(
        drawing,
        x + 34,
        y + height / 2 + total / 2 - 2.8,
        lines,
        size=8.2,
        leading=8.9,
        color=NAVY,
        bold_first=True,
        anchor="start",
    )


def _anchor_box(
    drawing: Drawing,
    y: float,
    lines: tuple[str, ...],
    target_y: float,
) -> None:
    x, width, height = 340, 175, 38
    _box(
        drawing,
        x,
        y,
        width,
        height,
        lines,
        fill=PALE_GREEN,
        stroke=GREEN,
        font_size=7.4,
    )
    _arrow(drawing, x, y + height / 2, 280, target_y, GREEN)


def _research_ladder() -> Drawing:
    drawing = Drawing(540, 500)
    _text(
        drawing,
        18,
        480,
        "From imagination through executable mathematics to evidence",
        size=14,
        color=NAVY,
        bold=True,
    )
    _text(
        drawing,
        18,
        464,
        "Compute expands evaluation; evidence constrains justification.",
        size=8.5,
        color=GRAY,
    )
    _text(
        drawing,
        18,
        451,
        "Future FTQC expands executable dynamics; it does not supply evidence.",
        size=8.1,
        color=GRAY,
    )
    _text(
        drawing,
        30,
        430,
        "Bottom-up candidate generation",
        size=9.2,
        color=NAVY,
        bold=True,
    )
    _text(
        drawing,
        340,
        430,
        "Top-down reality constraints",
        size=9.2,
        color=GREEN,
        bold=True,
    )

    labels = (
        ("Pre-particle executable rules",),
        ("Persistent excitations",),
        ("Particle-like signatures",),
        ("Atom-like states",),
        ("Molecule-like systems",),
        ("Biochemical dynamics",),
        ("Cellular microdynamics",),
        ("Aging: drift and resilience loss",),
        ("Safety-constrained rejuvenation",),
    )
    y_positions = tuple(393 - 36 * index for index in range(len(labels)))
    for index, (lines, y) in enumerate(zip(labels, y_positions, strict=True), start=1):
        _stage_box(drawing, str(index), y, lines, biological=index >= 7)
    for upper, lower in pairwise(y_positions):
        _arrow(drawing, 155, upper, 155, lower + 28, NAVY)

    anchors = (
        (("Physics and", "particle data"), 2),
        (("Atomic spectra and", "molecular structure"), 4),
        (("Biochemical and", "cellular perturbations"), 6),
        (("Longitudinal aging and", "intervention data"), 8),
    )
    for lines, target_index in anchors:
        target_y = y_positions[target_index] + 14
        _anchor_box(drawing, target_y - 19, lines, target_y)

    drawing.add(Rect(30, 55, 485, 45, rx=6, ry=6, fillColor=PALE_GREEN, strokeColor=GREEN))
    _text(
        drawing,
        272.5,
        82,
        "No premature coarse-graining",
        size=8.2,
        color=GREEN,
        bold=True,
        anchor="middle",
    )
    _text(
        drawing,
        272.5,
        66,
        "Sufficient fidelity preserves upper observables and decisions.",
        size=7.4,
        color=GRAY,
        anchor="middle",
    )
    drawing.add(Rect(30, 9, 485, 35, rx=6, ry=6, fillColor=PALE_AMBER, strokeColor=AMBER))
    _text(
        drawing,
        272.5,
        29,
        "Local All: complete finite-grammar accounting",
        size=8.1,
        color=AMBER,
        bold=True,
        anchor="middle",
    )
    _text(
        drawing,
        272.5,
        16,
        "Ambiguity | class inadequacy | indeterminate | current test: 256 ECA rules",
        size=7.0,
        color=GRAY,
        anchor="middle",
    )
    return drawing


def _workflow_card(
    drawing: Drawing,
    x: float,
    number: str,
    title: tuple[str, ...],
    action: str,
    output: tuple[str, ...],
    *,
    protected: bool,
) -> None:
    y, width, height = 61, 75, 138
    fill = PALE_GREEN if protected else PALE_BLUE
    stroke = GREEN if protected else BLUE
    drawing.add(
        Rect(
            x,
            y,
            width,
            height,
            rx=6,
            ry=6,
            fillColor=fill,
            strokeColor=stroke,
            strokeWidth=1.1,
        )
    )
    drawing.add(
        Rect(
            x + width / 2 - 10,
            y + 108,
            20,
            20,
            rx=4,
            ry=4,
            fillColor=NAVY,
            strokeColor=NAVY,
        )
    )
    _text(
        drawing,
        x + width / 2,
        y + 114,
        number,
        size=8.8,
        color=WHITE,
        bold=True,
        anchor="middle",
    )
    total = (len(title) - 1) * 9
    _multiline(
        drawing,
        x + width / 2,
        y + 94 + total / 2,
        title,
        size=8.1,
        leading=9,
        color=NAVY,
        bold_first=True,
        anchor="middle",
    )
    _text(
        drawing,
        x + width / 2,
        y + 67,
        action,
        size=6.2,
        color=GRAY,
        anchor="middle",
    )
    _text(
        drawing,
        x + width / 2,
        y + 51,
        "OUTPUT",
        size=5.5,
        color=GRAY,
        bold=True,
        anchor="middle",
    )
    drawing.add(
        Rect(
            x + 5,
            y + 10,
            width - 10,
            34,
            rx=4,
            ry=4,
            fillColor=WHITE,
            strokeColor=GRID,
            strokeWidth=0.8,
        )
    )
    output_total = (len(output) - 1) * 7.4
    _multiline(
        drawing,
        x + width / 2,
        y + 27 + output_total / 2 - 2.2,
        output,
        size=6.5,
        leading=7.4,
        color=stroke,
        bold_first=True,
        anchor="middle",
    )


def _six_step_workflow() -> Drawing:
    drawing = Drawing(540, 260)
    _text(
        drawing,
        18,
        240,
        "APHFS: six scientific decisions",
        size=14,
        color=NAVY,
        bold=True,
    )
    _text(
        drawing,
        18,
        224,
        "Each output becomes a premise for the next step; failure narrows the claim.",
        size=8.5,
        color=GRAY,
    )

    specs = (
        ("1", ("Define", "scope"), "declare search", ("candidate", "class"), False),
        ("2", ("Complete", "accounting"), "record all", ("terminal", "ledger"), False),
        ("3", ("Identify", "equivalence"), "match signatures", ("signature", "classes"), False),
        (
            "4",
            ("Test class", "adequacy"),
            "decide or abstain",
            ("retain / inadequate /", "indeterminate"),
            False,
        ),
        (
            "5",
            ("Verify scale", "and fidelity"),
            "test refinements",
            ("observable +", "decision check"),
            True,
        ),
        (
            "6",
            ("Evaluate on", "held-out data"),
            "judge fixed pipeline",
            ("scientific", "result"),
            True,
        ),
    )
    xs = tuple(12 + 88 * index for index in range(len(specs)))
    for spec, x in zip(specs, xs, strict=True):
        number, title, action, output, protected = spec
        _workflow_card(
            drawing,
            x,
            number,
            title,
            action,
            output,
            protected=protected,
        )
    for left, right in pairwise(xs):
        _arrow(drawing, left + 77, 130, right - 2, 130, NAVY)

    drawing.add(
        Rect(
            18,
            12,
            504,
            31,
            rx=5,
            ry=5,
            fillColor=PALE_AMBER,
            strokeColor=AMBER,
            strokeWidth=0.9,
        )
    )
    _text(
        drawing,
        270,
        25,
        "Evidence can retain, preserve ambiguity, reject the class, or remain indeterminate.",
        size=7.5,
        color=AMBER,
        bold=True,
        anchor="middle",
    )
    return drawing


def _save(drawing: Drawing, base: Path) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    pdf_path = base.with_suffix(".pdf")
    renderSVG.drawToFile(drawing, str(base.with_suffix(".svg")))
    _register_pdf_fonts()
    renderPDF.drawToFile(_pdf_font_clone(drawing), str(pdf_path))
    pdftoppm = shutil.which("pdftoppm")
    if pdftoppm is None:
        raise RuntimeError("pdftoppm is required to render PNG figures")
    subprocess.run(
        [pdftoppm, "-png", "-r", "180", "-singlefile", str(pdf_path), str(base)],
        check=True,
        capture_output=True,
    )


def generate(output_dir: Path) -> None:
    _save(_research_ladder(), output_dir / "framework_research_ladder_v3_5")
    _save(_six_step_workflow(), output_dir / "aphfs_six_step_workflow_v3_5")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    generate(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
