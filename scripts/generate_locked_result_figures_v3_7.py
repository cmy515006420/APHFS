#!/usr/bin/env python3
"""Render the Phase 3.7 evidence-class Figure 3 from safe aggregate data only.

This release-only script reads already exported, SHA-bound aggregate CSV files.
It does not import ``aphfs``, open protected role material or a protected result
container, and cannot invoke benchmark, calibration, or locked-audit code.
PDF and SVG are canonical deterministic outputs.  PNG is a renderer-dependent
convenience preview produced from the canonical PDF by the local ``pdftoppm``.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

from reportlab import rl_config
from reportlab.graphics import renderPDF, renderSVG
from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont


rl_config.invariant = 1

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data/source"
DEFAULT_FIGURE_DIR = ROOT / "figures"
FONT_DIR = ROOT / "assets/fonts"
FONT_REGULAR = FONT_DIR / "LiberationSans-Regular.ttf"
FONT_BOLD = FONT_DIR / "LiberationSans-Bold.ttf"
PDF_FONT_REGULAR = "APHFS-LiberationSans"
PDF_FONT_BOLD = "APHFS-LiberationSans-Bold"
EXPECTED_RESULT_SHA256 = (
    "6fb3f08e48b4d3496e190fbc38b029ee7c15e327c504924f8c03b6e2083aec9c"
)
EXPECTED_EVIDENCE_CLASSES = (
    (
        "analytical_deterministic_formula_conformance",
        "A0;C;D0;D1;D2-MEM",
        "Analytical / deterministic / formula conformance",
    ),
    (
        "constructed_workload_conformance",
        "A1;B0;B1;E;F0",
        "Constructed-workload conformance",
    ),
    (
        "constructed_closed_map_certificate_pipeline_conformance",
        "D2-CERT",
        "Constructed closed-map certificate-pipeline conformance",
    ),
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_bound_rows(path: Path) -> list[dict[str, str]]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"safe source must be a regular non-symlink file: {path}")
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError(f"safe source is empty: {path}")
    if any(row.get("source_result_sha256") != EXPECTED_RESULT_SHA256 for row in rows):
        raise RuntimeError(f"safe source has a wrong immutable-result binding: {path}")
    return rows


def register_pdf_fonts() -> None:
    for path in (FONT_REGULAR, FONT_BOLD):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"embedded PDF font is missing: {path}")
    pdfmetrics.registerFont(TTFont(PDF_FONT_REGULAR, str(FONT_REGULAR)))
    pdfmetrics.registerFont(TTFont(PDF_FONT_BOLD, str(FONT_BOLD)))


def pdf_font_clone(drawing: Drawing) -> Drawing:
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


def text(
    drawing: Drawing,
    x: float,
    y: float,
    value: str,
    *,
    size: float = 8,
    color: colors.Color = colors.HexColor("#142337"),
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


def panel(
    drawing: Drawing,
    x: float,
    y: float,
    width: float,
    height: float,
    label: str,
    title: str,
) -> None:
    drawing.add(
        Rect(
            x,
            y,
            width,
            height,
            rx=5,
            ry=5,
            fillColor=colors.HexColor("#F8FAFC"),
            strokeColor=colors.HexColor("#CBD5E1"),
            strokeWidth=0.8,
        )
    )
    text(drawing, x + 10, y + height - 18, label, size=10, bold=True)
    text(drawing, x + 30, y + height - 18, title, size=8.5, bold=True)


def validate_sources(
    a1_rows: list[dict[str, str]],
    b_rows: list[dict[str, str]],
    d2_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, str]],
) -> None:
    a1 = {
        (row["metric"], int(row["retained_count"])): int(row["block_count"])
        for row in a1_rows
    }
    expected_a1 = {
        ("retained_candidate_count", 1): 59,
        ("retained_candidate_count", 2): 5,
        ("retained_signature_class_count", 1): 61,
        ("retained_signature_class_count", 2): 3,
    }
    if a1 != expected_a1:
        raise RuntimeError(f"A1 display-source contract mismatch: {a1!r}")

    b = {row["endpoint"]: row for row in b_rows}
    if set(b) != {"B0", "B1"}:
        raise RuntimeError("B0/B1 display-source endpoint contract mismatch")
    if b["B0"]["decision"] != "RETAIN_CLASS" or int(b["B0"]["block_count"]) != 64:
        raise RuntimeError("B0 immutable display contract mismatch")
    if (
        b["B1"]["decision"] != "MODEL_CLASS_INADEQUATE"
        or int(b["B1"]["block_count"]) != 64
        or b["B1"]["minimum_class_lower_bound"] != "0.5"
    ):
        raise RuntimeError("B1 immutable display contract mismatch")

    if len(d2_rows) != 1:
        raise RuntimeError("D2 display-source row-count mismatch")
    d2 = d2_rows[0]
    expected_d2 = {
        "endpoint": "D2-CERT",
        "status": "NOT_CONTRADICTED_BY_LOCKED_AUDIT",
        "violation_count": "0",
        "denominator": "64",
        "executed_rule_id": "170",
        "coarse_map": "global binary density",
    }
    for key, expected in expected_d2.items():
        if d2.get(key) != expected:
            raise RuntimeError(f"D2 immutable display contract mismatch for {key}")

    actual_classes = tuple(
        (row["display_category"], row["endpoints"], row["public_label"])
        for row in evidence_rows
    )
    if actual_classes != EXPECTED_EVIDENCE_CLASSES:
        raise RuntimeError(f"evidence-class display contract mismatch: {actual_classes!r}")
    if any(row.get("categories_are_inferentially_interchangeable") != "False" for row in evidence_rows):
        raise RuntimeError("evidence classes must remain inferentially non-interchangeable")


def draw_figure(
    a1_rows: list[dict[str, str]],
    b_rows: list[dict[str, str]],
    d2_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, str]],
) -> Drawing:
    validate_sources(a1_rows, b_rows, d2_rows, evidence_rows)
    drawing = Drawing(540, 470)
    navy = colors.HexColor("#142337")
    blue = colors.HexColor("#315A7D")
    light_blue = colors.HexColor("#A9C5DA")
    green = colors.HexColor("#2F6B4F")
    amber = colors.HexColor("#9A5A00")
    gray = colors.HexColor("#4C566A")

    text(
        drawing,
        270,
        449,
        "What the evaluation resolved and what remained ambiguous",
        size=14,
        color=navy,
        bold=True,
        anchor="middle",
    )
    text(
        drawing,
        270,
        432,
        "Panels separate immutable outcomes from their scientific evidence classes.",
        size=8.2,
        color=gray,
        anchor="middle",
    )

    panel(drawing, 14, 239, 250, 181, "A", "A1 preserves observational ambiguity")
    a1 = {
        (row["metric"], int(row["retained_count"])): int(row["block_count"])
        for row in a1_rows
    }
    for label, metric, y in (
        ("Retained candidates", "retained_candidate_count", 352),
        ("Retained signature classes", "retained_signature_class_count", 296),
    ):
        one = a1[(metric, 1)]
        two = a1[(metric, 2)]
        text(drawing, 27, y + 23, label, size=8.3, bold=True)
        text(drawing, 249, y + 23, f"{one} x 1; {two} x 2", size=7.5, color=gray, anchor="end")
        one_width = 220 * one / 64
        drawing.add(Rect(28, y, one_width, 18, fillColor=light_blue, strokeColor=navy, strokeWidth=0.5))
        drawing.add(Rect(28 + one_width, y, 220 - one_width, 18, fillColor=blue, strokeColor=navy, strokeWidth=0.5))
    drawing.add(Rect(28, 261, 9, 9, fillColor=light_blue, strokeColor=navy, strokeWidth=0.5))
    text(drawing, 42, 262, "1 retained", size=7.2)
    drawing.add(Rect(99, 261, 9, 9, fillColor=blue, strokeColor=navy, strokeWidth=0.5))
    text(drawing, 113, 262, "2 retained", size=7.2)
    text(drawing, 249, 247, "generating rule retained: 64/64", size=7.2, color=green, bold=True, anchor="end")

    panel(drawing, 276, 239, 250, 181, "B", "ECA class: retention and inadequacy")
    b = {row["endpoint"]: row for row in b_rows}
    for endpoint, descriptor, qualifier, decision, row_color, y in (
        ("B0", "in-class generating rule", "", "Class retained", green, 347),
        ("B1", "ECA class", "constructed radius-two setting", "MODEL_CLASS_INADEQUATE", amber, 281),
    ):
        text(drawing, 290, y + (38 if qualifier else 27), f"{endpoint}: {descriptor}", size=8.1, bold=True)
        if qualifier:
            text(drawing, 290, y + 26, qualifier, size=7.2, color=gray)
        drawing.add(Rect(291, y, 218, 21, rx=3, ry=3, fillColor=colors.white, strokeColor=row_color, strokeWidth=1.2))
        text(drawing, 299, y + 7, decision, size=7.5, color=row_color, bold=True)
        text(drawing, 501, y + 7, f"{b[endpoint]['block_count']}/64", size=7.8, color=row_color, bold=True, anchor="end")
    text(drawing, 290, 265, "B1 minimum class lower bound: 0.5", size=7.5, color=gray)
    text(drawing, 290, 249, "Inadequacy is limited to this constructed setting.", size=7.3, color=gray)

    panel(drawing, 14, 18, 250, 208, "C", "D2-CERT: certificate-pipeline conformance")
    d2 = d2_rows[0]
    text(drawing, 28, 174, "Periodic Rule 170 is a cyclic shift.", size=8.1, bold=True)
    text(drawing, 28, 157, "Global density is analytically preserved.", size=8.0, color=blue)
    drawing.add(Line(28, 146, 249, 146, strokeColor=colors.HexColor("#D8DEE9"), strokeWidth=0.8))
    drawing.add(Circle(34, 126, 3.5, fillColor=green, strokeColor=green))
    text(drawing, 44, 123, "0/64 calibration conformance failures", size=7.7, bold=True)
    drawing.add(Circle(34, 105, 3.5, fillColor=green, strokeColor=green))
    text(drawing, 44, 102, "0/64 held-out conformance failures", size=7.7, bold=True)
    text(drawing, 28, 80, "Checks the certificate pipeline, not unknown", size=7.2, color=gray)
    text(drawing, 28, 67, "coarse-law accuracy.", size=7.2, color=gray)
    text(drawing, 28, 47, f"Machine status: {d2['status']}", size=6.1, color=amber, bold=True)

    panel(drawing, 276, 18, 250, 208, "D", "Evidence classes are not interchangeable")
    category_colors = (blue, green, amber)
    category_y = (164, 112, 60)
    for row, row_color, y in zip(evidence_rows, category_colors, category_y, strict=True):
        text(drawing, 291, y + 24, row["public_label"], size=6.7, bold=True)
        drawing.add(Rect(291, y + 5, 218, 13, rx=2, ry=2, fillColor=row_color, strokeColor=navy, strokeWidth=0.4))
        text(drawing, 291, y - 8, row["endpoints"].replace(";", ", "), size=7.0, color=gray)
    text(drawing, 291, 36, "Categories describe evidence type; they are not pooled", size=6.5, color=gray)
    text(drawing, 291, 26, "performance evidence.", size=6.5, color=gray)
    return drawing


def save_figure(drawing: Drawing, path_base: Path) -> list[Path]:
    path_base.parent.mkdir(parents=True, exist_ok=True)
    pdf_path = path_base.with_suffix(".pdf")
    svg_path = path_base.with_suffix(".svg")
    png_path = path_base.with_suffix(".png")
    renderSVG.drawToFile(drawing, str(svg_path))
    register_pdf_fonts()
    renderPDF.STATE_DEFAULTS["fontName"] = PDF_FONT_REGULAR
    # ReportLab otherwise registers its inherited Times-Roman graphics-state
    # default even though every visible String is assigned an embedded font.
    # Supplying the registered TrueType face as the initial canvas font keeps
    # the canonical PDF free of an unused, unembedded base-font resource.
    renderPDF.drawToFile(
        pdf_font_clone(drawing),
        str(pdf_path),
        initialFontName=PDF_FONT_REGULAR,
    )
    pdftoppm = shutil.which("pdftoppm")
    if pdftoppm is None:
        raise RuntimeError("pdftoppm is required for the convenience PNG preview")
    subprocess.run(
        [pdftoppm, "-png", "-r", "300", "-singlefile", str(pdf_path), str(path_base)],
        check=True,
        capture_output=True,
        text=True,
    )
    if not png_path.is_file():
        raise RuntimeError("PNG renderer did not create the expected preview")
    return [pdf_path, svg_path, png_path]


def generate(data_dir: Path, figure_dir: Path) -> list[Path]:
    a1_rows = read_bound_rows(data_dir / "a1_retained_ambiguity.csv")
    b_rows = read_bound_rows(data_dir / "b0_b1_decision_summary.csv")
    d2_rows = read_bound_rows(data_dir / "d2_certificate_interval.csv")
    evidence_rows = read_bound_rows(data_dir / "evidence_category_summary_v3_7.csv")
    drawing = draw_figure(a1_rows, b_rows, d2_rows, evidence_rows)
    return save_figure(drawing, figure_dir / "scientific_result_evidence_classes_v3_7")


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--figure-dir", type=Path, default=DEFAULT_FIGURE_DIR)
    args = parser.parse_args()
    outputs = generate(args.data_dir.resolve(), args.figure_dir.resolve())
    print("SOURCE_DATA_ONLY=YES PROTECTED_RESULT_OPENED=NO")
    print(f"SOURCE_RESULT_SHA256={EXPECTED_RESULT_SHA256}")
    for output in outputs:
        print(f"WROTE {display_path(output)} SHA256={sha256(output)}")
    print("PDF_SVG_CANONICAL=YES PNG_RENDERER_DEPENDENT_PREVIEW=YES")
    print("BENCHMARK_RUNS=0 CALIBRATION_RUNS=0 LOCKED_AUDIT_RUNS=0")
    print("RAW_ROLE_READS=0 ROLE_REPLAY=0 ROLE_REMATERIALIZATION=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
