"""Release-only tests for the final public APHFS Figure 3 evidence semantics.

These tests execute only the public aggregate-to-figure renderer. They never
import ``aphfs`` or open protected roles/results and cannot invoke scientific
execution paths.
"""

from __future__ import annotations

import hashlib
import struct
import subprocess
import sys
from pathlib import Path

from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/generate_locked_result_figures_v3_7.py"
MAIN = ROOT / "manuscript/main_v3_8.tex"
STEM = "scientific_result_evidence_classes_v3_7"
OLD_LABELS = (
    "Finite-sample endpoints",
    "D2-CERT certificate withdrawal",
    "Certificate withdrawal",
)
REQUIRED_LABELS = (
    "A1 preserves observational ambiguity",
    "59 x 1; 5 x 2",
    "61 x 1; 3 x 2",
    "B0: in-class generating rule",
    "64/64",
    "constructed radius-two setting",
    "B1 minimum class lower bound: 0.5",
    "Periodic Rule 170 is a cyclic shift.",
    "Global density is analytically preserved.",
    "0/64 calibration conformance failures",
    "0/64 held-out conformance failures",
    "Machine status: NOT_CONTRADICTED_BY_LOCKED_AUDIT",
    "Analytical / deterministic / formula conformance",
    "Constructed-workload conformance",
    "Constructed closed-map certificate-pipeline conformance",
    "Categories describe evidence type; they are not pooled",
    "performance evidence.",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def png_dimensions(path: Path) -> tuple[int, int]:
    raw = path.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    assert raw[12:16] == b"IHDR"
    width, height = struct.unpack(">II", raw[16:24])
    return width, height


def render(destination: Path) -> str:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--figure-dir", str(destination)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "SOURCE_DATA_ONLY=YES PROTECTED_RESULT_OPENED=NO" in completed.stdout
    assert "BENCHMARK_RUNS=0 CALIBRATION_RUNS=0 LOCKED_AUDIT_RUNS=0" in completed.stdout
    return completed.stdout


def pdf_text(path: Path) -> str:
    # Use the Python dependency locked in requirements-release-v2_5.txt so the
    # public test does not silently require an undeclared Poppler text utility.
    return " ".join(" ".join((page.extract_text() or "").split()) for page in PdfReader(path).pages)


def test_current_figure_has_exact_evidence_semantics() -> None:
    current_pdf = ROOT / "figures" / f"{STEM}.pdf"
    current_svg = ROOT / "figures" / f"{STEM}.svg"
    current_png = ROOT / "figures" / f"{STEM}.png"
    assert current_pdf.is_file() and current_svg.is_file() and current_png.is_file()
    joined = "\n".join(
        (
            pdf_text(current_pdf),
            current_svg.read_text(encoding="utf-8"),
            MAIN.read_text(encoding="utf-8"),
        )
    )
    for stale in OLD_LABELS:
        assert stale not in joined
    normalized = " ".join(joined.split())
    for required in REQUIRED_LABELS:
        assert required in normalized
    assert png_dimensions(current_png) == (2250, 1959)


def test_pdf_svg_canonical_and_png_same_renderer_parity(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    render(first)
    render(second)
    for suffix in ("pdf", "svg"):
        left = first / f"{STEM}.{suffix}"
        right = second / f"{STEM}.{suffix}"
        assert digest(left) == digest(right)
        assert left.read_bytes() == right.read_bytes()
    first_png = first / f"{STEM}.png"
    second_png = second / f"{STEM}.png"
    assert png_dimensions(first_png) == png_dimensions(second_png) == (2250, 1959)
    assert digest(first_png) == digest(second_png)
    assert first_png.read_bytes() == second_png.read_bytes()


def test_renderer_policy_is_explicit_in_source() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "PDF and SVG are canonical deterministic outputs" in source
    assert "PNG is a renderer-dependent" in source
    assert "PROTECTED_RESULT_OPENED=NO" in source
