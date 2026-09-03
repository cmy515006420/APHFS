#!/usr/bin/env python3
"""Build the three local-only APHFS Phase 3.7 release candidates.

This is a standard-library-only release packager.  It copies only an explicit
allowlist, never imports ``aphfs``, never opens a raw role or protected result
container, and never invokes a benchmark, calibration, materializer, or locked
runner.  The public GitHub candidate is reused byte-for-byte as the bioRxiv
supplementary reproducibility archive; no fourth top-level ZIP is created.

Use ``--preflight-only`` while Phase 3.7 inputs are still being prepared.  That
mode is read-only and creates no staging directory or archive.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "tools/validate_v37_release_packages.py"

GITHUB_NAME = "APHFS_GITHUB_PUBLIC_RELEASE_CANDIDATE_v3"
BIORXIV_NAME = "APHFS_bioRxiv_submission_package_v3"
REVIEW_NAME = "APHFS_FINAL_RELEASE_ONLY_CORRECTION_REVIEW_BUNDLE_v3_7"
GITHUB_OUTPUT = ROOT / "release" / f"{GITHUB_NAME}.zip"
BIORXIV_OUTPUT = ROOT / "release" / f"{BIORXIV_NAME}.zip"
REVIEW_OUTPUT = ROOT / "handoff" / f"{REVIEW_NAME}.zip"

SUPPLEMENTARY_REPRO_NAME = "APHFS_reproducibility_artifacts_bioRxiv_v3.zip"
ZIP_TIME = (2026, 9, 3, 16, 0, 0)
MAX_GITHUB_BYTES = 120 * 1024 * 1024
MAX_BIORXIV_BYTES = 120 * 1024 * 1024
MAX_REVIEW_BYTES = 180 * 1024 * 1024

TITLE = (
    "All-Possibility Hierarchical Filtering Simulation (APHFS): A "
    "Resource-Bounded Framework from Executable Rules toward Multiscale "
    "Biology, Aging, and Rejuvenation Research"
)
FINAL_DOCX = "APHFS_Preprint_v1_0_bioRxiv_release_candidate_v3_7.docx"
FINAL_PDF = "APHFS_Preprint_v1_0_bioRxiv_release_candidate_v3_7.pdf"
BASELINE_DOCX = "APHFS_Preprint_v1_0_external_reviews_revised_candidate_v3_6.docx"
BASELINE_PDF = "APHFS_Preprint_v1_0_external_reviews_revised_candidate_v3_6.pdf"

RESULT_SHA256 = "6fb3f08e48b4d3496e190fbc38b029ee7c15e327c504924f8c03b6e2083aec9c"
RECEIPT_SHA256 = "730bfe099a74b1ccfa281e653e9330bf91a5e73c30b24a58cf52dd88028c4766"
CORE_SHA256 = "23946aea15d0a406c011ec2162a258f9bcf8702fcdc0ad4812f831b9064221e6"
PROTOCOL_SHA256 = "5c28bab547056fb188e5e24c9ff3f26aefc5b85117aa01439e362c7f72ad8527"
CONFIG_SHA256 = "23da043818dd11ac5a47dfb6a94198af333aa3673d543381f5fcbb9b62a41ed9"
FIDELITY_SHA256 = "24c28988441d9f53beb7976b60e3807ea27e3f38104a99d51af09887a6d9f137"
V36_PDF_SHA256 = "34ad35aee6386ab8915dabdbb70b30da1d0fab999d025a95a900076cd0a39124"
V36_DOCX_SHA256 = "e93cb365edd5d3ebf4d876b3b8dfd9ab37b0380a97a92c55ca050b012ad8f918"
V36_REVIEW_ZIP_SHA256 = "cb61c01653f50696902a224f5c1042c4f897ae5b84662a8ef9f334cdc4042cd8"
AMENDMENT_V2_SHA256 = "af59253b4f8ac9e9c570120712462daed52322b4aab0a57c8a61b7a39cf5b949"
GRAMMAR_SHA256 = "c4fd6f0e8fb6038db47d68f1bc1ddf2636e7947d323256d68c4e7ac8f9d6182c"


def _lines(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


SOURCE_CODE_FILES = _lines(
    """
src/aphfs/__init__.py
src/aphfs/benchmarks/__init__.py
src/aphfs/benchmarks/a.py
src/aphfs/benchmarks/b.py
src/aphfs/benchmarks/c.py
src/aphfs/benchmarks/confirmatory.py
src/aphfs/benchmarks/d.py
src/aphfs/benchmarks/e.py
src/aphfs/benchmarks/f0.py
src/aphfs/benchmarks/final_freeze.py
src/aphfs/benchmarks/freeze_preflight.py
src/aphfs/benchmarks/preflight.py
src/aphfs/benchmarks/runner.py
src/aphfs/bounds/__init__.py
src/aphfs/bounds/statistics.py
src/aphfs/cli/__init__.py
src/aphfs/cli/main.py
src/aphfs/coarse_graining/__init__.py
src/aphfs/coarse_graining/formal.py
src/aphfs/coarse_graining/memory.py
src/aphfs/constants.py
src/aphfs/eca/__init__.py
src/aphfs/eca/core.py
src/aphfs/eca/inference.py
src/aphfs/fidelity/__init__.py
src/aphfs/fidelity/contracts.py
src/aphfs/fidelity/ledger.py
src/aphfs/grammar/__init__.py
src/aphfs/grammar/registry.py
src/aphfs/inference/__init__.py
src/aphfs/inference/inadequacy.py
src/aphfs/pipelines/__init__.py
src/aphfs/pipelines/calibration.py
src/aphfs/pipelines/locked.py
src/aphfs/pipelines/locked_execution.py
src/aphfs/pipelines/protected.py
src/aphfs/provenance/__init__.py
src/aphfs/provenance/amendment.py
src/aphfs/provenance/hashing.py
src/aphfs/provenance/io.py
src/aphfs/provenance/runtime_freeze.py
src/aphfs/provenance/splits.py
src/aphfs/roles/__init__.py
src/aphfs/roles/approvals.py
src/aphfs/roles/certificates.py
src/aphfs/roles/protected_materialization.py
src/aphfs/roles/workflow.py
src/aphfs/schema/__init__.py
src/aphfs/schema/benchmark_results.py
src/aphfs/schema/validation.py
src/aphfs/signatures/__init__.py
src/aphfs/signatures/canonical.py
"""
)

SCHEMA_FILES = _lines(
    """
manifests/schema/amended_runtime_verification_record_v1.schema.json
manifests/schema/amended_runtime_verification_record_v2.schema.json
manifests/schema/author_final_freeze_approval_v1.schema.json
manifests/schema/author_non_scientific_amendment_approval_v1.schema.json
manifests/schema/author_non_scientific_amendment_scope_approval_v2.schema.json
manifests/schema/authorization_record.schema.json
manifests/schema/benchmarks/A0.result.schema.json
manifests/schema/benchmarks/A1.result.schema.json
manifests/schema/benchmarks/B0.result.schema.json
manifests/schema/benchmarks/B1.result.schema.json
manifests/schema/benchmarks/C.result.schema.json
manifests/schema/benchmarks/D0.result.schema.json
manifests/schema/benchmarks/D1.result.schema.json
manifests/schema/benchmarks/D2-CERT.result.schema.json
manifests/schema/benchmarks/D2-MEM.result.schema.json
manifests/schema/benchmarks/E.result.schema.json
manifests/schema/benchmarks/F0.result.schema.json
manifests/schema/calibration_certificate_record_v1.schema.json
manifests/schema/calibration_certificate_record_v2.schema.json
manifests/schema/calibration_execution_approval_v1.schema.json
manifests/schema/calibration_materialization_approval_v1.schema.json
manifests/schema/calibration_review_approval_v1.schema.json
manifests/schema/candidate_ledger.schema.json
manifests/schema/config.schema.json
manifests/schema/development_output.schema.json
manifests/schema/document_build_environment_manifest_v1.schema.json
manifests/schema/fidelity_contracts.schema.json
manifests/schema/final_freeze_record_v2.schema.json
manifests/schema/final_freeze_record_v3.schema.json
manifests/schema/final_freeze_record_v4.schema.json
manifests/schema/final_freeze_record_v5.schema.json
manifests/schema/freeze_record.schema.json
manifests/schema/grammar_manifest.schema.json
manifests/schema/locked_execution_approval_v1.schema.json
manifests/schema/locked_execution_failure_v1.schema.json
manifests/schema/locked_execution_intent_v1.schema.json
manifests/schema/locked_execution_receipt_v1.schema.json
manifests/schema/locked_materialization_approval_v1.schema.json
manifests/schema/locked_result_provenance_context_v1.schema.json
manifests/schema/non_scientific_amendment_review_approval_v1.schema.json
manifests/schema/non_scientific_freeze_amendment_v1.schema.json
manifests/schema/non_scientific_freeze_amendment_v2.schema.json
manifests/schema/preflight_result.schema.json
manifests/schema/protected_benchmark_config.schema.json
manifests/schema/protected_benchmark_config_v3.schema.json
manifests/schema/protected_execution_authorization_v1.schema.json
manifests/schema/protected_execution_authorization_v2.schema.json
manifests/schema/protected_fidelity_contracts_v2.schema.json
manifests/schema/protected_fidelity_contracts_v3.schema.json
manifests/schema/protected_locked_result_bundle_actual_v1.schema.json
manifests/schema/protected_protocol_v4.schema.json
manifests/schema/protected_protocol_v6.schema.json
manifests/schema/protected_result_bundle_actual_v1.schema.json
manifests/schema/protected_result_bundle_actual_v2.schema.json
manifests/schema/protected_result_bundle_v2.schema.json
manifests/schema/protected_role_manifest_v1.schema.json
manifests/schema/protected_role_manifest_v2.schema.json
manifests/schema/protected_role_manifest_v3.schema.json
manifests/schema/protected_role_materialization_authorization_v1.schema.json
manifests/schema/protocol.schema.json
manifests/schema/result_bundle.schema.json
manifests/schema/role_manifest.schema.json
manifests/schema/runtime_allowlist_v1.schema.json
manifests/schema/runtime_allowlist_v2.schema.json
manifests/schema/runtime_environment_manifest_v1.schema.json
manifests/schema/runtime_environment_manifest_v2.schema.json
manifests/schema/runtime_environment_manifest_v3.schema.json
manifests/schema/sealed_artifact_carryforward_v1.schema.json
manifests/schema/sealed_artifact_carryforward_v2.schema.json
manifests/schema/test_only_synthetic_locked_e2e_public_summary_v2_3.schema.json
manifests/schema/test_only_synthetic_locked_result_bundle_v1.schema.json
manifests/schema/test_only_synthetic_locked_result_bundle_v2.schema.json
"""
)

FIXED_CONFIG_FILES = _lines(
    """
configs/protected/protected_protocol_v6.json
configs/protected/protected_benchmark_config_v3.json
configs/protected/protected_fidelity_contracts_v3.json
manifests/grammar/eca_v4_final_review.json
"""
)

SAFE_EVIDENCE_FILES = _lines(
    """
safe_handoff/locked_audit_v2_4/LOCKED_RESULT_PUBLIC_SUMMARY_v2_4.json
safe_handoff/locked_audit_v2_4/LOCKED_RESOURCE_TIMING_SUMMARY_v2_4.json
safe_handoff/locked_audit_v2_4/LOCKED_ENDPOINT_SOURCE_DATA_v2_4.csv
safe_handoff/locked_audit_v2_4/LOCKED_FAILURE_INDETERMINATE_LEDGER_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_BLOCK_RECOMPUTATION_LEDGER_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_CP_RECOMPUTATION_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_D2_CERT_RECOMPUTATION_v2_4.json
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_DETERMINISTIC_CONTROL_LEDGER_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_ENDPOINT_SUMMARY_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_F0_DESCRIPTIVE_STRATA_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_FAILURE_INDETERMINATE_LEDGER_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_FIDELITY_RECOMPUTATION_LEDGER_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_POLICY_COST_SUMMARY_v2_4.csv
safe_handoff/locked_audit_v2_4/recomputation_v1/LOCKED_REVIEW_SOURCE_DATA_MANIFEST_v2_4.json
safe_handoff/locked_audit_v2_4/recomputation_v1/RECOMPUTATION_ISSUES_v2_4.json
"""
)

SOURCE_DATA_FILES = _lines(
    """
data/source/a1_retained_ambiguity.csv
data/source/b0_b1_decision_summary.csv
data/source/d2_certificate_interval.csv
data/source/evidence_category_summary_v3_7.csv
data/source/f0_conformance_summary.csv
data/source/policy_cost_components_v2_6.csv
data/source/policy_cost_results.csv
"""
)

FIGURE_FILES = tuple(
    f"figures/{stem}.{suffix}"
    for stem in (
        "framework_research_ladder_v3_5",
        "aphfs_six_step_workflow_v3_5",
        "scientific_result_evidence_classes_v3_7",
        "policy_cost_composition_v3_4",
    )
    for suffix in ("pdf", "svg", "png")
)

PUBLIC_TOOL_FILES = _lines(
    """
scripts/generate_framework_figures_v3_5.py
scripts/generate_locked_result_figures_v3_7.py
tools/recompute_locked_result_readonly_v2_4.py
tools/build_v37_release_packages.py
tools/validate_v37_release_packages.py
tests/release/test_figure3_evidence_sync_v3_7.py
pyproject.toml
requirements.lock
requirements-release-v2_5.txt
manifests/protected_runtime_requirements_v2.lock
release/materials/FIGURE_RENDERER_POLICY_v3_1.md
assets/fonts/LICENSE_LIBERATION
assets/fonts/LiberationSans-Regular.ttf
assets/fonts/LiberationSans-Bold.ttf
"""
)

AUDIT_FILES = _lines(
    """
docs/V3_6_FINAL_INDEPENDENT_REVIEW_RECORD_v3_7.md
docs/FIGURE3_EVIDENCE_CLASS_SYNCHRONIZATION_AUDIT_v3_7.md
docs/AI_MODEL_NOMENCLATURE_AND_DISCLOSURE_AUDIT_v3_7.md
docs/CORE_THEORY_PRESERVATION_TRACE_v3_7.md
docs/FINAL_LAYOUT_AND_FLOAT_AUDIT_v3_7.md
docs/BIORXIV_SCOPE_AND_SCREENING_NOTE_AUDIT_v3_7.md
docs/DATA_CODE_RELEASE_CONTENT_TRUTH_AUDIT_v3_7.md
docs/SCIENTIFIC_RESULT_UNCHANGED_ATTESTATION_v3_7.md
docs/FINAL_RELEASE_ONLY_REVISION_LEDGER_v3_7.md
docs/UNRESOLVED_LIVE_PUBLICATION_ACTIONS_v3_7.md
"""
)

REVIEW_TOOL_FILES = _lines(
    """
tools/build_docx_v37_release_candidate.py
tools/build_v37_release_packages.py
tools/validate_v37_release_packages.py
scripts/generate_locked_result_figures_v3_7.py
tests/release/test_figure3_evidence_sync_v3_7.py
requirements-release-v2_5.txt
"""
)

DATA_CODE_FUTURE_WORDING = (
    "The accompanying Supplement and versioned reproducibility archive provide the "
    "executable source tree, fixed configurations and schemas, environment locks, "
    "safe aggregate source tables, figure-generation code, A0 candidate/signature "
    "records, and read-only tools for reconstructing reported endpoint counts, "
    "exact-binomial calculations, aggregate tables, figures, intervals, and costs. "
    "The archive does not rerun the original one-time evaluation and is not an "
    "independently written implementation, new-role replication, or validation on "
    "new data. Code is licensed under the MIT License; the manuscript, documentation, "
    "and released aggregate data use CC BY 4.0. A public repository URL will be added "
    "only after the author separately authorizes publication and verifies the final "
    "remote contents."
)

PUBLIC_AI_DISCLOSURE = (
    "The author used OpenAI ChatGPT (primarily GPT-5.6 Sol through the standard and "
    "reasoning settings available in the author's account) and OpenAI Codex for "
    "outlining and drafting, methodological and formal suggestions, software "
    "implementation and refactoring, tests, mathematical exposition, figure "
    "preparation, literature organization, adversarial review, release engineering, "
    "and editing. Anthropic Claude (primarily Claude Opus 5 and Claude Fable 5.1) was "
    "used for methodological critique, adversarial review, and revision suggestions. "
    "Google Gemini and xAI Grok were used only for limited exploratory critique; their "
    "exact versions were not recorded, and no specific retained substantive "
    "contribution is attributed to them. The model-version history is therefore "
    "partial. AI outputs were treated as provisional suggestions, not evidence or "
    "independent validation. Mingyuan Chen originated the central research direction, "
    "set the scientific questions and claim boundaries, reviewed the manuscript and "
    "reported results, checked the functions and assumptions of Equations (1)--(10), "
    "the Clopper--Pearson calculations, relevant portions of load-bearing sources, and "
    "reported file-integrity checks, and directly observed the public read-only "
    "aggregate recomputation. The author has functional-level understanding of the "
    "core scientific code but did not conduct a repository-wide line-by-line review. "
    "The author made the final scientific decisions and accepts responsibility for the "
    "work within this disclosed review scope. No human, animal, clinical, or "
    "identifiable private biological data were supplied to these systems. AI systems "
    "are not authors or CRediT contributors."
)

MANUSCRIPT_SOURCE_PAIRS = (
    (FINAL_DOCX, FINAL_DOCX),
    (f"manuscript/{FINAL_PDF}", f"manuscript/{FINAL_PDF}"),
    ("manuscript/main_v3_7.tex", "manuscript/main_v3_7.tex"),
    ("manuscript/supplement_v3_7.tex", "manuscript/supplement_v3_7.tex"),
    ("manuscript/references_v3_7.bib", "manuscript/references_v3_7.bib"),
    ("manuscript/main_v3_7.bbl", "manuscript/main_v3_7.bbl"),
    ("manuscript/placeins.sty", "manuscript/placeins.sty"),
)

RELEASE_METADATA_FILES = _lines(
    """
release/biorxiv_metadata_v3_7.md
release/biorxiv_screening_note_v3_7.txt
release/biorxiv_upload_checklist_v3_7.md
"""
)

INSTRUCTION_FILES = _lines(
    """
CODEX_PHASE_3_7_FINAL_RELEASE_ONLY_CORRECTION_AND_BIORXIV_LOCAL_PACKAGE_v3_7_CN.md
APHFS_V3_7_MANDATORY_PATCH_SPEC_CN.md
"""
)

FORBIDDEN_PARTS = {
    ".git",
    ".venv",
    ".venv-protected-freeze-v1",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    "__pycache__",
    "protected_roles",
    "protected_results",
    "immutable_records_snapshot",
    "raw_roles",
    "raw_role_values",
    "authorizations",
    "chat_transcripts",
}
FORBIDDEN_NAMES = {
    ".DS_Store",
    "Thumbs.db",
    ".actual_locked_v1_started",
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
}
FORBIDDEN_ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".7z", ".rar", ".dmg")
WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


GITHUB_GENERATED = {
    "README.md",
    "README_PREPUBLICATION.md",
    "README_PUBLIC_TEMPLATE.md",
    "LICENSE",
    "LICENSE-DATA",
    "LICENSES/MIT.txt",
    "LICENSES/CC-BY-4.0-NOTICE.txt",
    "LICENSES/LICENSE_MAPPING.md",
    "CITATION.cff",
    "SECURITY.md",
    "PRIVACY.md",
    ".gitignore",
    "BUILD_PROVENANCE.json",
    "PUBLIC_ALLOWLIST.json",
    "PACKAGE_PRIVACY_AUDIT.md",
    "PROJECT_TREE.txt",
    "FILE_MANIFEST.csv",
    "SHA256SUMS.txt",
}
BIORXIV_GENERATED = {
    "00_README_FIRST.md",
    "PACKAGE_PRIVACY_AUDIT.md",
    "PROJECT_TREE.txt",
    "FILE_MANIFEST.csv",
    "SHA256SUMS.txt",
}
REVIEW_GENERATED = {
    "00_README_FIRST.md",
    "08_PACKAGE_AUDIT/PACKAGE_PRIVACY_AUDIT.md",
    "08_PACKAGE_AUDIT/FRESH_EXTRACTION_VALIDATION.md",
    "08_PACKAGE_AUDIT/PACKAGE_RELATIONSHIP.md",
    "08_PACKAGE_AUDIT/PROJECT_TREE.txt",
    "08_PACKAGE_AUDIT/FILE_MANIFEST.csv",
    "08_PACKAGE_AUDIT/SHA256SUMS.txt",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def safe_relative(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or any(ord(character) < 32 for character in value)
        or any(unicodedata.category(character) in {"Cc", "Cf"} for character in value)
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.as_posix() != value
        or not pure.parts
        or any(":" in part or part.endswith((" ", ".")) for part in pure.parts)
        or any(part.split(".", 1)[0].casefold() in WINDOWS_RESERVED for part in pure.parts)
    ):
        raise ValueError(f"unsafe relative path: {value!r}")
    if {part.casefold() for part in pure.parts} & {
        part.casefold() for part in FORBIDDEN_PARTS
    }:
        raise ValueError(f"forbidden package path: {value}")
    if pure.name in FORBIDDEN_NAMES or pure.name.endswith(
        (".pyc", ".pyo", ".bak", ".tmp", "~")
    ):
        raise ValueError(f"cache, backup, or guard path: {value}")
    if value.casefold().endswith(FORBIDDEN_ARCHIVE_SUFFIXES):
        raise ValueError(f"unapproved archive/image path: {value}")
    return pure


def require_regular(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or non-regular source: {label}")
    if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
        raise ValueError(f"special source file: {label}")
    return path


def source_path(relative: str) -> Path:
    pure = safe_relative(relative)
    cursor = ROOT
    for part in pure.parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(f"symlinked source component: {relative}")
    path = require_regular(cursor, relative)
    if not path.resolve(strict=True).is_relative_to(ROOT.resolve(strict=True)):
        raise ValueError(f"source escapes project root: {relative}")
    return path


def _prefixed(prefix: str, relatives: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    return tuple((f"{prefix}/{relative}", relative) for relative in relatives)


def github_pairs() -> tuple[tuple[str, str], ...]:
    manuscript = tuple(
        (f"manuscript/{PurePosixPath(destination).name}", source)
        if not destination.startswith("manuscript/")
        else (destination, source)
        for destination, source in MANUSCRIPT_SOURCE_PAIRS
    )
    return (
        manuscript
        + _prefixed("", SOURCE_CODE_FILES)
        + _prefixed("", SCHEMA_FILES)
        + _prefixed("", FIXED_CONFIG_FILES)
        + _prefixed("", SAFE_EVIDENCE_FILES)
        + _prefixed("", SOURCE_DATA_FILES)
        + _prefixed("", FIGURE_FILES)
        + _prefixed("", PUBLIC_TOOL_FILES)
    )


def _normalize_pairs(pairs: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    seen: dict[str, str] = {}
    for destination, source in pairs:
        destination = destination.lstrip("/")
        safe_relative(destination)
        safe_relative(source)
        key = collision_key(destination)
        if key in seen:
            raise ValueError(f"duplicate/colliding destination: {seen[key]!r} / {destination!r}")
        seen[key] = destination
        normalized.append((destination, source))
    return tuple(normalized)


def biorxiv_pairs() -> tuple[tuple[str, str], ...]:
    return (
        (f"01_MAIN_MANUSCRIPT/{FINAL_PDF}", f"manuscript/{FINAL_PDF}"),
        ("03_SUBMISSION_METADATA/biorxiv_metadata_v3_7.md", "release/biorxiv_metadata_v3_7.md"),
        (
            "03_SUBMISSION_METADATA/biorxiv_screening_note_v3_7.txt",
            "release/biorxiv_screening_note_v3_7.txt",
        ),
        (
            "03_SUBMISSION_METADATA/biorxiv_upload_checklist_v3_7.md",
            "release/biorxiv_upload_checklist_v3_7.md",
        ),
    )


def review_pairs() -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for destination, source in MANUSCRIPT_SOURCE_PAIRS:
        pairs.append((f"01_FINAL_MANUSCRIPT/{PurePosixPath(destination).name}", source))
    pairs.extend(_prefixed("01_FINAL_MANUSCRIPT", FIGURE_FILES))
    pairs.extend(
        (f"02_RELEASE_METADATA/{PurePosixPath(relative).name}", relative)
        for relative in RELEASE_METADATA_FILES
    )
    pairs.extend(
        (f"03_FINAL_AUDITS/{PurePosixPath(relative).name}", relative)
        for relative in AUDIT_FILES
    )
    pairs.append(("03_FINAL_AUDITS/DECISIONS.md", "DECISIONS.md"))
    pairs.extend(
        (f"04_PHASE3_7_INSTRUCTIONS/{PurePosixPath(relative).name}", relative)
        for relative in INSTRUCTION_FILES
    )
    pairs.append(
        (
            f"05_V3_6_READONLY_BASELINE/{BASELINE_PDF}",
            f"manuscript/{BASELINE_PDF}",
        )
    )
    pairs.append((f"05_V3_6_READONLY_BASELINE/{BASELINE_DOCX}", BASELINE_DOCX))
    pairs.extend(_prefixed("06_RELEASE_ONLY_TOOLING", REVIEW_TOOL_FILES))
    return tuple(pairs)


def expected_github() -> set[str]:
    return {destination for destination, _ in _normalize_pairs(github_pairs())} | GITHUB_GENERATED


def expected_biorxiv() -> set[str]:
    return (
        {destination for destination, _ in _normalize_pairs(biorxiv_pairs())}
        | {f"02_SUPPLEMENTARY_FILES/{SUPPLEMENTARY_REPRO_NAME}"}
        | BIORXIV_GENERATED
    )


def expected_review() -> set[str]:
    return (
        {destination for destination, _ in _normalize_pairs(review_pairs())}
        | {
            f"07_LOCAL_RELEASE_PACKAGES/{GITHUB_NAME}.zip",
            f"07_LOCAL_RELEASE_PACKAGES/{BIORXIV_NAME}.zip",
        }
        | REVIEW_GENERATED
    )


def iter_tree_files(root: Path) -> list[Path]:
    files: list[Path] = []
    seen: dict[str, str] = {}
    for current, directories, names in os.walk(root, followlinks=False):
        base = Path(current)
        directories[:] = sorted(directories)
        for name in directories:
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            if path.is_symlink():
                raise ValueError(f"symlink directory: {relative}")
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            key = collision_key(relative)
            if key in seen and seen[key] != relative:
                raise ValueError(f"case/Unicode collision: {seen[key]!r} / {relative!r}")
            seen[key] = relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"non-regular staged file: {relative}")
            if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                raise ValueError(f"special staged file: {relative}")
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def copy_pairs(stage: Path, pairs: tuple[tuple[str, str], ...]) -> None:
    for destination, source in _normalize_pairs(pairs):
        target = stage.joinpath(*PurePosixPath(destination).parts)
        if target.exists() or target.is_symlink():
            raise ValueError(f"refusing to overwrite staged path: {destination}")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path(source), target, follow_symlinks=False)
        target.chmod(0o644)


def copy_external(stage: Path, destination: str, source: Path) -> None:
    safe_relative(destination)
    require_regular(source, destination)
    target = stage.joinpath(*PurePosixPath(destination).parts)
    if target.exists() or target.is_symlink():
        raise ValueError(f"refusing to overwrite staged path: {destination}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target, follow_symlinks=False)
    target.chmod(0o644)


def write_text_new(path: Path, text: str) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to overwrite generated path: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o644)


def license_for(relative: str) -> str:
    if relative.startswith("assets/fonts/"):
        return "OFL-1.1"
    if relative in {"LICENSE", "LICENSES/MIT.txt"}:
        return "MIT"
    if relative.startswith(
        ("src/", "scripts/", "tools/", "tests/", "configs/", "manifests/schema/")
    ) or relative in {
        "pyproject.toml",
        "requirements.lock",
        "requirements-release-v2_5.txt",
        "manifests/protected_runtime_requirements_v2.lock",
    }:
        return "MIT"
    return "CC-BY-4.0"


def privacy_text() -> str:
    return """# Package privacy and archive-safety audit

Status: PASS only when accepted by the bundled standard-library validator.

This package was assembled from a finite explicit allowlist. Raw calibration
and locked role values, protected result containers, private authorization or
approval records, chat transcripts, credentials, workstation paths, caches,
virtual environments, historical review archives, and unrelated data are not
included. Validation is fail-closed for traversal, absolute or backslash
paths, links, special/encrypted members, duplicate or Unicode/case-colliding
names, CRC failures, secrets, local paths, and unapproved nested archives.
ZIP/DOCX members are recursively inspected. No remote, push, or upload was
created or performed.
"""


def public_readme() -> str:
    return f"""# APHFS local public-release candidate v3

Status: local pre-publication candidate. No Git remote, repository URL, DOI,
push, or external upload is represented by this archive.

The central APHFS theory and research direction were conceived by Mingyuan
Chen. The current 256-rule elementary-cellular-automaton study is an enumerable
test of the framework's search, accounting, ambiguity, inadequacy, fidelity,
and decision machinery; it is not a physical, biological, aging, rejuvenation,
or therapeutic validation.

Immutable identity anchors:

- locked result SHA-256: `{RESULT_SHA256}`
- locked receipt SHA-256: `{RECEIPT_SHA256}`

This candidate contains the executable source tree, fixed public
configurations and schemas, environment locks, safe aggregate source tables,
figure-generation code, A0 accounting/signature evidence through the finite
grammar and released audit ledger, and a read-only audit tool. It deliberately
contains no raw role values or protected result container. It cannot replay the
one-time evaluation and is not an independently written implementation,
new-role replication, or validation on new data.

PDF and SVG figures are canonical byte-reproducible outputs. PNG files are
renderer-dependent convenience previews; their integrity and dimensions, not
cross-renderer byte identity, are the public contract.

Code is licensed under MIT. The manuscript, documentation, figures, and
released aggregate data use CC BY 4.0. See `LICENSES/LICENSE_MAPPING.md`.

## Data and Code Availability

{DATA_CODE_FUTURE_WORDING}

## AI-assisted technologies

{PUBLIC_AI_DISCLOSURE}

Validate a fresh extraction without importing APHFS:

```bash
python3 -I -B tools/validate_v37_release_packages.py --kind github --path .
```

The release-only Figure 3 reproducibility check reads safe aggregate tables;
it does not open protected results or raw roles and does not execute a
benchmark, calibration, or locked audit. It requires a local Poppler
installation providing `pdftoppm` and `pdftotext` on `PATH`:

```bash
python3.12 -m venv ../v37-test
../v37-test/bin/python -m pip install -r requirements-release-v2_5.txt
../v37-test/bin/python -m pytest -q -s tests/release/test_figure3_evidence_sync_v3_7.py
```
"""


def public_template() -> str:
    return f"""# APHFS public repository template

Publication state: `PREPUBLICATION_LOCAL_CANDIDATE`.

Repository URL: `VERIFIED_REPOSITORY_URL_TO_BE_INSERTED_AFTER_AUTHOR_AUTHORIZATION`

Do not replace that placeholder until the author has separately authorized a
remote, verified the remote contents, and approved public release. The local
candidate preserves result `{RESULT_SHA256}` and receipt `{RECEIPT_SHA256}`.

## Data and Code Availability

{DATA_CODE_FUTURE_WORDING}

## AI-assisted technologies

{PUBLIC_AI_DISCLOSURE}
"""


def citation_cff() -> str:
    return f'''cff-version: 1.2.0
message: "If you use this software, please cite the accompanying preprint."
type: software
title: "APHFS public release candidate"
version: 1.0.0
authors:
  - family-names: Chen
    given-names: Mingyuan
    affiliation: >-
      Department of Biochemistry and Molecular Biology, Johns Hopkins Bloomberg
      School of Public Health, Johns Hopkins University
license: MIT
preferred-citation:
  type: article
  title: "{TITLE}"
  authors:
    - family-names: Chen
      given-names: Mingyuan
  year: 2026
'''


def license_mapping_text() -> str:
    return """# License mapping

The MIT License applies to software under `src/`, `scripts/`, `tools/`,
`tests/`, `configs/`, and software-oriented schema/environment files.

CC BY 4.0 applies to the manuscript, documentation, figures, and released
aggregate/source data. No raw role values or protected result container are
licensed or distributed by this candidate.

The bundled Liberation Sans font files under `assets/fonts/` remain under the
SIL Open Font License 1.1 reproduced in `assets/fonts/LICENSE_LIBERATION`.
"""


def _hashes_for_provenance() -> dict[str, str]:
    amendment_path = source_path("manifests/non_scientific_freeze_amendment_v2.json")
    if sha256(amendment_path) != AMENDMENT_V2_SHA256:
        raise ValueError("cumulative non-scientific amendment v2 identity drift")
    try:
        amendment = json.loads(amendment_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError("cumulative non-scientific amendment v2 is malformed") from error
    rows = amendment.get("amended_runtime_rows")
    if not isinstance(rows, list) or len(rows) != 151:
        raise ValueError("cumulative amendment runtime inventory row count drift")
    row_map: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"categories", "path", "sha256"}:
            raise ValueError("cumulative amendment runtime row is malformed")
        relative = safe_relative(str(row["path"])).as_posix()
        digest = str(row["sha256"])
        if relative in row_map or len(digest) != 64:
            raise ValueError("duplicate or malformed cumulative amendment runtime row")
        row_map[relative] = digest
    for relative in SOURCE_CODE_FILES + FIXED_CONFIG_FILES[:3]:
        if row_map.get(relative) != sha256(source_path(relative)):
            raise ValueError(f"frozen runtime source drift: {relative}")
    if sha256(source_path("manifests/grammar/eca_v4_final_review.json")) != GRAMMAR_SHA256:
        raise ValueError("frozen finite grammar identity drift")
    anchors = {
        "frozen_eca_core_sha256": sha256(source_path("src/aphfs/eca/core.py")),
        "protected_protocol_v6_sha256": sha256(
            source_path("configs/protected/protected_protocol_v6.json")
        ),
        "protected_benchmark_config_v3_sha256": sha256(
            source_path("configs/protected/protected_benchmark_config_v3.json")
        ),
        "protected_fidelity_contracts_v3_sha256": sha256(
            source_path("configs/protected/protected_fidelity_contracts_v3.json")
        ),
        "finite_grammar_sha256": GRAMMAR_SHA256,
        "cumulative_non_scientific_amendment_v2_sha256": AMENDMENT_V2_SHA256,
    }
    expected = {
        "frozen_eca_core_sha256": CORE_SHA256,
        "protected_protocol_v6_sha256": PROTOCOL_SHA256,
        "protected_benchmark_config_v3_sha256": CONFIG_SHA256,
        "protected_fidelity_contracts_v3_sha256": FIDELITY_SHA256,
        "finite_grammar_sha256": GRAMMAR_SHA256,
        "cumulative_non_scientific_amendment_v2_sha256": AMENDMENT_V2_SHA256,
    }
    if anchors != expected:
        raise ValueError(f"frozen scientific identity drift: expected={expected} actual={anchors}")
    return anchors


def write_github_generated(stage: Path, expected: set[str]) -> None:
    readme = public_readme()
    write_text_new(stage / "README.md", readme)
    write_text_new(stage / "README_PREPUBLICATION.md", readme)
    write_text_new(stage / "README_PUBLIC_TEMPLATE.md", public_template())
    shutil.copyfile(source_path("release/materials/LICENSES/MIT.txt"), stage / "LICENSE")
    (stage / "LICENSE").chmod(0o644)
    shutil.copyfile(
        source_path("release/materials/LICENSES/CC-BY-4.0-NOTICE.txt"),
        stage / "LICENSE-DATA",
    )
    (stage / "LICENSE-DATA").chmod(0o644)
    (stage / "LICENSES").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path("release/materials/LICENSES/MIT.txt"), stage / "LICENSES/MIT.txt")
    shutil.copyfile(
        source_path("release/materials/LICENSES/CC-BY-4.0-NOTICE.txt"),
        stage / "LICENSES/CC-BY-4.0-NOTICE.txt",
    )
    (stage / "LICENSES/MIT.txt").chmod(0o644)
    (stage / "LICENSES/CC-BY-4.0-NOTICE.txt").chmod(0o644)
    write_text_new(stage / "LICENSES/LICENSE_MAPPING.md", license_mapping_text())
    write_text_new(stage / "CITATION.cff", citation_cff())
    write_text_new(
        stage / "SECURITY.md",
        "# Security\n\n"
        "This local candidate has no remote or public issue tracker. Do not add "
        "credentials, raw roles, protected results, or private authorization records.\n",
    )
    write_text_new(stage / "PRIVACY.md", privacy_text())
    write_text_new(
        stage / ".gitignore",
        ".DS_Store\n.venv/\n.venv-*/\n__pycache__/\n.pytest_cache/\n.mypy_cache/\n.ruff_cache/\n*.py[cod]\n*.log\n",
    )
    provenance = {
        "record_type": "aphfs_phase3_7_local_public_candidate_build_provenance",
        "version": "v3.7",
        "candidate_is_unpublished": True,
        "git_remote_created": False,
        "push_performed": False,
        "external_upload_performed": False,
        "scientific_result_changed": False,
        "locked_result_sha256": RESULT_SHA256,
        "locked_receipt_sha256": RECEIPT_SHA256,
        "v3_6_review_bundle_sha256_reference_only": V36_REVIEW_ZIP_SHA256,
        "scientific_identity": _hashes_for_provenance(),
        "scientific_execution_counts": {
            "benchmark": 0,
            "calibration": 0,
            "locked_audit": 0,
            "role_replay": 0,
            "role_rematerialization": 0,
            "retuning": 0,
            "new_protected_computation": 0,
        },
    }
    write_text_new(
        stage / "BUILD_PROVENANCE.json",
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
    )
    allowlist = {
        "record_type": "aphfs_phase3_7_explicit_public_allowlist",
        "version": "v3.7",
        "paths": sorted(expected),
        "excluded": [
            "raw calibration or locked role values",
            "protected result containers",
            "private approval and authorization records",
            "chat transcripts",
            "historical review archives",
            "credentials, caches, virtual environments, and local paths",
        ],
    }
    write_text_new(
        stage / "PUBLIC_ALLOWLIST.json",
        json.dumps(allowlist, indent=2, sort_keys=True) + "\n",
    )
    write_text_new(stage / "PACKAGE_PRIVACY_AUDIT.md", privacy_text())


def write_biorxiv_generated(stage: Path, github_sha: str) -> None:
    write_text_new(
        stage / "00_README_FIRST.md",
        f"""# APHFS local bioRxiv submission candidate v3

This is a local candidate only. It has not been uploaded or submitted, and no
live repository URL is claimed. The main manuscript is the PDF under
`01_MAIN_MANUSCRIPT/`. The file
`02_SUPPLEMENTARY_FILES/{SUPPLEMENTARY_REPRO_NAME}` is the supplementary
reproducibility archive. Its bytes are identical to the separately delivered
GitHub public-release candidate v3 (SHA-256 `{github_sha}`). It is not a second
scientific execution and does not contain raw role values or a protected result
container.

Working route: bioRxiv first; Systems Biology; New Results; CC BY 4.0.
No remote, push, upload, or live-form action occurred.
""",
    )
    write_text_new(stage / "PACKAGE_PRIVACY_AUDIT.md", privacy_text())


def write_review_generated(stage: Path, github_sha: str, biorxiv_sha: str) -> None:
    write_text_new(
        stage / "00_README_FIRST.md",
        f"""# APHFS Phase 3.7 final release-only correction review bundle

This bundle contains the v3.7 manuscript, Figure 3 correction and other public
figures, bioRxiv metadata, the complete Phase 3.7 audit set, governing
instructions, a read-only v3.6 comparison manuscript, release-only tooling, and
the two local release candidates.

- GitHub candidate SHA-256: `{github_sha}`
- bioRxiv package SHA-256: `{biorxiv_sha}`
- immutable locked result SHA-256: `{RESULT_SHA256}`
- immutable locked receipt SHA-256: `{RECEIPT_SHA256}`
- v3.6 full review bundle identity (reference only; old ZIP excluded): `{V36_REVIEW_ZIP_SHA256}`

Scientific result changed: NO. Benchmark rerun = 0; calibration rerun = 0;
locked-audit rerun = 0; role replay/rematerialization = 0; retuning = 0; new
protected computation = 0; Git remote/push = 0; external upload = 0.

The package excludes raw roles, protected result containers, private approval
or authorization records, chat transcripts, caches, and historical ZIPs.
Review the manuscript first, then the Figure 3 synchronization audit, remaining
audits, metadata, local packages, and package-audit records.
""",
    )
    write_text_new(stage / "08_PACKAGE_AUDIT/PACKAGE_PRIVACY_AUDIT.md", privacy_text())
    write_text_new(
        stage / "08_PACKAGE_AUDIT/FRESH_EXTRACTION_VALIDATION.md",
        """# Fresh-extraction validation

Status: PASS only for an archive accepted by the bundled validator. The builder
constructs each archive twice with fixed ordering, timestamps, modes, and
storage method and requires byte identity. The standalone validator checks CRC,
archive bounds and member types before manual path-safe extraction to a new
temporary directory, then repeats exact-allowlist, SHA-256, privacy, nested
archive, document, figure, and immutable-anchor checks.
""",
    )
    write_text_new(
        stage / "08_PACKAGE_AUDIT/PACKAGE_RELATIONSHIP.md",
        f"""# Package relationship

The review bundle contains the separately delivered GitHub candidate
`{GITHUB_NAME}.zip` (SHA-256 `{github_sha}`) and bioRxiv package
`{BIORXIV_NAME}.zip` (SHA-256 `{biorxiv_sha}`). The bioRxiv package embeds the
same GitHub-candidate bytes under the submission-facing name
`{SUPPLEMENTARY_REPRO_NAME}`. No fourth top-level archive is created. Historical
review ZIPs and protected containers are excluded.
""",
    )


def write_ledgers(stage: Path, expected: set[str], base: str = "") -> None:
    prefix = f"{base.rstrip('/')}/" if base else ""
    manifest_rel = f"{prefix}FILE_MANIFEST.csv"
    sums_rel = f"{prefix}SHA256SUMS.txt"
    tree_rel = f"{prefix}PROJECT_TREE.txt"
    write_text_new(stage / tree_rel, "".join(f"{path}\n" for path in sorted(expected)))
    actual = {path.relative_to(stage).as_posix() for path in iter_tree_files(stage)}
    before_manifest = expected - {manifest_rel, sums_rel}
    if actual != before_manifest:
        raise ValueError(
            f"pre-manifest allowlist mismatch: missing={sorted(before_manifest-actual)} "
            f"extra={sorted(actual-before_manifest)}"
        )
    manifest = stage / manifest_rel
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(("relative_path", "size_bytes", "sha256", "license"))
        for relative in sorted(before_manifest):
            path = stage.joinpath(*PurePosixPath(relative).parts)
            writer.writerow((relative, path.stat().st_size, sha256(path), license_for(relative)))
    manifest.chmod(0o644)
    sums_payload = expected - {sums_rel}
    write_text_new(
        stage / sums_rel,
        "".join(
            f"{sha256(stage.joinpath(*PurePosixPath(relative).parts))}  {relative}\n"
            for relative in sorted(sums_payload)
        ),
    )
    final = {path.relative_to(stage).as_posix() for path in iter_tree_files(stage)}
    if final != expected:
        raise ValueError(
            f"final allowlist mismatch: missing={sorted(expected-final)} "
            f"extra={sorted(final-expected)}"
        )


def deterministic_zip(stage: Path, destination: Path, root_name: str) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"refusing to overwrite archive candidate: {destination}")
    entries: dict[str, Path | None] = {f"{root_name}/": None}
    for path in iter_tree_files(stage):
        relative = path.relative_to(stage).as_posix()
        pure = safe_relative(relative)
        parent = PurePosixPath(root_name)
        for part in pure.parts[:-1]:
            parent /= part
            entries[parent.as_posix() + "/"] = None
        entries[f"{root_name}/{relative}"] = path
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = b""
        for member in sorted(entries):
            source = entries[member]
            info = zipfile.ZipInfo(member, date_time=ZIP_TIME)
            info.create_system = 3
            info.extra = b""
            info.comment = b""
            info.compress_type = zipfile.ZIP_STORED
            if source is None:
                info.external_attr = (stat.S_IFDIR | 0o755) << 16 | 0x10
                archive.writestr(info, b"")
            else:
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, source.read_bytes())
    destination.chmod(0o644)


def run_validator(path: Path, kind: str) -> dict[str, object]:
    require_regular(VALIDATOR, "v3.7 package validator")
    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(VALIDATOR), "--kind", kind, "--path", str(path)],
        cwd=ROOT,
        env={
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"validator emitted non-JSON for {kind}: {completed.stderr.strip()}"
        ) from error
    if completed.returncode != 0 or report.get("status") != "PASS":
        raise ValueError(f"validator rejected {kind}: {report}")
    return report


def _source_status(pairs: tuple[tuple[str, str], ...]) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    invalid: list[str] = []
    for _, relative in _normalize_pairs(pairs):
        try:
            path = source_path(relative)
        except ValueError:
            missing.append(relative)
            continue
        if path.stat(follow_symlinks=False).st_size <= 0:
            invalid.append(f"empty source: {relative}")
    return sorted(set(missing)), sorted(set(invalid))


def preflight() -> dict[str, object]:
    groups = {
        "github": github_pairs(),
        "biorxiv": biorxiv_pairs(),
        "review": review_pairs(),
    }
    missing: set[str] = set()
    invalid: list[str] = []
    for pairs in groups.values():
        group_missing, group_invalid = _source_status(pairs)
        missing.update(group_missing)
        invalid.extend(group_invalid)
    identity_errors: list[str] = []
    if not missing:
        try:
            _hashes_for_provenance()
            if sha256(source_path(f"manuscript/{BASELINE_PDF}")) != V36_PDF_SHA256:
                identity_errors.append("v3.6 baseline PDF SHA-256 mismatch")
            if sha256(source_path(BASELINE_DOCX)) != V36_DOCX_SHA256:
                identity_errors.append("v3.6 baseline DOCX SHA-256 mismatch")
        except (OSError, ValueError) as error:
            identity_errors.append(str(error))
    existing_outputs = [
        str(path.resolve(strict=False))
        for path in (GITHUB_OUTPUT, BIORXIV_OUTPUT, REVIEW_OUTPUT)
        if path.exists() or path.is_symlink()
    ]
    ready = not missing and not invalid and not identity_errors and not existing_outputs
    return {
        "status": "READY" if ready else "WAITING_FOR_ARTIFACTS_OR_CLEAN_OUTPUTS",
        "read_only": True,
        "missing_sources": sorted(missing),
        "invalid_sources": sorted(invalid),
        "identity_errors": identity_errors,
        "existing_outputs_that_would_not_be_overwritten": existing_outputs,
        "expected_file_counts": {
            "github": len(expected_github()),
            "biorxiv": len(expected_biorxiv()),
            "review": len(expected_review()),
        },
        "package_relationship": "github bytes reused as bioRxiv supplementary reproducibility ZIP",
        "scientific_execution_counters": {
            "benchmark": 0,
            "calibration": 0,
            "locked_audit": 0,
            "role_replay": 0,
            "role_rematerialization": 0,
            "retuning": 0,
            "new_protected_computation": 0,
            "git_remote_or_push": 0,
            "external_upload": 0,
        },
    }


def _double_zip(
    stage: Path,
    workspace: Path,
    kind: str,
    root_name: str,
) -> tuple[Path, dict[str, object]]:
    first = workspace / f"{kind}_a.zip"
    second = workspace / f"{kind}_b.zip"
    deterministic_zip(stage, first, root_name)
    deterministic_zip(stage, second, root_name)
    if first.read_bytes() != second.read_bytes():
        raise ValueError(f"{kind} archive is not byte-deterministic")
    report = run_validator(first, kind)
    return first, report


def build() -> dict[str, object]:
    readiness = preflight()
    if readiness["status"] != "READY":
        raise ValueError(f"preflight is not READY: {readiness}")
    for output in (GITHUB_OUTPUT, BIORXIV_OUTPUT, REVIEW_OUTPUT):
        if output.exists() or output.is_symlink():
            raise ValueError(f"refusing to overwrite existing output: {output}")

    with tempfile.TemporaryDirectory(prefix=".aphfs-v37-release-build-", dir=ROOT) as temporary:
        workspace = Path(temporary)

        github_stage = workspace / GITHUB_NAME
        github_stage.mkdir(mode=0o755)
        copy_pairs(github_stage, github_pairs())
        write_github_generated(github_stage, expected_github())
        write_ledgers(github_stage, expected_github())
        run_validator(github_stage, "github")
        github_zip, github_validation = _double_zip(
            github_stage, workspace, "github", GITHUB_NAME
        )
        if github_zip.stat().st_size > MAX_GITHUB_BYTES:
            raise ValueError("GitHub candidate exceeds configured size ceiling")
        github_digest = sha256(github_zip)

        biorxiv_stage = workspace / BIORXIV_NAME
        biorxiv_stage.mkdir(mode=0o755)
        copy_pairs(biorxiv_stage, biorxiv_pairs())
        copy_external(
            biorxiv_stage,
            f"02_SUPPLEMENTARY_FILES/{SUPPLEMENTARY_REPRO_NAME}",
            github_zip,
        )
        write_biorxiv_generated(biorxiv_stage, github_digest)
        write_ledgers(biorxiv_stage, expected_biorxiv())
        run_validator(biorxiv_stage, "biorxiv")
        biorxiv_zip, biorxiv_validation = _double_zip(
            biorxiv_stage, workspace, "biorxiv", BIORXIV_NAME
        )
        if biorxiv_zip.stat().st_size > MAX_BIORXIV_BYTES:
            raise ValueError("bioRxiv candidate exceeds configured size ceiling")
        biorxiv_digest = sha256(biorxiv_zip)

        review_stage = workspace / REVIEW_NAME
        review_stage.mkdir(mode=0o755)
        copy_pairs(review_stage, review_pairs())
        copy_external(
            review_stage,
            f"07_LOCAL_RELEASE_PACKAGES/{GITHUB_NAME}.zip",
            github_zip,
        )
        copy_external(
            review_stage,
            f"07_LOCAL_RELEASE_PACKAGES/{BIORXIV_NAME}.zip",
            biorxiv_zip,
        )
        write_review_generated(review_stage, github_digest, biorxiv_digest)
        write_ledgers(review_stage, expected_review(), "08_PACKAGE_AUDIT")
        run_validator(review_stage, "review")
        review_zip, review_validation = _double_zip(
            review_stage, workspace, "review", REVIEW_NAME
        )
        if review_zip.stat().st_size > MAX_REVIEW_BYTES:
            raise ValueError("review bundle exceeds configured size ceiling")

        GITHUB_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        BIORXIV_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        REVIEW_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        os.replace(github_zip, GITHUB_OUTPUT)
        os.replace(biorxiv_zip, BIORXIV_OUTPUT)
        os.replace(review_zip, REVIEW_OUTPUT)

    return {
        "status": "PASS",
        "mode": "PHASE_3_7_LOCAL_RELEASE_ONLY_DETERMINISTIC_BUILD",
        "scientific_result_changed": False,
        "github_candidate": {
            "path": str(GITHUB_OUTPUT.resolve()),
            "size_bytes": GITHUB_OUTPUT.stat().st_size,
            "sha256": sha256(GITHUB_OUTPUT),
            "validation": github_validation,
        },
        "biorxiv_submission": {
            "path": str(BIORXIV_OUTPUT.resolve()),
            "size_bytes": BIORXIV_OUTPUT.stat().st_size,
            "sha256": sha256(BIORXIV_OUTPUT),
            "nested_reproducibility_sha256": sha256(GITHUB_OUTPUT),
            "validation": biorxiv_validation,
        },
        "final_review_bundle": {
            "path": str(REVIEW_OUTPUT.resolve()),
            "size_bytes": REVIEW_OUTPUT.stat().st_size,
            "sha256": sha256(REVIEW_OUTPUT),
            "validation": review_validation,
        },
        "scientific_execution_counters": readiness["scientific_execution_counters"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="read-only exact-source readiness check; creates no stage or ZIP",
    )
    args = parser.parse_args()
    try:
        report = preflight() if args.preflight_only else build()
        exit_code = 0 if report["status"] in {"PASS", "READY"} else 2
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        report = {"status": "FAIL", "error": f"{type(error).__name__}: {error}"}
        exit_code = 1
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
