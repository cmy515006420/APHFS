"""Transparent verification for the v2.2 non-scientific runtime amendment.

The approved v1.8 freeze remains immutable.  This module verifies a narrowly
scoped execution-plumbing delta against the freeze's exact 127-row baseline;
it never treats the amended runtime as a replacement scientific freeze.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from aphfs.provenance.hashing import sha256_file, sha256_json
from aphfs.provenance.runtime_freeze import (
    RuntimeFreezeMismatch,
    compute_runtime_inventory,
    freeze_record_payload_sha256,
)
from aphfs.schema.validation import load_json_object, validate_instance

NON_SCIENTIFIC_AMENDMENT_MISMATCH = "NON_SCIENTIFIC_AMENDMENT_MISMATCH"
SEALED_ARTIFACT_CARRYFORWARD_MISMATCH = "SEALED_ARTIFACT_CARRYFORWARD_MISMATCH"
V22_REVIEW_BUNDLE_SHA256 = (
    "b1c0d11b2ffe240e9c76b1ab5752e0d5edf8e7a61153fefc00f2db6ea339f696"
)
LOCKED_ISOLATED_EXACT_COMMAND_SHA256 = (
    "cc09888f1e978ee2836032123278d34d5d00c702707e3dfb99bb8902d57ab97e"
)


class NonScientificAmendmentMismatch(PermissionError):
    """Raised before protected values are parsed or a benchmark is called."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"{NON_SCIENTIFIC_AMENDMENT_MISMATCH}: {detail}")
        self.code = NON_SCIENTIFIC_AMENDMENT_MISMATCH


class SealedArtifactCarryforwardMismatch(PermissionError):
    """Raised when an immutable calibration/role provenance binding drifts."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"{SEALED_ARTIFACT_CARRYFORWARD_MISMATCH}: {detail}")
        self.code = SEALED_ARTIFACT_CARRYFORWARD_MISMATCH


# This is deliberately exact.  A later execution-plumbing change needs a new,
# separately reviewed amendment instead of silently widening a prefix/glob.
V22_ALLOWED_RUNTIME_CHANGE_PATHS = frozenset(
    {
        "manifests/schema/amended_runtime_verification_record_v1.schema.json",
        "manifests/schema/author_non_scientific_amendment_approval_v1.schema.json",
        "manifests/schema/locked_execution_approval_v1.schema.json",
        "manifests/schema/locked_execution_failure_v1.schema.json",
        "manifests/schema/locked_execution_intent_v1.schema.json",
        "manifests/schema/locked_execution_receipt_v1.schema.json",
        "manifests/schema/non_scientific_freeze_amendment_v1.schema.json",
        "manifests/schema/sealed_artifact_carryforward_v1.schema.json",
        "manifests/schema/test_only_synthetic_locked_result_bundle_v1.schema.json",
        "scripts/run_locked_audit.py",
        "scripts/run_locked_audit_once.py",
        "src/aphfs/pipelines/locked_execution.py",
        "src/aphfs/pipelines/protected.py",
        "src/aphfs/provenance/amendment.py",
        "src/aphfs/provenance/runtime_freeze.py",
        "src/aphfs/roles/certificates.py",
    }
)

_CARRYFORWARD_PATHS = {
    "calibration_role_manifest": "protected_roles/calibration/calibration_role_v1.json",
    "calibration_result_bundle": (
        "protected_results/calibration/calibration_result_bundle_v1.json"
    ),
    "calibration_certificate_record": (
        "protected_results/calibration/calibration_certificate_record_v2.json"
    ),
    "calibration_review_approval": (
        "authorizations/calibration_review_approval_v1.json"
    ),
    "calibration_role_commitment_public": (
        "safe_handoff/calibration_role_commitment_public_v1.json"
    ),
    "locked_role_manifest": "protected_roles/locked/locked_role_v1.json",
    "locked_role_commitment_public": (
        "safe_handoff/locked_role_commitment_public_v1.json"
    ),
    "locked_materialization_approval": (
        "authorizations/locked_materialization_approval_v1.json"
    ),
    "locked_materialization_intent": (
        "protected_role_provenance/locked_materialization_intent_v1.json"
    ),
    "locked_materialization_receipt": (
        "protected_role_provenance/locked_materialization_receipt_v1.json"
    ),
}

_V21_CARRYFORWARD_RAW_SHA256 = {
    "calibration_role_manifest": (
        "72cee46237964b59b5b2274f51d895ace3ebedf1b2335826fa299f9e0ebae74a"
    ),
    "calibration_result_bundle": (
        "71bad876e585867a76aa7ab07df4faa60d196220ef4e94e252c13fb6e93e0ad5"
    ),
    "calibration_certificate_record": (
        "d39f19cc09b091cc41a63123ae8a72055bbe45d354cb0923b2374fd276f30fab"
    ),
    "calibration_review_approval": (
        "c9bc66388d49de797a26ade4fc15892bf3518d7d1db37f1c59776b728d9a7d7a"
    ),
    "calibration_role_commitment_public": (
        "fbfb442390f12babedfbcddad63d6aa31f461335ebc91b8be753eb4ee3654595"
    ),
    "locked_role_manifest": (
        "3d405fbb77764d94881f4cfc25dee27357ccb478d8856102628c0d199591ecdf"
    ),
    "locked_role_commitment_public": (
        "e272a984280bacffa49f192e23081b22d1904fd8f4645a5a48b9fbe0e4c20a30"
    ),
    "locked_materialization_approval": (
        "d549df48c99b711ab5146b930a12aa347804fe4636b3a2e89e68d6404a824325"
    ),
    "locked_materialization_intent": (
        "fe199d772d198b0a9051977b5ebb9cf247ed580cd20d088e6a176eb0cbe4cd33"
    ),
    "locked_materialization_receipt": (
        "43b8dccbbd991c470f141681f87b7891bd44dffb6e37989783e3e19e3fbe18b4"
    ),
}

_V21_ROLE_COMMITMENTS = {
    "calibration": (
        "19607c1da74e7edef0a03d90199745519d51618c894037f6d9d4fc6e01b0e4d7"
    ),
    "locked": (
        "c018abe17e6b9f5cbf80997bc03c086746867e1e87a58f0fea90f311a1782596"
    ),
}

_V18_MANUSCRIPT_SHA256 = {
    "APHFS_Preprint_Draft_v1_8_precalibration.docx": (
        "b5fe3435497ce59f1a639ccd53fa482d9c7b4ec15e7dd66a693b63ff52fe5175"
    ),
    "manuscript/APHFS_Preprint_Draft_v1_8_precalibration.pdf": (
        "b10b3386705508c1f4b63053ed952421fea49978033c6b4790c6d22ca0cc5c15"
    ),
    "manuscript/main.tex": (
        "c82175f1691d02492736dd568c7594a3a9d278fc770c4f75975e7d83b39a9963"
    ),
    "manuscript/supplement.tex": (
        "fc2d62c9de4cf8c12bde1f7013edf687ad69707674c09f0a4334122ea5b5b1ad"
    ),
    "manuscript/references.bib": (
        "fae4ee5c9fa51e3af2b145b32f45ebab941f7bf86483cbb1ac32a9b6b523e42b"
    ),
    "manuscript/arxiv_metadata_v1_8_draft.md": (
        "ca33e6c0562971ab4846f113ea815663903cd73eb483bae8b5f13249e7848de6"
    ),
    "manuscript/figures/docx_equation_v17_comparator.png": (
        "2044dff8ea1a760308cda808d9e8a8f8fa8e3046c5729fc70e325799ddaedd5d"
    ),
    "manuscript/figures/docx_equation_v17_cross_domain.png": (
        "052c13c1b6d529253acdf723b36d1795b5f0ee10de53173c43b2efcfed177a4b"
    ),
    "manuscript/figures/docx_equation_v17_finite_cardinality.png": (
        "cff3eb4ee95414fea553a62538718510a0ee56a54566a9031b5d361f81420e80"
    ),
    "manuscript/figures/docx_equation_v17_finite_concentration.png": (
        "0accd4f2211b05647f8e726c18ae7f933fd090b5f4fa31a0ae54777d5345eff3"
    ),
    "manuscript/figures/figure1_bidirectional_v18.png": (
        "7a68cc2b1fd1d3b6b93f673feed994c856086875113e4ca94bc0aec7ea77c545"
    ),
    "manuscript/figures/figure1_bidirectional_v18.tex": (
        "df51fd1df733393b4a514dcadd5f8554f53c2525b47686a15ef9a9e171fc1788"
    ),
}


def _safe_relative_path(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise NonScientificAmendmentMismatch("record contains an unsafe path")
    return path


def _unique_by_path(rows: list[dict[str, Any]], *, label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        relative = _safe_relative_path(str(row["path"])).as_posix()
        if relative in indexed:
            raise NonScientificAmendmentMismatch(f"duplicate {label} path")
        indexed[relative] = row
    return indexed


def _base_category_hashes(rows: list[dict[str, Any]]) -> dict[str, str]:
    categories = {
        category
        for row in rows
        for category in str(row["categories"]).split(",")
        if category
    }
    return {
        category: sha256_json(
            [
                {"path": row["path"], "sha256": row["sha256"]}
                for row in rows
                if category in str(row["categories"]).split(",")
            ]
        )
        for category in sorted(categories)
    }


def _expected_scientific_paths(project_root: Path) -> dict[str, str]:
    categories: dict[str, str] = {}
    patterns = (
        ("src/aphfs/benchmarks/**/*.py", "SCIENTIFIC_ENGINE"),
        ("src/aphfs/eca/**/*.py", "SCIENTIFIC_ENGINE"),
        ("src/aphfs/fidelity/**/*.py", "SCIENTIFIC_ENGINE"),
        ("manifests/schema/benchmarks/*.json", "BENCHMARK_RESULT_SCHEMA"),
    )
    for pattern, category in patterns:
        matches = sorted(path for path in project_root.glob(pattern) if path.is_file())
        if not matches:
            raise NonScientificAmendmentMismatch(
                f"scientific protected pattern matched no files: {pattern}"
            )
        for path in matches:
            categories[path.relative_to(project_root).as_posix()] = category
    exact = {
        "src/aphfs/bounds/statistics.py": "SCIENTIFIC_ENGINE",
        "src/aphfs/schema/benchmark_results.py": "SCIENTIFIC_ENGINE",
        "configs/protected/protected_protocol_v6.json": (
            "PROTOCOL_CONFIG_FIDELITY"
        ),
        "configs/protected/protected_benchmark_config_v3.json": (
            "PROTOCOL_CONFIG_FIDELITY"
        ),
        "configs/protected/protected_fidelity_contracts_v3.json": (
            "PROTOCOL_CONFIG_FIDELITY"
        ),
        "APHFS_Preprint_Draft_v1_8_precalibration.docx": "MANUSCRIPT_V1_8",
        "manuscript/APHFS_Preprint_Draft_v1_8_precalibration.pdf": (
            "MANUSCRIPT_V1_8"
        ),
        "manuscript/main.tex": "MANUSCRIPT_V1_8",
        "manuscript/supplement.tex": "MANUSCRIPT_V1_8",
        "manuscript/references.bib": "MANUSCRIPT_V1_8",
        "manuscript/arxiv_metadata_v1_8_draft.md": "MANUSCRIPT_V1_8",
        "manuscript/figures/docx_equation_v17_comparator.png": "MANUSCRIPT_V1_8",
        "manuscript/figures/docx_equation_v17_cross_domain.png": "MANUSCRIPT_V1_8",
        "manuscript/figures/docx_equation_v17_finite_cardinality.png": "MANUSCRIPT_V1_8",
        "manuscript/figures/docx_equation_v17_finite_concentration.png": "MANUSCRIPT_V1_8",
        "manuscript/figures/figure1_bidirectional_v18.png": "MANUSCRIPT_V1_8",
        "manuscript/figures/figure1_bidirectional_v18.tex": "MANUSCRIPT_V1_8",
    }
    for relative, category in exact.items():
        if not (project_root / relative).is_file():
            raise NonScientificAmendmentMismatch(
                f"scientific protected file is absent: {relative}"
            )
        categories[relative] = category
    return categories


def validate_author_amendment_approval(
    *,
    project_root: Path,
    approval_path: Path,
    amendment_path: Path,
    base_freeze_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Validate the one-way author binding without authorizing a locked run."""
    approval = load_json_object(approval_path)
    validate_instance(
        approval,
        project_root
        / "manifests/schema/author_non_scientific_amendment_approval_v1.schema.json",
        instance_name=approval_path.as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_NON_SCIENTIFIC_AMENDMENT_AUTHOR_APPROVAL"
        if allow_test_only_synthetic
        else "NON_SCIENTIFIC_AMENDMENT_AUTHOR_APPROVAL"
    )
    if approval.get("artifact_label") != expected_label:
        raise NonScientificAmendmentMismatch("amendment approval label mismatch")
    amendment = load_json_object(amendment_path)
    expected = {
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_inventory_sha256": amendment.get(
            "base_runtime_inventory_sha256"
        ),
        "amended_runtime_inventory_sha256": amendment.get(
            "amended_runtime_inventory_sha256"
        ),
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
    }
    if any(approval.get(key) != value for key, value in expected.items()):
        raise NonScientificAmendmentMismatch("author amendment approval binding mismatch")
    if any(
        approval.get(key) is not False
        for key in (
            "locked_execution_authorized",
            "calibration_rerun_authorized",
            "role_rematerialization_authorized",
            "scientific_change_authorized",
        )
    ):
        raise NonScientificAmendmentMismatch("amendment approval exceeds v2.2 scope")
    return approval


def verify_sealed_artifact_carryforward(
    *,
    project_root: Path,
    carryforward_path: Path,
    amendment_path: Path,
    amendment_approval_path: Path,
    base_freeze_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Hash sealed files without parsing either protected role manifest."""
    carry = load_json_object(carryforward_path)
    validate_instance(
        carry,
        project_root / "manifests/schema/sealed_artifact_carryforward_v1.schema.json",
        instance_name=carryforward_path.as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_SEALED_ARTIFACT_CARRYFORWARD"
        if allow_test_only_synthetic
        else "SEALED_ARTIFACT_CARRYFORWARD"
    )
    if carry.get("artifact_label") != expected_label:
        raise SealedArtifactCarryforwardMismatch("carry-forward label mismatch")
    top_expected = {
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
        "author_non_scientific_amendment_approval_sha256": sha256_file(
            amendment_approval_path
        ),
    }
    if any(carry.get(key) != value for key, value in top_expected.items()):
        raise SealedArtifactCarryforwardMismatch("carry-forward provenance mismatch")
    amendment = load_json_object(amendment_path)
    if (
        carry.get("base_runtime_inventory_sha256")
        != amendment.get("base_runtime_inventory_sha256")
        or carry.get("amended_runtime_inventory_sha256")
        != amendment.get("amended_runtime_inventory_sha256")
    ):
        raise SealedArtifactCarryforwardMismatch(
            "carry-forward runtime inventory binding mismatch"
        )
    rows = cast(list[dict[str, Any]], carry["artifacts"])
    by_id = {str(row["artifact_id"]): row for row in rows}
    if len(by_id) != len(rows) or set(by_id) != set(_CARRYFORWARD_PATHS):
        raise SealedArtifactCarryforwardMismatch("carry-forward artifact set mismatch")
    for artifact_id, expected_relative in _CARRYFORWARD_PATHS.items():
        row = by_id[artifact_id]
        if row.get("path") != expected_relative:
            raise SealedArtifactCarryforwardMismatch(
                f"carry-forward fixed path mismatch for {artifact_id}"
            )
        path = project_root / expected_relative
        if path.is_symlink() or not path.is_file():
            raise SealedArtifactCarryforwardMismatch(
                f"carry-forward artifact is absent or symbolic: {artifact_id}"
            )
        if row.get("raw_sha256") != sha256_file(path):
            raise SealedArtifactCarryforwardMismatch(
                f"carry-forward raw hash mismatch for {artifact_id}"
            )
        if (
            not allow_test_only_synthetic
            and row.get("raw_sha256")
            != _V21_CARRYFORWARD_RAW_SHA256[artifact_id]
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"carry-forward differs from reviewed v2.1: {artifact_id}"
            )
        expected_contains_values = artifact_id in {
            "calibration_role_manifest",
            "locked_role_manifest",
        }
        if (
            row.get("referenced_artifact_contains_sealed_values")
            is not expected_contains_values
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"carry-forward sealed-value declaration mismatch for {artifact_id}"
            )
    calibration_public = load_json_object(
        project_root / _CARRYFORWARD_PATHS["calibration_role_commitment_public"]
    )
    locked_public = load_json_object(
        project_root / _CARRYFORWARD_PATHS["locked_role_commitment_public"]
    )
    for prefix, public, role_id, public_id in (
        (
            "calibration",
            calibration_public,
            "calibration_role_manifest",
            "calibration_role_commitment_public",
        ),
        (
            "locked",
            locked_public,
            "locked_role_manifest",
            "locked_role_commitment_public",
        ),
    ):
        role_row = by_id[role_id]
        public_row = by_id[public_id]
        commitment = public.get("commitment_sha256")
        if (
            public.get("raw_manifest_sha256") != role_row["raw_sha256"]
            or role_row.get("commitment_sha256") != commitment
            or public_row.get("commitment_sha256") != commitment
            or public.get("values_included") is not False
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"{prefix} public commitment binding mismatch"
            )
        if not allow_test_only_synthetic and commitment != _V21_ROLE_COMMITMENTS[
            prefix
        ]:
            raise SealedArtifactCarryforwardMismatch(
                f"{prefix} commitment differs from reviewed v2.1"
            )
    return carry


def verify_runtime_freeze_with_non_scientific_amendment(
    *,
    project_root: Path,
    allowlist_path: Path,
    base_freeze_path: Path,
    expected_base_freeze_file_sha256: str,
    amendment_path: Path,
    amendment_approval_path: Path,
    carryforward_path: Path,
    protocol_path: Path,
    config_path: Path,
    fidelity_path: Path,
    runtime_environment_manifest_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Verify base rows + exact delta + scientific identity before value parsing."""
    if sha256_file(base_freeze_path) != expected_base_freeze_file_sha256:
        raise RuntimeFreezeMismatch("base final-freeze raw hash mismatch")
    freeze = load_json_object(base_freeze_path)
    validate_instance(
        freeze,
        project_root / "manifests/schema/final_freeze_record_v5.schema.json",
        instance_name=base_freeze_path.as_posix(),
    )
    approved = (
        freeze.get("status") == "FINAL_FREEZE_APPROVED"
        and freeze.get("protected_execution_authorized") is True
    )
    synthetic = (
        allow_test_only_synthetic
        and freeze.get("status") == "TEST_ONLY_SYNTHETIC_FINAL_FREEZE_APPROVED"
    )
    if not (approved or synthetic):
        raise RuntimeFreezeMismatch("base freeze is not an approved execution record")
    if freeze.get("final_freeze_record_sha256") != freeze_record_payload_sha256(freeze):
        raise RuntimeFreezeMismatch("base freeze canonical payload hash mismatch")

    amendment = load_json_object(amendment_path)
    validate_instance(
        amendment,
        project_root / "manifests/schema/non_scientific_freeze_amendment_v1.schema.json",
        instance_name=amendment_path.as_posix(),
    )
    expected_amendment_label = (
        "TEST_ONLY_SYNTHETIC_NON_SCIENTIFIC_EXECUTION_PLUMBING_AMENDMENT"
        if allow_test_only_synthetic
        else "NON_SCIENTIFIC_EXECUTION_PLUMBING_AMENDMENT"
    )
    if amendment.get("artifact_label") != expected_amendment_label:
        raise NonScientificAmendmentMismatch("amendment label mismatch")
    expected_base = {
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_allowlist_sha256": sha256_file(allowlist_path),
        "base_runtime_inventory_sha256": freeze.get("runtime_inventory_sha256"),
    }
    if any(amendment.get(key) != value for key, value in expected_base.items()):
        raise NonScientificAmendmentMismatch("base freeze/allowlist binding mismatch")
    validate_author_amendment_approval(
        project_root=project_root,
        approval_path=amendment_approval_path,
        amendment_path=amendment_path,
        base_freeze_path=base_freeze_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )

    base_rows = cast(list[dict[str, Any]], amendment["base_runtime_rows"])
    base_by_path = _unique_by_path(base_rows, label="base runtime")
    base_categories = _base_category_hashes(base_rows)
    category_fields = {
        "source": "source_sha256",
        "scripts": "script_sha256",
        "schemas": "schema_sha256",
        "analysis": "analysis_sha256",
        "static_manifests": "static_manifest_sha256",
    }
    for category, field in category_fields.items():
        if base_categories.get(category) != freeze.get(field):
            raise NonScientificAmendmentMismatch(
                f"base row ledger category hash mismatch: {category}"
            )
    base_inventory_payload = {
        "allowlist_sha256": sha256_file(allowlist_path),
        "rows": base_rows,
        "environment_sha256": freeze["environment_sha256"],
        "runtime_environment_manifest_sha256": freeze[
            "runtime_environment_manifest_sha256"
        ],
    }
    if sha256_json(base_inventory_payload) != freeze["runtime_inventory_sha256"]:
        raise NonScientificAmendmentMismatch(
            "base row ledger does not reconstruct the frozen inventory"
        )

    changes = cast(list[dict[str, Any]], amendment["allowed_changed_files"])
    changes_by_path = _unique_by_path(changes, label="amendment change")
    if not set(changes_by_path).issubset(V22_ALLOWED_RUNTIME_CHANGE_PATHS):
        raise NonScientificAmendmentMismatch("changed file exceeds the v2.2 exact allowlist")
    expected_rows = {path: dict(row) for path, row in base_by_path.items()}
    for relative, change in changes_by_path.items():
        change_type = change["change_type"]
        if change_type == "MODIFIED":
            if relative not in base_by_path or change["old_sha256"] != base_by_path[
                relative
            ]["sha256"]:
                raise NonScientificAmendmentMismatch(
                    f"modified-file old hash mismatch: {relative}"
                )
            expected_rows[relative]["sha256"] = change["new_sha256"]
        elif change_type == "ADDED":
            if relative in base_by_path or change["old_sha256"] is not None:
                raise NonScientificAmendmentMismatch(
                    f"added-file baseline mismatch: {relative}"
                )
        else:  # schema validation should make this unreachable
            raise NonScientificAmendmentMismatch("unsupported change type")

    current_inventory = compute_runtime_inventory(
        project_root,
        allowlist_path,
        runtime_environment_manifest_path,
    )
    current_rows = [dict(row) for row in current_inventory.rows]
    current_by_path = _unique_by_path(current_rows, label="current runtime")
    for relative, change in changes_by_path.items():
        if relative not in current_by_path:
            raise NonScientificAmendmentMismatch(
                f"amended runtime file is absent: {relative}"
            )
        if change["new_sha256"] != current_by_path[relative]["sha256"]:
            raise NonScientificAmendmentMismatch(
                f"amended runtime new hash mismatch: {relative}"
            )
        if change["change_type"] == "ADDED":
            expected_rows[relative] = dict(current_by_path[relative])
    if expected_rows != current_by_path:
        raise NonScientificAmendmentMismatch(
            "current runtime has an unregistered addition, deletion, or mutation"
        )
    if amendment["amended_runtime_inventory_sha256"] != (
        current_inventory.runtime_inventory_sha256
    ):
        raise NonScientificAmendmentMismatch("amended runtime inventory hash mismatch")

    scientific_rows = cast(
        list[dict[str, Any]], amendment["scientific_protected_files"]
    )
    scientific_by_path = _unique_by_path(scientific_rows, label="scientific protected")
    expected_scientific = _expected_scientific_paths(project_root)
    if set(scientific_by_path) != set(expected_scientific):
        raise NonScientificAmendmentMismatch("scientific protected set is incomplete")
    if set(scientific_by_path).intersection(changes_by_path):
        raise NonScientificAmendmentMismatch("scientific file appears in amendment delta")
    for relative, expected_category in expected_scientific.items():
        row = scientific_by_path[relative]
        path = project_root / relative
        if row.get("category") != expected_category or row.get("sha256") != sha256_file(
            path
        ):
            raise NonScientificAmendmentMismatch(
                f"scientific protected file drift: {relative}"
            )
        if (
            not allow_test_only_synthetic
            and expected_category == "MANUSCRIPT_V1_8"
            and row.get("sha256") != _V18_MANUSCRIPT_SHA256[relative]
        ):
            raise NonScientificAmendmentMismatch(
                f"v1.8 manuscript differs from reviewed baseline: {relative}"
            )
    scientific_hash = sha256_json(scientific_rows)

    protected_hashes = {
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_sha256": sha256_file(fidelity_path),
    }
    if any(freeze.get(key) != value for key, value in protected_hashes.items()):
        raise NonScientificAmendmentMismatch("protocol/config/fidelity drift")
    verify_sealed_artifact_carryforward(
        project_root=project_root,
        carryforward_path=carryforward_path,
        amendment_path=amendment_path,
        amendment_approval_path=amendment_approval_path,
        base_freeze_path=base_freeze_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    return {
        "record_type": "AMENDED_RUNTIME_VERIFICATION_RECORD_V1",
        "status": "AMENDED_RUNTIME_VERIFIED_NON_SCIENTIFIC_DELTA_ONLY",
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "amended_runtime_inventory_sha256": current_inventory.runtime_inventory_sha256,
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
        "author_non_scientific_amendment_approval_sha256": sha256_file(
            amendment_approval_path
        ),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            carryforward_path
        ),
        "scientific_protected_set_sha256": scientific_hash,
        "runtime_file_count": len(current_rows),
        "allowed_changed_file_count": len(changes),
        "scientific_engine_changed": False,
        "protected_values_parsed": False,
        "benchmark_called": False,
    }


def validate_author_amendment_scope_approval_v2(
    *,
    project_root: Path,
    approval_path: Path,
    amendment_path: Path,
    base_freeze_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Validate review-scope authority; this never authorizes locked execution."""
    approval = load_json_object(approval_path)
    validate_instance(
        approval,
        project_root
        / "manifests/schema/author_non_scientific_amendment_scope_approval_v2.schema.json",
        instance_name=approval_path.as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_CUMULATIVE_AMENDMENT_AUTHOR_SCOPE_APPROVAL"
        if allow_test_only_synthetic
        else "CUMULATIVE_AMENDMENT_AUTHOR_SCOPE_APPROVAL"
    )
    amendment = load_json_object(amendment_path)
    expected = {
        "artifact_label": expected_label,
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_inventory_sha256": amendment.get(
            "base_runtime_inventory_sha256"
        ),
        "amended_runtime_inventory_sha256": amendment.get(
            "amended_runtime_inventory_sha256"
        ),
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
        "supersedes_unapproved_review_candidate_sha256": amendment.get(
            "supersedes_unapproved_review_candidate_sha256"
        ),
    }
    if any(approval.get(key) != value for key, value in expected.items()):
        raise NonScientificAmendmentMismatch(
            "cumulative amendment author-scope binding mismatch"
        )
    if any(
        approval.get(key) is not False
        for key in (
            "locked_execution_authorized",
            "calibration_rerun_authorized",
            "role_rematerialization_authorized",
            "scientific_change_authorized",
        )
    ):
        raise NonScientificAmendmentMismatch(
            "cumulative amendment scope exceeds review-only authority"
        )
    return approval


def verify_sealed_artifact_carryforward_v2(
    *,
    project_root: Path,
    carryforward_path: Path,
    amendment_path: Path,
    amendment_scope_approval_path: Path,
    base_freeze_path: Path,
    allow_test_only_synthetic: bool = False,
    verify_referenced_files: bool = True,
) -> dict[str, Any]:
    """Verify the exact v2.1 ten-artifact set without parsing role JSON values."""
    carry = load_json_object(carryforward_path)
    validate_instance(
        carry,
        project_root / "manifests/schema/sealed_artifact_carryforward_v2.schema.json",
        instance_name=carryforward_path.as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_CUMULATIVE_SEALED_ARTIFACT_CARRYFORWARD"
        if allow_test_only_synthetic
        else "CUMULATIVE_SEALED_ARTIFACT_CARRYFORWARD"
    )
    amendment = load_json_object(amendment_path)
    expected = {
        "artifact_label": expected_label,
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_inventory_sha256": amendment.get(
            "base_runtime_inventory_sha256"
        ),
        "amended_runtime_inventory_sha256": amendment.get(
            "amended_runtime_inventory_sha256"
        ),
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
        "author_non_scientific_amendment_scope_approval_sha256": sha256_file(
            amendment_scope_approval_path
        ),
    }
    if any(carry.get(key) != value for key, value in expected.items()):
        raise SealedArtifactCarryforwardMismatch(
            "cumulative carry-forward provenance mismatch"
        )
    rows = cast(list[dict[str, Any]], carry["artifacts"])
    by_id = {str(row["artifact_id"]): row for row in rows}
    if len(by_id) != len(rows) or set(by_id) != set(_CARRYFORWARD_PATHS):
        raise SealedArtifactCarryforwardMismatch(
            "cumulative carry-forward artifact set mismatch"
        )
    for artifact_id, relative in _CARRYFORWARD_PATHS.items():
        row = by_id[artifact_id]
        if row.get("path") != relative:
            raise SealedArtifactCarryforwardMismatch(
                f"cumulative carry-forward path mismatch: {artifact_id}"
            )
        if not allow_test_only_synthetic and row.get("raw_sha256") != (
            _V21_CARRYFORWARD_RAW_SHA256[artifact_id]
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"cumulative carry-forward differs from v2.1: {artifact_id}"
            )
        if verify_referenced_files:
            path = project_root / relative
            if path.is_symlink() or not path.is_file():
                raise SealedArtifactCarryforwardMismatch(
                    f"cumulative carry-forward target absent or symbolic: {artifact_id}"
                )
            # This is a streaming raw-file hash only.  Role manifests are not
            # parsed until after the one-time locked guard.
            if sha256_file(path) != row.get("raw_sha256"):
                raise SealedArtifactCarryforwardMismatch(
                    f"cumulative carry-forward target hash mismatch: {artifact_id}"
                )
        expected_contains_values = artifact_id in {
            "calibration_role_manifest",
            "locked_role_manifest",
        }
        if row.get("referenced_artifact_contains_sealed_values") is not (
            expected_contains_values
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"cumulative carry-forward value declaration mismatch: {artifact_id}"
            )
    for prefix, role_id, public_id in (
        ("calibration", "calibration_role_manifest", "calibration_role_commitment_public"),
        ("locked", "locked_role_manifest", "locked_role_commitment_public"),
    ):
        commitment = by_id[role_id].get("commitment_sha256")
        if (
            commitment != by_id[public_id].get("commitment_sha256")
            or (
                not allow_test_only_synthetic
                and commitment != _V21_ROLE_COMMITMENTS[prefix]
            )
        ):
            raise SealedArtifactCarryforwardMismatch(
                f"cumulative {prefix} commitment binding mismatch"
            )
    return carry


def verify_runtime_freeze_with_cumulative_amendment_v2(
    *,
    project_root: Path,
    base_allowlist_path: Path,
    amended_allowlist_path: Path,
    base_freeze_path: Path,
    expected_base_freeze_file_sha256: str,
    amendment_path: Path,
    amendment_scope_approval_path: Path,
    carryforward_path: Path,
    protocol_path: Path,
    config_path: Path,
    fidelity_path: Path,
    runtime_environment_manifest_path: Path,
    superseded_amendment_path: Path,
    superseded_scope_approval_path: Path,
    superseded_carryforward_path: Path,
    superseded_verification_path: Path,
    allow_test_only_synthetic: bool = False,
    verify_referenced_carryforward_files: bool = True,
) -> dict[str, Any]:
    """Rebuild original base and current cumulative runtime before value parsing."""
    if sha256_file(base_freeze_path) != expected_base_freeze_file_sha256:
        raise RuntimeFreezeMismatch("base final-freeze raw hash mismatch")
    freeze = load_json_object(base_freeze_path)
    validate_instance(
        freeze,
        project_root / "manifests/schema/final_freeze_record_v5.schema.json",
        instance_name=base_freeze_path.as_posix(),
    )
    approved = (
        freeze.get("status") == "FINAL_FREEZE_APPROVED"
        and freeze.get("protected_execution_authorized") is True
    )
    synthetic = (
        allow_test_only_synthetic
        and freeze.get("status") == "TEST_ONLY_SYNTHETIC_FINAL_FREEZE_APPROVED"
    )
    if not (approved or synthetic):
        raise RuntimeFreezeMismatch("base freeze is not an approved execution record")
    if freeze.get("final_freeze_record_sha256") != freeze_record_payload_sha256(freeze):
        raise RuntimeFreezeMismatch("base freeze canonical payload hash mismatch")

    amendment = load_json_object(amendment_path)
    validate_instance(
        amendment,
        project_root / "manifests/schema/non_scientific_freeze_amendment_v2.schema.json",
        instance_name=amendment_path.as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_CUMULATIVE_NON_SCIENTIFIC_EXECUTION_PLUMBING_AMENDMENT"
        if allow_test_only_synthetic
        else "CUMULATIVE_NON_SCIENTIFIC_EXECUTION_PLUMBING_AMENDMENT"
    )
    expected_top = {
        "artifact_label": expected_label,
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_allowlist_sha256": sha256_file(base_allowlist_path),
        "amended_runtime_allowlist_sha256": sha256_file(amended_allowlist_path),
        "base_runtime_environment_manifest_sha256": freeze.get(
            "runtime_environment_manifest_sha256"
        ),
        "amended_runtime_environment_manifest_sha256": sha256_file(
            runtime_environment_manifest_path
        ),
        "base_runtime_inventory_sha256": freeze.get("runtime_inventory_sha256"),
        "supersedes_unapproved_review_candidate_sha256": sha256_file(
            superseded_amendment_path
        ),
        "superseded_v22_author_scope_approval_sha256": sha256_file(
            superseded_scope_approval_path
        ),
        "superseded_v22_carryforward_sha256": sha256_file(
            superseded_carryforward_path
        ),
        "superseded_v22_verification_record_sha256": sha256_file(
            superseded_verification_path
        ),
        "exact_command_sha256": LOCKED_ISOLATED_EXACT_COMMAND_SHA256,
    }
    if not allow_test_only_synthetic:
        expected_top["superseded_v22_review_bundle_sha256"] = (
            V22_REVIEW_BUNDLE_SHA256
        )
    if any(amendment.get(key) != value for key, value in expected_top.items()):
        raise NonScientificAmendmentMismatch(
            "cumulative amendment base, predecessor, environment, or command binding mismatch"
        )
    validate_author_amendment_scope_approval_v2(
        project_root=project_root,
        approval_path=amendment_scope_approval_path,
        amendment_path=amendment_path,
        base_freeze_path=base_freeze_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )

    base_rows = cast(list[dict[str, Any]], amendment["base_runtime_rows"])
    base_by_path = _unique_by_path(base_rows, label="cumulative base runtime")
    base_categories = _base_category_hashes(base_rows)
    category_fields = {
        "source": "source_sha256",
        "scripts": "script_sha256",
        "schemas": "schema_sha256",
        "analysis": "analysis_sha256",
        "static_manifests": "static_manifest_sha256",
    }
    for category, field in category_fields.items():
        if base_categories.get(category) != freeze.get(field):
            raise NonScientificAmendmentMismatch(
                f"cumulative base category mismatch: {category}"
            )
    base_inventory_payload = {
        "allowlist_sha256": sha256_file(base_allowlist_path),
        "rows": base_rows,
        "environment_sha256": freeze["environment_sha256"],
        "runtime_environment_manifest_sha256": freeze[
            "runtime_environment_manifest_sha256"
        ],
    }
    if sha256_json(base_inventory_payload) != freeze["runtime_inventory_sha256"]:
        raise NonScientificAmendmentMismatch(
            "cumulative record does not reconstruct original base inventory"
        )

    current_inventory = compute_runtime_inventory(
        project_root,
        amended_allowlist_path,
        runtime_environment_manifest_path,
    )
    current_rows = [dict(row) for row in current_inventory.rows]
    current_by_path = _unique_by_path(current_rows, label="cumulative current runtime")
    registered_current_rows = cast(
        list[dict[str, Any]], amendment["amended_runtime_rows"]
    )
    if registered_current_rows != current_rows:
        raise NonScientificAmendmentMismatch(
            "registered amended rows differ from actual current runtime"
        )
    if amendment.get("amended_runtime_inventory_sha256") != (
        current_inventory.runtime_inventory_sha256
    ):
        raise NonScientificAmendmentMismatch(
            "cumulative amended runtime inventory hash mismatch"
        )
    if amendment.get("base_runtime_file_count") != len(base_rows) or amendment.get(
        "amended_runtime_file_count"
    ) != len(current_rows):
        raise NonScientificAmendmentMismatch("cumulative runtime row count mismatch")

    deleted = set(base_by_path) - set(current_by_path)
    if deleted:
        raise NonScientificAmendmentMismatch("cumulative amendment deletes base files")
    actual_delta = {
        path
        for path, row in current_by_path.items()
        if path not in base_by_path or row["sha256"] != base_by_path[path]["sha256"]
    }
    changes = cast(list[dict[str, Any]], amendment["allowed_changed_files"])
    changes_by_path = _unique_by_path(changes, label="cumulative amendment change")
    if set(changes_by_path) != actual_delta:
        raise NonScientificAmendmentMismatch(
            "cumulative changed-file ledger is not the exact base-to-current delta"
        )
    for relative, change in changes_by_path.items():
        current_hash = current_by_path[relative]["sha256"]
        if change.get("new_sha256") != current_hash:
            raise NonScientificAmendmentMismatch(
                f"cumulative changed-file new hash mismatch: {relative}"
            )
        if relative in base_by_path:
            if (
                change.get("change_type") != "MODIFIED"
                or change.get("old_sha256") != base_by_path[relative]["sha256"]
            ):
                raise NonScientificAmendmentMismatch(
                    f"cumulative modified-file baseline mismatch: {relative}"
                )
        elif change.get("change_type") != "ADDED" or change.get("old_sha256") is not None:
            raise NonScientificAmendmentMismatch(
                f"cumulative added-file baseline mismatch: {relative}"
            )

    scientific_rows = cast(
        list[dict[str, Any]], amendment["scientific_protected_files"]
    )
    scientific_by_path = _unique_by_path(
        scientific_rows, label="cumulative scientific protected"
    )
    expected_scientific = _expected_scientific_paths(project_root)
    if set(scientific_by_path) != set(expected_scientific):
        raise NonScientificAmendmentMismatch(
            "cumulative scientific protected set is incomplete"
        )
    if set(scientific_by_path) & set(changes_by_path):
        raise NonScientificAmendmentMismatch(
            "scientific file appears in cumulative execution-plumbing delta"
        )
    for relative, expected_category in expected_scientific.items():
        row = scientific_by_path[relative]
        actual_hash = sha256_file(project_root / relative)
        if row.get("category") != expected_category or row.get("sha256") != actual_hash:
            raise NonScientificAmendmentMismatch(
                f"cumulative scientific protected file drift: {relative}"
            )
        if (
            not allow_test_only_synthetic
            and expected_category == "MANUSCRIPT_V1_8"
            and actual_hash != _V18_MANUSCRIPT_SHA256[relative]
        ):
            raise NonScientificAmendmentMismatch(
                f"v1.8 manuscript differs from reviewed baseline: {relative}"
            )
    protected_hashes = {
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_sha256": sha256_file(fidelity_path),
    }
    if any(freeze.get(key) != value for key, value in protected_hashes.items()):
        raise NonScientificAmendmentMismatch("protocol/config/fidelity drift")
    verify_sealed_artifact_carryforward_v2(
        project_root=project_root,
        carryforward_path=carryforward_path,
        amendment_path=amendment_path,
        amendment_scope_approval_path=amendment_scope_approval_path,
        base_freeze_path=base_freeze_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
        verify_referenced_files=verify_referenced_carryforward_files,
    )
    return {
        "record_type": "AMENDED_RUNTIME_VERIFICATION_RECORD_V2",
        "status": "CUMULATIVE_AMENDED_RUNTIME_VERIFIED_NON_SCIENTIFIC_DELTA_ONLY",
        "base_final_freeze_record_sha256": sha256_file(base_freeze_path),
        "base_runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "amended_runtime_inventory_sha256": current_inventory.runtime_inventory_sha256,
        "base_runtime_allowlist_sha256": sha256_file(base_allowlist_path),
        "amended_runtime_allowlist_sha256": sha256_file(amended_allowlist_path),
        "runtime_environment_manifest_sha256": sha256_file(
            runtime_environment_manifest_path
        ),
        "exact_command_sha256": LOCKED_ISOLATED_EXACT_COMMAND_SHA256,
        "non_scientific_amendment_record_sha256": sha256_file(amendment_path),
        "author_non_scientific_amendment_scope_approval_sha256": sha256_file(
            amendment_scope_approval_path
        ),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            carryforward_path
        ),
        "scientific_protected_set_sha256": sha256_json(scientific_rows),
        "runtime_file_count": len(current_rows),
        "allowed_changed_file_count": len(changes),
        "scientific_engine_changed": False,
        "protected_values_parsed": False,
        "benchmark_called": False,
    }
