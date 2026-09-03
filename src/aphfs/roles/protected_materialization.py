"""Default-closed protected role materialization.

The production path uses the operating-system CSPRNG and is intentionally not
invoked during protocol-integrity closure.  Tests may exercise the same
transaction in temporary directories with an explicit synthetic marker.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from aphfs.provenance.hashing import sha256_file, sha256_json
from aphfs.provenance.io import write_json_new
from aphfs.provenance.runtime_freeze import verify_runtime_freeze
from aphfs.roles.approvals import (
    require_bound_file,
    validate_approval_record,
)
from aphfs.schema.validation import load_json_object, validate_instance

ProtectedRole = Literal["calibration", "locked"]
PROTECTED_ROLE_COUNT = 64


def _commitment_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "commitment_sha256"}


def materialize_protected_role(
    *,
    project_root: Path,
    role: ProtectedRole,
    output_path: Path,
    approval_path: Path | None,
    author_approval_record_path: Path | None,
    final_freeze_record_path: Path,
    calibration_manifest_path: Path | None = None,
    calibration_result_bundle_path: Path | None = None,
    calibration_certificate_record_path: Path | None = None,
    calibration_review_approval_path: Path | None = None,
    protocol_path: Path | None = None,
    config_path: Path | None = None,
    fidelity_path: Path | None = None,
    runtime_environment_manifest_path: Path | None = None,
    enable_protected_role_materialization: bool = False,
    allow_test_only_synthetic: bool = False,
    token_source: Callable[[], int] | None = None,
) -> dict[str, Any]:
    """New-write one role transaction, or reject before generating any value."""
    if not enable_protected_role_materialization:
        raise PermissionError("PROTECTED_ROLE_MATERIALIZATION_DEFAULT_CLOSED")
    if approval_path is None or author_approval_record_path is None:
        raise PermissionError("Protected role materialization requires approval records")
    protocol_path = protocol_path or (
        project_root / "configs/protected/protected_protocol_v6.json"
    )
    config_path = config_path or (
        project_root / "configs/protected/protected_benchmark_config_v3.json"
    )
    fidelity_path = fidelity_path or (
        project_root / "configs/protected/protected_fidelity_contracts_v3.json"
    )
    runtime_environment_manifest_path = runtime_environment_manifest_path or (
        project_root / "manifests/protected_runtime_environment_manifest_v2.json"
    )
    validate_approval_record(
        project_root=project_root,
        approval_path=author_approval_record_path,
        expected_record_type="AUTHOR_FINAL_FREEZE_APPROVAL_V1",
        freeze_record_path=final_freeze_record_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    approval_type = (
        "CALIBRATION_MATERIALIZATION_APPROVAL_V1"
        if role == "calibration"
        else "LOCKED_MATERIALIZATION_APPROVAL_V1"
    )
    approval = validate_approval_record(
        project_root=project_root,
        approval_path=approval_path,
        expected_record_type=approval_type,
        freeze_record_path=final_freeze_record_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    if approval.get("applicable_role") != role:
        raise PermissionError("Materialization authorization role mismatch")
    if approval.get("count") != PROTECTED_ROLE_COUNT:
        raise PermissionError("Materialization authorization count mismatch")
    require_bound_file(
        approval,
        "author_final_freeze_approval_sha256",
        author_approval_record_path,
    )
    freeze = verify_runtime_freeze(
        project_root=project_root,
        allowlist_path=project_root / "manifests/runtime_allowlist_v1.json",
        freeze_record_path=final_freeze_record_path,
        expected_freeze_file_sha256=str(approval["final_freeze_record_sha256"]),
        protocol_path=protocol_path,
        config_path=config_path,
        fidelity_path=fidelity_path,
        runtime_environment_manifest_path=runtime_environment_manifest_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    freeze_file_hash = sha256_file(final_freeze_record_path)
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite role manifest: {output_path}")
    prior_values: set[int] = set()
    calibration_commitment: str | None = None
    if role == "locked":
        required = (
            calibration_manifest_path,
            calibration_result_bundle_path,
            calibration_certificate_record_path,
            calibration_review_approval_path,
        )
        if any(path is None for path in required):
            raise PermissionError("Locked materialization requires the full calibration chain")
        calibration_manifest_path = cast(Path, calibration_manifest_path)
        calibration_result_bundle_path = cast(Path, calibration_result_bundle_path)
        calibration_certificate_record_path = cast(
            Path, calibration_certificate_record_path
        )
        calibration_review_approval_path = cast(
            Path, calibration_review_approval_path
        )
        review = validate_approval_record(
            project_root=project_root,
            approval_path=calibration_review_approval_path,
            expected_record_type="CALIBRATION_REVIEW_APPROVAL_V1",
            freeze_record_path=final_freeze_record_path,
            allow_test_only_synthetic=allow_test_only_synthetic,
        )
        require_bound_file(
            review,
            "applicable_result_sha256",
            calibration_result_bundle_path,
        )
        require_bound_file(
            review,
            "applicable_certificate_sha256",
            calibration_certificate_record_path,
        )
        require_bound_file(
            approval,
            "calibration_review_approval_sha256",
            calibration_review_approval_path,
        )
        require_bound_file(
            approval,
            "applicable_result_sha256",
            calibration_result_bundle_path,
        )
        require_bound_file(
            approval,
            "applicable_certificate_sha256",
            calibration_certificate_record_path,
        )
        require_bound_file(
            approval,
            "calibration_role_manifest_raw_sha256",
            calibration_manifest_path,
        )
        result_bundle = load_json_object(calibration_result_bundle_path)
        validate_instance(
            result_bundle,
            project_root
            / "manifests/schema/protected_result_bundle_actual_v2.schema.json",
            instance_name=calibration_result_bundle_path.as_posix(),
        )
        if result_bundle.get("role") != "calibration":
            raise PermissionError("Locked materialization requires a calibration result")
        certificate = load_json_object(calibration_certificate_record_path)
        validate_instance(
            certificate,
            project_root
            / "manifests/schema/calibration_certificate_record_v2.schema.json",
            instance_name=calibration_certificate_record_path.as_posix(),
        )
        if certificate.get("certificate_status") != "CALIBRATION_CERTIFICATE_GRANTED":
            raise PermissionError("Locked materialization requires a granted certificate")
        if certificate.get("final_freeze_record_sha256") != freeze_file_hash:
            raise PermissionError("Calibration certificate freeze binding mismatch")
        if certificate.get("runtime_inventory_sha256") != freeze.get(
            "runtime_inventory_sha256"
        ):
            raise PermissionError("Calibration certificate runtime binding mismatch")
        if certificate.get("calibration_result_bundle_sha256") != sha256_file(
            calibration_result_bundle_path
        ):
            raise PermissionError("Calibration certificate result binding mismatch")
        calibration = load_json_object(calibration_manifest_path)
        validate_instance(
            calibration,
            project_root / "manifests/schema/protected_role_manifest_v3.schema.json",
            instance_name=calibration_manifest_path.as_posix(),
        )
        if calibration.get("role") != "calibration":
            raise PermissionError("Calibration manifest role mismatch")
        calibration_commitment = str(calibration.get("commitment_sha256"))
        payload = {
            key: value
            for key, value in calibration.items()
            if key != "commitment_sha256"
        }
        if calibration_commitment != sha256_json(payload):
            raise PermissionError("Calibration manifest commitment mismatch")
        if approval.get("calibration_role_commitment_sha256") != calibration_commitment:
            raise PermissionError("Locked authorization lacks calibration commitment binding")
        values = calibration.get("values")
        if not isinstance(values, list) or not all(isinstance(value, int) for value in values):
            raise PermissionError("Calibration manifest values are malformed")
        prior_values = set(values)
    generator = token_source or (lambda: secrets.randbits(256))
    values = [generator() for _ in range(PROTECTED_ROLE_COUNT)]
    if len(set(values)) != PROTECTED_ROLE_COUNT:
        raise RuntimeError("CSPRNG collision aborts the entire materialization transaction")
    if prior_values.intersection(values):
        raise RuntimeError("Cross-role collision aborts the entire materialization transaction")
    manifest: dict[str, Any] = {
        "schema_version": "3",
        "label": (
            "TEST_ONLY_SYNTHETIC_PROTECTED_ROLE"
            if allow_test_only_synthetic
            else "PROTECTED_ROLE"
        ),
        "role": role,
        "derivation": "OS_CSPRNG_SECRETS_RANDBITS_256_V1",
        "count": PROTECTED_ROLE_COUNT,
        "values": values,
        "final_freeze_record_sha256": freeze_file_hash,
        "runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "author_final_freeze_approval_sha256": sha256_file(
            author_approval_record_path
        ),
        "materialization_approval_sha256": sha256_file(approval_path),
        "calibration_role_commitment_sha256": calibration_commitment,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "outcome_data_consulted": False,
        "overwrite_permitted": False,
    }
    manifest["commitment_sha256"] = sha256_json(_commitment_payload(manifest))
    validate_instance(
        manifest,
        project_root / "manifests/schema/protected_role_manifest_v3.schema.json",
        instance_name="protected role materialization",
    )
    write_json_new(output_path, manifest)
    os.chmod(output_path, 0o600)
    return manifest
