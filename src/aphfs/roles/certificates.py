"""Immutable calibration certificate records and locked-audit verification."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aphfs.provenance.hashing import sha256_file
from aphfs.provenance.io import write_json_new
from aphfs.roles.approvals import (
    require_bound_file,
    validate_approval_record,
)
from aphfs.schema.validation import load_json_object, validate_instance


def write_granted_calibration_certificate(
    *,
    project_root: Path,
    output_path: Path,
    bundle_path: Path,
    bundle: dict[str, Any],
    freeze_record_path: Path,
) -> dict[str, Any]:
    """New-write a certificate only for a complete actual calibration grant."""
    result = bundle["benchmark_results"][0]
    if (
        bundle.get("role") != "calibration"
        or result.get("status") != "CALIBRATION_CERTIFICATE_GRANTED"
        or result.get("certificate_granted") is not True
    ):
        raise PermissionError("No granted actual calibration certificate to record")
    freeze = load_json_object(freeze_record_path)
    record: dict[str, Any] = {
        "schema_version": "2",
        "certificate_status": "CALIBRATION_CERTIFICATE_GRANTED",
        "final_freeze_record_sha256": sha256_file(freeze_record_path),
        "runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "protocol_sha256": bundle["protocol_sha256"],
        "config_sha256": bundle["config_sha256"],
        "fidelity_sha256": bundle["fidelity_contract_sha256"],
        "calibration_role_commitment_sha256": bundle["role_commitment_sha256"],
        "calibration_result_bundle_sha256": sha256_file(bundle_path),
        "K": result["violation_count"],
        "m": result["denominator"],
        "U_CP": result["exact_one_sided_upper"],
        "delta": result["delta"],
        "calibration_beta": result["calibration_beta"],
        "locked_gamma": result["locked_gamma"],
        "event_definition": (
            "maximum Rule 170 global-density discrepancy over the frozen horizon "
            "exceeds epsilon=0, or any registered adverse/fidelity event occurs"
        ),
        "Q_definition_and_version": "APHFS-D2-CERT-Q-V6",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "no_retuning_declaration": True,
    }
    schema = project_root / "manifests/schema/calibration_certificate_record_v2.schema.json"
    validate_instance(record, schema)
    write_json_new(output_path, record)
    validate_instance(record, schema)
    return record


def verify_locked_certificate_chain(
    *,
    project_root: Path,
    authorization: dict[str, Any],
    certificate_path: Path,
    calibration_bundle_path: Path,
    calibration_review_approval_path: Path,
    freeze_record_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Verify immutable calibration evidence before a locked D2 audit."""
    expected = {
        "applicable_certificate_sha256": sha256_file(certificate_path),
        "applicable_result_sha256": sha256_file(calibration_bundle_path),
        "calibration_review_approval_sha256": sha256_file(
            calibration_review_approval_path
        ),
    }
    if any(authorization.get(key) != value for key, value in expected.items()):
        raise PermissionError("Locked authorization certificate-chain binding mismatch")
    review = validate_approval_record(
        project_root=project_root,
        approval_path=calibration_review_approval_path,
        expected_record_type="CALIBRATION_REVIEW_APPROVAL_V1",
        freeze_record_path=freeze_record_path,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    require_bound_file(
        review,
        "applicable_result_sha256",
        calibration_bundle_path,
    )
    require_bound_file(
        review,
        "applicable_certificate_sha256",
        certificate_path,
    )
    if review.get("certificate_status") != "CALIBRATION_CERTIFICATE_GRANTED":
        raise PermissionError("Calibration review did not approve a granted certificate")
    if review.get("reviewer_decision") != "APPROVE_LOCKED_MATERIALIZATION":
        raise PermissionError("Calibration review did not approve locked materialization")
    if review.get("locked_materialization_approved") is not True:
        raise PermissionError("Calibration review explicitly closes locked materialization")
    if review.get("no_retuning_declaration") is not True:
        raise PermissionError("Calibration review lacks no-retuning declaration")
    record = load_json_object(certificate_path)
    validate_instance(
        record,
        project_root / "manifests/schema/calibration_certificate_record_v2.schema.json",
        instance_name=certificate_path.as_posix(),
    )
    if record["certificate_status"] != "CALIBRATION_CERTIFICATE_GRANTED":
        raise PermissionError("Locked D2 has no granted calibration certificate")
    if record["final_freeze_record_sha256"] != sha256_file(freeze_record_path):
        raise PermissionError("Calibration certificate freeze binding mismatch")
    if (
        record["calibration_result_bundle_sha256"]
        != expected["applicable_result_sha256"]
    ):
        raise PermissionError("Calibration certificate result-bundle binding mismatch")
    freeze = load_json_object(freeze_record_path)
    if record["runtime_inventory_sha256"] != freeze["runtime_inventory_sha256"]:
        raise PermissionError("Calibration certificate runtime binding mismatch")
    bundle = load_json_object(calibration_bundle_path)
    validate_instance(
        bundle,
        project_root
        / "manifests/schema"
        / (
            "test_only_synthetic_locked_result_bundle_v1.schema.json"
            if allow_test_only_synthetic
            else "protected_result_bundle_actual_v2.schema.json"
        ),
        instance_name=calibration_bundle_path.as_posix(),
    )
    if bundle.get("role") != "calibration":
        raise PermissionError("Certificate chain does not bind a calibration result")
    result = bundle["benchmark_results"][0]
    if (
        result.get("certificate_granted") is not True
        or result.get("certificate_reviewed") is not False
        or result.get("calibration_executed") is not True
        or result.get("locked_audit_executed") is not False
    ):
        raise PermissionError("Calibration result certificate state is inconsistent")
    if record["K"] != result["violation_count"] or record["m"] != result["denominator"]:
        raise PermissionError("Certificate binomial count binding mismatch")
    if record["U_CP"] != result["exact_one_sided_upper"]:
        raise PermissionError("Certificate confidence-bound binding mismatch")
    if record["calibration_beta"] != result["calibration_beta"]:
        raise PermissionError("Certificate calibration-beta binding mismatch")
    if record["locked_gamma"] != result["locked_gamma"]:
        raise PermissionError("Certificate locked-gamma binding mismatch")
    return record
