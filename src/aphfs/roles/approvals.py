"""Semantic validation for future protected-action approval records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aphfs.provenance.hashing import sha256_file
from aphfs.provenance.runtime_freeze import (
    build_freeze_record,
    freeze_record_payload_sha256,
)
from aphfs.schema.validation import load_json_object, validate_instance

_SCHEMAS = {
    "AUTHOR_FINAL_FREEZE_APPROVAL_V1": "author_final_freeze_approval_v1.schema.json",
    "CALIBRATION_MATERIALIZATION_APPROVAL_V1": (
        "calibration_materialization_approval_v1.schema.json"
    ),
    "CALIBRATION_EXECUTION_APPROVAL_V1": (
        "calibration_execution_approval_v1.schema.json"
    ),
    "CALIBRATION_REVIEW_APPROVAL_V1": (
        "calibration_review_approval_v1.schema.json"
    ),
    "LOCKED_MATERIALIZATION_APPROVAL_V1": (
        "locked_materialization_approval_v1.schema.json"
    ),
    "LOCKED_EXECUTION_APPROVAL_V1": "locked_execution_approval_v1.schema.json",
}


def validate_approval_record(
    *,
    project_root: Path,
    approval_path: Path,
    expected_record_type: str,
    freeze_record_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Validate schema, action semantics, and freeze/runtime bindings."""
    schema_name = _SCHEMAS.get(expected_record_type)
    if schema_name is None:
        raise ValueError(f"Unknown approval record type: {expected_record_type}")
    approval = load_json_object(approval_path)
    validate_instance(
        approval,
        project_root / "manifests/schema" / schema_name,
        instance_name=approval_path.as_posix(),
    )
    if approval["record_type"] != expected_record_type:
        raise PermissionError("Approval record type mismatch")
    if approval["approval_status"] != "APPROVED":
        raise PermissionError("Approval record is not approved")
    freeze = load_json_object(freeze_record_path)
    approved_status = freeze.get("status") == "FINAL_FREEZE_APPROVED"
    synthetic_status = (
        allow_test_only_synthetic
        and freeze.get("status") == "TEST_ONLY_SYNTHETIC_FINAL_FREEZE_APPROVED"
    )
    if not (approved_status or synthetic_status):
        raise PermissionError("Approval cannot promote an unapproved freeze candidate")
    if expected_record_type == "AUTHOR_FINAL_FREEZE_APPROVAL_V1":
        # The author record must precede the approved freeze, so it binds the
        # reviewed candidate.  The approved record then binds the raw author
        # record.  This two-way provenance avoids the impossible circular
        # requirement that each file contain the other's final raw hash.
        if approval.get("binding_target") != "FINAL_FREEZE_CANDIDATE_RECORD":
            raise PermissionError("Author approval binding target mismatch")
        if approval["final_freeze_record_sha256"] != freeze.get(
            "source_candidate_record_sha256"
        ):
            raise PermissionError("Author approval candidate hash mismatch")
        if freeze.get("author_final_freeze_approval_sha256") != sha256_file(
            approval_path
        ):
            raise PermissionError("Approved freeze author-approval binding mismatch")
    elif approval["final_freeze_record_sha256"] != sha256_file(
        freeze_record_path
    ):
        raise PermissionError("Approval approved-final-freeze raw hash mismatch")
    if approval["runtime_inventory_sha256"] != freeze.get(
        "runtime_inventory_sha256"
    ):
        raise PermissionError("Approval runtime inventory binding mismatch")
    return approval


def require_bound_file(
    approval: dict[str, Any],
    field: str,
    path: Path,
) -> None:
    """Require that an approval field binds the raw bytes of a named artifact."""
    if approval.get(field) != sha256_file(path):
        raise PermissionError(f"Approval binding mismatch for {field}")


def promote_reviewed_freeze_candidate(
    *,
    project_root: Path,
    candidate_path: Path,
    author_approval_path: Path,
    allowlist_path: Path,
    protocol_path: Path,
    config_path: Path,
    fidelity_path: Path,
    runtime_environment_manifest_path: Path,
    document_build_environment_manifest_path: Path,
) -> dict[str, Any]:
    """Build, but do not write, an approved record from a reviewed candidate.

    The caller must separately opt in and new-write the returned record.  This
    function makes the authorization order non-circular: the author approval
    binds the candidate raw bytes, and the approved record binds that approval.
    """
    candidate = load_json_object(candidate_path)
    validate_instance(
        candidate,
        project_root / "manifests/schema/final_freeze_record_v5.schema.json",
        instance_name=candidate_path.as_posix(),
    )
    if (
        candidate.get("status")
        != "FINAL_FREEZE_CANDIDATE_AWAITING_AUTHOR_AND_CHATGPT_REVIEW"
        or candidate.get("protected_execution_authorized") is not False
    ):
        raise PermissionError("Only an unapproved review candidate can be promoted")
    if candidate.get("final_freeze_record_sha256") != freeze_record_payload_sha256(
        candidate
    ):
        raise PermissionError("Candidate canonical payload hash mismatch")

    approval = load_json_object(author_approval_path)
    validate_instance(
        approval,
        project_root
        / "manifests/schema/author_final_freeze_approval_v1.schema.json",
        instance_name=author_approval_path.as_posix(),
    )
    if approval["final_freeze_record_sha256"] != sha256_file(candidate_path):
        raise PermissionError("Author approval does not bind the reviewed candidate")
    if approval["runtime_inventory_sha256"] != candidate.get(
        "runtime_inventory_sha256"
    ):
        raise PermissionError("Author approval runtime inventory mismatch")

    rebuilt_candidate = build_freeze_record(
        project_root=project_root,
        allowlist_path=allowlist_path,
        protocol_path=protocol_path,
        config_path=config_path,
        fidelity_path=fidelity_path,
        runtime_environment_manifest_path=runtime_environment_manifest_path,
        document_build_environment_manifest_path=(
            document_build_environment_manifest_path
        ),
        status="FINAL_FREEZE_CANDIDATE_AWAITING_AUTHOR_AND_CHATGPT_REVIEW",
    )
    if candidate != rebuilt_candidate:
        raise PermissionError("Candidate no longer matches the exact current runtime")

    return build_freeze_record(
        project_root=project_root,
        allowlist_path=allowlist_path,
        protocol_path=protocol_path,
        config_path=config_path,
        fidelity_path=fidelity_path,
        runtime_environment_manifest_path=runtime_environment_manifest_path,
        document_build_environment_manifest_path=(
            document_build_environment_manifest_path
        ),
        status="FINAL_FREEZE_APPROVED",
        protected_execution_authorized=True,
        source_candidate_record_sha256=sha256_file(candidate_path),
        author_final_freeze_approval_sha256=sha256_file(author_approval_path),
    )
