"""Single-use orchestration for a future separately authorized locked audit.

Only TEST_ONLY_SYNTHETIC artifacts exercise this path during v2.3.  The real
entry has one fixed isolated command and no variable paths or synthetic flags.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aphfs.pipelines.protected import (
    _LOCKED_ORCHESTRATOR_CAPABILITY,
    _run_locked_analysis_after_one_time_guard,
)
from aphfs.provenance.amendment import (
    verify_runtime_freeze_with_cumulative_amendment_v2,
)
from aphfs.provenance.hashing import sha256_bytes, sha256_file, sha256_json
from aphfs.roles.approvals import require_bound_file, validate_approval_record
from aphfs.roles.certificates import verify_locked_certificate_chain
from aphfs.schema.validation import load_json_object, validate_instance

LOCKED_EXECUTION_ALREADY_CONSUMED = "LOCKED_EXECUTION_ALREADY_CONSUMED"
LOCKED_EXECUTION_OUTPUT_PREEXISTS = "LOCKED_EXECUTION_OUTPUT_PREEXISTS"
LOCKED_EXECUTION_PRECHECK_FAILED = "LOCKED_EXECUTION_PRECHECK_FAILED"
LOCKED_EXECUTION_EXCEPTION_AFTER_GUARD = "LOCKED_EXECUTION_EXCEPTION_AFTER_GUARD"
LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND = "LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND"
LOCKED_RESULT_PROVENANCE_INCOMPLETE = "LOCKED_RESULT_PROVENANCE_INCOMPLETE"

LOCKED_RUN_ID = "aphfs_actual_locked_audit_v1"
LOCKED_EXACT_ARGV = (
    ".venv-protected-freeze-v1/bin/python",
    "-I",
    "scripts/run_locked_audit_once.py",
)
LOCKED_EXACT_COMMAND_SHA256 = sha256_json(
    {"cwd": "PROJECT_ROOT", "argv": list(LOCKED_EXACT_ARGV)}
)

LOCKED_PATHS = {
    "approval": "authorizations/locked_execution_approval_v1.json",
    "base_freeze": "manifests/final_freeze_approved_record_v1.json",
    "author_approval": "authorizations/author_final_freeze_approval_v1.json",
    "base_allowlist": "manifests/runtime_allowlist_v1.json",
    "amended_allowlist": "manifests/runtime_allowlist_v2.json",
    "amendment": "manifests/non_scientific_freeze_amendment_v2.json",
    "amendment_approval": (
        "authorizations/author_non_scientific_amendment_scope_approval_v2.json"
    ),
    "amendment_review_approval": (
        "authorizations/non_scientific_amendment_review_approval_v1.json"
    ),
    "carryforward": "manifests/sealed_artifact_carryforward_v2.json",
    "amended_verification": "manifests/amended_runtime_verification_record_v2.json",
    "superseded_amendment": "manifests/non_scientific_freeze_amendment_v1.json",
    "superseded_scope_approval": (
        "authorizations/author_non_scientific_amendment_approval_v1.json"
    ),
    "superseded_carryforward": "manifests/sealed_artifact_carryforward_v1.json",
    "superseded_verification": "manifests/amended_runtime_verification_record_v1.json",
    "locked_role": "protected_roles/locked/locked_role_v1.json",
    "locked_materialization_approval": (
        "authorizations/locked_materialization_approval_v1.json"
    ),
    "calibration_result": (
        "protected_results/calibration/calibration_result_bundle_v1.json"
    ),
    "calibration_certificate": (
        "protected_results/calibration/calibration_certificate_record_v2.json"
    ),
    "calibration_review_approval": "authorizations/calibration_review_approval_v1.json",
    "protocol": "configs/protected/protected_protocol_v6.json",
    "config": "configs/protected/protected_benchmark_config_v3.json",
    "fidelity": "configs/protected/protected_fidelity_contracts_v3.json",
    "runtime_environment": "manifests/protected_runtime_environment_manifest_v3.json",
    "intent": "protected_results/locked/locked_execution_intent_v1.json",
    "guard": "protected_results/locked/.actual_locked_v1_started",
    "result": "protected_results/locked/locked_result_bundle_v1.json",
    "failure": "protected_results/locked/locked_result_bundle_v1.json.failure.json",
    "receipt": "protected_results/locked/locked_execution_receipt_v1.json",
}

_CONTEXT_FIELDS = (
    "final_freeze_record_sha256",
    "base_runtime_inventory_sha256",
    "non_scientific_amendment_record_sha256",
    "sealed_artifact_carryforward_record_sha256",
    "amendment_review_approval_sha256",
    "amendment_review_bundle_sha256",
    "amended_runtime_verification_record_sha256",
    "amended_runtime_inventory_sha256",
    "runtime_environment_manifest_sha256",
    "exact_command_sha256",
    "execution_approval_sha256",
    "execution_intent_sha256",
    "execution_guard_sha256",
    "calibration_result_bundle_sha256",
    "calibration_certificate_record_sha256",
    "calibration_review_approval_sha256",
    "role_manifest_raw_sha256",
    "role_commitment_sha256",
    "protocol_sha256",
    "config_sha256",
    "fidelity_contract_sha256",
    "author_final_freeze_approval_sha256",
    "locked_materialization_approval_sha256",
)


class LockedExecutionConsumed(PermissionError):
    def __init__(self) -> None:
        super().__init__(LOCKED_EXECUTION_ALREADY_CONSUMED)
        self.code = LOCKED_EXECUTION_ALREADY_CONSUMED


class LockedExecutionAfterGuardFailure(RuntimeError):
    def __init__(self) -> None:
        super().__init__(LOCKED_EXECUTION_EXCEPTION_AFTER_GUARD)
        self.code = LOCKED_EXECUTION_EXCEPTION_AFTER_GUARD


class LockedResultProvenanceIncomplete(PermissionError):
    def __init__(self) -> None:
        super().__init__(LOCKED_RESULT_PROVENANCE_INCOMPLETE)
        self.code = LOCKED_RESULT_PROVENANCE_INCOMPLETE


@dataclass(frozen=True, slots=True)
class LockedResultProvenanceContext:
    context_schema_version: str
    final_freeze_record_sha256: str
    base_runtime_inventory_sha256: str
    non_scientific_amendment_record_sha256: str
    sealed_artifact_carryforward_record_sha256: str
    amendment_review_approval_sha256: str
    amendment_review_bundle_sha256: str
    amended_runtime_verification_record_sha256: str
    amended_runtime_inventory_sha256: str
    runtime_environment_manifest_sha256: str
    exact_command_sha256: str
    execution_approval_sha256: str
    execution_intent_sha256: str
    execution_guard_sha256: str
    calibration_result_bundle_sha256: str
    calibration_certificate_record_sha256: str
    calibration_review_approval_sha256: str
    role_manifest_raw_sha256: str
    role_commitment_sha256: str
    protocol_sha256: str
    config_sha256: str
    fidelity_contract_sha256: str
    author_final_freeze_approval_sha256: str
    locked_materialization_approval_sha256: str

    def payload(self) -> dict[str, str]:
        return asdict(self)

    def sha256(self) -> str:
        return sha256_json(self.payload())


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _paths(project_root: Path) -> dict[str, Path]:
    return {key: project_root / relative for key, relative in LOCKED_PATHS.items()}


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _atomic_write_new(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    """O_EXCL new-write, file fsync, close, and immediate no-follow readback."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("atomic new-write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise OSError("new-write readback target is not a regular non-symlink")
    if stat.S_IMODE(info.st_mode) != mode:
        raise OSError("new-write readback mode mismatch")
    read_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        read_flags |= os.O_NOFOLLOW
    read_descriptor = os.open(path, read_flags)
    try:
        opened = os.fstat(read_descriptor)
        if not stat.S_ISREG(opened.st_mode) or stat.S_IMODE(opened.st_mode) != mode:
            raise OSError("new-write opened target identity mismatch")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(read_descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(read_descriptor)
    if digest.hexdigest() != sha256_bytes(payload):
        raise OSError("new-write readback hash mismatch")


def _atomic_json_new(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_new(path, _json_bytes(value))


def validate_fixed_process_command(project_root: Path) -> None:
    """Reject wrappers, extra flags, alternate scripts, cwd, and alternate venvs."""
    if (
        len(sys.argv) != 1
        or Path.cwd().resolve() != project_root.resolve()
        or list(sys.orig_argv) != list(LOCKED_EXACT_ARGV)
    ):
        raise PermissionError(LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND)
    try:
        executable = Path(sys.executable).absolute().relative_to(
            project_root.absolute()
        ).as_posix()
        script = Path(sys.argv[0]).absolute().relative_to(
            project_root.absolute()
        ).as_posix()
    except ValueError as exc:
        raise PermissionError(LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND) from exc
    if (executable, "-I", script) != LOCKED_EXACT_ARGV:
        raise PermissionError(LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND)
    if (
        sys.flags.isolated != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.no_user_site != 1
        or sys.flags.safe_path is not True
    ):
        raise PermissionError(LOCKED_EXECUTION_REQUIRES_FIXED_COMMAND)


def _validate_bootstrap_provenance(
    project_root: Path, bootstrap_provenance: dict[str, Any] | None
) -> None:
    if bootstrap_provenance is None:
        raise PermissionError("LOCKED_BOOTSTRAP_PROVENANCE_MISSING")
    manifest_path = project_root / LOCKED_PATHS["runtime_environment"]
    manifest = load_json_object(manifest_path)
    validate_instance(
        manifest,
        project_root / "manifests/schema/runtime_environment_manifest_v3.schema.json",
        instance_name=manifest_path.as_posix(),
    )
    expected = {
        "python_flags": manifest["python_flags"],
        "bootstrap_environment": manifest["bootstrap_environment"],
        "import_provenance": manifest["import_provenance"],
    }
    if bootstrap_provenance != expected or manifest.get(
        "exact_command_sha256"
    ) != LOCKED_EXACT_COMMAND_SHA256:
        raise PermissionError("LOCKED_BOOTSTRAP_PROVENANCE_MISMATCH")


def _validate_regular_mode_0600(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise PermissionError("LOCKED_ROLE_MANIFEST_NOT_REGULAR")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("LOCKED_ROLE_MANIFEST_PERMISSION_MISMATCH")


def _carryforward_locked_row(carryforward: dict[str, Any]) -> dict[str, Any]:
    rows = [
        row
        for row in carryforward["artifacts"]
        if row.get("artifact_id") == "locked_role_manifest"
    ]
    if len(rows) != 1:
        raise PermissionError("LOCKED_CARRYFORWARD_ROLE_BINDING_MISMATCH")
    return dict(rows[0])


def _preexisting_output_check(paths: dict[str, Path]) -> None:
    if os.path.lexists(paths["intent"]) or os.path.lexists(paths["guard"]):
        raise LockedExecutionConsumed()
    for key in ("result", "failure", "receipt"):
        if os.path.lexists(paths[key]):
            raise PermissionError(f"{LOCKED_EXECUTION_OUTPUT_PREEXISTS}:{key}")


def _validate_amendment_review_gate(
    *,
    project_root: Path,
    paths: dict[str, Path],
    authorization: dict[str, Any],
    freeze: dict[str, Any],
    amendment: dict[str, Any],
    allow_test_only_synthetic: bool,
) -> dict[str, Any]:
    review = load_json_object(paths["amendment_review_approval"])
    validate_instance(
        review,
        project_root
        / "manifests/schema/non_scientific_amendment_review_approval_v1.schema.json",
        instance_name=paths["amendment_review_approval"].as_posix(),
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_NON_SCIENTIFIC_AMENDMENT_INDEPENDENT_REVIEW_APPROVAL"
        if allow_test_only_synthetic
        else "NON_SCIENTIFIC_AMENDMENT_INDEPENDENT_REVIEW_APPROVAL"
    )
    exact_scope = {
        "ISOLATED_BOOTSTRAP",
        "CUMULATIVE_AMENDMENT",
        "SEALED_CARRYFORWARD",
        "LOCKED_RESULT_PROVENANCE",
        "ONE_TIME_STATE_MACHINE",
        "SCIENTIFIC_BINARY_IDENTITY",
        "PACKAGE_PRIVACY",
    }
    expected = {
        "artifact_label": expected_label,
        "base_final_freeze_record_sha256": sha256_file(paths["base_freeze"]),
        "base_runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "amended_runtime_inventory_sha256": amendment[
            "amended_runtime_inventory_sha256"
        ],
        "runtime_environment_manifest_sha256": sha256_file(
            paths["runtime_environment"]
        ),
        "non_scientific_amendment_record_sha256": sha256_file(paths["amendment"]),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            paths["carryforward"]
        ),
    }
    if any(review.get(key) != value for key, value in expected.items()):
        raise PermissionError("LOCKED_AMENDMENT_REVIEW_BINDING_MISMATCH")
    if set(review["reviewer_scope"]) != exact_scope:
        raise PermissionError("LOCKED_AMENDMENT_REVIEW_SCOPE_MISMATCH")
    review_sha = sha256_file(paths["amendment_review_approval"])
    if (
        authorization.get("non_scientific_amendment_review_approval_sha256")
        != review_sha
        or authorization.get("amendment_review_bundle_sha256")
        != review.get("review_bundle_sha256")
    ):
        raise PermissionError("LOCKED_AMENDMENT_REVIEW_APPROVAL_NOT_BOUND")
    return review


def _validate_locked_approval_and_preflight(
    *,
    project_root: Path,
    paths: dict[str, Path],
    allow_test_only_synthetic: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    authorization = validate_approval_record(
        project_root=project_root,
        approval_path=paths["approval"],
        expected_record_type="LOCKED_EXECUTION_APPROVAL_V1",
        freeze_record_path=paths["base_freeze"],
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    expected_label = (
        "TEST_ONLY_SYNTHETIC_LOCKED_EXECUTION_APPROVAL"
        if allow_test_only_synthetic
        else "PROTECTED_LOCKED_EXECUTION_APPROVAL"
    )
    base_freeze_sha = sha256_file(paths["base_freeze"])
    freeze = load_json_object(paths["base_freeze"])
    amendment = load_json_object(paths["amendment"])
    expected = {
        "artifact_label": expected_label,
        "run_id": LOCKED_RUN_ID,
        "exact_command_sha256": LOCKED_EXACT_COMMAND_SHA256,
        "final_freeze_record_sha256": base_freeze_sha,
        "base_final_freeze_record_sha256": base_freeze_sha,
        "runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "base_runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "amended_runtime_inventory_sha256": amendment[
            "amended_runtime_inventory_sha256"
        ],
        "runtime_environment_manifest_sha256": sha256_file(
            paths["runtime_environment"]
        ),
        "non_scientific_amendment_record_sha256": sha256_file(paths["amendment"]),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            paths["carryforward"]
        ),
        "amended_runtime_verification_record_sha256": sha256_file(
            paths["amended_verification"]
        ),
    }
    if any(authorization.get(key) != value for key, value in expected.items()):
        raise PermissionError("LOCKED_EXECUTION_EXACT_ACTION_BINDING_MISMATCH")
    for field, key in (
        ("author_final_freeze_approval_sha256", "author_approval"),
        ("materialization_approval_sha256", "locked_materialization_approval"),
        ("calibration_review_approval_sha256", "calibration_review_approval"),
        ("applicable_result_sha256", "calibration_result"),
        ("applicable_certificate_sha256", "calibration_certificate"),
        ("protocol_sha256", "protocol"),
        ("config_sha256", "config"),
        ("fidelity_sha256", "fidelity"),
    ):
        require_bound_file(authorization, field, paths[key])

    validate_approval_record(
        project_root=project_root,
        approval_path=paths["author_approval"],
        expected_record_type="AUTHOR_FINAL_FREEZE_APPROVAL_V1",
        freeze_record_path=paths["base_freeze"],
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    review = _validate_amendment_review_gate(
        project_root=project_root,
        paths=paths,
        authorization=authorization,
        freeze=freeze,
        amendment=amendment,
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    amended_verification = verify_runtime_freeze_with_cumulative_amendment_v2(
        project_root=project_root,
        base_allowlist_path=paths["base_allowlist"],
        amended_allowlist_path=paths["amended_allowlist"],
        base_freeze_path=paths["base_freeze"],
        expected_base_freeze_file_sha256=base_freeze_sha,
        amendment_path=paths["amendment"],
        amendment_scope_approval_path=paths["amendment_approval"],
        carryforward_path=paths["carryforward"],
        protocol_path=paths["protocol"],
        config_path=paths["config"],
        fidelity_path=paths["fidelity"],
        runtime_environment_manifest_path=paths["runtime_environment"],
        superseded_amendment_path=paths["superseded_amendment"],
        superseded_scope_approval_path=paths["superseded_scope_approval"],
        superseded_carryforward_path=paths["superseded_carryforward"],
        superseded_verification_path=paths["superseded_verification"],
        allow_test_only_synthetic=allow_test_only_synthetic,
    )
    registered_verification = load_json_object(paths["amended_verification"])
    validate_instance(
        registered_verification,
        project_root
        / "manifests/schema/amended_runtime_verification_record_v2.schema.json",
        instance_name=paths["amended_verification"].as_posix(),
    )
    dynamic_comparable = dict(amended_verification)
    registered_comparable = dict(registered_verification)
    registered_comparable.pop("verification_timestamp_utc", None)
    if registered_comparable != dynamic_comparable:
        raise PermissionError("LOCKED_AMENDED_RUNTIME_VERIFICATION_RECORD_MISMATCH")

    verify_locked_certificate_chain(
        project_root=project_root,
        authorization=authorization,
        certificate_path=paths["calibration_certificate"],
        calibration_bundle_path=paths["calibration_result"],
        calibration_review_approval_path=paths["calibration_review_approval"],
        freeze_record_path=paths["base_freeze"],
        allow_test_only_synthetic=allow_test_only_synthetic,
    )

    # Streaming raw hash only.  The role JSON is not parsed until after guard.
    _validate_regular_mode_0600(paths["locked_role"])
    if authorization.get("role_manifest_raw_sha256") != sha256_file(
        paths["locked_role"]
    ):
        raise PermissionError("LOCKED_ROLE_RAW_SHA256_MISMATCH")
    carryforward = load_json_object(paths["carryforward"])
    locked_row = _carryforward_locked_row(carryforward)
    if (
        locked_row.get("raw_sha256") != authorization["role_manifest_raw_sha256"]
        or locked_row.get("commitment_sha256")
        != authorization.get("role_commitment_sha256")
    ):
        raise PermissionError("LOCKED_ROLE_REGISTERED_COMMITMENT_MISMATCH")
    return authorization, amended_verification, carryforward, review


def _build_provenance_context(
    *,
    paths: dict[str, Path],
    authorization: dict[str, Any],
    amended_verification: dict[str, Any],
    review: dict[str, Any],
    intent_sha: str,
    guard_sha: str,
    project_root: Path,
) -> LockedResultProvenanceContext:
    freeze = load_json_object(paths["base_freeze"])
    context = LockedResultProvenanceContext(
        context_schema_version="1",
        final_freeze_record_sha256=sha256_file(paths["base_freeze"]),
        base_runtime_inventory_sha256=str(freeze["runtime_inventory_sha256"]),
        non_scientific_amendment_record_sha256=sha256_file(paths["amendment"]),
        sealed_artifact_carryforward_record_sha256=sha256_file(
            paths["carryforward"]
        ),
        amendment_review_approval_sha256=sha256_file(
            paths["amendment_review_approval"]
        ),
        amendment_review_bundle_sha256=str(review["review_bundle_sha256"]),
        amended_runtime_verification_record_sha256=sha256_file(
            paths["amended_verification"]
        ),
        amended_runtime_inventory_sha256=str(
            amended_verification["amended_runtime_inventory_sha256"]
        ),
        runtime_environment_manifest_sha256=sha256_file(
            paths["runtime_environment"]
        ),
        exact_command_sha256=LOCKED_EXACT_COMMAND_SHA256,
        execution_approval_sha256=sha256_file(paths["approval"]),
        execution_intent_sha256=intent_sha,
        execution_guard_sha256=guard_sha,
        calibration_result_bundle_sha256=sha256_file(paths["calibration_result"]),
        calibration_certificate_record_sha256=sha256_file(
            paths["calibration_certificate"]
        ),
        calibration_review_approval_sha256=sha256_file(
            paths["calibration_review_approval"]
        ),
        role_manifest_raw_sha256=str(authorization["role_manifest_raw_sha256"]),
        role_commitment_sha256=str(authorization["role_commitment_sha256"]),
        protocol_sha256=sha256_file(paths["protocol"]),
        config_sha256=sha256_file(paths["config"]),
        fidelity_contract_sha256=sha256_file(paths["fidelity"]),
        author_final_freeze_approval_sha256=sha256_file(paths["author_approval"]),
        locked_materialization_approval_sha256=sha256_file(
            paths["locked_materialization_approval"]
        ),
    )
    payload = context.payload()
    validate_instance(
        payload,
        project_root
        / "manifests/schema/locked_result_provenance_context_v1.schema.json",
        instance_name="locked result provenance context",
    )
    approval_expected = {
        "base_runtime_inventory_sha256": context.base_runtime_inventory_sha256,
        "amended_runtime_inventory_sha256": context.amended_runtime_inventory_sha256,
        "non_scientific_amendment_record_sha256": (
            context.non_scientific_amendment_record_sha256
        ),
        "sealed_artifact_carryforward_record_sha256": (
            context.sealed_artifact_carryforward_record_sha256
        ),
        "non_scientific_amendment_review_approval_sha256": (
            context.amendment_review_approval_sha256
        ),
        "amendment_review_bundle_sha256": context.amendment_review_bundle_sha256,
        "amended_runtime_verification_record_sha256": (
            context.amended_runtime_verification_record_sha256
        ),
        "runtime_environment_manifest_sha256": (
            context.runtime_environment_manifest_sha256
        ),
        "exact_command_sha256": context.exact_command_sha256,
        "role_manifest_raw_sha256": context.role_manifest_raw_sha256,
        "role_commitment_sha256": context.role_commitment_sha256,
        "protocol_sha256": context.protocol_sha256,
        "config_sha256": context.config_sha256,
        "fidelity_sha256": context.fidelity_contract_sha256,
    }
    if any(authorization.get(key) != value for key, value in approval_expected.items()):
        raise LockedResultProvenanceIncomplete()
    return context


def _attach_and_validate_locked_result(
    *,
    base_bundle: dict[str, Any],
    context: LockedResultProvenanceContext,
    project_root: Path,
    synthetic: bool,
) -> dict[str, Any]:
    bundle = dict(base_bundle)
    bundle.update(context.payload())
    bundle.update(
        {
            "schema_version": "5",
            "record_type": (
                "TEST_ONLY_SYNTHETIC_LOCKED_RESULT_BUNDLE_V2"
                if synthetic
                else "PROTECTED_LOCKED_RESULT_BUNDLE_ACTUAL_V1"
            ),
            "runtime_inventory_sha256": context.amended_runtime_inventory_sha256,
            "locked_provenance_context_sha256": context.sha256(),
        }
    )
    schema = project_root / "manifests/schema" / (
        "test_only_synthetic_locked_result_bundle_v2.schema.json"
        if synthetic
        else "protected_locked_result_bundle_actual_v1.schema.json"
    )
    _validate_locked_result_matches_context(
        bundle=bundle,
        context=context,
        schema=schema,
    )
    return bundle


def _validate_locked_result_matches_context(
    *,
    bundle: dict[str, Any],
    context: LockedResultProvenanceContext,
    schema: Path,
) -> None:
    """Enforce schema plus cross-object equality before result new-write."""
    try:
        validate_instance(bundle, schema, instance_name="locked-specific result bundle")
    except Exception as exc:
        raise LockedResultProvenanceIncomplete() from exc
    payload = context.payload()
    if (
        any(bundle.get(field) != payload[field] for field in _CONTEXT_FIELDS)
        or bundle.get("runtime_inventory_sha256")
        != context.amended_runtime_inventory_sha256
        or bundle.get("locked_provenance_context_sha256") != context.sha256()
    ):
        raise LockedResultProvenanceIncomplete()


def _receipt_context_matches(
    receipt: dict[str, Any], context: LockedResultProvenanceContext
) -> bool:
    payload = context.payload()
    return all(receipt.get(field) == payload[field] for field in _CONTEXT_FIELDS) and (
        receipt.get("locked_provenance_context_sha256") == context.sha256()
    )


def run_locked_audit_once(
    *,
    project_root: Path,
    allow_test_only_synthetic: bool = False,
    analysis_runner: Callable[..., dict[str, Any]] | None = None,
    bootstrap_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Consume one exact approval once; never retry after intent/guard creation."""
    if not allow_test_only_synthetic:
        validate_fixed_process_command(project_root)
        _validate_bootstrap_provenance(project_root, bootstrap_provenance)
        if analysis_runner is not None:
            raise PermissionError("REAL_LOCKED_ANALYSIS_RUNNER_OVERRIDE_FORBIDDEN")
    paths = _paths(project_root)
    process_start = _now()
    authorization, amended_verification, _, review = (
        _validate_locked_approval_and_preflight(
            project_root=project_root,
            paths=paths,
            allow_test_only_synthetic=allow_test_only_synthetic,
        )
    )
    _preexisting_output_check(paths)
    synthetic = allow_test_only_synthetic
    intent: dict[str, Any] = {
        "record_type": "LOCKED_EXECUTION_INTENT_V1",
        "artifact_label": (
            "TEST_ONLY_SYNTHETIC_LOCKED_EXECUTION_INTENT"
            if synthetic
            else "PROTECTED_LOCKED_EXECUTION_INTENT"
        ),
        "status": "LOCKED_EXECUTION_INTENT_NEW_WRITTEN_BEFORE_GUARD",
        "run_id": LOCKED_RUN_ID,
        "role": "locked",
        "creation_timestamp_utc": _now(),
        "execution_approval_sha256": sha256_file(paths["approval"]),
        "exact_command_sha256": LOCKED_EXACT_COMMAND_SHA256,
        "base_final_freeze_record_sha256": sha256_file(paths["base_freeze"]),
        "base_runtime_inventory_sha256": amended_verification[
            "base_runtime_inventory_sha256"
        ],
        "amended_runtime_inventory_sha256": amended_verification[
            "amended_runtime_inventory_sha256"
        ],
        "runtime_environment_manifest_sha256": sha256_file(
            paths["runtime_environment"]
        ),
        "non_scientific_amendment_record_sha256": sha256_file(paths["amendment"]),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            paths["carryforward"]
        ),
        "amendment_review_approval_sha256": sha256_file(
            paths["amendment_review_approval"]
        ),
        "amended_runtime_verification_record_sha256": sha256_file(
            paths["amended_verification"]
        ),
        "role_manifest_raw_sha256": authorization["role_manifest_raw_sha256"],
        "role_commitment_sha256": authorization["role_commitment_sha256"],
        "intent_path": LOCKED_PATHS["intent"],
        "guard_path": LOCKED_PATHS["guard"],
        "result_path": LOCKED_PATHS["result"],
        "failure_path": LOCKED_PATHS["failure"],
        "receipt_path": LOCKED_PATHS["receipt"],
        "one_time_use_policy": "NEW_WRITE_SINGLE_USE",
        "protected_values_parsed": False,
        "benchmark_called": False,
    }
    validate_instance(
        intent,
        project_root / "manifests/schema/locked_execution_intent_v1.schema.json",
        instance_name="locked execution intent",
    )
    try:
        _atomic_json_new(paths["intent"], intent)
    except FileExistsError as exc:
        raise LockedExecutionConsumed() from exc
    intent_sha = sha256_file(paths["intent"])
    guard_payload = {
        "record_type": "LOCKED_EXECUTION_PERMANENT_GUARD_V1",
        "run_id": LOCKED_RUN_ID,
        "execution_approval_sha256": sha256_file(paths["approval"]),
        "exact_command_sha256": LOCKED_EXACT_COMMAND_SHA256,
        "intent_sha256": intent_sha,
        "non_scientific_amendment_record_sha256": sha256_file(paths["amendment"]),
        "sealed_artifact_carryforward_record_sha256": sha256_file(
            paths["carryforward"]
        ),
        "amendment_review_approval_sha256": sha256_file(
            paths["amendment_review_approval"]
        ),
    }
    try:
        _atomic_json_new(paths["guard"], guard_payload)
    except FileExistsError as exc:
        raise LockedExecutionConsumed() from exc
    guard_sha = sha256_file(paths["guard"])

    context: LockedResultProvenanceContext | None = None
    terminal_write_started = False
    try:
        if not synthetic:
            validate_fixed_process_command(project_root)
            _validate_bootstrap_provenance(project_root, bootstrap_provenance)
        if (
            authorization.get("exact_command_sha256") != LOCKED_EXACT_COMMAND_SHA256
            or sha256_file(paths["approval"]) != intent["execution_approval_sha256"]
        ):
            raise PermissionError("LOCKED_EXACT_COMMAND_RECHECK_FAILED")
        # Immutable, schema-validated provenance is built after permanent
        # consumption but before role parsing or any benchmark call.
        context = _build_provenance_context(
            paths=paths,
            authorization=authorization,
            amended_verification=amended_verification,
            review=review,
            intent_sha=intent_sha,
            guard_sha=guard_sha,
            project_root=project_root,
        )
        execution_context = {
            "status": "LOCKED_EXECUTION_PREFLIGHT_VERIFIED_AND_GUARD_CREATED",
            "certificate_chain_verified": True,
            "protected_values_parsed": False,
            "benchmark_called": False,
            "execution_approval_sha256": context.execution_approval_sha256,
            "intent_sha256": context.execution_intent_sha256,
            "guard_sha256": context.execution_guard_sha256,
            "amended_runtime_inventory_sha256": (
                context.amended_runtime_inventory_sha256
            ),
            "locked_provenance_context_sha256": context.sha256(),
        }
        runner = analysis_runner or _run_locked_analysis_after_one_time_guard
        base_bundle = runner(
            project_root=project_root,
            config_path=paths["config"],
            protocol_path=paths["protocol"],
            fidelity_path=paths["fidelity"],
            role_manifest_path=paths["locked_role"],
            run_id=LOCKED_RUN_ID,
            authorization=authorization,
            execution_approval_record_path=paths["approval"],
            final_freeze_record_path=paths["base_freeze"],
            author_approval_record_path=paths["author_approval"],
            execution_context=execution_context,
            orchestrator_capability=_LOCKED_ORCHESTRATOR_CAPABILITY,
            allow_test_only_synthetic_authorization=synthetic,
        )
        bundle = _attach_and_validate_locked_result(
            base_bundle=base_bundle,
            context=context,
            project_root=project_root,
            synthetic=synthetic,
        )
        result_bytes = _json_bytes(bundle)
        receipt: dict[str, Any] = {
            "record_type": "LOCKED_EXECUTION_RECEIPT_V1",
            "artifact_label": (
                "TEST_ONLY_SYNTHETIC_LOCKED_EXECUTION_RECEIPT"
                if synthetic
                else "PROTECTED_LOCKED_EXECUTION_RECEIPT"
            ),
            "status": "LOCKED_EXECUTION_COMPLETED_ONCE",
            "run_id": LOCKED_RUN_ID,
            "role": "locked",
            **context.payload(),
            "locked_provenance_context_sha256": context.sha256(),
            "guard_path": LOCKED_PATHS["guard"],
            "receipt_path": LOCKED_PATHS["receipt"],
            "process_start_utc": process_start,
            "process_end_utc": _now(),
            "result_path": LOCKED_PATHS["result"],
            "failure_path": LOCKED_PATHS["failure"],
            "result_sha256": sha256_bytes(result_bytes),
            "failure_sha256": None,
            "guard_permanently_retained": True,
            "retry_permitted": False,
            "raw_role_values_included": False,
            "exception_text_redacted": True,
        }
        if not _receipt_context_matches(receipt, context):
            raise LockedResultProvenanceIncomplete()
        validate_instance(
            receipt,
            project_root / "manifests/schema/locked_execution_receipt_v1.schema.json",
            instance_name="locked execution receipt",
        )
        receipt_bytes = _json_bytes(receipt)
        terminal_write_started = True
        _atomic_write_new(paths["result"], result_bytes)
        _atomic_write_new(paths["receipt"], receipt_bytes)
        return bundle
    except Exception as exc:
        if terminal_write_started:
            raise LockedExecutionAfterGuardFailure() from None
        error_name = type(exc).__name__
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", error_name) is None:
            error_name = "Exception"
        failure_code = (
            LOCKED_RESULT_PROVENANCE_INCOMPLETE
            if isinstance(exc, LockedResultProvenanceIncomplete)
            else LOCKED_EXECUTION_EXCEPTION_AFTER_GUARD
        )
        failure: dict[str, Any] = {
            "record_type": "LOCKED_EXECUTION_FAILURE_V1",
            "artifact_label": (
                "TEST_ONLY_SYNTHETIC_LOCKED_EXECUTION_FAILURE"
                if synthetic
                else "PROTECTED_LOCKED_EXECUTION_FAILURE"
            ),
            "status": "LOCKED_EXECUTION_FAILED_AFTER_GUARD",
            "failure_code": failure_code,
            "phase": "AFTER_PERMANENT_GUARD",
            "run_id": LOCKED_RUN_ID,
            "role": "locked",
            "error_type": error_name,
            "error_text": "REDACTED",
            "intent_sha256": intent_sha,
            "guard_sha256": guard_sha,
            "execution_approval_sha256": sha256_file(paths["approval"]),
            "process_start_utc": process_start,
            "failure_time_utc": _now(),
            "raw_role_values_included": False,
            "retry_permitted": False,
        }
        validate_instance(
            failure,
            project_root / "manifests/schema/locked_execution_failure_v1.schema.json",
            instance_name="locked execution failure",
        )
        failure_bytes = _json_bytes(failure)
        receipt = {
            "record_type": "LOCKED_EXECUTION_RECEIPT_V1",
            "artifact_label": (
                "TEST_ONLY_SYNTHETIC_LOCKED_EXECUTION_RECEIPT"
                if synthetic
                else "PROTECTED_LOCKED_EXECUTION_RECEIPT"
            ),
            "status": "LOCKED_EXECUTION_FAILED_AFTER_GUARD",
            "run_id": LOCKED_RUN_ID,
            "role": "locked",
            **(context.payload() if context is not None else {
                "context_schema_version": "1",
                "final_freeze_record_sha256": sha256_file(paths["base_freeze"]),
                "base_runtime_inventory_sha256": amended_verification[
                    "base_runtime_inventory_sha256"
                ],
                "non_scientific_amendment_record_sha256": sha256_file(
                    paths["amendment"]
                ),
                "sealed_artifact_carryforward_record_sha256": sha256_file(
                    paths["carryforward"]
                ),
                "amendment_review_approval_sha256": sha256_file(
                    paths["amendment_review_approval"]
                ),
                "amendment_review_bundle_sha256": review["review_bundle_sha256"],
                "amended_runtime_verification_record_sha256": sha256_file(
                    paths["amended_verification"]
                ),
                "amended_runtime_inventory_sha256": amended_verification[
                    "amended_runtime_inventory_sha256"
                ],
                "runtime_environment_manifest_sha256": sha256_file(
                    paths["runtime_environment"]
                ),
                "exact_command_sha256": LOCKED_EXACT_COMMAND_SHA256,
                "execution_approval_sha256": sha256_file(paths["approval"]),
                "execution_intent_sha256": intent_sha,
                "execution_guard_sha256": guard_sha,
                "calibration_result_bundle_sha256": sha256_file(
                    paths["calibration_result"]
                ),
                "calibration_certificate_record_sha256": sha256_file(
                    paths["calibration_certificate"]
                ),
                "calibration_review_approval_sha256": sha256_file(
                    paths["calibration_review_approval"]
                ),
                "role_manifest_raw_sha256": authorization[
                    "role_manifest_raw_sha256"
                ],
                "role_commitment_sha256": authorization["role_commitment_sha256"],
                "protocol_sha256": sha256_file(paths["protocol"]),
                "config_sha256": sha256_file(paths["config"]),
                "fidelity_contract_sha256": sha256_file(paths["fidelity"]),
                "author_final_freeze_approval_sha256": sha256_file(
                    paths["author_approval"]
                ),
                "locked_materialization_approval_sha256": sha256_file(
                    paths["locked_materialization_approval"]
                ),
            }),
            "locked_provenance_context_sha256": (
                context.sha256() if context is not None else None
            ),
            "guard_path": LOCKED_PATHS["guard"],
            "receipt_path": LOCKED_PATHS["receipt"],
            "process_start_utc": process_start,
            "process_end_utc": _now(),
            "result_path": LOCKED_PATHS["result"],
            "failure_path": LOCKED_PATHS["failure"],
            "result_sha256": None,
            "failure_sha256": sha256_bytes(failure_bytes),
            "guard_permanently_retained": True,
            "retry_permitted": False,
            "raw_role_values_included": False,
            "exception_text_redacted": True,
        }
        validate_instance(
            receipt,
            project_root / "manifests/schema/locked_execution_receipt_v1.schema.json",
            instance_name="locked execution failure receipt",
        )
        receipt_bytes = _json_bytes(receipt)
        terminal_write_started = True
        try:
            _atomic_write_new(paths["failure"], failure_bytes)
            _atomic_write_new(paths["receipt"], receipt_bytes)
        except Exception:
            raise LockedExecutionAfterGuardFailure() from None
        raise LockedExecutionAfterGuardFailure() from None
