"""One protected-shaped analysis path with runtime-enforced freeze gates."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

from aphfs.benchmarks.confirmatory import (
    run_confirmatory_a0,
    run_confirmatory_a1,
    run_confirmatory_b0,
    run_confirmatory_b1,
    run_confirmatory_c,
    run_confirmatory_d0,
    run_confirmatory_d1,
    run_confirmatory_d2_cert,
    run_confirmatory_d2_mem,
    run_confirmatory_e,
    run_confirmatory_f0,
)
from aphfs.constants import PUBLIC_MOCK_ROLE_LABEL
from aphfs.provenance.hashing import sha256_file, sha256_json
from aphfs.provenance.runtime_freeze import verify_runtime_freeze
from aphfs.roles.approvals import (
    require_bound_file,
    validate_approval_record,
)
from aphfs.roles.workflow import verify_public_mock_manifest
from aphfs.schema.benchmark_results import (
    bind_fidelity_contract_snapshots,
    validate_benchmark_results,
)
from aphfs.schema.validation import load_json_object, validate_instance, validate_json_file

_LOCKED_ORCHESTRATOR_CAPABILITY = object()


def _verify_actual_role_manifest(
    *,
    role: str,
    role_manifest_path: Path,
    authorization: dict[str, Any],
    project_root: Path,
    allow_test_only_synthetic_authorization: bool,
) -> tuple[dict[str, Any], list[int]]:
    if authorization.get("role_manifest_raw_sha256") != sha256_file(role_manifest_path):
        raise PermissionError("Actual role manifest raw-file hash mismatch")
    manifest = load_json_object(role_manifest_path)
    validate_instance(
        manifest,
        project_root / "manifests/schema/protected_role_manifest_v3.schema.json",
        instance_name=role_manifest_path.as_posix(),
    )
    allowed_label = (
        "TEST_ONLY_SYNTHETIC_PROTECTED_ROLE"
        if allow_test_only_synthetic_authorization
        else "PROTECTED_ROLE"
    )
    if manifest.get("role") != role or manifest.get("label") != allowed_label:
        raise PermissionError("Actual protected manifest role or label mismatch")
    if manifest.get("final_freeze_record_sha256") != authorization.get(
        "final_freeze_record_sha256"
    ):
        raise PermissionError("Role manifest freeze binding mismatch")
    if manifest.get("runtime_inventory_sha256") != authorization.get(
        "runtime_inventory_sha256"
    ):
        raise PermissionError("Role manifest runtime binding mismatch")
    if manifest.get("author_final_freeze_approval_sha256") != authorization.get(
        "author_final_freeze_approval_sha256"
    ):
        raise PermissionError("Role manifest author-approval binding mismatch")
    if manifest.get("materialization_approval_sha256") != authorization.get(
        "materialization_approval_sha256"
    ):
        raise PermissionError("Role manifest materialization-approval binding mismatch")
    values = manifest.get("values")
    if not isinstance(values, list) or len(values) != 64:
        raise PermissionError("Actual protected role must contain exactly 64 values")
    if len(set(values)) != 64 or not all(isinstance(value, int) for value in values):
        raise PermissionError("Actual protected values must be unique integers")
    payload = {
        key: value for key, value in manifest.items() if key != "commitment_sha256"
    }
    if manifest.get("commitment_sha256") != sha256_json(payload):
        raise PermissionError("Actual protected role commitment mismatch")
    if authorization.get("role_commitment_sha256") != manifest["commitment_sha256"]:
        raise PermissionError("Authorization does not bind the role commitment")
    return manifest, [int(value) for value in values]


def _with_role(config: dict[str, Any], role: str) -> dict[str, Any]:
    copied = deepcopy(config)
    copied["role"] = role
    return copied


def _run_locked_endpoint_set(
    *,
    benchmarks: dict[str, dict[str, Any]],
    values: list[int],
) -> list[dict[str, Any]]:
    """Run the frozen locked endpoint set after the one-time guard exists."""
    a0, signatures = run_confirmatory_a0(benchmarks["A0"])
    return [
        a0,
        run_confirmatory_a1(_with_role(benchmarks["A1"], "locked"), values, signatures),
        run_confirmatory_b0(_with_role(benchmarks["B0"], "locked"), values),
        run_confirmatory_b1(_with_role(benchmarks["B1"], "locked"), values),
        run_confirmatory_c(benchmarks["C"]),
        run_confirmatory_d0(benchmarks["D0"], values),
        run_confirmatory_d1(),
        run_confirmatory_d2_cert(
            _with_role(benchmarks["D2-CERT"], "locked"),
            values,
            "locked",
            calibration_certificate_verified=True,
        ),
        run_confirmatory_d2_mem(benchmarks["D2-MEM"]),
        run_confirmatory_e(_with_role(benchmarks["E"], "locked"), values),
        run_confirmatory_f0(_with_role(benchmarks["F0"], "locked"), values),
    ]


def _run_locked_analysis_after_one_time_guard(
    *,
    project_root: Path,
    config_path: Path,
    protocol_path: Path,
    fidelity_path: Path,
    role_manifest_path: Path,
    run_id: str,
    authorization: dict[str, Any],
    execution_approval_record_path: Path,
    final_freeze_record_path: Path,
    author_approval_record_path: Path,
    execution_context: dict[str, Any],
    orchestrator_capability: object,
    allow_test_only_synthetic_authorization: bool = False,
) -> dict[str, Any]:
    """Parse locked values only after the orchestrator has consumed the guard."""
    fixed_intent = project_root / (
        "protected_results/locked/locked_execution_intent_v1.json"
    )
    fixed_guard = project_root / "protected_results/locked/.actual_locked_v1_started"
    fixed_result = project_root / "protected_results/locked/locked_result_bundle_v1.json"
    fixed_failure = project_root / (
        "protected_results/locked/locked_result_bundle_v1.json.failure.json"
    )
    fixed_receipt = project_root / (
        "protected_results/locked/locked_execution_receipt_v1.json"
    )
    if (
        orchestrator_capability is not _LOCKED_ORCHESTRATOR_CAPABILITY
        or fixed_result.exists()
        or fixed_failure.exists()
        or fixed_receipt.exists()
        or execution_context.get("status")
        != "LOCKED_EXECUTION_PREFLIGHT_VERIFIED_AND_GUARD_CREATED"
        or execution_context.get("certificate_chain_verified") is not True
        or execution_context.get("protected_values_parsed") is not False
        or execution_context.get("benchmark_called") is not False
        or fixed_intent.is_symlink()
        or fixed_guard.is_symlink()
        or not fixed_intent.is_file()
        or not fixed_guard.is_file()
        or execution_context.get("intent_sha256") != sha256_file(fixed_intent)
        or execution_context.get("guard_sha256") != sha256_file(fixed_guard)
        or execution_context.get("execution_approval_sha256")
        != sha256_file(execution_approval_record_path)
    ):
        raise PermissionError("LOCKED_EXECUTION_CONTEXT_OR_GUARD_INVALID")
    if run_id != "aphfs_actual_locked_audit_v1":
        raise PermissionError("LOCKED_EXECUTION_RUN_ID_MISMATCH")
    config = validate_json_file(
        config_path,
        project_root / "manifests/schema/protected_benchmark_config_v3.schema.json",
    )
    protocol = validate_json_file(
        protocol_path,
        project_root / "manifests/schema/protected_protocol_v6.schema.json",
    )
    fidelity = validate_json_file(
        fidelity_path,
        project_root / "manifests/schema/protected_fidelity_contracts_v3.schema.json",
    )
    if (
        config["schema_version"] != "3"
        or protocol["protocol_schema_version"] != "6"
        or fidelity["schema_version"] != "3"
    ):
        raise PermissionError("Protected semantic version mismatch")
    role_manifest, values = _verify_actual_role_manifest(
        role="locked",
        role_manifest_path=role_manifest_path,
        authorization=authorization,
        project_root=project_root,
        allow_test_only_synthetic_authorization=(
            allow_test_only_synthetic_authorization
        ),
    )
    benchmarks = cast(dict[str, dict[str, Any]], config["benchmarks"])
    results = _run_locked_endpoint_set(benchmarks=benchmarks, values=values)
    bind_fidelity_contract_snapshots(results, fidelity)
    validate_benchmark_results(
        results,
        project_root,
        role="locked",
        fidelity_contracts=fidelity,
    )
    freeze = load_json_object(final_freeze_record_path)
    synthetic = allow_test_only_synthetic_authorization
    bundle: dict[str, Any] = {
        "schema_version": "4",
        "label": (
            "TEST_ONLY_SYNTHETIC_PROTECTED_RESULT"
            if synthetic
            else "PROTECTED_RESULT"
        ),
        "role": "locked",
        "run_id": run_id,
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_contract_sha256": sha256_file(fidelity_path),
        "role_commitment_sha256": str(role_manifest["commitment_sha256"]),
        "manuscript_evidence": not synthetic,
        "protected_execution": not synthetic,
        "benchmark_results": results,
        "final_freeze_record_sha256": sha256_file(final_freeze_record_path),
        "runtime_inventory_sha256": freeze["runtime_inventory_sha256"],
        "runtime_environment_manifest_sha256": freeze[
            "runtime_environment_manifest_sha256"
        ],
        "author_final_freeze_approval_sha256": sha256_file(
            author_approval_record_path
        ),
        "execution_approval_sha256": sha256_file(execution_approval_record_path),
    }
    validate_instance(
        bundle,
        project_root
        / "manifests/schema"
        / (
            "test_only_synthetic_locked_result_bundle_v1.schema.json"
            if synthetic
            else "protected_result_bundle_actual_v2.schema.json"
        ),
        instance_name="locked result bundle after one-time guard",
    )
    return bundle


def run_protected_shaped_analysis(
    *,
    project_root: Path,
    config_path: Path,
    protocol_path: Path,
    fidelity_path: Path,
    role_manifest_path: Path,
    role: str,
    run_id: str,
    authorization: dict[str, Any] | None = None,
    execution_approval_record_path: Path | None = None,
    final_freeze_record_path: Path | None = None,
    author_approval_record_path: Path | None = None,
    calibration_certificate_record_path: Path | None = None,
    calibration_result_bundle_path: Path | None = None,
    calibration_review_approval_path: Path | None = None,
    allow_test_only_synthetic_authorization: bool = False,
) -> dict[str, Any]:
    """Run one path; actual roles verify the whole runtime before role parsing."""
    if role == "locked":
        raise PermissionError("LOCKED_EXECUTION_REQUIRES_ONE_TIME_ORCHESTRATOR")
    protected_execution = role in {"calibration", "locked"}
    freeze_record: dict[str, Any] | None = None
    if protected_execution:
        if authorization is None or execution_approval_record_path is None:
            raise PermissionError(
                "Actual protected execution is hard-rejected without authorization"
            )
        if final_freeze_record_path is None or author_approval_record_path is None:
            raise PermissionError(
                "Actual protected execution requires freeze and author approval records"
            )
        author_approval = validate_approval_record(
            project_root=project_root,
            approval_path=author_approval_record_path,
            expected_record_type="AUTHOR_FINAL_FREEZE_APPROVAL_V1",
            freeze_record_path=final_freeze_record_path,
            allow_test_only_synthetic=allow_test_only_synthetic_authorization,
        )
        execution_type = (
            "CALIBRATION_EXECUTION_APPROVAL_V1"
            if role == "calibration"
            else "LOCKED_EXECUTION_APPROVAL_V1"
        )
        authorization = validate_approval_record(
            project_root=project_root,
            approval_path=execution_approval_record_path,
            expected_record_type=execution_type,
            freeze_record_path=final_freeze_record_path,
            allow_test_only_synthetic=allow_test_only_synthetic_authorization,
        )
        if authorization.get("applicable_role") != role:
            raise PermissionError("Protected authorization role mismatch")
        require_bound_file(
            authorization,
            "author_final_freeze_approval_sha256",
            author_approval_record_path,
        )
        freeze_record = verify_runtime_freeze(
            project_root=project_root,
            allowlist_path=project_root / "manifests/runtime_allowlist_v1.json",
            freeze_record_path=final_freeze_record_path,
            expected_freeze_file_sha256=str(
                authorization["final_freeze_record_sha256"]
            ),
            protocol_path=protocol_path,
            config_path=config_path,
            fidelity_path=fidelity_path,
            runtime_environment_manifest_path=project_root
            / "manifests/protected_runtime_environment_manifest_v2.json",
            allow_test_only_synthetic=allow_test_only_synthetic_authorization,
        )
        if author_approval["runtime_inventory_sha256"] != freeze_record[
            "runtime_inventory_sha256"
        ]:
            raise PermissionError("Author approval runtime binding mismatch")
        if authorization.get("protocol_sha256") != sha256_file(protocol_path):
            raise PermissionError("Authorization protocol hash mismatch")
        if authorization.get("config_sha256") != sha256_file(config_path):
            raise PermissionError("Authorization config hash mismatch")
        if authorization.get("fidelity_sha256") != sha256_file(fidelity_path):
            raise PermissionError("Authorization fidelity hash mismatch")
    config = validate_json_file(
        config_path,
        project_root / "manifests/schema/protected_benchmark_config_v3.schema.json",
    )
    protocol = validate_json_file(
        protocol_path,
        project_root / "manifests/schema/protected_protocol_v6.schema.json",
    )
    fidelity = validate_json_file(
        fidelity_path,
        project_root / "manifests/schema/protected_fidelity_contracts_v3.schema.json",
    )
    if (
        config["schema_version"] != "3"
        or protocol["protocol_schema_version"] != "6"
        or fidelity["schema_version"] != "3"
    ):
        raise PermissionError("Protected semantic version mismatch")
    certificate_verified = False
    if protected_execution:
        assert authorization is not None
        role_manifest, values = _verify_actual_role_manifest(
            role=role,
            role_manifest_path=role_manifest_path,
            authorization=authorization,
            project_root=project_root,
            allow_test_only_synthetic_authorization=(
                allow_test_only_synthetic_authorization
            ),
        )
    else:
        role_manifest = validate_json_file(
            role_manifest_path,
            project_root / "manifests/schema/role_manifest.schema.json",
        )
        verified = verify_public_mock_manifest(role_manifest)
        if verified != role:
            raise PermissionError("Public-mock manifest role mismatch")
        if role == "mock_locked":
            if authorization is None:
                raise PermissionError("Mock locked run requires separate authorization")
            if authorization.get("authorization") != "PUBLIC_MOCK_DRY_RUN_ONLY":
                raise PermissionError("Mock locked authorization is invalid")
            if authorization.get("role_commitment_sha256") != role_manifest.get(
                "commitment_sha256"
            ):
                raise PermissionError("Mock authorization role commitment mismatch")
        values = [int(value) for value in role_manifest["values"]]
    benchmarks = cast(dict[str, dict[str, Any]], config["benchmarks"])
    if role in {"mock_calibration", "calibration"}:
        results = [
            run_confirmatory_d2_cert(
                _with_role(benchmarks["D2-CERT"], role),
                values,
                role,
            )
        ]
    else:
        a0, signatures = run_confirmatory_a0(benchmarks["A0"])
        results = [
            a0,
            run_confirmatory_a1(_with_role(benchmarks["A1"], role), values, signatures),
            run_confirmatory_b0(_with_role(benchmarks["B0"], role), values),
            run_confirmatory_b1(_with_role(benchmarks["B1"], role), values),
            run_confirmatory_c(benchmarks["C"]),
            run_confirmatory_d0(benchmarks["D0"], values),
            run_confirmatory_d1(),
            run_confirmatory_d2_cert(
                _with_role(benchmarks["D2-CERT"], role),
                values,
                role,
                calibration_certificate_verified=certificate_verified,
            ),
            run_confirmatory_d2_mem(benchmarks["D2-MEM"]),
            run_confirmatory_e(_with_role(benchmarks["E"], role), values),
            run_confirmatory_f0(_with_role(benchmarks["F0"], role), values),
        ]
    bind_fidelity_contract_snapshots(results, fidelity)
    validate_benchmark_results(
        results,
        project_root,
        role=role,
        fidelity_contracts=fidelity,
    )
    bundle = {
        "schema_version": "4" if protected_execution else "3",
        "label": (
            "TEST_ONLY_SYNTHETIC_PROTECTED_RESULT"
            if protected_execution and allow_test_only_synthetic_authorization
            else "PROTECTED_RESULT"
            if protected_execution
            else PUBLIC_MOCK_ROLE_LABEL
        ),
        "role": role,
        "run_id": run_id,
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_contract_sha256": sha256_file(fidelity_path),
        "role_commitment_sha256": str(role_manifest["commitment_sha256"]),
        "manuscript_evidence": (
            protected_execution and not allow_test_only_synthetic_authorization
        ),
        "protected_execution": (
            protected_execution and not allow_test_only_synthetic_authorization
        ),
        "benchmark_results": results,
    }
    if freeze_record is not None and final_freeze_record_path is not None:
        bundle["final_freeze_record_sha256"] = sha256_file(final_freeze_record_path)
        bundle["runtime_inventory_sha256"] = freeze_record[
            "runtime_inventory_sha256"
        ]
        bundle["runtime_environment_manifest_sha256"] = freeze_record[
            "runtime_environment_manifest_sha256"
        ]
        bundle["author_final_freeze_approval_sha256"] = sha256_file(
            cast(Path, author_approval_record_path)
        )
        bundle["execution_approval_sha256"] = sha256_file(
            cast(Path, execution_approval_record_path)
        )
    return bundle
