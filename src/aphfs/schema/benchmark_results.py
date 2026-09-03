"""Scientific-semantic validation beyond JSON Schema surface checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from aphfs.provenance.hashing import sha256_json
from aphfs.schema.validation import SchemaValidationError, validate_instance

_REGISTERED_SUB_IDS = {
    "A0",
    "A1",
    "B0",
    "B1",
    "C",
    "D0",
    "D1",
    "D2-CERT",
    "D2-MEM",
    "E",
    "F0",
}
_LOCKED_EXACT_SET = _REGISTERED_SUB_IDS
_CALIBRATION_EXACT_SET = {"D2-CERT"}
_ROLE_DERIVED_SUB_IDS = {"A1", "B0", "B1", "D2-CERT", "E", "F0"}
_CANDIDATE_LEDGER_SUB_IDS = {"A1", "B0", "B1"}


def bind_fidelity_contract_snapshots(
    results: list[dict[str, Any]],
    fidelity_contracts: dict[str, Any],
) -> None:
    """Bind each result row to the exact frozen per-benchmark contract."""
    contracts = cast(dict[str, dict[str, Any]], fidelity_contracts["benchmarks"])
    for result in results:
        sub_id = str(result["sub_id"])
        contract = contracts[sub_id]
        snapshot = {
            "contract_sha256": sha256_json(contract),
            "registered_source": contract["registered_source"],
            "reference_source": contract["reference_source"],
            "protected_observables": contract["protected_observables"],
            "tolerances": contract["tolerances"],
            "time_range": contract["time_range"],
            "initial_state_or_environment_distribution": contract[
                "initial_state_or_environment_distribution"
            ],
            "distribution_version": contract.get("distribution_version", "NOT_APPLICABLE"),
            "decision_invariance_required": contract[
                "decision_invariance_required"
            ],
        }
        for fidelity in cast(list[dict[str, Any]], result["fidelity_records"]):
            fidelity["frozen_contract_snapshot"] = snapshot


def _validate_a0(result: dict[str, Any]) -> None:
    rows = cast(list[dict[str, Any]], result["candidate_ledger"])
    rule_ids = [int(row["rule_id"]) for row in rows]
    candidate_ids = [str(row["candidate_id"]) for row in rows]
    if rule_ids != list(range(256)):
        raise SchemaValidationError("A0 rule IDs are not exactly ordered 0..255")
    if len(set(candidate_ids)) != 256:
        raise SchemaValidationError("A0 has duplicate or missing candidate IDs")
    if result["boundaries"] != ["periodic", "fixed_zero", "fixed_one", "reflect"]:
        raise SchemaValidationError("A0 boundary register is incomplete")
    if result["terminal_candidate_ledger_count"] != 256:
        raise SchemaValidationError("A0 terminal ledger is incomplete")


def _adverse_block_count(result: dict[str, Any]) -> int:
    blocks = cast(list[dict[str, Any]], result["block_records"])
    if result["sub_id"] == "E" and any(
        bool(row.get("budget_exceeded"))
        for row in cast(dict[str, dict[str, Any]], result["policy_results"]).values()
    ):
        return len(blocks)
    return sum(
        bool(block.get("failure_event"))
        or block.get("failure_code") is not None
        for block in blocks
    )


def validate_benchmark_result(
    result: dict[str, Any],
    project_root: Path,
    fidelity_contracts: dict[str, Any] | None = None,
) -> None:
    """Validate one result, including ledgers and recomputed adverse counts."""
    sub_id = str(result.get("sub_id"))
    if sub_id not in _REGISTERED_SUB_IDS:
        raise SchemaValidationError(f"Unregistered benchmark sub_id: {sub_id}")
    schema = project_root / "manifests/schema/benchmarks" / f"{sub_id}.result.schema.json"
    validate_instance(result, schema, instance_name=f"{sub_id} result")
    if sub_id == "A0":
        _validate_a0(result)
    blocks = cast(list[dict[str, Any]], result["block_records"])
    denominator = int(result["denominator"])
    if denominator != len(blocks):
        raise SchemaValidationError(
            f"{sub_id} denominator {denominator} does not equal block count {len(blocks)}"
        )
    block_ids = [str(row.get("block_id", index)) for index, row in enumerate(blocks)]
    if len(set(block_ids)) != len(block_ids):
        raise SchemaValidationError(f"{sub_id} contains duplicate block IDs")
    numerator = int(result["numerator"])
    if not 0 <= numerator <= denominator:
        raise SchemaValidationError(f"{sub_id} numerator is outside [0, denominator]")
    if sub_id in _ROLE_DERIVED_SUB_IDS and numerator != _adverse_block_count(result):
        raise SchemaValidationError(
            f"{sub_id} numerator does not equal the recomputed adverse block count"
        )
    if sub_id in _CANDIDATE_LEDGER_SUB_IDS:
        for index, block in enumerate(blocks):
            if int(block.get("candidate_count", -1)) != 256:
                raise SchemaValidationError(
                    f"{sub_id} block {index} does not contain all 256 candidates"
                )
            losses = block.get("candidate_losses")
            if not isinstance(losses, dict) or len(losses) != 256:
                raise SchemaValidationError(
                    f"{sub_id} block {index} candidate loss ledger is incomplete"
                )
    fidelities = cast(list[dict[str, Any]], result["fidelity_records"])
    if not fidelities:
        raise SchemaValidationError(f"{sub_id} has no fidelity record")
    if sub_id in _ROLE_DERIVED_SUB_IDS:
        if len(fidelities) != len(blocks):
            raise SchemaValidationError(
                f"{sub_id} fidelity record count does not equal block count"
            )
        fidelity_ids = [str(row.get("block_id")) for row in fidelities]
        if fidelity_ids != block_ids:
            raise SchemaValidationError(
                f"{sub_id} block/fidelity IDs are not one-to-one and ordered"
            )
        if any(row.get("benchmark") != sub_id for row in fidelities):
            raise SchemaValidationError(f"{sub_id} fidelity benchmark binding mismatch")
    if (
        any(row.get("status") == "FIDELITY_INDETERMINATE" for row in fidelities)
        and numerator == 0
    ):
        raise SchemaValidationError(
            f"{sub_id} fidelity instability was not counted as adverse"
        )
    if fidelity_contracts is not None:
        contract = cast(
            dict[str, dict[str, Any]],
            fidelity_contracts["benchmarks"],
        )[sub_id]
        expected_hash = sha256_json(contract)
        for row in fidelities:
            snapshot = row.get("frozen_contract_snapshot")
            if not isinstance(snapshot, dict):
                raise SchemaValidationError(
                    f"{sub_id} fidelity record lacks frozen contract snapshot"
                )
            if snapshot.get("contract_sha256") != expected_hash:
                raise SchemaValidationError(
                    f"{sub_id} fidelity contract hash mismatch"
                )
            if snapshot.get("registered_source") != contract["registered_source"]:
                raise SchemaValidationError(
                    f"{sub_id} registered source differs from frozen contract"
                )
            if snapshot.get("reference_source") != contract["reference_source"]:
                raise SchemaValidationError(
                    f"{sub_id} reference source differs from frozen contract"
                )
            for key in (
                "protected_observables",
                "tolerances",
                "time_range",
                "initial_state_or_environment_distribution",
                "decision_invariance_required",
            ):
                if snapshot.get(key) != contract[key]:
                    raise SchemaValidationError(
                        f"{sub_id} frozen fidelity semantic mismatch: {key}"
                    )


def validate_benchmark_results(
    results: list[dict[str, Any]],
    project_root: Path,
    *,
    role: str | None = None,
    fidelity_contracts: dict[str, Any] | None = None,
) -> None:
    """Validate a result bundle's exact endpoint set and each scientific ledger."""
    sub_ids = [str(result.get("sub_id")) for result in results]
    if len(set(sub_ids)) != len(sub_ids):
        raise SchemaValidationError("Result bundle contains duplicate benchmark sub_id")
    if role in {"mock_calibration", "calibration"} and set(sub_ids) != _CALIBRATION_EXACT_SET:
        raise SchemaValidationError("Calibration bundle must contain exactly D2-CERT")
    if role in {"mock_locked", "locked"} and set(sub_ids) != _LOCKED_EXACT_SET:
        raise SchemaValidationError(
            "Locked bundle endpoint set is not exactly the frozen protocol set"
        )
    for result in results:
        validate_benchmark_result(result, project_root, fidelity_contracts)
    if role in {"mock_calibration", "calibration", "mock_locked", "locked"}:
        for result in results:
            if result["sub_id"] in _ROLE_DERIVED_SUB_IDS and result["denominator"] != 64:
                raise SchemaValidationError(
                    f"{result['sub_id']} protected-shaped bundle must contain 64 blocks"
                )
