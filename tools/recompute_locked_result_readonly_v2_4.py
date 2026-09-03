#!/usr/bin/env python3
"""Read-only, standard-library-only audit of an immutable locked result.

This program deliberately does not import APHFS and has no path that opens a
role manifest.  It accepts only the fixed locked result/failure basenames,
reads the source through O_RDONLY/O_NOFOLLOW, independently recomputes the
registered endpoint numerators and exact-binomial intervals, and writes only
redacted review tables into a brand-new output directory.

It is a post-execution audit tool, not a benchmark runner.  A negative result,
an indeterminate result, or a technical incident is preserved as observed.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Any

TOOL_VERSION = "APHFS_LOCKED_READONLY_RECOMPUTATION_V2_4_V1"
BLOCKING = "BLOCKING_RESULT_INCONSISTENCY"
NO_RESULT = "NOT_APPLICABLE_NO_RESULT"
PASS = "PASS"
PASS_TEST_ONLY = "PASS_TEST_ONLY_COMPATIBILITY"

_RESULT_NAME = "locked_result_bundle_v1.json"
_FAILURE_NAME = "locked_result_bundle_v1.json.failure.json"
_MAX_SOURCE_BYTES = 512 * 1024 * 1024
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

_ENDPOINTS = (
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
)
_EXPECTED_BLOCKS = {
    "A0": 256,
    "A1": 64,
    "B0": 64,
    "B1": 64,
    "C": 9,
    "D0": 64,
    "D1": 1,
    "D2-CERT": 64,
    "D2-MEM": 4,
    "E": 64,
    "F0": 64,
}
_EXPECTED_FIDELITIES = {
    "A0": 1,
    "A1": 64,
    "B0": 64,
    "B1": 64,
    "C": 1,
    "D0": 64,
    "D1": 1,
    "D2-CERT": 64,
    "D2-MEM": 1,
    "E": 64,
    "F0": 64,
}
_BLOCK_ID_ENDPOINTS = {"A1", "B0", "B1", "D0", "D2-CERT", "E", "F0"}
_CP_ENDPOINTS = {"A1", "B0", "B1", "E", "F0"}
_POLICIES = (
    "exhaustive",
    "fixed_order",
    "development_frozen_order",
    "adaptive_fidelity",
)
_V5_PROVENANCE_FIELDS = (
    "final_freeze_record_sha256",
    "base_runtime_inventory_sha256",
    "non_scientific_amendment_record_sha256",
    "sealed_artifact_carryforward_record_sha256",
    "amendment_review_approval_sha256",
    "amendment_review_bundle_sha256",
    "amended_runtime_verification_record_sha256",
    "amended_runtime_inventory_sha256",
    "runtime_inventory_sha256",
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
    "locked_provenance_context_sha256",
)


class AuditIssues:
    """Collect fixed-code inconsistencies without copying offending content."""

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []
        self._seen: set[tuple[str, str, str]] = set()

    def add(self, code: str, endpoint: str = "BUNDLE", audit_row_id: str = "") -> None:
        key = (endpoint, audit_row_id, code)
        if key in self._seen:
            return
        self._seen.add(key)
        self.rows.append(
            {
                "severity": BLOCKING,
                "endpoint": endpoint,
                "audit_row_id": audit_row_id,
                "code": code,
            }
        )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return (
        (_is_int(value) or isinstance(value, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _raw_role_identities() -> set[tuple[int, int]]:
    root = Path(__file__).resolve().parents[1]
    identities: set[tuple[int, int]] = set()
    for path in (
        root / "protected_roles/calibration/calibration_role_v1.json",
        root / "protected_roles/locked/locked_role_v1.json",
    ):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            identities.add((int(info.st_dev), int(info.st_ino)))
    return identities


def _validate_input_location(path: Path, allow_test_only_synthetic: bool) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("O_NOFOLLOW is required")
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise PermissionError("input must be a regular non-symlink file")
    if (int(info.st_dev), int(info.st_ino)) in _raw_role_identities():
        raise PermissionError("raw role inode is forbidden")
    resolved = path.resolve(strict=True)
    if "protected_roles" in resolved.parts:
        raise PermissionError("raw role paths are forbidden")
    if path.name not in {_RESULT_NAME, _FAILURE_NAME}:
        raise PermissionError("input basename is not a fixed locked result/failure path")
    actual_parent = (
        Path(__file__).resolve().parents[1] / "protected_results/locked"
    ).resolve(strict=False)
    if resolved.parent != actual_parent and not allow_test_only_synthetic:
        raise PermissionError("non-canonical input requires explicit test-only opt-in")


def _read_no_follow(path: Path) -> tuple[bytes, dict[str, int]]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PermissionError("input is not a regular file")
        if (int(info.st_dev), int(info.st_ino)) in _raw_role_identities():
            raise PermissionError("raw role inode is forbidden")
        if info.st_size > _MAX_SOURCE_BYTES:
            raise PermissionError("input exceeds the fixed audit size limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_SOURCE_BYTES:
                raise PermissionError("input grew beyond the fixed audit size limit")
            chunks.append(chunk)
        return b"".join(chunks), {
            "device": int(info.st_dev),
            "inode": int(info.st_ino),
            "size": int(info.st_size),
        }
    finally:
        os.close(descriptor)


def _load_json(raw: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is forbidden: {value}")

    return json.loads(raw.decode("utf-8"), parse_constant=reject_constant)


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


def _csv_bytes(fieldnames: list[str], rows: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=fieldnames,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        safe: dict[str, Any] = {}
        for field in fieldnames:
            value = row.get(field, "")
            text = str(value) if value is not None else ""
            if text.startswith(("=", "+", "-", "@")):
                text = "'" + text
            safe[field] = text
        writer.writerow(safe)
    return buffer.getvalue().encode("utf-8")


def _write_new(path: Path, payload: bytes) -> str:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("exclusive new-write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise OSError("written output is not a regular non-symlink")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise OSError("written output mode differs from 0600")
    readback, _ = _read_output_no_follow(path)
    expected = hashlib.sha256(payload).hexdigest()
    if hashlib.sha256(readback).hexdigest() != expected:
        raise OSError("written output read-back hash mismatch")
    return expected


def _read_output_no_follow(path: Path) -> tuple[bytes, int]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("output read-back is not regular")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), int(info.st_size)
    finally:
        os.close(descriptor)


def _safe_failure_code(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str) and _SAFE_CODE_RE.fullmatch(value):
        return value
    return "UNSAFE_OR_UNREGISTERED_FAILURE_CODE"


def _binomial_cdf(k: int, n: int, probability: Decimal) -> Decimal:
    if k < 0:
        return Decimal(0)
    if k >= n:
        return Decimal(1)
    one = Decimal(1)
    q = one - probability
    total = Decimal(0)
    for value in range(k + 1):
        total += (
            Decimal(math.comb(n, value))
            * (probability**value)
            * (q ** (n - value))
        )
    return total


def _cp_root(k: int, n: int, target: Decimal) -> Decimal:
    low = Decimal(0)
    high = Decimal(1)
    for _ in range(320):
        middle = (low + high) / Decimal(2)
        if _binomial_cdf(k, n, middle) > target:
            low = middle
        else:
            high = middle
    return (low + high) / Decimal(2)


def _cp_upper(k: int, n: int, alpha: Decimal) -> Decimal:
    if not 0 <= k <= n or n < 1:
        raise ValueError("invalid exact-binomial arguments")
    if k == n:
        return Decimal(1)
    return _cp_root(k, n, alpha)


def _cp_lower(k: int, n: int, alpha: Decimal) -> Decimal:
    if not 0 <= k <= n or n < 1:
        raise ValueError("invalid exact-binomial arguments")
    if k == 0:
        return Decimal(0)
    return _cp_root(k - 1, n, Decimal(1) - alpha)


def _cp_two_sided(k: int, n: int, alpha: Decimal) -> tuple[Decimal, Decimal]:
    return _cp_lower(k, n, alpha / Decimal(2)), _cp_upper(
        k, n, alpha / Decimal(2)
    )


def _decimal_text(value: Decimal | None) -> str:
    return "" if value is None else format(+value, "f")


def _reported_decimal(value: Any) -> Decimal | None:
    if not _is_number(value):
        return None
    return Decimal(str(value))


def _compare_decimal(
    reported: Any,
    recomputed: Decimal,
    issues: AuditIssues,
    endpoint: str,
    code: str,
) -> str:
    parsed = _reported_decimal(reported)
    if parsed is None:
        issues.add(code, endpoint)
        return ""
    difference = abs(parsed - recomputed)
    if difference > Decimal("1e-12"):
        issues.add(code, endpoint)
    return _decimal_text(difference)


def _require_dict(value: Any, issues: AuditIssues, endpoint: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        issues.add(code, endpoint)
        return {}
    return value


def _require_list(value: Any, issues: AuditIssues, endpoint: str, code: str) -> list[Any]:
    if not isinstance(value, list):
        issues.add(code, endpoint)
        return []
    return value


def _base_endpoint_check(
    result: dict[str, Any], endpoint: str, issues: AuditIssues
) -> tuple[list[Any], list[Any], list[Any]]:
    required = (
        "sub_id",
        "status",
        "numerator",
        "denominator",
        "block_records",
        "fidelity_records",
        "failure_ledger",
    )
    for field in required:
        if field not in result:
            issues.add(f"MISSING_REQUIRED_FIELD_{field.upper()}", endpoint)
    if result.get("sub_id") != endpoint:
        issues.add("ENDPOINT_SUB_ID_MISMATCH", endpoint)
    blocks = _require_list(
        result.get("block_records"), issues, endpoint, "BLOCK_RECORDS_NOT_ARRAY"
    )
    fidelities = _require_list(
        result.get("fidelity_records"), issues, endpoint, "FIDELITY_RECORDS_NOT_ARRAY"
    )
    failures = _require_list(
        result.get("failure_ledger"), issues, endpoint, "FAILURE_LEDGER_NOT_ARRAY"
    )
    if len(blocks) != _EXPECTED_BLOCKS[endpoint]:
        issues.add("BLOCK_COUNT_MISMATCH", endpoint)
    if len(fidelities) != _EXPECTED_FIDELITIES[endpoint]:
        issues.add("FIDELITY_COUNT_MISMATCH", endpoint)
    if result.get("denominator") != _EXPECTED_BLOCKS[endpoint]:
        issues.add("DENOMINATOR_MISMATCH", endpoint)
    return blocks, fidelities, failures


def _fidelity_index(
    endpoint: str,
    fidelities: list[Any],
    source_sha: str,
    issues: AuditIssues,
    fidelity_rows: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], str]:
    by_id: dict[str, dict[str, Any]] = {}
    aggregate_status = "PASS"
    for index, raw in enumerate(fidelities):
        audit_id = f"{endpoint}:FIDELITY:{index:03d}"
        row = _require_dict(raw, issues, endpoint, "FIDELITY_RECORD_NOT_OBJECT")
        block_id = row.get("block_id")
        status_value = row.get("status")
        status_text = status_value if isinstance(status_value, str) else "INVALID"
        if endpoint == "A0":
            required = {
                "status",
                "registered_source",
                "reference_source",
                "all_256_rules",
                "frozen_contract_snapshot",
            }
            structurally_complete = required <= set(row)
        else:
            required = {
                "contract_version",
                "benchmark",
                "block_id",
                "registered_tier",
                "reference_tier",
                "observable_tolerance",
                "observable_changed_beyond_tolerance",
                "decision_changed",
                "same_observation_unit_coupling",
                "further_refinement_required",
                "status",
                "frozen_contract_snapshot",
            }
            structurally_complete = required <= set(row)
            for tier_name in ("registered_tier", "reference_tier"):
                tier = row.get(tier_name)
                tier_complete = isinstance(tier, dict) and {
                    "source_path",
                    "settings",
                    "settings_sha256",
                    "observable",
                    "decision",
                } <= set(tier)
                if tier_complete and isinstance(tier, dict):
                    tier_complete = (
                        isinstance(tier.get("settings"), dict)
                        and tier.get("settings_sha256")
                        == _canonical_sha256(tier["settings"])
                    )
                if not tier_complete:
                    structurally_complete = False
            structurally_complete = (
                structurally_complete
                and row.get("benchmark") == endpoint
                and row.get("same_observation_unit_coupling") is True
            )
        snapshot = row.get("frozen_contract_snapshot")
        if not isinstance(snapshot, dict) or not {
            "contract_sha256",
            "registered_source",
            "reference_source",
            "protected_observables",
            "tolerances",
            "time_range",
            "initial_state_or_environment_distribution",
            "decision_invariance_required",
            "distribution_version",
        } <= set(snapshot):
            structurally_complete = False
        if status_text == "PASS" and endpoint != "A0":
            structurally_complete = (
                structurally_complete
                and row.get("observable_changed_beyond_tolerance") is False
                and row.get("decision_changed") is False
                and row.get("further_refinement_required") is False
            )
        if not structurally_complete:
            issues.add("FIDELITY_RECORD_INCOMPLETE_OR_INCONSISTENT", endpoint, audit_id)
        if status_text != "PASS":
            aggregate_status = status_text
        if isinstance(block_id, str):
            if block_id in by_id:
                issues.add("DUPLICATE_FIDELITY_BLOCK_ID", endpoint, block_id)
            by_id[block_id] = row
            audit_id = block_id
        fidelity_rows.append(
            {
                "endpoint": endpoint,
                "audit_row_id": audit_id,
                "source_block_id": block_id if isinstance(block_id, str) else "",
                "fidelity_index": index,
                "status": status_text,
                "decision_changed": row.get("decision_changed", ""),
                "observable_changed_beyond_tolerance": row.get(
                    "observable_changed_beyond_tolerance", ""
                ),
                "further_refinement_required": row.get(
                    "further_refinement_required", ""
                ),
                "source_result_sha256": source_sha,
            }
        )
    if endpoint in _BLOCK_ID_ENDPOINTS:
        expected = [f"{endpoint}:{index:03d}" for index in range(_EXPECTED_BLOCKS[endpoint])]
        actual = [
            row.get("block_id") if isinstance(row, dict) else None
            for row in fidelities
        ]
        if actual != expected:
            issues.add("FIDELITY_BLOCK_ID_SEQUENCE_MISMATCH", endpoint)
    return by_id, aggregate_status


def _record_failure_ledger(
    endpoint: str,
    failures: list[Any],
    source_sha: str,
    issues: AuditIssues,
    failure_rows: list[dict[str, Any]],
) -> None:
    for index, raw in enumerate(failures):
        row = _require_dict(raw, issues, endpoint, "FAILURE_LEDGER_ROW_NOT_OBJECT")
        code = _safe_failure_code(row.get("failure_code"))
        if code == "UNSAFE_OR_UNREGISTERED_FAILURE_CODE":
            issues.add("UNSAFE_OR_UNREGISTERED_FAILURE_CODE", endpoint)
        block_id = row.get("block_id") if isinstance(row.get("block_id"), str) else ""
        failure_rows.append(
            {
                "endpoint": endpoint,
                "audit_row_id": block_id or f"{endpoint}:FAILURE:{index:03d}",
                "source": "REPORTED_FAILURE_LEDGER",
                "failure_code": code,
                "counts_as_adverse": True,
                "source_result_sha256": source_sha,
            }
        )


def _validate_per_block_failure_ledger(
    endpoint: str,
    blocks: list[Any],
    failures: list[Any],
    issues: AuditIssues,
) -> None:
    expected: list[tuple[str, str]] = []
    for index, raw in enumerate(blocks):
        if not isinstance(raw, dict) or raw.get("failure_code") is None:
            continue
        block_id = f"{endpoint}:{index:03d}"
        code = _safe_failure_code(raw.get("failure_code"))
        if raw.get("block_id") != block_id or not code:
            issues.add("BLOCK_FAILURE_ID_OR_CODE_INVALID", endpoint, block_id)
        expected.append((block_id, code))
    reported: list[tuple[str, str]] = []
    for index, raw in enumerate(failures):
        if not isinstance(raw, dict):
            issues.add("FAILURE_LEDGER_ROW_NOT_OBJECT", endpoint, f"FAILURE:{index:03d}")
            continue
        block_id = raw.get("block_id")
        code = _safe_failure_code(raw.get("failure_code"))
        if not isinstance(block_id, str) or not code:
            issues.add("FAILURE_LEDGER_ID_OR_CODE_INVALID", endpoint, f"FAILURE:{index:03d}")
            continue
        reported.append((block_id, code))
    if reported != expected:
        issues.add("FAILURE_LEDGER_BLOCK_CROSSCHECK_MISMATCH", endpoint)


def _candidate_keys() -> set[str]:
    return {f"eca:{candidate:03d}" for candidate in range(256)}


def _failure_present(block: dict[str, Any]) -> tuple[bool, str]:
    code = _safe_failure_code(block.get("failure_code"))
    return block.get("failure_code") is not None, code


def _append_block_row(
    *,
    endpoint: str,
    index: int,
    block: dict[str, Any],
    fidelity: dict[str, Any] | None,
    primitive_event: bool,
    adverse: bool,
    structural_ok: bool,
    source_sha: str,
    block_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> None:
    source_id = block.get("block_id") if isinstance(block.get("block_id"), str) else ""
    audit_id = source_id or f"{endpoint}:AUDIT:{index:03d}"
    failure_present, failure_code = _failure_present(block)
    fidelity_status = (
        fidelity.get("status", "INVALID") if isinstance(fidelity, dict) else "MISSING"
    )
    block_rows.append(
        {
            "endpoint": endpoint,
            "audit_row_id": audit_id,
            "source_block_id": source_id,
            "block_index": index,
            "fidelity_status": fidelity_status,
            "primitive_event": primitive_event,
            "failure_code_present": failure_present,
            "recomputed_adverse": adverse,
            "structural_status": "PASS" if structural_ok else BLOCKING,
            "source_result_sha256": source_sha,
        }
    )
    if adverse:
        failure_rows.append(
            {
                "endpoint": endpoint,
                "audit_row_id": audit_id,
                "source": "RECOMPUTED_BLOCK_ADVERSE",
                "failure_code": failure_code or "RECOMPUTED_ADVERSE_EVENT",
                "counts_as_adverse": True,
                "source_result_sha256": source_sha,
            }
        )


def _compare_common_result(
    result: dict[str, Any],
    endpoint: str,
    numerator: int,
    expected_status: str,
    issues: AuditIssues,
) -> None:
    if result.get("numerator") != numerator:
        issues.add("REPORTED_NUMERATOR_MISMATCH", endpoint)
    if result.get("status") != expected_status:
        issues.add("REPORTED_STATUS_MISMATCH", endpoint)


def _cp_audit_row(
    *,
    endpoint: str,
    events: int,
    trials: int,
    result: dict[str, Any],
    issues: AuditIssues,
    source_sha: str,
) -> dict[str, Any]:
    alpha = Decimal("0.05")
    with localcontext() as context:
        context.prec = 90
        upper = _cp_upper(events, trials, alpha)
        lower, two_upper = _cp_two_sided(events, trials, alpha)
    upper_difference = _compare_decimal(
        result.get("exact_one_sided_95_upper"),
        upper,
        issues,
        endpoint,
        "CP_ONE_SIDED_UPPER_MISMATCH",
    )
    reported_interval = result.get("exact_two_sided_95_interval")
    lower_difference = ""
    two_upper_difference = ""
    if not isinstance(reported_interval, list) or len(reported_interval) != 2:
        issues.add("CP_TWO_SIDED_INTERVAL_MISSING", endpoint)
    else:
        lower_difference = _compare_decimal(
            reported_interval[0],
            lower,
            issues,
            endpoint,
            "CP_TWO_SIDED_LOWER_MISMATCH",
        )
        two_upper_difference = _compare_decimal(
            reported_interval[1],
            two_upper,
            issues,
            endpoint,
            "CP_TWO_SIDED_UPPER_MISMATCH",
        )
    decision = "CRITERION_MET" if upper <= Decimal("0.05") else "CRITERION_NOT_MET"
    return {
        "endpoint": endpoint,
        "event_semantics": "ADVERSE_BLOCK",
        "events": events,
        "trials": trials,
        "one_sided_alpha_name": "endpoint_alpha",
        "one_sided_alpha": "0.05",
        "one_sided_lower": "",
        "one_sided_upper": _decimal_text(upper),
        "two_sided_alpha_name": "endpoint_alpha",
        "two_sided_alpha": "0.05",
        "two_sided_lower": _decimal_text(lower),
        "two_sided_upper": _decimal_text(two_upper),
        "threshold": "0.05",
        "decision": decision,
        "reported_upper_absolute_difference": upper_difference,
        "reported_lower_absolute_difference": lower_difference,
        "reported_two_upper_absolute_difference": two_upper_difference,
        "source_result_sha256": source_sha,
    }


def _audit_a0(
    result: dict[str, Any],
    source_sha: str,
    issues: AuditIssues,
    block_rows: list[dict[str, Any]],
    fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, "A0", issues)
    _, fidelity_status = _fidelity_index(
        "A0", fidelities, source_sha, issues, fidelity_rows
    )
    mismatch_pattern = re.compile(
        r"^(?:truth-table:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-7]"
        r"|simulator:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):"
        r"(?:periodic|fixed_zero|fixed_one|reflect))$"
    )
    for index, failure in enumerate(failures):
        if not isinstance(failure, str) or not mismatch_pattern.fullmatch(failure):
            issues.add("A0_FAILURE_LEDGER_ROW_INVALID", "A0", f"A0:FAILURE:{index:03d}")
        failure_rows.append(
            {
                "endpoint": "A0",
                "audit_row_id": f"A0:FAILURE:{index:03d}",
                "source": "REPORTED_A0_MISMATCH_LEDGER",
                "failure_code": "A0_REFERENCE_PRODUCTION_MISMATCH",
                "counts_as_adverse": True,
                "source_result_sha256": source_sha,
            }
        )
    block_adverse = 0
    seen_rules: list[int] = []
    seen_candidates: set[str] = set()
    signatures: list[str] = []
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, "A0", "BLOCK_RECORD_NOT_OBJECT")
        rule_id = block.get("rule_id")
        candidate_id = block.get("candidate_id")
        structural_ok = _is_int(rule_id) and 0 <= rule_id <= 255
        if structural_ok:
            seen_rules.append(int(rule_id))
        if isinstance(candidate_id, str):
            seen_candidates.add(candidate_id)
        expected_candidate = f"eca:{int(rule_id):03d}" if structural_ok else ""
        truth = block.get("truth_table_000_to_111")
        expected_truth = (
            [(int(rule_id) >> code) & 1 for code in range(8)] if structural_ok else []
        )
        structural_ok = (
            structural_ok
            and candidate_id == expected_candidate
            and truth == expected_truth
            and block.get("execution_status") == "EXECUTED"
        )
        signature = block.get("canonical_signature")
        if not isinstance(signature, str) or not _HASH_RE.fullmatch(signature):
            structural_ok = False
        else:
            signatures.append(signature)
        failure_present, _ = _failure_present(block)
        event = failure_present or not structural_ok
        block_adverse += int(event)
        if not structural_ok:
            issues.add("A0_BLOCK_TRUTH_OR_IDENTITY_MISMATCH", "A0", expected_candidate)
        _append_block_row(
            endpoint="A0",
            index=index,
            block=block,
            fidelity=fidelities[0] if fidelities and isinstance(fidelities[0], dict) else None,
            primitive_event=event,
            adverse=event,
            structural_ok=structural_ok,
            source_sha=source_sha,
            block_rows=block_rows,
            failure_rows=failure_rows,
        )
    if seen_rules != list(range(256)) or len(seen_candidates) != 256:
        issues.add("A0_EXACT_256_RULE_COVERAGE_MISMATCH", "A0")
    if block_adverse:
        issues.add("A0_BLOCK_LEDGER_STRUCTURAL_FAILURE", "A0")
    if result.get("candidate_ledger") != blocks:
        issues.add("A0_CANDIDATE_AND_BLOCK_LEDGER_MISMATCH", "A0")
    if result.get("terminal_candidate_ledger_count") != 256:
        issues.add("A0_TERMINAL_LEDGER_COUNT_MISMATCH", "A0")
    if result.get("canonical_signature_count") != len(set(signatures)):
        issues.add("A0_CANONICAL_SIGNATURE_COUNT_MISMATCH", "A0")
    expected_match = not failures
    if result.get("independent_reference_production_match") is not expected_match:
        issues.add("A0_INDEPENDENT_SIMULATOR_CONCLUSION_MISMATCH", "A0")
    if (fidelity_status == "PASS") is not expected_match:
        issues.add("A0_FIDELITY_AND_FAILURE_LEDGER_MISMATCH", "A0")
    adverse = len(failures)
    expected_status = "PASS" if adverse == 0 else "FAIL"
    _compare_common_result(result, "A0", adverse, expected_status, issues)
    return adverse, expected_status


def _audit_a1(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]], a0_signatures: dict[int, str],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, "A1", issues)
    by_fidelity, _ = _fidelity_index("A1", fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger("A1", failures, source_sha, issues, failure_rows)
    expected_keys = _candidate_keys()
    adverse_count = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, "A1", "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"A1:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        losses = block.get("candidate_losses")
        structural_ok = isinstance(losses, dict) and set(losses) == expected_keys
        retained = sorted(
            candidate
            for candidate, loss in losses.items()
            if _is_number(loss) and float(loss) <= 0.0
        ) if isinstance(losses, dict) else []
        if retained != block.get("retained_candidates"):
            structural_ok = False
        truth_rule = block.get("truth_rule_generator_only")
        truth_candidate = (
            f"eca:{int(truth_rule):03d}"
            if _is_int(truth_rule) and 0 <= int(truth_rule) <= 255
            else ""
        )
        truth_retained = bool(truth_candidate and truth_candidate in retained)
        expected_truth_signature = (
            a0_signatures.get(int(truth_rule)) if truth_candidate else None
        )
        expected_retained_signatures = sorted(
            {
                a0_signatures[int(candidate.split(":")[1])]
                for candidate in retained
                if int(candidate.split(":")[1]) in a0_signatures
            }
        )
        truth_class_retained = bool(
            expected_truth_signature
            and expected_truth_signature in expected_retained_signatures
        )
        structural_ok = (
            structural_ok
            and block.get("block_id") == block_id
            and block.get("candidate_count") == 256
            and block.get("candidate_ledger_complete") is True
            and block.get("signature_ledger_complete") is True
            and block.get("truth_candidate_retained") is truth_retained
            and block.get("truth_signature_class") == expected_truth_signature
            and block.get("retained_signature_classes")
            == expected_retained_signatures
            and block.get("truth_class_retained") is truth_class_retained
            and fidelity is not None
        )
        failure_present, _ = _failure_present(block)
        fidelity_bad = not isinstance(fidelity, dict) or fidelity.get("status") != "PASS"
        event = (
            not structural_ok
            or not truth_retained
            or not truth_class_retained
            or fidelity_bad
            or failure_present
        )
        if block.get("failure_event") is not event:
            issues.add("A1_FAILURE_EVENT_FIELD_MISMATCH", "A1", block_id)
        if not structural_ok:
            issues.add("A1_LEDGER_OR_RETENTION_STRUCTURE_MISMATCH", "A1", block_id)
        adverse_count += int(event)
        _append_block_row(
            endpoint="A1", index=index, block=block, fidelity=fidelity,
            primitive_event=not truth_retained or not truth_class_retained,
            adverse=event, structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    _validate_per_block_failure_ledger("A1", blocks, failures, issues)
    status = "PASS" if adverse_count == 0 else "FAIL"
    _compare_common_result(result, "A1", adverse_count, status, issues)
    return adverse_count, status


def _decision_from_bounds(block: dict[str, Any], threshold: float) -> tuple[str, bool]:
    bounds = block.get("candidate_exact_lower_bounds")
    complete = (
        isinstance(bounds, dict)
        and set(bounds) == _candidate_keys()
        and block.get("candidate_count") == 256
        and block.get("alpha_ledger_complete") is True
        and all(_is_number(value) for value in bounds.values())
    )
    if not complete:
        return "INDETERMINATE", False
    minimum = min(float(value) for value in bounds.values())
    return ("MODEL_CLASS_INADEQUATE" if minimum > threshold else "RETAIN_CLASS"), True


def _audit_b(
    endpoint: str, result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, endpoint, issues)
    by_fidelity, _ = _fidelity_index(endpoint, fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger(endpoint, failures, source_sha, issues, failure_rows)
    adverse_count = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, endpoint, "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"{endpoint}:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        decision, complete = _decision_from_bounds(block, 0.2)
        bounds = block.get("candidate_exact_lower_bounds")
        class_bounds = block.get("class_lower_bounds")
        class_bounds_complete = (
            isinstance(bounds, dict)
            and isinstance(class_bounds, dict)
            and set(class_bounds)
            == {f"class:{candidate:03d}" for candidate in range(256)}
            and all(
                _is_number(class_bounds.get(candidate.replace("eca:", "class:")))
                and _is_number(value)
                and float(class_bounds[candidate.replace("eca:", "class:")])
                == float(value)
                for candidate, value in bounds.items()
            )
        )
        if not class_bounds_complete:
            issues.add("CLASS_LEVEL_BOUND_LEDGER_MISMATCH", endpoint, block_id)
        if block.get("decision") != decision:
            issues.add("RECORDED_CLASS_DECISION_MISMATCH", endpoint, block_id)
        structural_ok = (
            complete
            and class_bounds_complete
            and fidelity is not None
            and block.get("block_id") == block_id
        )
        if endpoint == "B1" and block.get(
            "distinguishable_from_every_radius_one_rule"
        ) is not True:
            structural_ok = False
        failure_present, _ = _failure_present(block)
        fidelity_bad = not isinstance(fidelity, dict) or fidelity.get("status") != "PASS"
        if endpoint == "B0":
            primitive = decision in {"MODEL_CLASS_INADEQUATE", "INDETERMINATE"}
        else:
            primitive = decision != "MODEL_CLASS_INADEQUATE"
        event = not structural_ok or primitive or fidelity_bad or failure_present
        if block.get("failure_event") is not event:
            issues.add("FAILURE_EVENT_FIELD_MISMATCH", endpoint, block_id)
        adverse_count += int(event)
        _append_block_row(
            endpoint=endpoint, index=index, block=block, fidelity=fidelity,
            primitive_event=primitive, adverse=event, structural_ok=structural_ok,
            source_sha=source_sha, block_rows=block_rows, failure_rows=failure_rows,
        )
    _validate_per_block_failure_ledger(endpoint, blocks, failures, issues)
    status = "PASS" if adverse_count == 0 else "FAIL"
    _compare_common_result(result, endpoint, adverse_count, status, issues)
    return adverse_count, status


def _audit_c(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, "C", issues)
    _, fidelity_status = _fidelity_index("C", fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger("C", failures, source_sha, issues, failure_rows)
    adverse_count = 0
    domain_exits = 0
    point_violations = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, "C", "BLOCK_RECORD_NOT_OBJECT")
        path = block.get("path") if isinstance(block.get("path"), list) else []
        structural_ok = bool(path) and block.get("clipping_applied") is False
        path_violation = False
        point_exit = False
        for point in path:
            if not isinstance(point, dict):
                structural_ok = False
                continue
            reference = point.get("reference")
            candidate = point.get("candidate")
            bound = point.get("bound")
            if not all(_is_number(value) for value in (reference, candidate, bound)):
                structural_ok = False
                continue
            computed_violation = abs(float(reference) - float(candidate)) > float(bound) + 1e-12
            computed_exit = not (
                -2.0 <= float(reference) <= 2.0 and -2.0 <= float(candidate) <= 2.0
            )
            if point.get("violation") is not computed_violation:
                structural_ok = False
            if point.get("domain_exit") is not computed_exit:
                structural_ok = False
            path_violation = path_violation or computed_violation
            point_violations += int(computed_violation)
            point_exit = point_exit or computed_exit
        if block.get("domain_exit") is not point_exit:
            structural_ok = False
        domain_exits += int(point_exit)
        event = path_violation or point_exit or fidelity_status != "PASS" or not structural_ok
        adverse_count += int(event)
        if not structural_ok:
            issues.add("C_PATH_RECORD_RECOMPUTATION_MISMATCH", "C", f"C:AUDIT:{index:03d}")
        _append_block_row(
            endpoint="C", index=index, block=block,
            fidelity=fidelities[0] if fidelities and isinstance(fidelities[0], dict) else None,
            primitive_event=path_violation or point_exit, adverse=event,
            structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    if fidelity_status != "PASS":
        adverse_count = 9
        status = "FIDELITY_INDETERMINATE"
    elif domain_exits:
        status = "DOMAIN_EXIT_WITHDRAWAL"
    elif adverse_count:
        status = "FAIL"
    else:
        status = "PASS"
    if result.get("domain_exit_count") != domain_exits:
        issues.add("C_DOMAIN_EXIT_COUNT_MISMATCH", "C")
    if result.get("pathwise_bound_violations") != point_violations:
        issues.add("C_PATHWISE_VIOLATION_COUNT_MISMATCH", "C")
    if result.get("clipping_applied") is not False:
        issues.add("C_CLIPPING_CONTRACT_MISMATCH", "C")
    _compare_common_result(result, "C", adverse_count, status, issues)
    return adverse_count, status


def _audit_d0(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, "D0", issues)
    by_fidelity, _ = _fidelity_index("D0", fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger("D0", failures, source_sha, issues, failure_rows)
    adverse_count = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, "D0", "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"D0:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        structural_ok = (
            block.get("block_id") == block_id
            and
            block.get("reported_rule_id") == 204
            and block.get("executed_rule_id") == 204
            and fidelity is not None
        )
        failure_present, _ = _failure_present(block)
        event = (
            block.get("full_microstate_identity") is not True
            or not isinstance(fidelity, dict)
            or fidelity.get("status") != "PASS"
            or failure_present
            or not structural_ok
        )
        adverse_count += int(event)
        _append_block_row(
            endpoint="D0", index=index, block=block, fidelity=fidelity,
            primitive_event=block.get("full_microstate_identity") is not True,
            adverse=event, structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    _validate_per_block_failure_ledger("D0", blocks, failures, issues)
    status = "PASS" if adverse_count == 0 else "FAIL"
    _compare_common_result(result, "D0", adverse_count, status, issues)
    return adverse_count, status


def _rule90_next_density(state: list[int]) -> float:
    following: list[int] = []
    for index in range(len(state)):
        left = state[(index - 1) % len(state)]
        center = state[index]
        right = state[(index + 1) % len(state)]
        code = (left << 2) | (center << 1) | right
        following.append((90 >> code) & 1)
    return sum(following) / len(following)


def _audit_d1(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    blocks, fidelities, failures = _base_endpoint_check(result, "D1", issues)
    _, fidelity_status = _fidelity_index("D1", fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger("D1", failures, source_sha, issues, failure_rows)
    block = _require_dict(blocks[0] if blocks else {}, issues, "D1", "BLOCK_RECORD_NOT_OBJECT")
    pair = block.get("microstate_pair")
    next_density = block.get("next_density")
    structural_ok = (
        isinstance(pair, list)
        and len(pair) == 2
        and all(isinstance(state, list) and state for state in pair)
        and all(
            _is_int(cell) and cell in (0, 1)
            for state in pair
            for cell in state
        )
        and isinstance(next_density, list)
        and len(next_density) == 2
        and all(_is_number(value) for value in next_density)
        and result.get("reported_rule_id") == 90
        and result.get("executed_rule_id") == 90
    )
    witness = False
    if structural_ok:
        densities = [sum(int(cell) for cell in state) / len(state) for state in pair]
        recomputed_next = [_rule90_next_density(state) for state in pair]
        structural_ok = (
            pair == [[1, 1, 0, 0], [1, 0, 1, 0]]
            and result.get("reported_rule_id") == 90
            and result.get("executed_rule_id") == 90
            and block.get("shared_density") == densities
            and all(
                abs(float(reported) - recomputed) <= 1e-12
                for reported, recomputed in zip(next_density, recomputed_next, strict=True)
            )
        )
        witness = (
            structural_ok
            and densities[0] == densities[1]
            and recomputed_next[0] != recomputed_next[1]
        )
    event = not witness or fidelity_status != "PASS" or not structural_ok
    _append_block_row(
        endpoint="D1", index=0, block=block,
        fidelity=fidelities[0] if fidelities and isinstance(fidelities[0], dict) else None,
        primitive_event=not witness, adverse=event, structural_ok=structural_ok,
        source_sha=source_sha, block_rows=block_rows, failure_rows=failure_rows,
    )
    numerator = int(event)
    status = "PASS" if numerator == 0 else "FAIL"
    if result.get("nonclosure_witness") is not witness:
        issues.add("D1_WITNESS_FIELD_MISMATCH", "D1")
    expected_failures = [] if status == "PASS" else [{"failure_code": "WITNESS_FAILURE"}]
    if failures != expected_failures:
        issues.add("D1_FAILURE_LEDGER_MISMATCH", "D1")
    _compare_common_result(result, "D1", numerator, status, issues)
    return numerator, status


def _audit_d2_cert(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]], cp_rows: list[dict[str, Any]],
) -> tuple[int, str, dict[str, Any]]:
    endpoint = "D2-CERT"
    blocks, fidelities, failures = _base_endpoint_check(result, endpoint, issues)
    by_fidelity, _ = _fidelity_index(endpoint, fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger(endpoint, failures, source_sha, issues, failure_rows)
    violations = 0
    adverse_count = 0
    fidelity_adverse = False
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, endpoint, "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"D2-CERT:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        discrepancy = block.get("maximum_density_discrepancy")
        structural_ok = (
            _is_number(discrepancy)
            and float(discrepancy) >= 0.0
            and block.get("block_id") == block_id
            and block.get("reported_rule_id") == 170
            and block.get("executed_rule_id") == 170
            and fidelity is not None
        )
        violation = bool(structural_ok and float(discrepancy) > 0.0)
        if block.get("violation") is not violation:
            structural_ok = False
            issues.add("D2_VIOLATION_FIELD_MISMATCH", endpoint, block_id)
        fidelity_bad = not isinstance(fidelity, dict) or fidelity.get("status") != "PASS"
        fidelity_adverse = fidelity_adverse or fidelity_bad
        failure_present, _ = _failure_present(block)
        adverse = violation or fidelity_bad or failure_present or not structural_ok
        violations += int(violation)
        adverse_count += int(adverse)
        _append_block_row(
            endpoint=endpoint, index=index, block=block, fidelity=fidelity,
            primitive_event=violation, adverse=adverse, structural_ok=structural_ok,
            source_sha=source_sha, block_rows=block_rows, failure_rows=failure_rows,
        )
    _validate_per_block_failure_ledger(endpoint, blocks, failures, issues)
    if result.get("violation_count") != violations:
        issues.add("D2_REPORTED_VIOLATION_COUNT_MISMATCH", endpoint)
    beta = Decimal("0.05")
    gamma = Decimal("0.05")
    delta = Decimal("0.05")
    if _reported_decimal(result.get("calibration_beta")) != beta:
        issues.add("D2_CALIBRATION_BETA_MISMATCH", endpoint)
    if _reported_decimal(result.get("locked_gamma")) != gamma:
        issues.add("D2_LOCKED_GAMMA_MISMATCH", endpoint)
    if _reported_decimal(result.get("delta")) != delta:
        issues.add("D2_DELTA_MISMATCH", endpoint)
    with localcontext() as context:
        context.prec = 90
        upper = _cp_upper(violations, 64, beta)
        lower = _cp_lower(violations, 64, gamma)
        two_lower, two_upper = _cp_two_sided(violations, 64, gamma)
    upper_difference = _compare_decimal(
        result.get("exact_one_sided_upper"), upper, issues, endpoint,
        "D2_ONE_SIDED_UPPER_MISMATCH",
    )
    lower_difference = _compare_decimal(
        result.get("exact_one_sided_lower"), lower, issues, endpoint,
        "D2_ONE_SIDED_LOWER_MISMATCH",
    )
    interval = result.get("exact_two_sided_interval")
    two_upper_difference = ""
    if not isinstance(interval, list) or len(interval) != 2:
        issues.add("D2_TWO_SIDED_INTERVAL_MISSING", endpoint)
    else:
        _compare_decimal(
            interval[0], two_lower, issues, endpoint, "D2_TWO_SIDED_LOWER_MISMATCH"
        )
        two_upper_difference = _compare_decimal(
            interval[1], two_upper, issues, endpoint, "D2_TWO_SIDED_UPPER_MISMATCH"
        )
    complete = len(blocks) == 64 and len(fidelities) == 64
    if fidelity_adverse:
        status = "FIDELITY_INDETERMINATE"
    elif complete:
        status = (
            "LOCKED_AUDIT_WITHDRAWAL_TRIGGERED"
            if lower > delta
            else "NOT_CONTRADICTED_BY_LOCKED_AUDIT"
        )
    else:
        status = "INDETERMINATE"
    if result.get("certificate_granted") is not False:
        issues.add("D2_LOCKED_RESULT_MUST_NOT_GRANT_CERTIFICATE", endpoint)
    for field, expected in (
        ("certificate_reviewed", True),
        ("calibration_certificate_verified", True),
        ("calibration_executed", False),
        ("locked_audit_executed", True),
    ):
        if result.get(field) is not expected:
            issues.add(f"D2_{field.upper()}_MISMATCH", endpoint)
    _compare_common_result(result, endpoint, adverse_count, status, issues)
    cp_row = {
        "endpoint": endpoint,
        "event_semantics": "VIOLATION_ONLY_FOR_CP;ADVERSE_BLOCK_FOR_NUMERATOR",
        "events": violations,
        "trials": 64,
        "one_sided_alpha_name": "calibration_beta_for_upper;locked_gamma_for_lower",
        "one_sided_alpha": "0.05",
        "one_sided_lower": _decimal_text(lower),
        "one_sided_upper": _decimal_text(upper),
        "two_sided_alpha_name": "locked_gamma",
        "two_sided_alpha": "0.05",
        "two_sided_lower": _decimal_text(two_lower),
        "two_sided_upper": _decimal_text(two_upper),
        "threshold": "0.05",
        "decision": status,
        "reported_upper_absolute_difference": upper_difference,
        "reported_lower_absolute_difference": lower_difference,
        "reported_two_upper_absolute_difference": two_upper_difference,
        "source_result_sha256": source_sha,
    }
    cp_rows.append(cp_row)
    details = {
        "record_type": "LOCKED_D2_CERT_READONLY_RECOMPUTATION_V2_4",
        "source_result_sha256": source_sha,
        "trials": 64,
        "recomputed_violation_count": violations,
        "recomputed_adverse_count": adverse_count,
        "calibration_beta": "0.05",
        "locked_gamma": "0.05",
        "delta": "0.05",
        "exact_one_sided_upper": _decimal_text(upper),
        "exact_one_sided_lower": _decimal_text(lower),
        "exact_two_sided_interval": [
            _decimal_text(two_lower),
            _decimal_text(two_upper),
        ],
        "withdrawal_comparison": "exact_one_sided_lower > delta",
        "recomputed_status": status,
        "fidelity_adverse": fidelity_adverse,
        "block_and_fidelity_count_complete": complete,
        "benchmark_engine_called": False,
        "raw_role_files_opened": False,
    }
    return adverse_count, status, details


def _audit_d2_mem(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    endpoint = "D2-MEM"
    blocks, fidelities, failures = _base_endpoint_check(result, endpoint, issues)
    _, fidelity_status = _fidelity_index(endpoint, fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger(endpoint, failures, source_sha, issues, failure_rows)
    mapping: dict[int, set[int]] = {0: set(), 1: set()}
    pairs: set[tuple[int, int]] = set()
    lag1_exact = True
    parsed_blocks: list[dict[str, Any]] = []
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, endpoint, "BLOCK_RECORD_NOT_OBJECT")
        parsed_blocks.append(block)
        initial = block.get("initial_microstate")
        sequence = block.get("coarse_sequence")
        structural_ok = (
            isinstance(initial, list)
            and len(initial) == 2
            and all(value in (0, 1) and _is_int(value) for value in initial)
            and isinstance(sequence, list)
            and len(sequence) == 4
            and all(value in (0, 1) and _is_int(value) for value in sequence)
        )
        if structural_ok:
            pair = (int(initial[0]), int(initial[1]))
            pairs.add(pair)
            mapping[int(sequence[0])].add(int(sequence[1]))
            lag1_exact = lag1_exact and int(sequence[2]) == int(sequence[0])
        else:
            issues.add("D2_MEM_BLOCK_STRUCTURE_MISMATCH", endpoint, f"D2-MEM:{index:03d}")
            lag1_exact = False
        _append_block_row(
            endpoint=endpoint, index=index, block=block,
            fidelity=fidelities[0] if fidelities and isinstance(fidelities[0], dict) else None,
            primitive_event=not structural_ok or (
                structural_ok and int(sequence[2]) != int(sequence[0])
            ),
            adverse=not structural_ok or (
                structural_ok and int(sequence[2]) != int(sequence[0])
            ),
            structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    lag0_fails = any(len(outputs) > 1 for outputs in mapping.values())
    complete = pairs == {(0, 0), (0, 1), (1, 0), (1, 1)}
    endpoint_failure = not (complete and lag0_fails and lag1_exact and fidelity_status == "PASS")
    numerator = int(endpoint_failure)
    status = "PASS" if numerator == 0 else "FAIL"
    if result.get("lag0_fails") is not lag0_fails:
        issues.add("D2_MEM_LAG0_FIELD_MISMATCH", endpoint)
    if result.get("lag1_exact_repair") is not lag1_exact:
        issues.add("D2_MEM_LAG1_FIELD_MISMATCH", endpoint)
    _compare_common_result(result, endpoint, numerator, status, issues)
    return numerator, status


def _audit_e(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]], policy_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    endpoint = "E"
    blocks, fidelities, failures = _base_endpoint_check(result, endpoint, issues)
    by_fidelity, _ = _fidelity_index(endpoint, fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger(endpoint, failures, source_sha, issues, failure_rows)
    totals = {policy: 0 for policy in _POLICIES}
    block_failures = {policy: 0 for policy in _POLICIES}
    adverse_blocks = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, endpoint, "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"E:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        policies = block.get("policy_results")
        structural_ok = (
            isinstance(policies, dict)
            and set(policies) == set(_POLICIES)
            and block.get("block_id") == block_id
            and block.get("support_is_complete_truth_table") is True
        )
        exhaustive = policies.get("exhaustive", {}) if isinstance(policies, dict) else {}
        common = structural_ok
        hidden = False
        if structural_ok:
            for policy in _POLICIES:
                row = policies.get(policy)
                if not isinstance(row, dict):
                    structural_ok = False
                    common = False
                    continue
                ledger = row.get("cost_ledger")
                if not isinstance(ledger, dict):
                    structural_ok = False
                    common = False
                    continue
                components = (
                    "ordering_units",
                    "probe_steps",
                    "candidate_block_steps",
                    "reference_refinement_steps",
                    "retry_steps",
                )
                if not all(_is_int(ledger.get(field)) for field in components):
                    structural_ok = False
                    common = False
                    continue
                unbilled = ledger.get("unbilled_loss_accesses")
                if (
                    not _is_int(unbilled)
                    or int(unbilled) < 0
                    or any(int(ledger[field]) < 0 for field in components)
                ):
                    structural_ok = False
                    common = False
                    continue
                computed_total = sum(int(ledger[field]) for field in components)
                if ledger.get("total_cost_units") != computed_total:
                    structural_ok = False
                totals[policy] += computed_total
                same = (
                    row.get("decision") == exhaustive.get("decision")
                    and row.get("best_candidate") == exhaustive.get("best_candidate")
                )
                block_failures[policy] += int(not same)
                common = common and same and row.get("fidelity_status") == "PASS"
                computed_hidden = int(unbilled) > 0
                if row.get("hidden_precomputation_detected") is not computed_hidden:
                    structural_ok = False
                hidden = hidden or computed_hidden
        if block.get("all_policies_match_exhaustive") is not common:
            structural_ok = False
        if block.get("hidden_cost_detected") is not hidden:
            structural_ok = False
        expected_failure_code = (
            "UNBILLED_LOSS_ACCESS"
            if hidden
            else ("POLICY_ESTIMAND_DISAGREEMENT" if not common else None)
        )
        if block.get("failure_code") != expected_failure_code:
            structural_ok = False
            issues.add("E_BLOCK_FAILURE_CODE_MISMATCH", endpoint, block_id)
        failure_present, _ = _failure_present(block)
        fidelity_bad = not isinstance(fidelity, dict) or fidelity.get("status") != "PASS"
        event = not structural_ok or hidden or not common or fidelity_bad or failure_present
        adverse_blocks += int(event)
        _append_block_row(
            endpoint=endpoint, index=index, block=block, fidelity=fidelity,
            primitive_event=hidden or not common, adverse=event,
            structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    aggregate = result.get("policy_results")
    aggregate_ok = isinstance(aggregate, dict) and set(aggregate) == set(_POLICIES)
    budget_exceeded = False
    if not aggregate_ok:
        issues.add("E_AGGREGATE_POLICY_SET_MISMATCH", endpoint)
        aggregate = {}
    for policy in _POLICIES:
        reported = aggregate.get(policy, {}) if isinstance(aggregate, dict) else {}
        reported_budget = reported.get("budget") if isinstance(reported, dict) else None
        computed_exceeded = totals[policy] > 300000
        budget_exceeded = budget_exceeded or computed_exceeded
        if (
            not isinstance(reported, dict)
            or reported.get("total_cost_units") != totals[policy]
            or reported.get("block_failures") != block_failures[policy]
            or reported_budget != 300000
            or reported.get("budget_exceeded") is not computed_exceeded
        ):
            issues.add("E_AGGREGATE_COST_LEDGER_MISMATCH", endpoint, policy)
        policy_rows.append(
            {
                "policy": policy,
                "recomputed_total_cost_units": totals[policy],
                "reported_total_cost_units": (
                    reported.get("total_cost_units") if isinstance(reported, dict) else ""
                ),
                "budget": 300000,
                "recomputed_budget_exceeded": computed_exceeded,
                "recomputed_block_failures": block_failures[policy],
                "source_result_sha256": source_sha,
            }
        )
    numerator = 64 if budget_exceeded else adverse_blocks
    status = "PASS" if numerator == 0 else "FAIL"
    _compare_common_result(result, endpoint, numerator, status, issues)
    return numerator, status


def _audit_f0(
    result: dict[str, Any], source_sha: str, issues: AuditIssues,
    block_rows: list[dict[str, Any]], fidelity_rows: list[dict[str, Any]],
    failure_rows: list[dict[str, Any]], strata_rows: list[dict[str, Any]],
) -> tuple[int, str]:
    endpoint = "F0"
    blocks, fidelities, failures = _base_endpoint_check(result, endpoint, issues)
    by_fidelity, _ = _fidelity_index(endpoint, fidelities, source_sha, issues, fidelity_rows)
    _record_failure_ledger(endpoint, failures, source_sha, issues, failure_rows)
    counts = {
        "registered_translation": 0,
        "single_cell_perturbation": 0,
        "negative_control": 0,
    }
    adverse_count = 0
    for index, raw in enumerate(blocks):
        block = _require_dict(raw, issues, endpoint, "BLOCK_RECORD_NOT_OBJECT")
        block_id = f"F0:{index:03d}"
        fidelity = by_fidelity.get(block_id)
        case_type = block.get("case_type")
        structural_ok = (
            case_type in counts
            and fidelity is not None
            and block.get("block_id") == block_id
        )
        if structural_ok:
            counts[str(case_type)] += 1
        similarity = block.get("similarity")
        if not _is_number(similarity):
            structural_ok = False
        if case_type == "negative_control":
            conformance = (
                _is_number(similarity)
                and float(similarity) < 0.99
                and
                block.get("detected_template") is None
                and block.get("detected_translation") is None
            )
        elif case_type in {"registered_translation", "single_cell_perturbation"}:
            conformance = (
                block.get("detected_template") == block.get("expected_template_generator_only")
                and block.get("detected_translation")
                == block.get("expected_translation_generator_only")
                and _is_number(similarity)
                and float(similarity) >= 0.99
            )
        else:
            conformance = False
        if block.get("template_conformance") is not conformance:
            structural_ok = False
            issues.add("F0_CONFORMANCE_FIELD_MISMATCH", endpoint, block_id)
        failure_present, _ = _failure_present(block)
        fidelity_bad = not isinstance(fidelity, dict) or fidelity.get("status") != "PASS"
        event = not structural_ok or not conformance or fidelity_bad or failure_present
        adverse_count += int(event)
        _append_block_row(
            endpoint=endpoint, index=index, block=block, fidelity=fidelity,
            primitive_event=not conformance, adverse=event,
            structural_ok=structural_ok, source_sha=source_sha,
            block_rows=block_rows, failure_rows=failure_rows,
        )
    _validate_per_block_failure_ledger(endpoint, blocks, failures, issues)
    reported_counts = result.get("descriptive_strata_counts")
    if reported_counts != counts:
        issues.add("F0_DESCRIPTIVE_STRATA_COUNT_MISMATCH", endpoint)
    for case_type, count in counts.items():
        strata_rows.append(
            {
                "case_type": case_type,
                "count": count,
                "inferential_endpoint_registered": False,
                "source_result_sha256": source_sha,
            }
        )
    status = "PASS" if adverse_count == 0 else "FAIL"
    _compare_common_result(result, endpoint, adverse_count, status, issues)
    return adverse_count, status


def _audit_result(
    bundle: dict[str, Any], source_sha: str, issues: AuditIssues
) -> dict[str, Any]:
    synthetic = str(bundle.get("label", "")).startswith("TEST_ONLY_SYNTHETIC")
    if bundle.get("role") != "locked" or bundle.get("run_id") != "aphfs_actual_locked_audit_v1":
        issues.add("LOCKED_BUNDLE_IDENTITY_MISMATCH")
    if synthetic:
        if bundle.get("schema_version") not in {"4", "5"}:
            issues.add("TEST_ONLY_RESULT_SCHEMA_VERSION_UNSUPPORTED")
        if bundle.get("manuscript_evidence") is not False or bundle.get(
            "protected_execution"
        ) is not False:
            issues.add("TEST_ONLY_RESULT_EVIDENCE_FLAGS_INVALID")
    else:
        if (
            bundle.get("schema_version") != "5"
            or bundle.get("record_type") != "PROTECTED_LOCKED_RESULT_BUNDLE_ACTUAL_V1"
            or bundle.get("label") != "PROTECTED_RESULT"
            or bundle.get("manuscript_evidence") is not True
            or bundle.get("protected_execution") is not True
        ):
            issues.add("ACTUAL_LOCKED_RESULT_V5_IDENTITY_MISMATCH")
        for field in _V5_PROVENANCE_FIELDS:
            if not isinstance(bundle.get(field), str) or not _HASH_RE.fullmatch(
                str(bundle.get(field))
            ):
                issues.add(f"V5_PROVENANCE_FIELD_INVALID_{field.upper()}")
        if bundle.get("runtime_inventory_sha256") != bundle.get(
            "amended_runtime_inventory_sha256"
        ):
            issues.add("ACTUAL_RUNTIME_IS_NOT_AMENDED_RUNTIME")
    raw_results = bundle.get("benchmark_results")
    if not isinstance(raw_results, list):
        issues.add("BENCHMARK_RESULTS_NOT_ARRAY")
        raw_results = []
    results = [row for row in raw_results if isinstance(row, dict)]
    if len(results) != len(raw_results):
        issues.add("BENCHMARK_RESULT_ROW_NOT_OBJECT")
    ids = [str(row.get("sub_id", "")) for row in results]
    if tuple(ids) != _ENDPOINTS:
        issues.add("ENDPOINT_EXACT_ORDER_OR_SET_MISMATCH")
    by_id = {str(row.get("sub_id")): row for row in results}
    if len(by_id) != 11 or set(by_id) != set(_ENDPOINTS):
        issues.add("ENDPOINT_EXACT_SET_MISMATCH")
    a0_signatures: dict[int, str] = {}
    a0_result = by_id.get("A0", {})
    if isinstance(a0_result, dict) and isinstance(a0_result.get("block_records"), list):
        for row in a0_result["block_records"]:
            if (
                isinstance(row, dict)
                and _is_int(row.get("rule_id"))
                and 0 <= int(row["rule_id"]) <= 255
                and isinstance(row.get("canonical_signature"), str)
                and _HASH_RE.fullmatch(row["canonical_signature"])
            ):
                a0_signatures[int(row["rule_id"])] = row["canonical_signature"]
    if set(a0_signatures) != set(range(256)):
        issues.add("A0_SIGNATURE_MAP_INCOMPLETE")

    block_rows: list[dict[str, Any]] = []
    fidelity_rows: list[dict[str, Any]] = []
    failure_rows: list[dict[str, Any]] = []
    cp_rows: list[dict[str, Any]] = []
    deterministic_rows: list[dict[str, Any]] = []
    policy_rows: list[dict[str, Any]] = []
    strata_rows: list[dict[str, Any]] = []
    endpoint_rows: list[dict[str, Any]] = []
    d2_details: dict[str, Any] = {
        "record_type": "LOCKED_D2_CERT_READONLY_RECOMPUTATION_V2_4",
        "source_result_sha256": source_sha,
        "status": "NOT_COMPUTED",
    }
    for endpoint in _ENDPOINTS:
        before = len(issues.rows)
        result = by_id.get(endpoint)
        if result is None:
            issues.add("ENDPOINT_MISSING", endpoint)
            numerator = -1
            status = "MISSING"
        elif endpoint == "A0":
            numerator, status = _audit_a0(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows
            )
        elif endpoint == "A1":
            numerator, status = _audit_a1(
                result,
                source_sha,
                issues,
                block_rows,
                fidelity_rows,
                failure_rows,
                a0_signatures,
            )
        elif endpoint in {"B0", "B1"}:
            numerator, status = _audit_b(
                endpoint, result, source_sha, issues, block_rows, fidelity_rows,
                failure_rows,
            )
        elif endpoint == "C":
            numerator, status = _audit_c(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows
            )
        elif endpoint == "D0":
            numerator, status = _audit_d0(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows
            )
        elif endpoint == "D1":
            numerator, status = _audit_d1(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows
            )
        elif endpoint == "D2-CERT":
            numerator, status, d2_details = _audit_d2_cert(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows,
                cp_rows,
            )
        elif endpoint == "D2-MEM":
            numerator, status = _audit_d2_mem(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows
            )
        elif endpoint == "E":
            numerator, status = _audit_e(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows,
                policy_rows,
            )
        else:
            numerator, status = _audit_f0(
                result, source_sha, issues, block_rows, fidelity_rows, failure_rows,
                strata_rows,
            )
        if result is not None and endpoint in _CP_ENDPOINTS and len(
            result.get("block_records", [])
        ) == 64 and len(result.get("fidelity_records", [])) == 64:
            cp_rows.append(
                _cp_audit_row(
                    endpoint=endpoint,
                    events=numerator,
                    trials=64,
                    result=result,
                    issues=issues,
                    source_sha=source_sha,
                )
            )
        endpoint_rows.append(
            {
                "endpoint": endpoint,
                "category": (
                    "FINITE_SAMPLE_MACHINERY_ENDPOINT"
                    if endpoint in _CP_ENDPOINTS or endpoint == "D2-CERT"
                    else "DETERMINISTIC_OR_FORMULA_CONFORMANCE"
                ),
                "reported_status": result.get("status", "") if result else "",
                "recomputed_status": status,
                "reported_numerator": result.get("numerator", "") if result else "",
                "recomputed_numerator": numerator if numerator >= 0 else "",
                "reported_denominator": result.get("denominator", "") if result else "",
                "registered_denominator": _EXPECTED_BLOCKS[endpoint],
                "block_record_count": len(result.get("block_records", [])) if result else 0,
                "fidelity_record_count": len(result.get("fidelity_records", [])) if result else 0,
                "failure_ledger_count": len(result.get("failure_ledger", [])) if result else 0,
                "recomputation_match": len(issues.rows) == before,
                "source_result_sha256": source_sha,
            }
        )
        if endpoint not in _CP_ENDPOINTS and endpoint != "D2-CERT":
            deterministic_rows.append(
                {
                    "endpoint": endpoint,
                    "reported_numerator": result.get("numerator", "") if result else "",
                    "recomputed_numerator": numerator if numerator >= 0 else "",
                    "denominator": _EXPECTED_BLOCKS[endpoint],
                    "reported_status": result.get("status", "") if result else "",
                    "recomputed_status": status,
                    "clopper_pearson_applicable": False,
                    "source_result_sha256": source_sha,
                }
            )
    return {
        "synthetic": synthetic,
        "endpoint_rows": endpoint_rows,
        "block_rows": block_rows,
        "fidelity_rows": fidelity_rows,
        "failure_rows": failure_rows,
        "cp_rows": cp_rows,
        "deterministic_rows": deterministic_rows,
        "policy_rows": policy_rows,
        "strata_rows": strata_rows,
        "d2_details": d2_details,
    }


def _write_result_outputs(
    output_dir: Path,
    audit: dict[str, Any],
    issues: AuditIssues,
    source_sha_before: str,
    source_sha_after: str,
    source_identity_before: dict[str, int],
    source_identity_after: dict[str, int],
    source_size: int,
    source_name: str,
) -> tuple[dict[str, Any], str]:
    payloads: list[tuple[str, bytes, int]] = []
    csv_specs: list[tuple[str, list[str], list[dict[str, Any]]]] = [
        (
            "LOCKED_ENDPOINT_SUMMARY_v2_4.csv",
            [
                "endpoint", "category", "reported_status", "recomputed_status",
                "reported_numerator", "recomputed_numerator", "reported_denominator",
                "registered_denominator", "block_record_count", "fidelity_record_count",
                "failure_ledger_count", "recomputation_match", "source_result_sha256",
            ],
            audit["endpoint_rows"],
        ),
        (
            "LOCKED_BLOCK_RECOMPUTATION_LEDGER_v2_4.csv",
            [
                "endpoint", "audit_row_id", "source_block_id", "block_index",
                "fidelity_status", "primitive_event", "failure_code_present",
                "recomputed_adverse", "structural_status", "source_result_sha256",
            ],
            audit["block_rows"],
        ),
        (
            "LOCKED_FIDELITY_RECOMPUTATION_LEDGER_v2_4.csv",
            [
                "endpoint", "audit_row_id", "source_block_id", "fidelity_index",
                "status", "decision_changed",
                "observable_changed_beyond_tolerance", "further_refinement_required",
                "source_result_sha256",
            ],
            audit["fidelity_rows"],
        ),
        (
            "LOCKED_CP_RECOMPUTATION_v2_4.csv",
            [
                "endpoint", "event_semantics", "events", "trials",
                "one_sided_alpha_name", "one_sided_alpha", "one_sided_lower",
                "one_sided_upper", "two_sided_alpha_name", "two_sided_alpha",
                "two_sided_lower", "two_sided_upper", "threshold", "decision",
                "reported_upper_absolute_difference", "reported_lower_absolute_difference",
                "reported_two_upper_absolute_difference", "source_result_sha256",
            ],
            audit["cp_rows"],
        ),
        (
            "LOCKED_DETERMINISTIC_CONTROL_LEDGER_v2_4.csv",
            [
                "endpoint", "reported_numerator", "recomputed_numerator", "denominator",
                "reported_status", "recomputed_status", "clopper_pearson_applicable",
                "source_result_sha256",
            ],
            audit["deterministic_rows"],
        ),
        (
            "LOCKED_FAILURE_INDETERMINATE_LEDGER_v2_4.csv",
            [
                "endpoint", "audit_row_id", "source", "failure_code",
                "counts_as_adverse", "source_result_sha256",
            ],
            audit["failure_rows"],
        ),
        (
            "LOCKED_POLICY_COST_SUMMARY_v2_4.csv",
            [
                "policy", "recomputed_total_cost_units", "reported_total_cost_units",
                "budget", "recomputed_budget_exceeded", "recomputed_block_failures",
                "source_result_sha256",
            ],
            audit["policy_rows"],
        ),
        (
            "LOCKED_F0_DESCRIPTIVE_STRATA_v2_4.csv",
            [
                "case_type", "count", "inferential_endpoint_registered",
                "source_result_sha256",
            ],
            audit["strata_rows"],
        ),
    ]
    for name, fields, rows in csv_specs:
        payloads.append((name, _csv_bytes(fields, rows), len(rows)))
    payloads.append(
        (
            "LOCKED_D2_CERT_RECOMPUTATION_v2_4.json",
            _json_bytes(audit["d2_details"]),
            1,
        )
    )
    payloads.append(
        (
            "RECOMPUTATION_ISSUES_v2_4.json",
            _json_bytes(
                {
                    "record_type": "LOCKED_RESULT_RECOMPUTATION_ISSUES_V2_4",
                    "status": BLOCKING if issues.rows else PASS,
                    "issue_count": len(issues.rows),
                    "issues": issues.rows,
                    "source_result_sha256": source_sha_before,
                }
            ),
            len(issues.rows),
        )
    )
    os.mkdir(output_dir, 0o700)
    derived: list[dict[str, Any]] = []
    for name, payload, rows in payloads:
        sha = _write_new(output_dir / name, payload)
        derived.append(
            {
                "path": name,
                "sha256": sha,
                "bytes": len(payload),
                "row_count": rows,
                "contains_raw_role_values": False,
            }
        )
    source_unchanged = (
        source_sha_before == source_sha_after
        and source_identity_before == source_identity_after
    )
    overall = BLOCKING if issues.rows or not source_unchanged else (
        PASS_TEST_ONLY if audit["synthetic"] else PASS
    )
    manifest = {
        "record_type": "LOCKED_REVIEW_SOURCE_DATA_MANIFEST_V2_4",
        "tool_version": TOOL_VERSION,
        "source_result_name": source_name,
        "source_result_size_bytes": source_size,
        "source_hash_before_recomputation": source_sha_before,
        "source_hash_after_recomputation": source_sha_after,
        "source_file_identity_stable": source_identity_before == source_identity_after,
        "source_unchanged": source_unchanged,
        "source_is_test_only_synthetic": audit["synthetic"],
        "overall_consistency_status": overall,
        "blocking_result_inconsistency_count": len(issues.rows),
        "endpoint_exact_set": list(_ENDPOINTS),
        "endpoint_count": 11,
        "block_ledger_row_count": len(audit["block_rows"]),
        "fidelity_ledger_row_count": len(audit["fidelity_rows"]),
        "cp_algorithm_id": "STDLIB_DECIMAL_BINOMIAL_CDF_BISECTION_PRECISION_90_V1",
        "benchmark_engine_imported": False,
        "benchmark_engine_called": False,
        "aphfs_imported": False,
        "raw_role_files_opened": False,
        "raw_role_values_included": False,
        "role_value_commitments_exported": False,
        "manuscript_modified": False,
        "derived_files": derived,
    }
    manifest_payload = _json_bytes(manifest)
    manifest_sha = _write_new(
        output_dir / "LOCKED_REVIEW_SOURCE_DATA_MANIFEST_v2_4.json",
        manifest_payload,
    )
    return manifest, manifest_sha


def _write_no_result_outputs(
    output_dir: Path,
    failure: dict[str, Any],
    issues: AuditIssues,
    source_sha_before: str,
    source_sha_after: str,
    source_identity_before: dict[str, int],
    source_identity_after: dict[str, int],
    source_size: int,
) -> tuple[dict[str, Any], str]:
    os.mkdir(output_dir, 0o700)
    code = _safe_failure_code(failure.get("failure_code"))
    summary = {
        "record_type": "LOCKED_RESULT_RECOMPUTATION_NOT_APPLICABLE_V2_4",
        "status": NO_RESULT,
        "source_failure_sha256": source_sha_before,
        "failure_code": code,
        "failure_phase": (
            failure.get("phase")
            if isinstance(failure.get("phase"), str)
            and _SAFE_CODE_RE.fullmatch(str(failure.get("phase")))
            else "REDACTED_OR_UNREGISTERED"
        ),
        "endpoint_results_present": False,
        "benchmark_engine_called": False,
        "raw_role_files_opened": False,
        "raw_role_values_included": False,
    }
    summary_payload = _json_bytes(summary)
    summary_sha = _write_new(output_dir / "NOT_APPLICABLE_NO_RESULT_v2_4.json", summary_payload)
    source_unchanged = (
        source_sha_before == source_sha_after
        and source_identity_before == source_identity_after
    )
    manifest = {
        "record_type": "LOCKED_REVIEW_SOURCE_DATA_MANIFEST_V2_4",
        "tool_version": TOOL_VERSION,
        "source_result_name": _FAILURE_NAME,
        "source_result_size_bytes": source_size,
        "source_hash_before_recomputation": source_sha_before,
        "source_hash_after_recomputation": source_sha_after,
        "source_file_identity_stable": source_identity_before == source_identity_after,
        "source_unchanged": source_unchanged,
        "overall_consistency_status": (
            NO_RESULT if source_unchanged and not issues.rows else BLOCKING
        ),
        "blocking_result_inconsistency_count": len(issues.rows),
        "blocking_result_inconsistency_codes": [
            row["code"] for row in issues.rows
        ],
        "endpoint_count": 0,
        "benchmark_engine_imported": False,
        "benchmark_engine_called": False,
        "aphfs_imported": False,
        "raw_role_files_opened": False,
        "raw_role_values_included": False,
        "manuscript_modified": False,
        "derived_files": [
            {
                "path": "NOT_APPLICABLE_NO_RESULT_v2_4.json",
                "sha256": summary_sha,
                "bytes": len(summary_payload),
                "row_count": 1,
                "contains_raw_role_values": False,
            }
        ],
    }
    manifest_payload = _json_bytes(manifest)
    manifest_sha = _write_new(
        output_dir / "LOCKED_REVIEW_SOURCE_DATA_MANIFEST_v2_4.json",
        manifest_payload,
    )
    return manifest, manifest_sha


def run(
    input_path: Path,
    output_dir: Path,
    expected_sha256: str | None,
    allow_test_only_synthetic: bool,
) -> int:
    if output_dir.exists() or output_dir.is_symlink():
        raise FileExistsError("output directory must be new")
    parent = output_dir.parent
    if parent.is_symlink() or not parent.is_dir():
        raise FileNotFoundError("output parent must be an existing non-symlink directory")
    _validate_input_location(input_path, allow_test_only_synthetic)
    raw_before, identity_before = _read_no_follow(input_path)
    sha_before = hashlib.sha256(raw_before).hexdigest()
    parsed = _load_json(raw_before)
    if not isinstance(parsed, dict):
        raise ValueError("source JSON must be an object")
    synthetic_label = str(
        parsed.get("label", parsed.get("artifact_label", ""))
    ).startswith("TEST_ONLY_SYNTHETIC")
    if allow_test_only_synthetic is not synthetic_label:
        raise PermissionError("actual and TEST_ONLY inputs require distinct invocation modes")
    if expected_sha256 is not None and sha_before != expected_sha256:
        issues = AuditIssues()
        issues.add("EXPECTED_SOURCE_SHA256_MISMATCH")
    else:
        issues = AuditIssues()
    if input_path.name == _FAILURE_NAME:
        if (
            parsed.get("record_type") != "LOCKED_EXECUTION_FAILURE_V1"
            or "benchmark_results" in parsed
        ):
            raise ValueError("failure input has an invalid fixed record identity")
        raw_after, identity_after = _read_no_follow(input_path)
        sha_after = hashlib.sha256(raw_after).hexdigest()
        manifest, manifest_sha = _write_no_result_outputs(
            output_dir,
            parsed,
            issues,
            sha_before,
            sha_after,
            identity_before,
            identity_after,
            len(raw_before),
        )
        print(manifest["overall_consistency_status"])
        print(f"SOURCE_SHA256={sha_before}")
        print(f"MANIFEST_SHA256={manifest_sha}")
        return 0 if manifest["overall_consistency_status"] == NO_RESULT else 2
    if "benchmark_results" not in parsed:
        raise ValueError("result input contains no benchmark_results")
    audit = _audit_result(parsed, sha_before, issues)
    raw_after, identity_after = _read_no_follow(input_path)
    sha_after = hashlib.sha256(raw_after).hexdigest()
    if sha_before != sha_after or identity_before != identity_after:
        issues.add("SOURCE_CHANGED_DURING_READONLY_RECOMPUTATION")
    manifest, manifest_sha = _write_result_outputs(
        output_dir,
        audit,
        issues,
        sha_before,
        sha_after,
        identity_before,
        identity_after,
        len(raw_before),
        input_path.name,
    )
    print(manifest["overall_consistency_status"])
    print(f"SOURCE_SHA256={sha_before}")
    print(f"MANIFEST_SHA256={manifest_sha}")
    return 2 if manifest["overall_consistency_status"] == BLOCKING else 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only independent audit of one immutable locked result/failure."
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument(
        "--allow-test-only-synthetic",
        action="store_true",
        help="permit only a TEST_ONLY_SYNTHETIC fixture outside the canonical result path",
    )
    args = parser.parse_args(argv)
    if args.expected_sha256 is not None and not _HASH_RE.fullmatch(args.expected_sha256):
        parser.error("--expected-sha256 must be 64 lowercase hexadecimal characters")
    return args


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(
            args.input,
            args.output_dir,
            args.expected_sha256,
            args.allow_test_only_synthetic,
        )
    except Exception as exc:
        # Never print source content or arbitrary exception messages.  The
        # exception class is sufficient for a pre/post-processing incident.
        print(f"READONLY_RECOMPUTATION_TOOL_ERROR:{type(exc).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
