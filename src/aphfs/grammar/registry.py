"""Exact 256-candidate ECA registry and ledger validation."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from aphfs.constants import TERMINAL_STATUSES


@dataclass(frozen=True)
class CandidateRecord:
    candidate_id: str
    description_bits: int
    rule_id: int
    parse_status: str
    execution_status: str
    canonical_signature_id: str | None
    representative_id: str | None
    resource_usage: dict[str, int | float]
    failure_code: str | None
    source_hash: str
    config_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def enumerate_eca_registry(
    source_hash: str,
    config_hash: str,
    *,
    status_by_rule: dict[int, str] | None = None,
    signature_by_rule: dict[int, str] | None = None,
    failure_code_by_rule: dict[int, str] | None = None,
    resource_usage_by_rule: dict[int, dict[str, int | float]] | None = None,
) -> list[CandidateRecord]:
    statuses = status_by_rule or {}
    signatures = signature_by_rule or {}
    failure_codes = failure_code_by_rule or {}
    resources = resource_usage_by_rule or {}
    supplied_rule_ids = set(statuses) | set(signatures) | set(failure_codes) | set(resources)
    if not supplied_rule_ids <= set(range(256)):
        raise ValueError("registry maps contain an out-of-range rule ID")
    records = []
    for rule_id in range(256):
        status = statuses.get(rule_id, "EXECUTED")
        failure_code = failure_codes.get(rule_id)
        if status != "EXECUTED" and failure_code is None:
            failure_code = status
        records.append(
            CandidateRecord(
                candidate_id=f"eca:{rule_id:03d}",
                description_bits=8,
                rule_id=rule_id,
                parse_status="VALID",
                execution_status=status,
                canonical_signature_id=signatures.get(rule_id),
                representative_id=None,
                resource_usage=resources.get(rule_id, {}),
                failure_code=failure_code,
                source_hash=source_hash,
                config_hash=config_hash,
            )
        )
    validate_exhaustive_eca_ledger(records)
    return records


def validate_exhaustive_eca_ledger(records: Iterable[CandidateRecord]) -> None:
    rows = list(records)
    if len(rows) != 256:
        raise ValueError("Exhaustive ECA ledger must contain exactly 256 candidates")
    expected_ids = {f"eca:{rule_id:03d}" for rule_id in range(256)}
    actual_ids = {row.candidate_id for row in rows}
    if actual_ids != expected_ids:
        raise ValueError("ECA candidate IDs are incomplete or duplicated")
    rule_ids = {row.rule_id for row in rows}
    if rule_ids != set(range(256)):
        raise ValueError("ECA rule IDs are incomplete or duplicated")
    for row in rows:
        if row.execution_status not in TERMINAL_STATUSES:
            raise ValueError(f"Nonterminal status for {row.candidate_id}: {row.execution_status}")
        if row.execution_status == "CANONICAL_DUPLICATE" and not row.representative_id:
            raise ValueError("CANONICAL_DUPLICATE requires a representative pointer")
        if row.execution_status == "EXECUTED" and row.failure_code is not None:
            raise ValueError("EXECUTED candidates cannot carry a failure code")
        if row.execution_status != "EXECUTED" and not row.failure_code:
            raise ValueError("Non-EXECUTED candidates require a failure code")
