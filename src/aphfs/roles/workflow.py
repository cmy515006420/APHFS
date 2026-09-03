"""Public mock-role workflow and hard guards for protected roles."""

from __future__ import annotations

from typing import Any, Literal, cast

from aphfs.constants import PUBLIC_MOCK_ROLE_LABEL
from aphfs.provenance.hashing import sha256_json

PublicMockRole = Literal["mock_calibration", "mock_locked"]
PUBLIC_MOCK_ROLES: tuple[PublicMockRole, ...] = ("mock_calibration", "mock_locked")
_ROLE_BASES: dict[PublicMockRole, int] = {
    "mock_calibration": 1_000_000,
    "mock_locked": 2_000_000,
}


def _commitment_payload(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "commitment_sha256"}


def build_public_mock_manifest(role: PublicMockRole, count: int) -> dict[str, Any]:
    """Create visible deterministic values that cannot be mistaken for protected values."""
    if role not in PUBLIC_MOCK_ROLES:
        raise PermissionError("Only public mock roles may be materialized in Phase 1B-FREEZE-PREP")
    if count < 1:
        raise ValueError("Mock role count must be positive")
    base = _ROLE_BASES[role]
    manifest: dict[str, Any] = {
        "schema_version": "1",
        "label": PUBLIC_MOCK_ROLE_LABEL,
        "role": role,
        "value_source": "PUBLIC_DETERMINISTIC_FIXTURE",
        "values": [base + index for index in range(count)],
    }
    manifest["commitment_sha256"] = sha256_json(_commitment_payload(manifest))
    return manifest


def verify_public_mock_manifest(manifest: dict[str, Any]) -> PublicMockRole:
    """Verify label, role, uniqueness, namespace separation, and commitment."""
    if manifest.get("label") != PUBLIC_MOCK_ROLE_LABEL:
        raise PermissionError("Role manifest is not visibly labeled as a public mock")
    role_value = manifest.get("role")
    if role_value not in PUBLIC_MOCK_ROLES:
        raise PermissionError("Protected role manifests are forbidden in this phase")
    role = cast(PublicMockRole, role_value)
    values = manifest.get("values")
    if not isinstance(values, list) or not values or not all(isinstance(v, int) for v in values):
        raise ValueError("Mock values must be a nonempty integer list")
    if len(values) != len(set(values)):
        raise ValueError("Mock values must be unique")
    base = _ROLE_BASES[role]
    if any(value < base or value >= base + 1_000_000 for value in values):
        raise ValueError("Mock value escaped its public deterministic namespace")
    expected = sha256_json(_commitment_payload(manifest))
    if manifest.get("commitment_sha256") != expected:
        raise ValueError("Mock role commitment mismatch")
    return role


def reject_protected_role_materialization(role: str) -> None:
    """Fail closed for real protected roles during freeze preparation."""
    if role in {"calibration", "locked"}:
        raise PermissionError(
            "Real calibration/locked role materialization requires a later, separate authorization"
        )
    if role not in PUBLIC_MOCK_ROLES:
        raise ValueError(f"Unknown role: {role}")
