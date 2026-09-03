"""Locked-audit entry point routed through the protected-shaped pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aphfs.pipelines.protected import run_protected_shaped_analysis
from aphfs.schema.validation import validate_json_file


def run_mock_locked_analysis(
    *,
    project_root: Path,
    config_path: Path,
    protocol_path: Path,
    role_manifest_path: Path,
    authorization_path: Path,
    signatures: dict[int, str],
    run_id: str,
    fidelity_path: Path | None = None,
) -> dict[str, Any]:
    del signatures
    authorization = validate_json_file(
        authorization_path,
        project_root / "manifests/schema/authorization_record.schema.json",
    )
    return run_protected_shaped_analysis(
        project_root=project_root,
        config_path=config_path,
        protocol_path=protocol_path,
        fidelity_path=(
            fidelity_path
            or project_root / "configs/protected/protected_fidelity_contracts_v3.json"
        ),
        role_manifest_path=role_manifest_path,
        role="mock_locked",
        run_id=run_id,
        authorization=authorization,
    )
