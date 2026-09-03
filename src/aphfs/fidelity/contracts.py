"""Run genuine per-benchmark paired fidelity checks on public mock blocks."""

from __future__ import annotations

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
from aphfs.provenance.hashing import sha256_file
from aphfs.roles.workflow import verify_public_mock_manifest
from aphfs.schema.validation import validate_json_file


def run_public_mock_fidelity_dry_run(
    *,
    project_root: Path,
    config_path: Path,
    contracts_path: Path,
    role_manifest_path: Path,
) -> dict[str, Any]:
    """Execute independent tier implementations on the same public mock units."""
    config = validate_json_file(
        config_path,
        project_root / "manifests/schema/protected_benchmark_config_v3.schema.json",
    )
    contracts = validate_json_file(
        contracts_path,
        project_root / "manifests/schema/protected_fidelity_contracts_v3.schema.json",
    )
    role_manifest = validate_json_file(
        role_manifest_path,
        project_root / "manifests/schema/role_manifest.schema.json",
    )
    role = verify_public_mock_manifest(role_manifest)
    values = [int(value) for value in role_manifest["values"]]
    benchmarks = cast(dict[str, dict[str, Any]], config["benchmarks"])
    a0, signatures = run_confirmatory_a0(benchmarks["A0"])
    results = [
        a0,
        run_confirmatory_a1(benchmarks["A1"], values, signatures),
        run_confirmatory_b0(benchmarks["B0"], values),
        run_confirmatory_b1(benchmarks["B1"], values),
        run_confirmatory_c(benchmarks["C"]),
        run_confirmatory_d0(benchmarks["D0"], values),
        run_confirmatory_d1(),
        run_confirmatory_d2_cert(benchmarks["D2-CERT"], values, role),
        run_confirmatory_d2_mem(benchmarks["D2-MEM"]),
        run_confirmatory_e(benchmarks["E"], values),
        run_confirmatory_f0(benchmarks["F0"], values),
    ]
    records = [
        {
            "benchmark": result["sub_id"],
            "fidelity_records": result["fidelity_records"],
            "all_blocks_stable": all(
                row["status"] == "PASS" for row in result["fidelity_records"]
            ),
        }
        for result in results
    ]
    return {
        "schema_version": "2",
        "label": PUBLIC_MOCK_ROLE_LABEL,
        "evidence_scope": "DEVELOPMENT_FIDELITY_DRY_RUN_NOT_SCIENTIFIC_EVIDENCE",
        "fidelity_contract_sha256": sha256_file(contracts_path),
        "mock_role_commitment_sha256": role_manifest["commitment_sha256"],
        "registered_contract_benchmarks": sorted(contracts["benchmarks"]),
        "records": records,
        "all_adjacent_tier_decisions_stable": all(
            record["all_blocks_stable"] for record in records
        ),
        "failure_action": "FIDELITY_INDETERMINATE_COUNTS_ADVERSE",
        "certificate_transfer_across_benchmarks": False,
    }
