"""Single-command development-only runner and artifact writer."""

from __future__ import annotations

import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, cast

import numpy as np

from aphfs.benchmarks.a import run_a0, run_a1
from aphfs.benchmarks.b import run_b0, run_b1
from aphfs.benchmarks.c import run_c
from aphfs.benchmarks.d import run_d0, run_d1, run_d2
from aphfs.benchmarks.e import run_e
from aphfs.benchmarks.f0 import run_f0
from aphfs.benchmarks.preflight import run_resource_preflight
from aphfs.constants import BENCHMARK_SUB_IDS, DEVELOPMENT_LABEL
from aphfs.eca.core import Boundary, simulate_vectorized
from aphfs.fidelity.ledger import ErrorLedger, RefinementContext, assess_refinement
from aphfs.grammar.registry import enumerate_eca_registry
from aphfs.provenance.hashing import sha256_file, sha256_json
from aphfs.provenance.io import write_json_new, write_jsonl_new
from aphfs.provenance.splits import FrozenConfig, load_development_manifest


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def _source_tree_hash(source_root: Path) -> str:
    rows = []
    for path in sorted(source_root.rglob("*.py")):
        rows.append({"path": path.relative_to(source_root).as_posix(), "sha256": sha256_file(path)})
    return sha256_json(rows)


def _validate_development_config(config: dict[str, Any]) -> None:
    if config.get("mode") != "development":
        raise PermissionError("Only development mode is authorized")
    if config.get("label") != DEVELOPMENT_LABEL:
        raise ValueError("Development evidence-boundary label is missing or altered")
    if tuple(config["benchmark_sub_ids"]) != BENCHMARK_SUB_IDS:
        raise ValueError("Development config must enumerate the exact authorized sub-IDs")
    fidelity = config.get("fidelity_validation")
    if not isinstance(fidelity, dict):
        raise ValueError("Development config must register a fidelity validation fixture")
    required = {
        "rule_id",
        "width",
        "horizon",
        "boundary",
        "initial_state",
        "protected_observable",
        "observable_tolerance",
        "decision_threshold",
        "initial_state_or_environment_distribution",
    }
    if set(fidelity) != required:
        raise ValueError("Development fidelity fixture fields are incomplete or unexpected")


def _run_fidelity_development_fixture(config: dict[str, Any]) -> dict[str, Any]:
    fidelity = config["fidelity_validation"]
    width = int(fidelity["width"])
    initial = np.zeros(width, dtype=np.uint8)
    if fidelity["initial_state"] == "single_center":
        initial[width // 2] = 1
    else:
        raise ValueError("Unsupported registered fidelity initial state")
    history = simulate_vectorized(
        int(fidelity["rule_id"]),
        initial,
        int(fidelity["horizon"]),
        cast(Boundary, str(fidelity["boundary"])),
    )
    fast_observable = float(np.mean(history[-1], dtype=np.float32))
    refined_observable = float(np.mean(history[-1], dtype=np.float64))
    threshold = float(fidelity["decision_threshold"])
    decision_before = "ABOVE_OR_EQUAL" if fast_observable >= threshold else "BELOW"
    decision_after = "ABOVE_OR_EQUAL" if refined_observable >= threshold else "BELOW"
    assessment = assess_refinement(
        context=RefinementContext(
            lower_level_change="float32 summary -> float64 summary",
            protected_observable=str(fidelity["protected_observable"]),
            observable_tolerance=float(fidelity["observable_tolerance"]),
            time_horizon=int(fidelity["horizon"]),
            initial_state_or_environment_distribution=str(
                fidelity["initial_state_or_environment_distribution"]
            ),
        ),
        fast_observable=fast_observable,
        refined_observable=refined_observable,
        decision_before=decision_before,
        decision_after=decision_after,
        interval=(refined_observable, refined_observable),
        threshold=threshold,
        numerical_allowance=float(fidelity["observable_tolerance"]),
    )
    return {
        **assessment.to_dict(),
        "fast_observable_value": fast_observable,
        "refined_observable_value": refined_observable,
        "decision_threshold": threshold,
        "evidence_scope": "DEVELOPMENT_FIDELITY_MECHANISM_FIXTURE_NOT_SCIENTIFIC_EVIDENCE",
    }


def run_development_all(
    *,
    project_root: Path,
    config_path: Path,
    proposed_protocol_path: Path,
    development_seed_path: Path,
    output_directory: Path,
    preflight_directory: Path,
    grammar_manifest_path: Path,
) -> dict[str, Any]:
    protected_parts = {"calibration", "locked"}
    for path in (output_directory, preflight_directory):
        if {part.lower() for part in path.parts} & protected_parts:
            raise PermissionError(f"Development runner cannot write protected path: {path}")
    config = load_json(config_path)
    _validate_development_config(config)
    frozen = FrozenConfig.freeze(config)
    seeds = load_development_manifest(development_seed_path)
    proposed = load_json(proposed_protocol_path)
    if proposed.get("status") != "PROPOSED_AWAITING_AUTHOR_APPROVAL":
        raise ValueError("Proposed locked protocol must remain explicitly unapproved")
    if "seeds" in json.dumps(proposed).lower():
        raise ValueError("Proposed locked protocol must not contain seed values")
    seed_values = tuple(int(seed) for seed in seeds["seeds"])
    if len(seed_values) < 4:
        raise ValueError("At least four development seeds are required")
    rng_b = np.random.default_rng(seed_values[0])
    rng_e = np.random.default_rng(seed_values[1])
    source_hash = _source_tree_hash(project_root / "src")
    config_hash = frozen.digest

    started = time.perf_counter()
    a0, signatures = run_a0(config["benchmarks"]["A0"])
    summaries = [
        a0,
        run_a1(config["benchmarks"]["A1"], tuple(config["benchmarks"]["A1"]["development_rules"])),
        run_b0(config["benchmarks"]["B0"], rng_b),
        run_b1(),
        run_c(config["benchmarks"]["C"]),
        run_d0(),
        run_d1(),
        run_d2(),
        run_e(config["benchmarks"]["E"], rng_e),
        run_f0(config["benchmarks"]["F0"]),
    ]
    frozen.verify(config)
    seen_sub_ids = tuple(summary["sub_id"] for summary in summaries)
    if seen_sub_ids != BENCHMARK_SUB_IDS:
        raise AssertionError(f"Unexpected benchmark order: {seen_sub_ids}")

    records = enumerate_eca_registry(
        source_hash,
        config_hash,
        signature_by_rule=signatures,
    )
    grammar_manifest = {
        "schema_version": "1",
        "grammar_id": "eca-binary-radius-one-v1",
        "description_bits": 8,
        "rule_ids": list(range(256)),
        "candidate_ids": [record.candidate_id for record in records],
        "terminal_status_vocabulary": sorted(
            {record.execution_status for record in records}
        ),
        "source_hash": source_hash,
        "config_hash": config_hash,
    }
    if grammar_manifest_path.exists():
        if load_json(grammar_manifest_path) != grammar_manifest:
            raise ValueError("Existing grammar manifest differs from current frozen source/config")
    else:
        write_json_new(grammar_manifest_path, grammar_manifest)
    write_jsonl_new(output_directory / "candidate_ledger.jsonl", (row.to_dict() for row in records))
    write_json_new(output_directory / "benchmark_summaries.json", summaries)

    error_ledger = ErrorLedger()
    refinement_record = _run_fidelity_development_fixture(config)
    write_json_new(
        output_directory / "error_fidelity_ledger.json",
        {
            "label": DEVELOPMENT_LABEL,
            "components": error_ledger.components,
            "refinement_triggers": proposed["refinement_triggers"],
            "decision_changing_refinement_may_be_averaged_away": False,
            "raw_float_closeness_is_sufficient": False,
            "precision_sufficiency_rule": (
                "The registered upper-level observable must remain within its tolerance over "
                "the declared horizon and environment, and the registered decision must not change."
            ),
            "refinement_records": [refinement_record],
        },
    )
    preflight = run_resource_preflight(
        config,
        proposed,
        seed=seed_values[2],
    )
    write_json_new(preflight_directory / "resource_preflight.json", preflight)
    elapsed = time.perf_counter() - started
    manifest = {
        "label": DEVELOPMENT_LABEL,
        "run_id": str(config["run_id"]),
        "source_hash": source_hash,
        "config_hash": config_hash,
        "config_file_sha256": sha256_file(config_path),
        "development_seed_manifest_sha256": sha256_file(development_seed_path),
        "proposed_protocol_sha256": sha256_file(proposed_protocol_path),
        "benchmark_sub_ids": list(seen_sub_ids),
        "elapsed_seconds_engineering_only": elapsed,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "calibration_run": False,
        "locked_run": False,
        "calibration_seed_generated": False,
        "locked_seed_generated": False,
        "manuscript_evidence": False,
    }
    write_json_new(output_directory / "run_manifest.json", manifest)
    return manifest
