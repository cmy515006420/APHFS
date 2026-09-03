"""Measured benchmark-specific CPU/resource preflight using public mock roles."""

from __future__ import annotations

import json
import math
import resource
import tempfile
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any

from aphfs.benchmarks.confirmatory import (
    _public_state,
    run_confirmatory_a0,
    run_confirmatory_a1,
    run_confirmatory_b0,
    run_confirmatory_b1,
    run_confirmatory_c,
    run_confirmatory_d0,
    run_confirmatory_d1,
    run_confirmatory_d2,
    run_confirmatory_e,
    run_confirmatory_f0,
)
from aphfs.bounds.statistics import clopper_pearson_upper
from aphfs.constants import PUBLIC_MOCK_ROLE_LABEL
from aphfs.eca.core import simulate_reference
from aphfs.provenance.hashing import sha256_file
from aphfs.roles.workflow import verify_public_mock_manifest
from aphfs.schema.validation import validate_json_file


def _timed(function: Callable[[], Any]) -> tuple[Any, float, float]:
    wall_start = time.perf_counter()
    cpu_start = time.process_time()
    result = function()
    return result, time.perf_counter() - wall_start, time.process_time() - cpu_start


def _generation_probe(
    benchmark: str,
    config: dict[str, Any],
    values: list[int],
) -> None:
    if benchmark in {"A1", "D0", "D2", "E"}:
        width = int(config.get("width", 32))
        horizon = int(config.get("horizon", 1))
        rule = int(config.get("truth_rule", 204))
        for value in values:
            state = _public_state(value, width, f"preflight-{benchmark}")
            simulate_reference(rule, state, horizon, "periodic")
    elif benchmark == "F0":
        for value in values:
            _public_state(value, int(config["width"]), "preflight-F0")


def _serialize_result(result: dict[str, Any]) -> bytes:
    return json.dumps(
        result,
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> int:
    return path.write_bytes(data)


def run_benchmark_specific_preflight(
    *,
    project_root: Path,
    config_path: Path,
    protocol_path: Path,
    role_manifest_path: Path,
) -> dict[str, Any]:
    """Measure each real engine rather than extrapolating one neutral kernel."""
    config = validate_json_file(
        config_path,
        project_root / "manifests/schema/config.schema.json",
    )
    protocol = validate_json_file(
        protocol_path,
        project_root / "manifests/schema/protocol.schema.json",
    )
    role_manifest = validate_json_file(
        role_manifest_path,
        project_root / "manifests/schema/role_manifest.schema.json",
    )
    role = verify_public_mock_manifest(role_manifest)
    values = [int(value) for value in role_manifest["values"]]
    a0, signatures = run_confirmatory_a0(config["benchmarks"]["A0"])
    engines: dict[str, Callable[[], dict[str, Any]]] = {
        "A0": lambda: run_confirmatory_a0(config["benchmarks"]["A0"])[0],
        "A1": lambda: run_confirmatory_a1(
            config["benchmarks"]["A1"],
            values,
            signatures,
        ),
        "B0": lambda: run_confirmatory_b0(config["benchmarks"]["B0"], values),
        "B1": lambda: run_confirmatory_b1(config["benchmarks"]["B1"], values),
        "C": lambda: run_confirmatory_c(config["benchmarks"]["C"]),
        "D0": lambda: run_confirmatory_d0(config["benchmarks"]["D0"], values),
        "D1": run_confirmatory_d1,
        "D2": lambda: run_confirmatory_d2(config["benchmarks"]["D2"], values, role),
        "E": lambda: run_confirmatory_e(config["benchmarks"]["E"], values),
        "F0": lambda: run_confirmatory_f0(config["benchmarks"]["F0"], values),
    }
    records: list[dict[str, Any]] = []
    for benchmark, engine in engines.items():
        generation_config = config["benchmarks"][benchmark]
        _, generation_wall, generation_cpu = _timed(
            partial(
                _generation_probe,
                benchmark,
                generation_config,
                values,
            )
        )
        result, engine_wall, engine_cpu = _timed(engine)
        _, statistics_wall, statistics_cpu = _timed(
            lambda: [
                clopper_pearson_upper(events, len(values), 0.05)
                for events in range(len(values) + 1)
            ]
        )
        serialized, serialization_wall, serialization_cpu = _timed(
            partial(_serialize_result, result)
        )
        with tempfile.TemporaryDirectory(prefix="aphfs-preflight-write-") as directory:
            output_path = Path(directory) / f"{benchmark}.json"
            _, write_wall, write_cpu = _timed(
                partial(_write_bytes, output_path, serialized)
            )
            on_disk_bytes = output_path.stat().st_size
        records.append(
            {
                "benchmark": benchmark,
                "status": result["status"],
                "mock_role": role,
                "public_mock_count": len(values),
                "generation_probe_wall_seconds": generation_wall,
                "generation_probe_cpu_seconds": generation_cpu,
                "engine_end_to_end_wall_seconds": engine_wall,
                "engine_end_to_end_cpu_seconds": engine_cpu,
                "inference_or_formal_analysis_wall_seconds": (
                    0.0 if benchmark == "F0" else engine_wall
                ),
                "detection_wall_seconds": engine_wall if benchmark == "F0" else 0.0,
                "statistics_probe_wall_seconds": statistics_wall,
                "statistics_probe_cpu_seconds": statistics_cpu,
                "serialization_wall_seconds": serialization_wall,
                "serialization_cpu_seconds": serialization_cpu,
                "write_wall_seconds": write_wall,
                "write_cpu_seconds": write_cpu,
                "serialized_bytes": len(serialized),
                "on_disk_bytes": on_disk_bytes,
                "peak_rss_platform_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                "recommended_timeout_seconds": max(30, math.ceil(engine_wall * 10.0)),
                "failure_output_preservation_required": True,
            }
        )
    total_storage = sum(int(record["on_disk_bytes"]) for record in records)
    total_wall = sum(float(record["engine_end_to_end_wall_seconds"]) for record in records)
    return {
        "schema_version": "1",
        "label": PUBLIC_MOCK_ROLE_LABEL,
        "evidence_scope": "BENCHMARK_SPECIFIC_RESOURCE_PREFLIGHT_NOT_SCIENTIFIC_EVIDENCE",
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "role_commitment_sha256": role_manifest["commitment_sha256"],
        "hardware_contract": {
            "compute": "CPU_ONLY",
            "threads": 1,
            "gpu": False,
            "timing_method": "time.perf_counter and time.process_time",
            "rss_method": "resource.getrusage(RUSAGE_SELF).ru_maxrss",
        },
        "records": records,
        "total_engine_wall_seconds_sequential": total_wall,
        "total_serialized_bytes": total_storage,
        "dominant_wall_benchmark": max(
            records,
            key=lambda record: float(record["engine_end_to_end_wall_seconds"]),
        )["benchmark"],
        "dominant_storage_benchmark": max(
            records,
            key=lambda record: int(record["on_disk_bytes"]),
        )["benchmark"],
        "protected_execution_performed": False,
        "a0_preflight_status": a0["status"],
        "protocol_status": protocol["status"],
    }
