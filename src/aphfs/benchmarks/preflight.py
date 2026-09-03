"""Outcome-blind, benchmark-agnostic CPU and memory preflight."""

from __future__ import annotations

import copy
import os
import platform
import resource
import sys
import time
from typing import Any

import numpy as np

from aphfs.constants import DEVELOPMENT_LABEL
from aphfs.eca.core import simulate_vectorized


def _neutral_throughput(
    *,
    width: int,
    steps: int,
    repetitions: int,
    seed: int,
) -> dict[str, float]:
    rng = np.random.default_rng(seed)
    initial = rng.integers(0, 2, size=width, dtype=np.uint8)
    start = time.perf_counter()
    for _ in range(repetitions):
        simulate_vectorized(30, initial, steps, "periodic")
    elapsed = time.perf_counter() - start
    candidate_cell_steps = width * steps * repetitions
    return {
        "width": float(width),
        "steps": float(steps),
        "repetitions": float(repetitions),
        "candidate_cell_steps": float(candidate_cell_steps),
        "elapsed_seconds": elapsed,
        "candidate_cell_steps_per_second": candidate_cell_steps / max(elapsed, 1e-12),
    }


def _estimate_row(
    sub_id: str,
    candidate_step_operations: int,
    cell_steps_per_candidate_step: int,
    throughput: float,
    conservative_efficiency: float,
    bytes_per_candidate_step: int,
    width: int,
    horizon: int,
    candidate_timeout_seconds: int,
    timeout_unit_count: int,
) -> dict[str, Any]:
    total_cell_steps = candidate_step_operations * cell_steps_per_candidate_step
    cpu_seconds = total_cell_steps / throughput
    cpu_hours = cpu_seconds / 3600.0
    return {
        "sub_id": sub_id,
        "candidate_step_operations": candidate_step_operations,
        "estimated_candidate_cell_steps": total_cell_steps,
        "estimated_cpu_hours": cpu_hours,
        "estimated_wall_hours_4_core": cpu_hours / (4.0 * conservative_efficiency),
        "estimated_wall_hours_8_core": cpu_hours / (8.0 * conservative_efficiency),
        "estimated_storage_bytes": candidate_step_operations * bytes_per_candidate_step,
        "estimated_peak_memory_bytes_single_worker": 2 * width * (horizon + 1) + 1024 * 1024,
        "timeout_unit_count": timeout_unit_count,
        "worst_case_timeout_burden_seconds": candidate_timeout_seconds * timeout_unit_count,
    }


def run_resource_preflight(
    development_config: dict[str, Any],
    proposed_protocol: dict[str, Any],
    *,
    seed: int,
) -> dict[str, Any]:
    preflight = development_config["preflight"]
    measurements = [
        _neutral_throughput(
            width=int(profile["width"]),
            steps=int(profile["steps"]),
            repetitions=int(profile["repetitions"]),
            seed=seed + index,
        )
        for index, profile in enumerate(preflight["neutral_profiles"])
    ]
    throughput = min(row["candidate_cell_steps_per_second"] for row in measurements)
    efficiency = float(preflight["parallel_efficiency"])
    estimates = []
    for sub_id, profile in proposed_protocol["subbenchmarks"].items():
        estimates.append(
            _estimate_row(
                sub_id,
                int(profile["candidate_step_operations"]),
                int(profile["cell_steps_per_candidate_step"]),
                throughput,
                efficiency,
                int(profile["bytes_per_candidate_step"]),
                int(profile["width"]),
                int(profile["horizon"]),
                int(profile["candidate_timeout_seconds"]),
                int(profile["timeout_unit_count"]),
            )
        )
    total_cpu = sum(float(row["estimated_cpu_hours"]) for row in estimates)
    total_storage = sum(int(row["estimated_storage_bytes"]) for row in estimates)
    maximum_history = max(
        int(profile["width"]) * (int(profile["horizon"]) + 1)
        for profile in proposed_protocol["subbenchmarks"].values()
    )
    lower_resource = copy.deepcopy(proposed_protocol["lower_resource_option"])
    return {
        "label": DEVELOPMENT_LABEL,
        "preflight_type": "BENCHMARK_AGNOSTIC_OUTCOME_BLIND",
        "status": "PASS",
        "hardware": {
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "logical_cpu_count": os.cpu_count(),
            "thread_environment": {
                name: os.environ.get(name, "unset")
                for name in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
            },
            "peak_rss_units": "bytes on Linux; bytes on macOS as reported below",
            "observed_peak_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        },
        "neutral_measurements": measurements,
        "conservative_throughput_candidate_cell_steps_per_second": throughput,
        "parallel_efficiency_assumption": efficiency,
        "by_subbenchmark": estimates,
        "aggregate": {
            "estimated_cpu_hours": total_cpu,
            "estimated_wall_hours_4_core": total_cpu / (4.0 * efficiency),
            "estimated_wall_hours_8_core": total_cpu / (8.0 * efficiency),
            "estimated_storage_bytes": total_storage,
            "estimated_peak_history_bytes_single_worker": maximum_history,
            "worst_case_timeout_burden_seconds": sum(
                int(profile["candidate_timeout_seconds"])
                * int(profile["timeout_unit_count"])
                for profile in proposed_protocol["subbenchmarks"].values()
            ),
        },
        "finite_precision_policy": {
            "rule": "use lowest fidelity preserving registered decision",
            "escalation_only_on_frozen_triggers": True,
            "triggers": proposed_protocol["refinement_triggers"],
        },
        "lower_resource_option": lower_resource,
        "exact_proposed_final_configuration": proposed_protocol,
        "calibration_or_locked_execution": False,
        "calibration_or_locked_seed_generation": False,
    }
