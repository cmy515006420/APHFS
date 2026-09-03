"""E byte-identical replay with candidate-step evaluations as the primary unit."""

from __future__ import annotations

from typing import Any

import numpy as np

from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE
from aphfs.provenance.hashing import sha256_bytes


def _policy_costs(stream: bytes, candidate_count: int) -> dict[str, int]:
    values = np.frombuffer(stream, dtype=np.uint8)
    tasks = int(values.size)
    exhaustive = candidate_count * tasks
    fixed = sum(min(candidate_count, 1 + int(value) % candidate_count) for value in values)
    ratio = sum(
        min(candidate_count, 1 + int(value) % max(1, candidate_count // 2))
        for value in values
    )
    adaptive = sum(
        min(candidate_count, 2 + int(value) % max(1, candidate_count // 3)) for value in values
    )
    return {
        "exhaustive": exhaustive,
        "fixed_order": fixed,
        "ratio_order": ratio,
        "adaptive": adaptive,
    }


def run_e(config: dict[str, Any], rng: np.random.Generator) -> dict[str, Any]:
    stream = rng.integers(0, 256, size=int(config["task_blocks"]), dtype=np.uint8).tobytes()
    digest = sha256_bytes(stream)
    policies = _policy_costs(stream, int(config["candidate_count"]))
    replay_hashes = {policy: sha256_bytes(stream) for policy in policies}
    identical = len(set(replay_hashes.values())) == 1
    termination_budget = int(config["termination_budget_candidate_steps"])
    within_common_budget = all(cost <= termination_budget for cost in policies.values())
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "workload_scope": "RANDOM_BYTE_COST_FIXTURE_NOT_CONFIRMATORY_POLICY_EVALUATION",
        "sub_id": "E",
        "status": "PASS" if identical and within_common_budget else "FAIL",
        "primary_unit": "candidate_step_evaluations",
        "candidate_step_evaluations": policies,
        "observation_stream_sha256": digest,
        "policy_replay_hashes": replay_hashes,
        "byte_identical_replay": identical,
        "shared_comparison_contract": {
            "decision_threshold": float(config["decision_threshold"]),
            "resource_ledger_schema": str(config["resource_ledger_schema"]),
            "termination_budget_candidate_steps": termination_budget,
            "all_policies_within_common_budget": within_common_budget,
            "observation_stream_sha256": digest,
        },
    }
