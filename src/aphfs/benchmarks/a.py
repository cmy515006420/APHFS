"""A0 conformance and A1 outcome-blind recovery diagnostics."""

from __future__ import annotations

from typing import Any

import numpy as np
import numpy.typing as npt

from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE
from aphfs.eca.core import (
    Boundary,
    rule_output,
    rule_truth_table,
    simulate_reference,
    simulate_vectorized,
)
from aphfs.eca.inference import TransitionObservations, recover_consistent_rules
from aphfs.signatures.canonical import SignatureSpec, canonical_signature

SIGNATURE_SPEC = SignatureSpec(
    version="eca-signature-v1",
    probe_order=("single-center", "alternating"),
    summary_schema=("final-density", "trajectory-density"),
    quantizer_boundaries=(0.125, 0.25, 0.5, 0.75, 0.875),
)


def _probe_states(width: int) -> tuple[npt.NDArray[np.uint8], npt.NDArray[np.uint8]]:
    single = np.zeros(width, dtype=np.uint8)
    single[width // 2] = 1
    alternating = np.arange(width, dtype=np.uint8) % 2
    return single, alternating


def _summary(history: npt.NDArray[np.uint8]) -> tuple[float, float]:
    return float(history[-1].mean()), float(history.mean())


def run_a0(config: dict[str, Any]) -> tuple[dict[str, Any], dict[int, str]]:
    width = int(config["width"])
    steps = int(config["steps"])
    boundaries: tuple[Boundary, ...] = tuple(config["boundaries"])
    probes = _probe_states(width)
    signatures: dict[int, str] = {}
    mismatches = []
    candidate_steps = 0
    for rule_id in range(256):
        table = rule_truth_table(rule_id)
        for neighborhood in range(8):
            bits = ((neighborhood >> 2) & 1, (neighborhood >> 1) & 1, neighborhood & 1)
            if rule_output(rule_id, *bits) != table[neighborhood]:
                mismatches.append(f"truth-table:{rule_id}:{neighborhood}")
        signature_values: list[float] = []
        for boundary in boundaries:
            for probe in probes:
                reference = simulate_reference(rule_id, probe, steps, boundary)
                vectorized = simulate_vectorized(rule_id, probe, steps, boundary)
                candidate_steps += steps * width
                if not np.array_equal(reference, vectorized):
                    mismatches.append(f"simulator:{rule_id}:{boundary}")
                if boundary == "periodic":
                    signature_values.extend(_summary(vectorized))
        signatures[rule_id] = canonical_signature(signature_values, SIGNATURE_SPEC)
    return (
        {
            "label": DEVELOPMENT_LABEL,
            "engine_scope": ENGINEERING_FIXTURE_SCOPE,
            "sub_id": "A0",
            "status": "PASS" if not mismatches else "FAIL",
            "truth_tables_checked": 256,
            "neighborhoods_per_rule": 8,
            "boundaries": list(boundaries),
            "registered_initial_conditions": len(probes),
            "candidate_step_evaluations": candidate_steps,
            "mismatches": mismatches,
            "signature_spec_version": SIGNATURE_SPEC.version,
            "unique_signature_count": len(set(signatures.values())),
        },
        signatures,
    )


def _full_transition_observations(
    rule_id: int,
) -> TransitionObservations:
    previous = np.zeros((8, 5), dtype=np.uint8)
    for neighborhood in range(8):
        previous[neighborhood, 1:4] = (
            (neighborhood >> 2) & 1,
            (neighborhood >> 1) & 1,
            neighborhood & 1,
        )
    following = np.vstack(
        [
            simulate_vectorized(rule_id, row, 1, "fixed_zero")[1]
            for row in previous
        ]
    )
    return TransitionObservations(previous, following, "fixed_zero")


def run_a1(config: dict[str, Any], development_rules: tuple[int, ...]) -> dict[str, Any]:
    recovered: dict[str, list[int]] = {}
    exact = True
    for generating_rule in development_rules:
        observations = _full_transition_observations(generating_rule)
        consistent = recover_consistent_rules(observations)
        recovered[str(generating_rule)] = list(consistent)
        exact = exact and consistent == (generating_rule,)
    coarse_generating_rule = int(config["coarse_probe_rule"])
    initial = _probe_states(int(config["width"]))[0]
    target_density = float(
        simulate_vectorized(
            coarse_generating_rule,
            initial,
            int(config["steps"]),
            "periodic",
        )[-1].mean()
    )
    coarse_candidates = []
    for candidate in range(256):
        density = float(
            simulate_vectorized(
                candidate,
                initial,
                int(config["steps"]),
                "periodic",
            )[-1].mean()
        )
        if density == target_density:
            coarse_candidates.append(candidate)
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "A1",
        "status": "PASS" if exact and coarse_generating_rule in coarse_candidates else "FAIL",
        "full_transition_recovery": recovered,
        "full_transition_exact": exact,
        "coarse_observational_candidate_count": len(coarse_candidates),
        "coarse_observational_equivalence": len(coarse_candidates) > 1,
        "sealed_ground_truth_read_by_inference": False,
    }
