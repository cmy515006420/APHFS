"""B0 in-class control and B1 witnessed out-of-class diagnostics."""

from __future__ import annotations

from typing import Any

import numpy as np
import numpy.typing as npt

from aphfs.bounds.statistics import AlphaLedger, one_sided_lower_loss
from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE
from aphfs.inference.inadequacy import decide_class_inadequacy


def run_b0(config: dict[str, Any], rng: np.random.Generator) -> dict[str, Any]:
    candidate_count = int(config["candidate_count"])
    sample_size = int(config["sample_size"])
    threshold = float(config["threshold"])
    losses: dict[str, float | None] = {}
    classes: dict[str, tuple[str, ...]] = {}
    alpha = AlphaLedger(global_alpha=float(config["global_alpha"]))
    expected = set()
    for index in range(candidate_count):
        candidate = f"b0:{index:03d}"
        empirical = float(rng.beta(2.0, 8.0))
        look_alpha = alpha.allocate(
            candidate,
            "inadequacy",
            1,
            candidates=candidate_count,
            gates=1,
        )
        losses[candidate] = one_sided_lower_loss(empirical, sample_size, look_alpha)
        classes[candidate] = (candidate,)
        expected.add((candidate, "inadequacy", 1))
    decision = decide_class_inadequacy(
        candidate_bounds=losses,
        classes=classes,
        threshold=threshold,
        alpha_ledger_complete=alpha.is_complete(expected),
    )
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "workload_scope": "BETA_RANDOM_ENGINEERING_FIXTURE_NOT_CONFIRMATORY_B0",
        "sub_id": "B0",
        "status": "PASS" if decision.status == "RETAIN_CLASS" else "UNFAVORABLE",
        "decision": decision.status,
        "reason": decision.reason,
        "candidate_coverage": len(losses),
        "alpha_total": alpha.total_allocated,
    }


def radius_two_generator(neighborhood: npt.ArrayLike) -> int:
    values = np.asarray(neighborhood, dtype=np.uint8)
    if values.shape != (5,) or not np.all((values == 0) | (values == 1)):
        raise ValueError("B1 generator requires one binary radius-two neighborhood")
    return int(values[0] ^ values[4])


def b1_witness() -> dict[str, Any]:
    first = np.array([0, 0, 0, 0, 0], dtype=np.uint8)
    second = np.array([1, 0, 0, 0, 0], dtype=np.uint8)
    same_declared_interface = np.array_equal(first[1:4], second[1:4])
    outputs = (radius_two_generator(first), radius_two_generator(second))
    distinguishable = same_declared_interface and outputs[0] != outputs[1]
    return {
        "first_probe": first.tolist(),
        "second_probe": second.tolist(),
        "shared_radius_one_neighborhood": first[1:4].tolist(),
        "generator_outputs": list(outputs),
        "distinguishable_on_registered_witness_interface": distinguishable,
    }


def run_b1() -> dict[str, Any]:
    witness = b1_witness()
    distinguishable = bool(witness["distinguishable_on_registered_witness_interface"])
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "B1",
        "status": "PASS" if distinguishable else "OBSERVATIONAL_EQUIVALENCE",
        "classification": (
            "CONSTRUCTED_OUT_OF_CLASS" if distinguishable else "OBSERVATIONAL_EQUIVALENCE"
        ),
        "witness": witness,
    }
