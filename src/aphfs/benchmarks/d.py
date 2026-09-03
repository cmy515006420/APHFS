"""D0 identity, D1 counterexample, and D2 finite-memory repair diagnostics."""

from __future__ import annotations

from aphfs.coarse_graining.memory import (
    coarse_state,
    counterexample_pair,
    identity_discrepancy,
    micro_step,
    validate_memory_repair,
)
from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE


def run_d0() -> dict[str, object]:
    discrepancies = [identity_discrepancy((a, b)) for a in (0, 1) for b in (0, 1)]
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "D0",
        "status": "PASS" if max(discrepancies) == 0 else "FAIL",
        "maximum_exact_identity_discrepancy": max(discrepancies),
        "calibration_attempted": False,
    }


def run_d1() -> dict[str, object]:
    left, right = counterexample_pair()
    next_values = (coarse_state(micro_step(left)), coarse_state(micro_step(right)))
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "D1",
        "status": "PASS" if next_values[0] != next_values[1] else "FAIL",
        "microstate_pair": [list(left), list(right)],
        "shared_coarse_state": coarse_state(left),
        "next_coarse_values": list(next_values),
        "calibration_attempted": False,
    }


def run_d2() -> dict[str, object]:
    trajectory = ((0, 1), (1, 0), (0, 1), (1, 0), (0, 1))
    repaired = validate_memory_repair(trajectory)
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "D2",
        "status": "PASS" if repaired else "FAIL",
        "finite_memory_lag": 1,
        "exact_repair_on_constructed_fixture": repaired,
        "certificate_granted": False,
        "calibration_attempted": False,
    }
