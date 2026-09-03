"""C formal formula validation on constructed scalar systems."""

from __future__ import annotations

from typing import Any

from aphfs.coarse_graining.formal import run_constructed_scalar_case
from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE


def run_c(config: dict[str, Any]) -> dict[str, Any]:
    cases = []
    violations = 0
    for multiplier in config["candidate_multipliers"]:
        case = run_constructed_scalar_case(
            reference_multiplier=float(config["reference_multiplier"]),
            candidate_multiplier=float(multiplier),
            initial_reference=float(config["initial_reference"]),
            initial_candidate=float(config["initial_candidate"]),
            steps=int(config["steps"]),
        )
        case["candidate_multiplier"] = float(multiplier)
        if case["slack"] < -1e-12:
            violations += 1
        cases.append(case)
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "C",
        "status": "PASS" if violations == 0 else "FAIL",
        "module_scope": "CONSTRUCTED_SCALAR_FORMAL_VALIDATION_NOT_ECA_EVIDENCE",
        "cases": cases,
        "verified_bound_violations": violations,
    }
