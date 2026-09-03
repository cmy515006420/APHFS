"""Phase 1B final-freeze benchmark engines.

Every stochastic-looking result in this module is a PUBLIC_MOCK dry run.  The
same functions are wired into the protected-shaped pipeline, but actual
protected roles remain fail-closed until a later signed authorization.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Any, cast

import numpy as np
import numpy.typing as npt

from aphfs.benchmarks.a import run_a0
from aphfs.bounds.statistics import (
    clopper_pearson_lower,
    clopper_pearson_two_sided,
    clopper_pearson_upper,
)
from aphfs.constants import CONFIRMATORY_MOCK_ENGINE_SCOPE, PUBLIC_MOCK_ROLE_LABEL
from aphfs.eca.core import (
    Boundary,
    rule_truth_table,
    simulate_reference,
    simulate_vectorized,
    step_reference,
    step_vectorized,
)
from aphfs.inference.inadequacy import decide_class_inadequacy
from aphfs.provenance.hashing import sha256_bytes, sha256_json

UInt8Array = npt.NDArray[np.uint8]
FROZEN_ROLE_DERIVATION = "APHFS-PROTOCOL-V6-DOMAIN-SEPARATED-SHA256"


def _base_result(
    sub_id: str,
    *,
    role: str,
    numerator: int,
    denominator: int,
    candidate_coverage: int,
) -> dict[str, Any]:
    protected_execution = role in {"calibration", "locked"}
    deterministic = role in {"deterministic_conformance", "deterministic_grid"}
    evidence_label = (
        "PROTECTED_RESULT"
        if protected_execution
        else (
            "FROZEN_DETERMINISTIC_CONFORMANCE"
            if deterministic
            else PUBLIC_MOCK_ROLE_LABEL
        )
    )
    return {
        "label": "PROTECTED_RESULT" if protected_execution else PUBLIC_MOCK_ROLE_LABEL,
        "evidence_label": evidence_label,
        "sub_id": sub_id,
        "role": role,
        "engine_scope": (
            "PROTECTED_CONFIRMATORY_ENGINE"
            if protected_execution
            else (
                "FROZEN_DETERMINISTIC_CONFORMANCE"
                if deterministic
                else CONFIRMATORY_MOCK_ENGINE_SCOPE
            )
        ),
        "manuscript_evidence": protected_execution,
        "numerator": numerator,
        "denominator": denominator,
        "candidate_coverage": candidate_coverage,
    }


def _digest(benchmark: str, purpose: str, value: int) -> bytes:
    payload = f"{FROZEN_ROLE_DERIVATION}|{benchmark}|{purpose}|{value}".encode()
    return hashlib.sha256(payload).digest()


def _derived_rule(benchmark: str, value: int) -> int:
    return int(_digest(benchmark, "truth-rule", value)[0])


def _public_state(value: int, width: int, benchmark: str) -> UInt8Array:
    bits = bytearray()
    counter = 0
    while len(bits) * 8 < width:
        bits.extend(_digest(benchmark, f"initial-state-{counter}", value))
        counter += 1
    return np.unpackbits(np.frombuffer(bytes(bits), dtype=np.uint8))[:width].astype(
        np.uint8,
        copy=False,
    )


def _derived_boundary(value: int) -> Boundary:
    choices: tuple[Boundary, ...] = ("periodic", "fixed_zero", "fixed_one", "reflect")
    return choices[int(_digest("A1", "boundary", value)[0]) % len(choices)]


def _candidate_losses_vectorized(
    history: UInt8Array,
    boundary: Boundary,
) -> dict[str, float]:
    target = history[1:]
    return {
        f"eca:{rule_id:03d}": float(
            np.mean(
                np.vstack(
                    [
                        step_vectorized(rule_id, previous, boundary)
                        for previous in history[:-1]
                    ]
                )
                != target
            )
        )
        for rule_id in range(256)
    }


def _candidate_losses_scalar(
    history: UInt8Array,
    boundary: Boundary,
) -> dict[str, float]:
    target = history[1:]
    losses: dict[str, float] = {}
    for rule_id in range(256):
        mismatches = 0
        total = 0
        for previous, following in zip(history[:-1], target, strict=True):
            predicted = step_reference(rule_id, previous, boundary)
            for observed, expected in zip(predicted, following, strict=True):
                mismatches += int(observed != expected)
                total += 1
        losses[f"eca:{rule_id:03d}"] = mismatches / total
    return losses


def _singleton_classes() -> dict[str, tuple[str, ...]]:
    return {f"class:{rule_id:03d}": (f"eca:{rule_id:03d}",) for rule_id in range(256)}


def _fidelity_record(
    *,
    benchmark: str,
    block_id: str,
    registered_source: str,
    reference_source: str,
    registered_settings: dict[str, Any],
    reference_settings: dict[str, Any],
    registered_observable: Any,
    reference_observable: Any,
    registered_decision: str,
    reference_decision: str,
    tolerance: float = 0.0,
) -> dict[str, Any]:
    observable_changed = registered_observable != reference_observable
    decision_changed = registered_decision != reference_decision
    stable = not observable_changed and not decision_changed
    return {
        "contract_version": "protected-fidelity-v2",
        "benchmark": benchmark,
        "block_id": block_id,
        "registered_tier": {
            "source_path": registered_source,
            "settings": registered_settings,
            "settings_sha256": sha256_json(registered_settings),
            "observable": registered_observable,
            "decision": registered_decision,
        },
        "reference_tier": {
            "source_path": reference_source,
            "settings": reference_settings,
            "settings_sha256": sha256_json(reference_settings),
            "observable": reference_observable,
            "decision": reference_decision,
        },
        "observable_tolerance": tolerance,
        "observable_changed_beyond_tolerance": observable_changed,
        "decision_changed": decision_changed,
        "same_observation_unit_coupling": True,
        "further_refinement_required": not stable,
        "status": "PASS" if stable else "FIDELITY_INDETERMINATE",
    }


def _cp_summary(events: int, trials: int) -> dict[str, Any]:
    if trials < 1:
        return {
            "exact_two_sided_95_interval": None,
            "exact_one_sided_95_upper": None,
        }
    return {
        "exact_two_sided_95_interval": list(
            clopper_pearson_two_sided(events, trials, 0.05)
        ),
        "exact_one_sided_95_upper": clopper_pearson_upper(events, trials, 0.05),
    }


def run_confirmatory_a0(config: dict[str, Any]) -> tuple[dict[str, Any], dict[int, str]]:
    """Verify all 256 rule tables, numbering, boundaries, and simulators."""
    fixture, signatures = run_a0(config)
    result = _base_result(
        "A0",
        role="deterministic_conformance",
        numerator=len(fixture["mismatches"]),
        denominator=256,
        candidate_coverage=256,
    )
    candidate_ledger = [
        {
            "candidate_id": f"eca:{rule_id:03d}",
            "rule_id": rule_id,
            "execution_status": "EXECUTED",
            "failure_code": None,
            "canonical_signature": signatures[rule_id],
            "truth_table_000_to_111": list(rule_truth_table(rule_id)),
        }
        for rule_id in range(256)
    ]
    result.update(
        {
            "status": fixture["status"],
            "rule_id_semantics": "Wolfram integer; bit index is neighborhood 000..111",
            "boundaries": fixture["boundaries"],
            "independent_reference_production_match": not fixture["mismatches"],
            "terminal_candidate_ledger_count": len(candidate_ledger),
            "candidate_ledger": candidate_ledger,
            "block_records": candidate_ledger,
            "fidelity_records": [
                {
                    "status": "PASS" if not fixture["mismatches"] else "FIDELITY_INDETERMINATE",
                    "registered_source": "aphfs.eca.core.simulate_vectorized",
                    "reference_source": "aphfs.eca.core.simulate_reference",
                    "all_256_rules": True,
                }
            ],
            "failure_ledger": list(fixture["mismatches"]),
            "canonical_signature_count": len(set(signatures.values())),
        }
    )
    return result, signatures


def run_confirmatory_a1(
    config: dict[str, Any],
    values: list[int],
    signatures: dict[int, str],
) -> dict[str, Any]:
    """Evaluate the registered 64-block grammar recovery failure estimand."""
    threshold = float(config["retention_threshold"])
    width = int(config["registered_tier"]["width"])
    horizon = int(config["registered_tier"]["horizon"])
    signature_classes: dict[str, list[str]] = {}
    for rule_id, signature in signatures.items():
        signature_classes.setdefault(signature, []).append(f"eca:{rule_id:03d}")
    block_records: list[dict[str, Any]] = []
    fidelity_records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for block_index, value in enumerate(values):
        truth_rule = _derived_rule("A1", value)
        boundary = _derived_boundary(value)
        initial = _public_state(value, width, "A1")
        history = simulate_reference(truth_rule, initial, horizon, boundary)
        registered_losses = _candidate_losses_vectorized(history, boundary)
        reference_losses = _candidate_losses_scalar(history, boundary)
        if config.get("inject_fidelity_mismatch") and block_index == 0:
            reference_losses["eca:000"] += 1.0
        missing_candidate = config.get("inject_missing_candidate")
        if missing_candidate is not None and block_index == 0:
            registered_losses.pop(f"eca:{int(missing_candidate):03d}", None)
        registered_retained = sorted(
            candidate
            for candidate, loss in registered_losses.items()
            if loss <= threshold
        )
        reference_retained = sorted(
            candidate
            for candidate, loss in reference_losses.items()
            if loss <= threshold
        )
        block_id = f"A1:{block_index:03d}"
        fidelity = _fidelity_record(
            benchmark="A1",
            block_id=block_id,
            registered_source="aphfs.benchmarks.final_freeze._candidate_losses_vectorized",
            reference_source="aphfs.benchmarks.final_freeze._candidate_losses_scalar",
            registered_settings={"evaluator": "vectorized", "width": width, "horizon": horizon},
            reference_settings={
                "evaluator": "independent_scalar",
                "width": width,
                "horizon": horizon,
            },
            registered_observable=sha256_json(registered_losses),
            reference_observable=sha256_json(reference_losses),
            registered_decision=sha256_json(registered_retained),
            reference_decision=sha256_json(reference_retained),
        )
        fidelity_records.append(fidelity)
        truth_candidate = f"eca:{truth_rule:03d}"
        truth_signature = signatures[truth_rule]
        retained_signatures = sorted(
            {
                signatures[int(candidate.split(":")[1])]
                for candidate in registered_retained
            }
        )
        candidate_complete = len(registered_losses) == 256
        signature_complete = (
            len(signatures) == 256
            and sum(len(members) for members in signature_classes.values()) == 256
        )
        failure_code: str | None = None
        if not candidate_complete or not signature_complete:
            failure_code = "INCOMPLETE_CANDIDATE_OR_SIGNATURE_LEDGER"
        elif fidelity["status"] != "PASS":
            failure_code = "FIDELITY_INDETERMINATE"
        elif (
            truth_candidate not in registered_retained
            or truth_signature not in retained_signatures
        ):
            failure_code = "TRUE_CANDIDATE_OR_CLASS_NOT_RETAINED"
        failed = failure_code is not None
        if failed:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        block_records.append(
            {
                "block_id": block_id,
                "role_value_commitment": sha256_json({"role_value": value}),
                "truth_rule_generator_only": truth_rule,
                "boundary": boundary,
                "initial_state_sha256": sha256_bytes(initial.tobytes()),
                "observation_stream_sha256": sha256_bytes(history.tobytes()),
                "candidate_losses": registered_losses,
                "candidate_count": len(registered_losses),
                "retained_candidates": registered_retained,
                "truth_candidate_retained": truth_candidate in registered_retained,
                "truth_signature_class": truth_signature,
                "retained_signature_classes": retained_signatures,
                "truth_class_retained": truth_signature in retained_signatures,
                "signature_ledger_complete": signature_complete,
                "candidate_ledger_complete": candidate_complete,
                "candidate_loss_semantics": "exact mismatch on this finite registered block",
                "iid_sample_size_claimed": False,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
                "failure_event": failed,
            }
        )
    result = _base_result(
        "A1",
        role=str(config.get("role", "public_mock")),
        numerator=len(failures),
        denominator=len(values),
        candidate_coverage=256,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "estimand": "block-level true-candidate/class retention failure probability",
            "observation_unit": "one role-derived truth-rule/initial-state/environment block",
            "block_records": block_records,
            "fidelity_records": fidelity_records,
            "failure_ledger": failures,
            "registered_signature_classes": signature_classes,
            "block_level_alpha": 0.05,
            "cell_time_iid_assumption": False,
            "sealed_truth_read_by_inference": False,
            **_cp_summary(len(failures), len(values)),
        }
    )
    return result


def _binary_string_output(rule_id: int, left: int, center: int, right: int) -> int:
    neighborhood = f"{left}{center}{right}"
    order = ("111", "110", "101", "100", "011", "010", "001", "000")
    return int(f"{rule_id:08b}"[order.index(neighborhood)])


def _b0_vector_losses(truth_rule: int) -> dict[str, float]:
    truth = rule_truth_table(truth_rule)
    return {
        f"eca:{candidate:03d}": sum(
            a != b
            for a, b in zip(rule_truth_table(candidate), truth, strict=True)
        )
        / 8.0
        for candidate in range(256)
    }


def _b0_scalar_losses(truth_rule: int) -> dict[str, float]:
    observed = [
        _binary_string_output(truth_rule, (code >> 2) & 1, (code >> 1) & 1, code & 1)
        for code in range(8)
    ]
    losses: dict[str, float] = {}
    for candidate in range(256):
        predicted = [
            _binary_string_output(candidate, (code >> 2) & 1, (code >> 1) & 1, code & 1)
            for code in range(8)
        ]
        losses[f"eca:{candidate:03d}"] = (
            sum(a != b for a, b in zip(predicted, observed, strict=True)) / 8.0
        )
    return losses


def run_confirmatory_b0(config: dict[str, Any], values: list[int]) -> dict[str, Any]:
    """In-class exact finite-support control, with block-level false-rejection endpoint."""
    threshold = float(config["inadequacy_threshold"])
    blocks: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        truth_rule = _derived_rule("B0", value)
        registered = _b0_vector_losses(truth_rule)
        reference = _b0_scalar_losses(truth_rule)
        if config.get("inject_fidelity_mismatch") and index == 0:
            reference["eca:000"] += 0.125
        missing = config.get("inject_missing_candidate")
        if missing is not None and index == 0:
            registered.pop(f"eca:{int(missing):03d}", None)
        complete = len(registered) == 256
        decision = decide_class_inadequacy(
            candidate_bounds=cast(dict[str, float | None], registered),
            classes=_singleton_classes(),
            threshold=threshold,
            alpha_ledger_complete=complete,
        )
        reference_decision = decide_class_inadequacy(
            candidate_bounds=cast(dict[str, float | None], reference),
            classes=_singleton_classes(),
            threshold=threshold,
            alpha_ledger_complete=len(reference) == 256,
        )
        block_id = f"B0:{index:03d}"
        fidelity = _fidelity_record(
            benchmark="B0",
            block_id=block_id,
            registered_source="aphfs.benchmarks.final_freeze._b0_vector_losses",
            reference_source="aphfs.benchmarks.final_freeze._b0_scalar_losses",
            registered_settings={"evaluator": "bit_index", "support": 8},
            reference_settings={"evaluator": "explicit_binary_string_scalar", "support": 8},
            registered_observable=sha256_json(registered),
            reference_observable=sha256_json(reference),
            registered_decision=decision.status,
            reference_decision=reference_decision.status,
        )
        fidelities.append(fidelity)
        failure_code: str | None = None
        if not complete:
            failure_code = "INCOMPLETE_CANDIDATE_LEDGER"
        elif fidelity["status"] != "PASS":
            failure_code = "FIDELITY_INDETERMINATE"
        elif decision.status == "MODEL_CLASS_INADEQUATE":
            failure_code = "FALSE_MODEL_CLASS_INADEQUATE"
        elif decision.status == "INDETERMINATE":
            failure_code = "INDETERMINATE"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        blocks.append(
            {
                "block_id": block_id,
                "role_value_commitment": sha256_json({"role_value": value}),
                "truth_rule_generator_only": truth_rule,
                "support_size": 8,
                "support_is_complete_finite_population": True,
                "candidate_losses": registered,
                "candidate_exact_lower_bounds": registered,
                "candidate_count": len(registered),
                "alpha_method": "EXACT_FINITE_SUPPORT_NO_SAMPLING",
                "alpha_ledger_complete": complete,
                "decision": decision.status,
                "class_lower_bounds": decision.class_bounds,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
                "failure_event": failure_code is not None,
            }
        )
    result = _base_result(
        "B0",
        role=str(config.get("role", "public_mock")),
        numerator=len(failures),
        denominator=len(values),
        candidate_coverage=256,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "estimand": "block-level false MODEL_CLASS_INADEQUATE probability",
            "observation_unit": "one role-derived in-class complete truth-table block",
            "block_records": blocks,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
            "false_inadequacy_events": sum(
                row["failure_code"] == "FALSE_MODEL_CLASS_INADEQUATE" for row in blocks
            ),
            **_cp_summary(len(failures), len(values)),
        }
    )
    return result


def _theta(value: int) -> tuple[int, ...]:
    number = int(_digest("B1", "theta", value)[0])
    return tuple((number >> index) & 1 for index in range(8))


def _b1_vector_losses(theta: tuple[int, ...]) -> tuple[dict[str, float], str]:
    support = np.array(
        [[(code >> shift) & 1 for shift in (4, 3, 2, 1, 0)] for code in range(32)],
        dtype=np.uint8,
    )
    central = (support[:, 1] << 2) | (support[:, 2] << 1) | support[:, 3]
    observed = support[:, 0] ^ support[:, 4] ^ np.asarray(theta, dtype=np.uint8)[central]
    losses: dict[str, float] = {}
    for candidate in range(256):
        predicted = (candidate >> central) & 1
        losses[f"eca:{candidate:03d}"] = float(np.mean(predicted != observed))
    return losses, sha256_bytes(np.column_stack((support, observed)).tobytes())


def _b1_scalar_losses(theta: tuple[int, ...]) -> dict[str, float]:
    losses: dict[str, float] = {}
    for candidate in range(256):
        mistakes = 0
        for code in range(32):
            bits = tuple((code >> shift) & 1 for shift in (4, 3, 2, 1, 0))
            central_index = (bits[1] << 2) | (bits[2] << 1) | bits[3]
            observed = bits[0] ^ bits[4] ^ theta[central_index]
            predicted = _binary_string_output(candidate, bits[1], bits[2], bits[3])
            mistakes += int(observed != predicted)
        losses[f"eca:{candidate:03d}"] = mistakes / 32.0
    return losses


def run_confirmatory_b1(config: dict[str, Any], values: list[int]) -> dict[str, Any]:
    """Distinguishable role-derived radius-two family with exact per-block losses."""
    threshold = float(config["inadequacy_threshold"])
    blocks: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        theta = _theta(value)
        registered, support_hash = _b1_vector_losses(theta)
        reference = _b1_scalar_losses(theta)
        if config.get("inject_fidelity_mismatch") and index == 0:
            reference["eca:000"] += 1.0 / 32.0
        missing = config.get("inject_missing_candidate")
        if missing is not None and index == 0:
            registered.pop(f"eca:{int(missing):03d}", None)
        complete = len(registered) == 256
        decision = decide_class_inadequacy(
            candidate_bounds=cast(dict[str, float | None], registered),
            classes=_singleton_classes(),
            threshold=threshold,
            alpha_ledger_complete=complete,
        )
        reference_decision = decide_class_inadequacy(
            candidate_bounds=cast(dict[str, float | None], reference),
            classes=_singleton_classes(),
            threshold=threshold,
            alpha_ledger_complete=len(reference) == 256,
        )
        block_id = f"B1:{index:03d}"
        fidelity = _fidelity_record(
            benchmark="B1",
            block_id=block_id,
            registered_source="aphfs.benchmarks.final_freeze._b1_vector_losses",
            reference_source="aphfs.benchmarks.final_freeze._b1_scalar_losses",
            registered_settings={"evaluator": "numpy_complete_support", "support": 32},
            reference_settings={"evaluator": "scalar_complete_support", "support": 32},
            registered_observable=sha256_json(registered),
            reference_observable=sha256_json(reference),
            registered_decision=decision.status,
            reference_decision=reference_decision.status,
        )
        fidelities.append(fidelity)
        distinguishable = all(
            (0 ^ 0 ^ theta[central]) != (1 ^ 0 ^ theta[central])
            for central in range(8)
        )
        failure_code: str | None = None
        if not distinguishable:
            failure_code = "DISTINGUISHABILITY_AUDIT_FAILED"
        elif not complete:
            failure_code = "INCOMPLETE_CANDIDATE_LEDGER"
        elif fidelity["status"] != "PASS":
            failure_code = "FIDELITY_INDETERMINATE"
        elif decision.status != "MODEL_CLASS_INADEQUATE":
            failure_code = "DETECTION_FAILURE"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        blocks.append(
            {
                "block_id": block_id,
                "role_value_commitment": sha256_json({"role_value": value}),
                "theta_000_to_111": list(theta),
                "generator": "outer_left XOR outer_right XOR f_theta(left,center,right)",
                "support_size": 32,
                "support_is_complete_finite_population": True,
                "support_and_output_sha256": support_hash,
                "block_sha256": sha256_json(
                    {"value": value, "theta": theta, "support": support_hash}
                ),
                "distinguishable_from_every_radius_one_rule": distinguishable,
                "candidate_losses": registered,
                "candidate_exact_lower_bounds": registered,
                "candidate_count": len(registered),
                "candidate_loss_sample_size": 32,
                "role_block_count_used_as_candidate_sample_size": False,
                "alpha_method": "EXACT_FINITE_SUPPORT_NO_SAMPLING",
                "alpha_ledger_complete": complete,
                "decision": decision.status,
                "class_lower_bounds": decision.class_bounds,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
                "failure_event": failure_code is not None,
            }
        )
    result = _base_result(
        "B1",
        role=str(config.get("role", "public_mock")),
        numerator=len(failures),
        denominator=len(values),
        candidate_coverage=256,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "estimand": "block-level failure to detect a distinguishable radius-two family member",
            "observation_unit": "one role-derived theta with complete 32-neighborhood support",
            "block_records": blocks,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
            "all_blocks_distinguishable": all(
                row["distinguishable_from_every_radius_one_rule"] for row in blocks
            ),
            **_cp_summary(len(failures), len(values)),
        }
    )
    return result


def _c_float_tier(config: dict[str, Any]) -> dict[str, Any]:
    low, high = (float(item) for item in config["domain"])
    horizon = int(config["horizon"])
    cases: list[dict[str, Any]] = []
    violations = 0
    exits = 0
    for category, multiplier in {"contractive": 0.8, "neutral": 1.0, "expanding": 1.1}.items():
        for perturbation, initial_delta, model_delta, rounded in (
            ("initial_state", 0.02, 0.0, False),
            ("parameter_or_rule", 0.0, 0.02, False),
            ("rounding_or_numerical", 0.0, 0.0, True),
        ):
            reference = 0.5
            candidate = reference + initial_delta
            candidate_multiplier = multiplier + model_delta
            bound = abs(initial_delta)
            path: list[dict[str, Any]] = []
            exited = False
            for step in range(horizon + 1):
                error = abs(reference - candidate)
                violation = error > bound + 1e-12
                violations += int(violation)
                exited = not (low <= reference <= high and low <= candidate <= high)
                path.append(
                    {
                        "time": step,
                        "reference": reference,
                        "candidate": candidate,
                        "error": error,
                        "bound": bound,
                        "violation": violation,
                        "domain_exit": exited,
                    }
                )
                if exited or step == horizon:
                    break
                raw = candidate * candidate_multiplier
                following = round(raw, 6) if rounded else raw
                rounding_error = abs(following - raw)
                bound = (
                    abs(multiplier) * bound
                    + abs(multiplier - candidate_multiplier) * abs(candidate)
                    + rounding_error
                )
                reference *= multiplier
                candidate = following
            exits += int(exited)
            cases.append(
                {
                    "category": category,
                    "perturbation": perturbation,
                    "path": path,
                    "domain_exit": exited,
                    "clipping_applied": False,
                }
            )
    status = "DOMAIN_EXIT_WITHDRAWAL" if exits else ("FAIL" if violations else "PASS")
    return {"status": status, "violations": violations, "domain_exits": exits, "cases": cases}


def _c_decimal_tier(config: dict[str, Any]) -> dict[str, Any]:
    low, high = (Decimal(str(item)) for item in config["domain"])
    horizon = int(config["horizon"])
    cases: list[dict[str, Any]] = []
    violations = 0
    exits = 0
    quantum = Decimal("0.000000000001")
    with localcontext() as context:
        context.prec = 50
        for category, multiplier_text in (
            ("contractive", "0.8"),
            ("neutral", "1.0"),
            ("expanding", "1.1"),
        ):
            multiplier = Decimal(multiplier_text)
            for perturbation, initial_text, model_text, rounded in (
                ("initial_state", "0.02", "0.0", False),
                ("parameter_or_rule", "0.0", "0.02", False),
                ("rounding_or_numerical", "0.0", "0.0", True),
            ):
                initial_delta = Decimal(initial_text)
                model_delta = Decimal(model_text)
                reference = Decimal("0.5")
                candidate = reference + initial_delta
                candidate_multiplier = multiplier + model_delta
                bound = abs(initial_delta)
                path: list[dict[str, Any]] = []
                exited = False
                for step in range(horizon + 1):
                    error = abs(reference - candidate)
                    violation = error > bound
                    violations += int(violation)
                    exited = not (low <= reference <= high and low <= candidate <= high)
                    path.append(
                        {
                            "time": step,
                            "reference": str(reference),
                            "candidate": str(candidate),
                            "error": str(error),
                            "bound": str(bound),
                            "violation": violation,
                            "domain_exit": exited,
                        }
                    )
                    if exited or step == horizon:
                        break
                    raw = candidate * candidate_multiplier
                    following = raw.quantize(quantum) if rounded else raw
                    rounding_error = abs(following - raw)
                    bound = (
                        abs(multiplier) * bound
                        + abs(multiplier - candidate_multiplier) * abs(candidate)
                        + rounding_error
                    )
                    reference *= multiplier
                    candidate = following
                exits += int(exited)
                cases.append(
                    {
                        "category": category,
                        "perturbation": perturbation,
                        "path": path,
                        "domain_exit": exited,
                        "clipping_applied": False,
                    }
                )
    status = "DOMAIN_EXIT_WITHDRAWAL" if exits else ("FAIL" if violations else "PASS")
    return {"status": status, "violations": violations, "domain_exits": exits, "cases": cases}


def run_confirmatory_c(config: dict[str, Any]) -> dict[str, Any]:
    """Compare float/decimal-6 propagation with a Decimal/decimal-12 path."""
    registered = _c_float_tier(config)
    reference = _c_decimal_tier(config)
    if config.get("inject_fidelity_mismatch"):
        reference = dict(reference)
        reference["violations"] = int(reference["violations"]) + 1
        reference["status"] = "FAIL"
    fidelity = _fidelity_record(
        benchmark="C",
        block_id="C:deterministic-grid",
        registered_source="aphfs.benchmarks.final_freeze._c_float_tier",
        reference_source="aphfs.benchmarks.final_freeze._c_decimal_tier",
        registered_settings={"arithmetic": "binary64", "rounding_digits": 6},
        reference_settings={"arithmetic": "decimal.Decimal(prec=50)", "rounding_digits": 12},
        registered_observable={
            "violations": registered["violations"],
            "domain_exits": registered["domain_exits"],
        },
        reference_observable={
            "violations": reference["violations"],
            "domain_exits": reference["domain_exits"],
        },
        registered_decision=str(registered["status"]),
        reference_decision=str(reference["status"]),
    )
    failure_code: str | None = None
    if fidelity["status"] != "PASS":
        failure_code = "FIDELITY_INDETERMINATE"
        status = "FIDELITY_INDETERMINATE"
    else:
        status = str(registered["status"])
        if status == "DOMAIN_EXIT_WITHDRAWAL":
            failure_code = "DOMAIN_EXIT_WITHDRAWAL"
        elif status != "PASS":
            failure_code = "BOUND_VIOLATION"
    adverse_cases = sum(
        bool(case["domain_exit"])
        or any(bool(point["violation"]) for point in case["path"])
        for case in cast(list[dict[str, Any]], registered["cases"])
    )
    if fidelity["status"] != "PASS":
        adverse_cases = 9
    result = _base_result(
        "C",
        role="deterministic_grid",
        numerator=adverse_cases,
        denominator=9,
        candidate_coverage=0,
    )
    result.update(
        {
            "status": status,
            "estimand": "pathwise propagated-bound validity within the registered domain",
            "block_records": cast(list[dict[str, Any]], registered["cases"]),
            "fidelity_records": [fidelity],
            "failure_ledger": [] if failure_code is None else [{"failure_code": failure_code}],
            "domain": config["domain"],
            "pathwise_bound_violations": registered["violations"],
            "domain_exit_count": registered["domain_exits"],
            "clipping_applied": False,
        }
    )
    return result


def run_confirmatory_d0(config: dict[str, Any], values: list[int]) -> dict[str, Any]:
    """Rule 204 exact full-microstate identity control."""
    width = int(config["width"])
    horizon = int(config["horizon"])
    records: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        initial = _public_state(value, width, "D0")
        registered = simulate_vectorized(204, initial, horizon, "periodic")
        reference = simulate_reference(204, initial, horizon, "periodic")
        block_id = f"D0:{index:03d}"
        identity = bool(np.all(registered == initial[np.newaxis, :]))
        reference_identity = bool(np.all(reference == initial[np.newaxis, :]))
        fidelity = _fidelity_record(
            benchmark="D0",
            block_id=block_id,
            registered_source="aphfs.eca.core.simulate_vectorized",
            reference_source="aphfs.eca.core.simulate_reference",
            registered_settings={"rule_id": 204, "observable": "full_microstate"},
            reference_settings={"rule_id": 204, "observable": "full_microstate"},
            registered_observable=sha256_bytes(registered.tobytes()),
            reference_observable=sha256_bytes(reference.tobytes()),
            registered_decision="PASS" if identity else "FAIL",
            reference_decision="PASS" if reference_identity else "FAIL",
        )
        fidelities.append(fidelity)
        failure_code = None if identity and fidelity["status"] == "PASS" else "IDENTITY_FAILURE"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        records.append(
            {
                "block_id": block_id,
                "reported_rule_id": 204,
                "executed_rule_id": 204,
                "full_microstate_identity": identity,
                "trajectory_sha256": sha256_bytes(registered.tobytes()),
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
            }
        )
    result = _base_result(
        "D0",
        role="deterministic_conformance",
        numerator=len(failures),
        denominator=len(values),
        candidate_coverage=0,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "microdynamics": "ECA Rule 204 identity",
            "reported_rule_id": 204,
            "executed_rule_id": 204,
            "protected_observable": "complete microstate trajectory identity",
            "block_records": records,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
        }
    )
    return result


def run_confirmatory_d1() -> dict[str, Any]:
    """Rule 90 global-density non-closure witness."""
    first = np.array([1, 1, 0, 0], dtype=np.uint8)
    second = np.array([1, 0, 1, 0], dtype=np.uint8)
    registered = [step_vectorized(90, first, "periodic"), step_vectorized(90, second, "periodic")]
    reference = [step_reference(90, first, "periodic"), step_reference(90, second, "periodic")]
    next_density = [float(item.mean()) for item in registered]
    witness = float(first.mean()) == float(second.mean()) and next_density[0] != next_density[1]
    fidelity = _fidelity_record(
        benchmark="D1",
        block_id="D1:formal-witness",
        registered_source="aphfs.eca.core.step_vectorized",
        reference_source="aphfs.eca.core.step_reference",
        registered_settings={"rule_id": 90, "boundary": "periodic"},
        reference_settings={"rule_id": 90, "boundary": "periodic"},
        registered_observable=[item.tolist() for item in registered],
        reference_observable=[item.tolist() for item in reference],
        registered_decision="PASS" if witness else "FAIL",
        reference_decision=(
            "PASS"
            if all(
                np.array_equal(a, b)
                for a, b in zip(registered, reference, strict=True)
            )
            else "FAIL"
        ),
    )
    status = "PASS" if witness and fidelity["status"] == "PASS" else "FAIL"
    result = _base_result(
        "D1",
        role="deterministic_conformance",
        numerator=int(status != "PASS"),
        denominator=1,
        candidate_coverage=0,
    )
    result.update(
        {
            "status": status,
            "reported_rule_id": 90,
            "executed_rule_id": 90,
            "coarse_map": "global binary density",
            "nonclosure_witness": witness,
            "block_records": [
                {
                    "microstate_pair": [first.tolist(), second.tolist()],
                    "shared_density": [float(first.mean()), float(second.mean())],
                    "next_density": next_density,
                }
            ],
            "fidelity_records": [fidelity],
            "failure_ledger": [] if status == "PASS" else [{"failure_code": "WITNESS_FAILURE"}],
        }
    )
    return result


def run_confirmatory_d2_cert(
    config: dict[str, Any],
    values: list[int],
    role: str,
    *,
    calibration_certificate_verified: bool = False,
) -> dict[str, Any]:
    """Rule 170 translation-invariant density certificate machinery."""
    if role in {"mock_locked", "locked"} and not calibration_certificate_verified:
        result = _base_result(
            "D2-CERT",
            role=role,
            numerator=0,
            denominator=len(values),
            candidate_coverage=0,
        )
        result.update(
            {
                "status": "LOCKED_AUDIT_NOT_APPLICABLE_NO_CERTIFICATE",
                "estimand": "Rule 170 translation-invariant density-violation probability",
                "scope": "locked withdrawal audit not executed without an approved certificate",
                "reported_rule_id": 170,
                "executed_rule_id": 170,
                "coarse_map": "global binary density",
                "coarse_predictor": "identity",
                "violation_count": 0,
                "exact_one_sided_upper": None,
                "exact_one_sided_lower": None,
                "exact_two_sided_interval": None,
                "delta": float(config["delta"]),
                "calibration_beta": float(config["calibration_beta"]),
                "locked_gamma": float(config["locked_gamma"]),
                "certificate_granted": False,
                "certificate_reviewed": False,
                "calibration_certificate_verified": False,
                "calibration_executed": False,
                "locked_audit_executed": False,
                "block_records": [
                    {
                        "block_id": f"D2-CERT:{index:03d}",
                        "reported_rule_id": 170,
                        "executed_rule_id": 170,
                        "role_value_commitment": sha256_json({"role_value": value}),
                        "violation": False,
                        "fidelity_status": "NOT_APPLICABLE",
                        "failure_code": None,
                        "calibration_executed": False,
                        "locked_audit_executed": False,
                    }
                    for index, value in enumerate(values)
                ],
                "fidelity_records": [
                    {
                        "contract_version": "protected-fidelity-v3",
                        "benchmark": "D2-CERT",
                        "block_id": f"D2-CERT:{index:03d}",
                        "status": "NOT_APPLICABLE",
                        "reason": "NO_GRANTED_AND_REVIEWED_CALIBRATION_CERTIFICATE",
                    }
                    for index in range(len(values))
                ],
                "failure_ledger": [],
            }
        )
        return result
    registered_tier = cast(dict[str, Any], config["registered_tier"])
    width = int(registered_tier["width"])
    horizon = int(registered_tier["horizon"])
    epsilon = float(config["epsilon"])
    violations = 0
    records: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        initial = _public_state(value, width, "D2-CERT")
        registered = simulate_vectorized(170, initial, horizon, "periodic")
        reference = simulate_reference(170, initial, horizon, "periodic")
        registered_density = np.mean(registered, axis=1)
        reference_density = np.asarray(
            [sum(int(cell) for cell in row) / len(row) for row in reference]
        )
        discrepancy = float(np.max(np.abs(registered_density - registered_density[0])))
        reference_discrepancy = float(
            np.max(np.abs(reference_density - reference_density[0]))
        )
        event = discrepancy > epsilon
        violations += int(event)
        block_id = f"D2-CERT:{index:03d}"
        fidelity = _fidelity_record(
            benchmark="D2-CERT",
            block_id=block_id,
            registered_source="aphfs.eca.core.simulate_vectorized",
            reference_source="aphfs.eca.core.simulate_reference",
            registered_settings={"rule_id": 170, "width": width, "horizon": horizon},
            reference_settings={"rule_id": 170, "width": width, "horizon": horizon},
            registered_observable={"maximum_density_discrepancy": discrepancy, "violation": event},
            reference_observable={
                "maximum_density_discrepancy": reference_discrepancy,
                "violation": reference_discrepancy > epsilon,
            },
            registered_decision="VIOLATION" if event else "NO_VIOLATION",
            reference_decision=(
                "VIOLATION" if reference_discrepancy > epsilon else "NO_VIOLATION"
            ),
        )
        fidelities.append(fidelity)
        failure_code: str | None = None
        if fidelity["status"] != "PASS":
            failure_code = "FIDELITY_INDETERMINATE"
        elif event:
            failure_code = "CERTIFICATE_VIOLATION"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        records.append(
            {
                "block_id": block_id,
                "reported_rule_id": 170,
                "executed_rule_id": 170,
                "initial_state_sha256": sha256_bytes(initial.tobytes()),
                "maximum_density_discrepancy": discrepancy,
                "violation": event,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
            }
        )
    calibration_beta = float(config["calibration_beta"])
    locked_gamma = float(config["locked_gamma"])
    delta = float(config["delta"])
    upper = clopper_pearson_upper(violations, len(values), calibration_beta)
    lower = clopper_pearson_lower(violations, len(values), locked_gamma)
    two_sided = clopper_pearson_two_sided(
        violations,
        len(values),
        locked_gamma,
    )
    fidelity_failed = any(row["status"] != "PASS" for row in fidelities)
    if fidelity_failed:
        status = "FIDELITY_INDETERMINATE"
    elif len(values) != int(config["calibration_block_count"]) and role in {
        "mock_calibration",
        "calibration",
    }:
        status = "INDETERMINATE"
    elif role == "mock_calibration":
        status = (
            "PUBLIC_MOCK_CALIBRATION_CRITERION_MET"
            if upper <= delta
            else "PUBLIC_MOCK_CALIBRATION_CRITERION_NOT_MET"
        )
    elif role == "calibration":
        status = (
            "CALIBRATION_CERTIFICATE_GRANTED"
            if upper <= delta and not failures
            else "CALIBRATION_CERTIFICATE_NOT_GRANTED"
        )
    elif role == "locked":
        status = (
            "LOCKED_AUDIT_WITHDRAWAL_TRIGGERED"
            if lower > delta
            else "NOT_CONTRADICTED_BY_LOCKED_AUDIT"
        )
    else:
        status = "INDETERMINATE"
    result = _base_result(
        "D2-CERT",
        role=role,
        numerator=sum(record["failure_code"] is not None for record in records),
        denominator=len(values),
        candidate_coverage=0,
    )
    result.update(
        {
            "status": status,
            "estimand": "Rule 170 translation-invariant density-violation probability",
            "scope": "exact-binomial certificate machinery only",
            "reported_rule_id": 170,
            "executed_rule_id": 170,
            "coarse_map": "global binary density",
            "coarse_predictor": "identity",
            "violation_count": violations,
            "exact_one_sided_upper": upper,
            "exact_one_sided_lower": lower,
            "exact_two_sided_interval": list(two_sided),
            "delta": delta,
            "calibration_beta": calibration_beta,
            "locked_gamma": locked_gamma,
            "certificate_granted": status == "CALIBRATION_CERTIFICATE_GRANTED",
            "certificate_reviewed": role == "locked"
            and calibration_certificate_verified,
            "calibration_certificate_verified": calibration_certificate_verified,
            "calibration_executed": role == "calibration",
            "locked_audit_executed": role == "locked",
            "block_records": records,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
        }
    )
    return result


def run_confirmatory_d2_mem(config: dict[str, Any]) -> dict[str, Any]:
    """Validate the frozen lag ladder on the two-bit swap system."""
    records: list[dict[str, Any]] = []
    lag0_mapping: dict[int, set[int]] = {0: set(), 1: set()}
    lag1_errors = 0
    for first in (0, 1):
        for second in (0, 1):
            sequence = [first, second, first, second]
            lag0_mapping[sequence[0]].add(sequence[1])
            lag1_errors += int(sequence[2] != sequence[0])
            records.append(
                {
                    "initial_microstate": [first, second],
                    "coarse_sequence": sequence,
                    "lag0_prediction_is_ambiguous": len(lag0_mapping[first]) > 1,
                    "lag1_prediction_z_t_plus_1_equals_z_t_minus_1": sequence[2] == sequence[0],
                }
            )
    lag0_fails = any(len(outputs) > 1 for outputs in lag0_mapping.values())
    lag1_exact = lag1_errors == 0
    status = "PASS" if lag0_fails and lag1_exact else "FAIL"
    fidelity = _fidelity_record(
        benchmark="D2-MEM",
        block_id="D2-MEM:complete-state-census",
        registered_source="aphfs.benchmarks.final_freeze.run_confirmatory_d2_mem",
        reference_source="closed_form_swap_identity_z[t+1]=z[t-1]",
        registered_settings={"memory_ladder": config["memory_ladder"]},
        reference_settings={"complete_microstate_census": 4},
        registered_observable={"lag0_fails": lag0_fails, "lag1_errors": lag1_errors},
        reference_observable={"lag0_fails": True, "lag1_errors": 0},
        registered_decision=status,
        reference_decision="PASS",
    )
    result = _base_result(
        "D2-MEM",
        role="deterministic_conformance",
        numerator=int(status != "PASS"),
        denominator=4,
        candidate_coverage=0,
    )
    result.update(
        {
            "status": status,
            "system": "two-bit swap (a,b)->(b,a), coarse observable z=a",
            "memory_ladder": config["memory_ladder"],
            "lag0_fails": lag0_fails,
            "lag1_exact_repair": lag1_exact,
            "lag1_error_count": lag1_errors,
            "natural_emergence_evidence": False,
            "block_records": records,
            "fidelity_records": [fidelity],
            "failure_ledger": (
                []
                if status == "PASS"
                else [{"failure_code": "MEMORY_LADDER_FAILURE"}]
            ),
        }
    )
    return result


def run_confirmatory_d2(
    config: dict[str, Any],
    values: list[int],
    role: str,
) -> dict[str, Any]:
    """Compatibility alias for the registered D2-CERT endpoint."""
    return run_confirmatory_d2_cert(config, values, role)


@dataclass
class _CostMeter:
    ordering_units: int = 0
    probe_steps: int = 0
    candidate_block_steps: int = 0
    reference_refinement_steps: int = 0
    retry_steps: int = 0
    unbilled_loss_accesses: int = 0

    @property
    def total(self) -> int:
        return (
            self.ordering_units
            + self.probe_steps
            + self.candidate_block_steps
            + self.reference_refinement_steps
            + self.retry_steps
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "ordering_units": self.ordering_units,
            "probe_steps": self.probe_steps,
            "candidate_block_steps": self.candidate_block_steps,
            "reference_refinement_steps": self.reference_refinement_steps,
            "retry_steps": self.retry_steps,
            "unbilled_loss_accesses": self.unbilled_loss_accesses,
            "total_cost_units": self.total,
        }


def _e_observation(value: int) -> tuple[int, tuple[int, ...], str]:
    truth_rule = _derived_rule("E", value)
    outputs = rule_truth_table(truth_rule)
    return truth_rule, outputs, sha256_json({"support": list(range(8)), "outputs": outputs})


def _e_loss(candidate: int, outputs: tuple[int, ...], rows: tuple[int, ...]) -> float:
    table = rule_truth_table(candidate)
    return sum(table[row] != outputs[row] for row in rows) / len(rows)


def _e_reference_loss(candidate: int, outputs: tuple[int, ...]) -> float:
    mistakes = 0
    for code, observed in enumerate(outputs):
        predicted = _binary_string_output(
            candidate,
            (code >> 2) & 1,
            (code >> 1) & 1,
            code & 1,
        )
        mistakes += int(predicted != observed)
    return mistakes / 8.0


def _frozen_order(salt: str) -> list[int]:
    return sorted(
        range(256),
        key=lambda candidate: hashlib.sha256(f"{salt}|{candidate}".encode()).digest(),
    )


def _run_e_policy(
    name: str,
    outputs: tuple[int, ...],
    config: dict[str, Any],
) -> dict[str, Any]:
    meter = _CostMeter(probe_steps=8)
    numeric_order = list(range(256))
    fixed_order = _frozen_order(str(config["fixed_order_salt"]))
    development_order = _frozen_order(str(config["development_frozen_order_salt"]))
    traces: list[dict[str, Any]] = []
    accepted: int | None = None
    if name == "exhaustive":
        order = numeric_order
    elif name == "fixed_order":
        order = fixed_order
        meter.ordering_units += 256
    elif name == "development_frozen_order":
        order = development_order
        meter.ordering_units += 256
    elif name == "adaptive_fidelity":
        cheap_scores: list[tuple[float, int]] = []
        cheap_rows = (0, 2, 5, 7)
        for candidate in numeric_order:
            score = _e_loss(candidate, outputs, cheap_rows)
            meter.candidate_block_steps += len(cheap_rows)
            cheap_scores.append((score, candidate))
        meter.ordering_units += len(cheap_scores)
        order = [candidate for _, candidate in sorted(cheap_scores)]
    else:
        raise ValueError(f"unknown policy {name}")
    best_loss = math.inf
    best_candidate: int | None = None
    for candidate in order:
        loss = _e_loss(candidate, outputs, tuple(range(8)))
        meter.candidate_block_steps += 8
        if name == "adaptive_fidelity":
            meter.reference_refinement_steps += 8
            reference_loss = _e_reference_loss(candidate, outputs)
            if reference_loss != loss:
                meter.retry_steps += 8
                traces.append(
                    {
                        "candidate_id": f"eca:{candidate:03d}",
                        "loss": loss,
                        "reference_loss": reference_loss,
                        "failure_code": "FIDELITY_INDETERMINATE",
                    }
                )
                break
        if (loss, candidate) < (best_loss, best_candidate if best_candidate is not None else 256):
            best_loss = loss
            best_candidate = candidate
        traces.append({"candidate_id": f"eca:{candidate:03d}", "loss": loss})
        if name != "exhaustive" and loss == 0.0:
            accepted = candidate
            break
    if name == "exhaustive":
        accepted = best_candidate
    if config.get("inject_unbilled_loss_access"):
        meter.unbilled_loss_accesses += 1
    reference_loss = (
        _e_reference_loss(accepted, outputs) if accepted is not None else math.inf
    )
    if accepted is not None:
        meter.reference_refinement_steps += 8
    fidelity_ok = (
        accepted is not None
        and best_loss == 0.0
        and reference_loss == 0.0
        and meter.unbilled_loss_accesses == 0
    )
    return {
        "decision": "ACCEPT_BEST_CANDIDATE" if fidelity_ok else "INDETERMINATE",
        "best_candidate": None if accepted is None else f"eca:{accepted:03d}",
        "best_loss": best_loss,
        "reference_loss": reference_loss,
        "cost_ledger": meter.as_dict(),
        "trace": traces,
        "cheap_to_reference_triggered": name == "adaptive_fidelity",
        "hidden_precomputation_detected": meter.unbilled_loss_accesses > 0,
        "fidelity_status": "PASS" if fidelity_ok else "FIDELITY_INDETERMINATE",
    }


def run_confirmatory_e(config: dict[str, Any], values: list[int]) -> dict[str, Any]:
    """Fair lazy policy comparison with complete cost accounting."""
    policy_names = (
        "exhaustive",
        "fixed_order",
        "development_frozen_order",
        "adaptive_fidelity",
    )
    blocks: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    aggregate: dict[str, dict[str, Any]] = {
        name: {"total_cost_units": 0, "block_failures": 0, "block_records": []}
        for name in policy_names
    }
    budget = int(config["resource_caps"]["total_cost_units_per_policy"])
    for index, value in enumerate(values):
        truth_rule, outputs, stream_hash = _e_observation(value)
        results = {
            name: _run_e_policy(name, outputs, config)
            for name in policy_names
        }
        exhaustive = results["exhaustive"]
        common = all(
            row["decision"] == exhaustive["decision"]
            and row["best_candidate"] == exhaustive["best_candidate"]
            and row["fidelity_status"] == "PASS"
            for row in results.values()
        )
        hidden_cost = any(row["hidden_precomputation_detected"] for row in results.values())
        failure_code = None
        if hidden_cost:
            failure_code = "UNBILLED_LOSS_ACCESS"
        elif not common:
            failure_code = "POLICY_ESTIMAND_DISAGREEMENT"
        block_id = f"E:{index:03d}"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        fidelity = _fidelity_record(
            benchmark="E",
            block_id=block_id,
            registered_source="aphfs.benchmarks.final_freeze._e_loss",
            reference_source="aphfs.benchmarks.final_freeze._e_reference_loss",
            registered_settings={"evaluator": "bit_index", "support": 8},
            reference_settings={"evaluator": "explicit_binary_string_scalar", "support": 8},
            registered_observable=exhaustive["best_candidate"],
            reference_observable=exhaustive["best_candidate"],
            registered_decision=str(exhaustive["decision"]),
            reference_decision=(
                "ACCEPT_BEST_CANDIDATE"
                if exhaustive["reference_loss"] == 0.0
                else "INDETERMINATE"
            ),
        )
        fidelities.append(fidelity)
        for name, row in results.items():
            aggregate[name]["total_cost_units"] += row["cost_ledger"]["total_cost_units"]
            aggregate[name]["block_failures"] += int(
                row["decision"] != exhaustive["decision"]
                or row["best_candidate"] != exhaustive["best_candidate"]
            )
            aggregate[name]["block_records"].append(row)
        blocks.append(
            {
                "block_id": block_id,
                "role_value_commitment": sha256_json({"role_value": value}),
                "truth_rule_generator_only": truth_rule,
                "observation_stream_sha256": stream_hash,
                "support_is_complete_truth_table": True,
                "policy_results": results,
                "common_estimand": {
                    "final_valid_decision": exhaustive["decision"],
                    "best_valid_candidate": exhaustive["best_candidate"],
                    "failure_status": failure_code,
                },
                "all_policies_match_exhaustive": common,
                "hidden_cost_detected": hidden_cost,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
            }
        )
    budget_failures = []
    for name, row in aggregate.items():
        row["budget"] = budget
        row["budget_exceeded"] = row["total_cost_units"] > budget
        if row["budget_exceeded"]:
            budget_failures.append(
                {"policy": name, "failure_code": "RESOURCE_BUDGET_EXCEEDED"}
            )
    failures.extend(budget_failures)
    adverse_blocks = len(
        {
            str(row["block_id"])
            for row in failures
            if "block_id" in row
        }
    )
    if budget_failures:
        adverse_blocks = len(values)
    result = _base_result(
        "E",
        role=str(config.get("role", "public_mock")),
        numerator=adverse_blocks,
        denominator=len(values),
        candidate_coverage=256,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "estimand": "policy agreement on final decision and best valid candidate",
            "observation_unit": "one role-derived complete truth-table stream",
            "development_frozen_ordering": True,
            "protected_stream_used_to_learn_static_order": False,
            "lazy_candidate_evaluation": True,
            "all_cost_components_billed": True,
            "shared_observation_stream": True,
            "policy_results": aggregate,
            "block_records": blocks,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
            "adaptive_fidelity_final_decision_refined": all(
                row["policy_results"]["adaptive_fidelity"]["cheap_to_reference_triggered"]
                for row in blocks
            ),
            **_cp_summary(adverse_blocks, len(values)),
        }
    )
    return result


def _center_seed(bits: str, width: int) -> UInt8Array:
    seed = np.zeros(width, dtype=np.uint8)
    values = np.fromiter((int(bit) for bit in bits), dtype=np.uint8)
    start = (width - len(values)) // 2
    seed[start : start + len(values)] = values
    return seed


def _best_template_match_vector(
    observed: UInt8Array,
    templates: dict[str, UInt8Array],
) -> tuple[str, int, float]:
    best = ("", 0, -math.inf)
    for name, template in templates.items():
        for shift in range(template.shape[1]):
            score = 1.0 - float(np.mean(np.roll(template, shift, axis=1) != observed))
            if score > best[2]:
                best = (name, shift, score)
    return best


def _best_template_match_scalar(
    observed: UInt8Array,
    templates: dict[str, UInt8Array],
) -> tuple[str, int, float]:
    best = ("", 0, -math.inf)
    for name, template in templates.items():
        height, width = template.shape
        for shift in range(width):
            mismatch = 0
            for time_index in range(height):
                for position in range(width):
                    source = (position - shift) % width
                    mismatch += int(template[time_index, source] != observed[time_index, position])
            score = 1.0 - mismatch / (height * width)
            if score > best[2]:
                best = (name, shift, score)
    return best


def run_confirmatory_f0(config: dict[str, Any], values: list[int]) -> dict[str, Any]:
    """Known-template conformance audit under registered transforms and controls."""
    width = int(config["width"])
    horizon = int(config["horizon"])
    threshold = float(config["detection_threshold"])
    definitions = {
        "rule54": (54, "001101001", "PROJECT_DEFINED_RULE54_CONFORMANCE_FIXTURE"),
        "rule110": (110, "00010011011111", "PROJECT_DEFINED_RULE110_CONFORMANCE_FIXTURE"),
    }
    templates = {
        name: simulate_reference(rule, _center_seed(bits, width), horizon, "periodic")
        for name, (rule, bits, _) in definitions.items()
    }
    blocks: list[dict[str, Any]] = []
    fidelities: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        case_code = int(_digest("F0", "case-type", value)[0]) & 0b11
        expected_name: str | None
        expected_shift: int | None
        if case_code == 3:
            case_type = "negative_control"
            expected_name = None
            expected_shift = None
            observed = np.vstack(
                [
                    _public_state(value + time_index, width, "F0-negative-state")
                    for time_index in range(horizon + 1)
                ]
            )
        else:
            template_bit = int(_digest("F0", "template-identity", value)[0]) & 1
            expected_name = "rule54" if template_bit == 0 else "rule110"
            expected_shift = int(_digest("F0", "translation", value)[0]) % width
            observed = np.roll(templates[expected_name], expected_shift, axis=1)
            case_type = (
                "single_cell_perturbation"
                if case_code == 2
                else "registered_translation"
            )
            if case_code == 2:
                time_index = int(_digest("F0", "perturb-time", value)[0]) % (horizon + 1)
                position = int(_digest("F0", "perturb-position", value)[0]) % width
                observed[time_index, position] ^= 1
        registered = _best_template_match_vector(observed, templates)
        reference = _best_template_match_scalar(observed, templates)
        if config.get("inject_fidelity_mismatch") and index == 0:
            reference = (reference[0], (reference[1] + 1) % width, reference[2])
        registered_positive = registered[2] >= threshold
        reference_positive = reference[2] >= threshold
        registered_decision = (
            f"{registered[0]}:{registered[1]}" if registered_positive else "NEGATIVE"
        )
        reference_decision = (
            f"{reference[0]}:{reference[1]}" if reference_positive else "NEGATIVE"
        )
        block_id = f"F0:{index:03d}"
        fidelity = _fidelity_record(
            benchmark="F0",
            block_id=block_id,
            registered_source="aphfs.benchmarks.final_freeze._best_template_match_vector",
            reference_source="aphfs.benchmarks.final_freeze._best_template_match_scalar",
            registered_settings={"evaluator": "numpy", "threshold": threshold},
            reference_settings={"evaluator": "explicit_scalar", "threshold": threshold},
            registered_observable=registered_decision,
            reference_observable=reference_decision,
            registered_decision=registered_decision,
            reference_decision=reference_decision,
        )
        fidelities.append(fidelity)
        if expected_name is None:
            conformance = not registered_positive
        else:
            conformance = (
                registered_positive
                and registered[0] == expected_name
                and registered[1] == expected_shift
            )
        failure_code: str | None = None
        if fidelity["status"] != "PASS":
            failure_code = "FIDELITY_INDETERMINATE"
        elif not conformance:
            failure_code = "TEMPLATE_CONFORMANCE_FAILURE"
        if failure_code:
            failures.append({"block_id": block_id, "failure_code": failure_code})
        blocks.append(
            {
                "block_id": block_id,
                "case_type": case_type,
                "role_value_commitment": sha256_json({"role_value": value}),
                "expected_template_generator_only": expected_name,
                "expected_translation_generator_only": expected_shift,
                "observed_sha256": sha256_bytes(observed.tobytes()),
                "detected_template": registered[0] if registered_positive else None,
                "detected_translation": registered[1] if registered_positive else None,
                "similarity": registered[2],
                "template_conformance": conformance,
                "fidelity_status": fidelity["status"],
                "failure_code": failure_code,
            }
        )
    result = _base_result(
        "F0",
        role=str(config.get("role", "public_mock")),
        numerator=len(failures),
        denominator=len(values),
        candidate_coverage=0,
    )
    result.update(
        {
            "status": "PASS" if not failures else "FAIL",
            "benchmark_name": "known-template conformance audit",
            "sampling_law": "iid digest-derived mixture: clean=1/2, perturbation=1/4, negative=1/4",
            "case_type_domain": "F0|case-type",
            "template_identity_domain": "F0|template-identity",
            "fixture_provenance": {
                name: provenance
                for name, (_, _, provenance) in definitions.items()
            },
            "descriptive_strata_counts": {
                case_type: sum(
                    row["case_type"] == case_type for row in blocks
                )
                for case_type in (
                    "registered_translation",
                    "single_cell_perturbation",
                    "negative_control",
                )
            },
            "scope_reduction_path": "B",
            "persistent_structure_detection_claim": False,
            "future_frame_access": False,
            "reported_endpoints": [
                "known template identity conformance",
                "registered translation parameter conformance",
                "single-cell perturbation tolerance",
                "negative-control rejection",
            ],
            "deleted_endpoints": ["velocity", "lifetime", "held-out prediction"],
            "detector": {
                "input_contains_rule_or_template_label": False,
                "label_training_performed": False,
                "templates_are_ground_truth_trajectory_replays": True,
                "scope_is_conformance_only": True,
            },
            "block_records": blocks,
            "fidelity_records": fidelities,
            "failure_ledger": failures,
            **_cp_summary(len(failures), len(values)),
        }
    )
    return result
