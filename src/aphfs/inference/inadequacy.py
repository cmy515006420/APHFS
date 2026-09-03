"""Class-level inadequacy decisions without unsafe representative substitution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DecisionStatus = Literal["MODEL_CLASS_INADEQUATE", "RETAIN_CLASS", "INDETERMINATE"]


@dataclass(frozen=True)
class InadequacyDecision:
    status: DecisionStatus
    class_bounds: dict[str, float]
    global_minimum: float | None
    reason: str


def decide_class_inadequacy(
    *,
    candidate_bounds: dict[str, float | None],
    classes: dict[str, tuple[str, ...]],
    threshold: float,
    candidate_failures: set[str] | None = None,
    alpha_ledger_complete: bool,
    exact_interface_equivalence: set[str] | None = None,
    representative_only_classes: set[str] | None = None,
) -> InadequacyDecision:
    """Apply the v1.2 class-minimum gate.

    Finite-probe signature membership never licenses representative-only
    evaluation. A class may be representative-only only when it is listed in
    ``exact_interface_equivalence``.
    """
    failures = candidate_failures or set()
    exact_classes = exact_interface_equivalence or set()
    representative_classes = representative_only_classes or set()
    expected_candidates = {candidate for members in classes.values() for candidate in members}
    if set(candidate_bounds) != expected_candidates:
        return InadequacyDecision("INDETERMINATE", {}, None, "missing candidate coverage")
    if failures:
        return InadequacyDecision("INDETERMINATE", {}, None, "candidate execution failure")
    if not alpha_ledger_complete:
        return InadequacyDecision("INDETERMINATE", {}, None, "incomplete alpha ledger")
    unsafe = representative_classes - exact_classes
    if unsafe:
        return InadequacyDecision(
            "INDETERMINATE",
            {},
            None,
            "representative-only evaluation lacks full-interface equality proof",
        )
    class_bounds: dict[str, float] = {}
    for class_id, members in classes.items():
        values = [candidate_bounds[member] for member in members]
        if any(value is None for value in values):
            return InadequacyDecision("INDETERMINATE", {}, None, "missing lower bound")
        class_bounds[class_id] = min(float(value) for value in values if value is not None)
    global_minimum = min(class_bounds.values())
    if global_minimum > threshold:
        return InadequacyDecision(
            "MODEL_CLASS_INADEQUATE",
            class_bounds,
            global_minimum,
            "every simultaneously covered class minimum exceeds threshold",
        )
    return InadequacyDecision(
        "RETAIN_CLASS",
        class_bounds,
        global_minimum,
        "at least one class minimum does not exceed threshold",
    )

