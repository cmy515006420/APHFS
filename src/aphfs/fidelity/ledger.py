"""Separate error-source accounting and frozen refinement triggers."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from aphfs.constants import ERROR_SOURCES


@dataclass
class ErrorLedger:
    components: dict[str, float] = field(
        default_factory=lambda: {source: 0.0 for source in ERROR_SOURCES}
    )

    def record(self, source: str, magnitude: float) -> None:
        if source not in self.components:
            raise ValueError(f"Unknown error source: {source}")
        if magnitude < 0:
            raise ValueError("error magnitude must be nonnegative")
        self.components[source] = magnitude

    @property
    def total_allowance(self) -> float:
        return sum(self.components.values())


@dataclass(frozen=True)
class RefinementContext:
    lower_level_change: str
    protected_observable: str
    observable_tolerance: float
    time_horizon: int
    initial_state_or_environment_distribution: str

    def validate(self) -> None:
        text_fields = (
            self.lower_level_change,
            self.protected_observable,
            self.initial_state_or_environment_distribution,
        )
        if any(not value.strip() for value in text_fields):
            raise ValueError("refinement context text fields must be nonempty")
        if not math.isfinite(self.observable_tolerance) or self.observable_tolerance < 0:
            raise ValueError("observable_tolerance must be finite and nonnegative")
        if self.time_horizon < 0:
            raise ValueError("time_horizon must be nonnegative")


@dataclass(frozen=True)
class RefinementAssessment:
    action: str
    reasons: tuple[str, ...]
    stable_decision: bool
    observable_change: float
    observable_preserved: bool
    decision_before: str
    decision_after: str
    decision_changed: bool
    further_refinement_required: bool
    context: RefinementContext

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reasons": list(self.reasons),
            "stable_decision": self.stable_decision,
            "observable_change": self.observable_change,
            "observable_preserved": self.observable_preserved,
            "decision_before": self.decision_before,
            "decision_after": self.decision_after,
            "decision_changed": self.decision_changed,
            "further_refinement_required": self.further_refinement_required,
            "lower_level_change": self.context.lower_level_change,
            "protected_observable": self.context.protected_observable,
            "observable_tolerance": self.context.observable_tolerance,
            "time_horizon": self.context.time_horizon,
            "initial_state_or_environment_distribution": (
                self.context.initial_state_or_environment_distribution
            ),
        }


def assess_refinement(
    *,
    context: RefinementContext,
    fast_observable: float,
    refined_observable: float,
    decision_before: str,
    decision_after: str,
    interval: tuple[float, float],
    threshold: float,
    numerical_allowance: float,
    signature_boundary_contact: bool = False,
    decision_reversal: bool = False,
    cross_platform_disagreement: bool = False,
    invariant_failure: bool = False,
) -> RefinementAssessment:
    context.validate()
    lower, upper = interval
    numeric_values = (
        fast_observable,
        refined_observable,
        lower,
        upper,
        threshold,
        numerical_allowance,
    )
    if any(not math.isfinite(value) for value in numeric_values):
        raise ValueError("refinement assessment values must be finite")
    if lower > upper or numerical_allowance < 0:
        raise ValueError("invalid interval or numerical allowance")
    if not decision_before.strip() or not decision_after.strip():
        raise ValueError("decision labels must be nonempty")
    reasons: list[str] = []
    observable_change = abs(refined_observable - fast_observable)
    observable_preserved = observable_change <= context.observable_tolerance
    if not observable_preserved:
        reasons.append("upper-observable tolerance exceeded")
    if lower - numerical_allowance <= threshold <= upper + numerical_allowance:
        reasons.append("interval-threshold overlap")
    if signature_boundary_contact:
        reasons.append("signature-boundary contact")
    decision_changed = decision_before != decision_after
    if decision_reversal or decision_changed:
        reasons.append("decision reversal")
    if cross_platform_disagreement:
        reasons.append("cross-platform disagreement")
    if invariant_failure:
        reasons.append("invariant failure")
    unique_reasons = tuple(dict.fromkeys(reasons))
    stable = not unique_reasons and observable_preserved and not decision_changed
    return RefinementAssessment(
        action="FAST_TIER_STABLE" if stable else "REFINE",
        reasons=unique_reasons,
        stable_decision=stable,
        observable_change=observable_change,
        observable_preserved=observable_preserved,
        decision_before=decision_before,
        decision_after=decision_after,
        decision_changed=decision_changed,
        further_refinement_required=not stable,
        context=context,
    )
