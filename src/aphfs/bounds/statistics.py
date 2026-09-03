"""Auditable fixed-class and exact-binomial calculations."""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def fixed_class_radius(description_bits: int, sample_size: int, delta: float) -> float:
    """Two-sided Hoeffding/union-bound radius from the v1.2 theorem."""
    if description_bits < 0 or sample_size < 1 or not 0.0 < delta < 1.0:
        raise ValueError("invalid fixed-class radius arguments")
    numerator = (description_bits + 2) * math.log(2.0) + math.log(1.0 / delta)
    return math.sqrt(numerator / (2.0 * sample_size))


def candidate_gate_look_alpha(
    global_alpha: float,
    candidates: int,
    gates: int,
    look: int,
) -> float:
    if not 0.0 < global_alpha < 1.0:
        raise ValueError("global_alpha must be in (0, 1)")
    if candidates < 1 or gates < 1 or look < 1:
        raise ValueError("candidates, gates, and look must be positive")
    return 6.0 * global_alpha / (candidates * gates * math.pi**2 * look**2)


def one_sided_lower_loss(empirical_loss: float, sample_size: int, alpha: float) -> float:
    """One-sided Hoeffding lower confidence bound for bounded loss."""
    if not 0.0 <= empirical_loss <= 1.0:
        raise ValueError("empirical_loss must be in [0, 1]")
    if sample_size < 1 or not 0.0 < alpha < 1.0:
        raise ValueError("invalid sample_size or alpha")
    radius = math.sqrt(math.log(1.0 / alpha) / (2.0 * sample_size))
    return max(0.0, empirical_loss - radius)


@dataclass
class AlphaLedger:
    global_alpha: float
    allocations: dict[tuple[str, str, int], float] = field(default_factory=dict)

    def allocate(
        self,
        candidate_id: str,
        gate_id: str,
        look: int,
        *,
        candidates: int,
        gates: int,
    ) -> float:
        key = (candidate_id, gate_id, look)
        if key in self.allocations:
            raise ValueError(f"Duplicate alpha allocation: {key}")
        alpha = candidate_gate_look_alpha(
            self.global_alpha,
            candidates,
            gates,
            look,
        )
        self.allocations[key] = alpha
        if self.total_allocated > self.global_alpha + 1e-12:
            raise ValueError("Alpha ledger exceeds global budget")
        return alpha

    @property
    def total_allocated(self) -> float:
        return sum(self.allocations.values())

    def is_complete(self, expected: set[tuple[str, str, int]]) -> bool:
        complete = set(self.allocations) == expected
        within_budget = self.total_allocated <= self.global_alpha + 1e-12
        return complete and within_budget


def _binomial_cdf(k: int, n: int, probability: float) -> float:
    """P(X <= k) using a recurrence, with exact boundary handling."""
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if probability <= 0.0:
        return 1.0
    if probability >= 1.0:
        return 0.0
    q = 1.0 - probability
    term = q**n
    total = term
    for x in range(k):
        term *= (n - x) / (x + 1) * probability / q
        total += term
    return min(1.0, max(0.0, total))


def _bisect_decreasing_cdf(k: int, n: int, target: float) -> float:
    low = 0.0
    high = 1.0
    for _ in range(80):
        mid = (low + high) / 2.0
        if _binomial_cdf(k, n, mid) > target:
            low = mid
        else:
            high = mid
    return (low + high) / 2.0


def clopper_pearson_upper(successes: int, trials: int, alpha: float) -> float:
    """One-sided upper endpoint with coverage at least 1-alpha."""
    _validate_binomial_args(successes, trials, alpha)
    if successes == trials:
        return 1.0
    return _bisect_decreasing_cdf(successes, trials, alpha)


def clopper_pearson_lower(successes: int, trials: int, alpha: float) -> float:
    """One-sided lower endpoint with coverage at least 1-alpha."""
    _validate_binomial_args(successes, trials, alpha)
    if successes == 0:
        return 0.0
    return _bisect_decreasing_cdf(successes - 1, trials, 1.0 - alpha)


def clopper_pearson_two_sided(
    successes: int,
    trials: int,
    alpha: float,
) -> tuple[float, float]:
    _validate_binomial_args(successes, trials, alpha)
    return (
        clopper_pearson_lower(successes, trials, alpha / 2.0),
        clopper_pearson_upper(successes, trials, alpha / 2.0),
    )


def _validate_binomial_args(successes: int, trials: int, alpha: float) -> None:
    if trials < 1 or not 0 <= successes <= trials:
        raise ValueError("successes must be in [0, trials], with trials positive")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")


def zero_violation_sample_size(delta: float, alpha: float) -> int:
    if not 0.0 < delta < 1.0 or not 0.0 < alpha < 1.0:
        raise ValueError("delta and alpha must be in (0, 1)")
    return math.ceil(math.log(alpha) / math.log(1.0 - delta))
