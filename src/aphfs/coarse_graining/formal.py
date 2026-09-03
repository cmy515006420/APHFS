"""Constructed scalar systems for formula validation, separate from ECA evidence."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import chain

CROSS_SCALE_BOUND_WITHDRAWN = "CROSS_SCALE_BOUND_WITHDRAWN"


class CrossScaleBoundWithdrawn(ValueError):
    """Raised instead of returning a number when a registered domain premise fails."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"{CROSS_SCALE_BOUND_WITHDRAWN}: {detail}")
        self.code = CROSS_SCALE_BOUND_WITHDRAWN


def path_error_bound(
    initial_discrepancy: float,
    lipschitz: Sequence[float],
    local_errors: Sequence[float],
) -> float:
    if len(lipschitz) != len(local_errors):
        raise ValueError("lipschitz and local_errors must have equal length")
    if initial_discrepancy < 0 or any(
        value < 0 for value in chain(lipschitz, local_errors)
    ):
        raise ValueError("bound components must be nonnegative")
    discrepancy = initial_discrepancy
    for constant, local_error in zip(lipschitz, local_errors, strict=True):
        discrepancy = constant * discrepancy + local_error
    return discrepancy


def cross_scale_bound(
    coarse_map_lipschitz: Sequence[float],
    commutation_defects: Sequence[float],
    *,
    intermediate_admissible: Sequence[bool],
    paired_points_in_lipschitz_region: Sequence[bool],
) -> float:
    """Bound an iterated coarse-map/evolution commutation defect.

    If ``G_j`` is the Lipschitz constant of coarse map ``Gamma_j`` and
    ``eta_j`` bounds ``d(Gamma_j F_j, F_{j+1} Gamma_j)``, the r-transition
    defect is

    ``sum_q (prod_{j=q+1}^{r-1} G_j) eta_q``.

    For a start ``x in A_l`` and every ``q = 0, ..., r - 1``, the caller must
    provide affirmative registered evidence that
    ``Gamma_{l:l+q}(x) in A_{l+q}`` and that the paired points
    ``Gamma_{l:l+q} F_l(x)`` and
    ``F_{l+q} Gamma_{l:l+q}(x)`` lie in the registered ``G_{l+q}``-Lipschitz
    region.  A missing or false premise raises ``CROSS_SCALE_BOUND_WITHDRAWN``;
    the function never fills or extrapolates a finite bound after domain exit.

    This is not a paired-trajectory path-error bound: it has no initial
    mismatch term and the propagation constants belong to the subsequent
    coarse maps.
    """
    if len(coarse_map_lipschitz) != len(commutation_defects):
        raise ValueError(
            "coarse_map_lipschitz and commutation_defects must have equal length"
        )
    transition_count = len(commutation_defects)
    if len(intermediate_admissible) != transition_count:
        raise CrossScaleBoundWithdrawn(
            "intermediate-admissibility ledger does not cover every q"
        )
    if len(paired_points_in_lipschitz_region) != transition_count:
        raise CrossScaleBoundWithdrawn(
            "paired-point Lipschitz ledger does not cover every q"
        )
    if not all(intermediate_admissible):
        first_exit = next(
            index for index, admissible in enumerate(intermediate_admissible) if not admissible
        )
        raise CrossScaleBoundWithdrawn(
            f"Gamma intermediate image leaves A at q={first_exit}"
        )
    if not all(paired_points_in_lipschitz_region):
        first_exit = next(
            index
            for index, in_region in enumerate(paired_points_in_lipschitz_region)
            if not in_region
        )
        raise CrossScaleBoundWithdrawn(
            f"paired points leave registered Lipschitz region at q={first_exit}"
        )
    if any(
        value < 0
        for value in chain(coarse_map_lipschitz, commutation_defects)
    ):
        raise ValueError("bound components must be nonnegative")
    propagated = 0.0
    for constant, defect in zip(
        coarse_map_lipschitz,
        commutation_defects,
        strict=True,
    ):
        propagated = constant * propagated + defect
    return propagated


def run_constructed_scalar_case(
    *,
    reference_multiplier: float,
    candidate_multiplier: float,
    initial_reference: float,
    initial_candidate: float,
    steps: int,
) -> dict[str, float]:
    if steps < 1:
        raise ValueError("steps must be positive")
    reference = initial_reference
    candidate = initial_candidate
    local_errors = []
    for _ in range(steps):
        next_reference = reference_multiplier * reference
        next_candidate = candidate_multiplier * candidate
        local_errors.append(abs(reference_multiplier * candidate - next_candidate))
        reference, candidate = next_reference, next_candidate
    measured = abs(reference - candidate)
    bound = path_error_bound(
        abs(initial_reference - initial_candidate),
        [abs(reference_multiplier)] * steps,
        local_errors,
    )
    return {
        "measured_discrepancy": measured,
        "bound": bound,
        "slack": bound - measured,
    }
