"""Constructed formal-validation and finite-memory fixtures."""

from aphfs.coarse_graining.formal import (
    cross_scale_bound,
    path_error_bound,
)
from aphfs.coarse_graining.memory import (
    coarse_state,
    counterexample_pair,
    identity_discrepancy,
    micro_step,
)

__all__ = [
    "coarse_state",
    "counterexample_pair",
    "cross_scale_bound",
    "identity_discrepancy",
    "micro_step",
    "path_error_bound",
]

