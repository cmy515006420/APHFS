"""Elementary cellular-automaton implementations and inference."""

from aphfs.eca.core import (
    Boundary,
    rule_output,
    rule_truth_table,
    simulate_reference,
    simulate_vectorized,
)

__all__ = [
    "Boundary",
    "rule_output",
    "rule_truth_table",
    "simulate_reference",
    "simulate_vectorized",
]

