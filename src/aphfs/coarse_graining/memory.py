"""Exact D0/D1/D2 coarse-state fixtures."""

from __future__ import annotations

type Microstate = tuple[int, int]


def micro_step(state: Microstate) -> Microstate:
    a, b = state
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("microstate must be binary")
    return b, a


def coarse_state(state: Microstate) -> int:
    return state[0]


def identity_discrepancy(state: Microstate) -> int:
    return int(micro_step(state) != micro_step(state))


def counterexample_pair() -> tuple[Microstate, Microstate]:
    left = (0, 0)
    right = (0, 1)
    if coarse_state(left) != coarse_state(right):
        raise AssertionError("counterexample must share a coarse state")
    if coarse_state(micro_step(left)) == coarse_state(micro_step(right)):
        raise AssertionError("counterexample must differ at the next coarse state")
    return left, right


def memory_repair_prediction(current_coarse: int, previous_coarse: int) -> int:
    del current_coarse
    return previous_coarse


def validate_memory_repair(trajectory: tuple[Microstate, ...]) -> bool:
    if len(trajectory) < 3:
        raise ValueError("trajectory must contain at least three microstates")
    coarse = tuple(coarse_state(state) for state in trajectory)
    return all(
        coarse[index + 1] == memory_repair_prediction(coarse[index], coarse[index - 1])
        for index in range(1, len(coarse) - 1)
    )
