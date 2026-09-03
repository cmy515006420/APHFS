"""Outcome-blind ECA rule recovery utilities."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from aphfs.eca.core import Boundary, rule_output


@dataclass(frozen=True)
class TransitionObservations:
    previous: npt.NDArray[np.uint8]
    following: npt.NDArray[np.uint8]
    boundary: Boundary


def recover_consistent_rules(observations: TransitionObservations) -> tuple[int, ...]:
    """Return all rule IDs consistent with observed transitions.

    The function accepts only observations; no ground-truth field is part of the
    inference interface.
    """
    previous = np.asarray(observations.previous, dtype=np.uint8)
    following = np.asarray(observations.following, dtype=np.uint8)
    if previous.ndim != 2 or following.shape != previous.shape:
        raise ValueError("previous and following observations must be equal-shape matrices")
    candidates = []
    for rule_id in range(256):
        if _rule_matches(rule_id, previous, following, observations.boundary):
            candidates.append(rule_id)
    return tuple(candidates)


def _neighbor(row: npt.NDArray[np.uint8], index: int, boundary: Boundary) -> int:
    width = int(row.size)
    if 0 <= index < width:
        return int(row[index])
    if boundary == "periodic":
        return int(row[index % width])
    if boundary == "fixed_zero":
        return 0
    if boundary == "fixed_one":
        return 1
    if boundary == "reflect":
        return int(row[0] if index < 0 else row[-1])
    raise ValueError(boundary)


def _rule_matches(
    rule_id: int,
    previous: npt.NDArray[np.uint8],
    following: npt.NDArray[np.uint8],
    boundary: Boundary,
) -> bool:
    for row_index, row in enumerate(previous):
        for cell in range(row.size):
            predicted = rule_output(
                rule_id,
                _neighbor(row, cell - 1, boundary),
                int(row[cell]),
                _neighbor(row, cell + 1, boundary),
            )
            if predicted != int(following[row_index, cell]):
                return False
    return True

