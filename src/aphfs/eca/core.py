"""Independent reference and vectorized ECA simulators."""

from __future__ import annotations

from typing import Literal

import numpy as np
import numpy.typing as npt

Boundary = Literal["periodic", "fixed_zero", "fixed_one", "reflect"]
UInt8Array = npt.NDArray[np.uint8]


def _validate_rule(rule_id: int) -> None:
    if not 0 <= rule_id <= 255:
        raise ValueError("ECA rule_id must be in [0, 255]")


def _validate_state(initial: npt.ArrayLike) -> UInt8Array:
    state = np.asarray(initial, dtype=np.uint8)
    if state.ndim != 1 or state.size < 1:
        raise ValueError("initial state must be a non-empty one-dimensional array")
    if not np.all((state == 0) | (state == 1)):
        raise ValueError("ECA state values must be binary")
    return state.copy()


def rule_output(rule_id: int, left: int, center: int, right: int) -> int:
    """Return the Wolfram ECA output for one three-bit neighborhood."""
    _validate_rule(rule_id)
    if (left, center, right) not in {
        (0, 0, 0),
        (0, 0, 1),
        (0, 1, 0),
        (0, 1, 1),
        (1, 0, 0),
        (1, 0, 1),
        (1, 1, 0),
        (1, 1, 1),
    }:
        raise ValueError("neighborhood values must be binary")
    index = (left << 2) | (center << 1) | right
    return (rule_id >> index) & 1


def rule_truth_table(rule_id: int) -> tuple[int, ...]:
    """Return outputs for neighborhoods 000, 001, ..., 111."""
    _validate_rule(rule_id)
    return tuple((rule_id >> index) & 1 for index in range(8))


def _reference_neighbor(state: UInt8Array, index: int, boundary: Boundary) -> int:
    width = int(state.size)
    if 0 <= index < width:
        return int(state[index])
    if boundary == "periodic":
        return int(state[index % width])
    if boundary == "fixed_zero":
        return 0
    if boundary == "fixed_one":
        return 1
    if boundary == "reflect":
        return int(state[0] if index < 0 else state[-1])
    raise ValueError(f"Unsupported boundary: {boundary}")


def _validate_reference_state(initial: npt.ArrayLike) -> UInt8Array:
    """Reference-path validation kept separate from the production path."""
    state = np.array(initial, dtype=np.uint8, copy=True)
    if len(state.shape) != 1 or state.shape[0] == 0:
        raise ValueError("initial state must be a non-empty one-dimensional array")
    if any(int(value) not in (0, 1) for value in state):
        raise ValueError("ECA state values must be binary")
    return state


def _reference_rule_output(rule_id: int, left: int, center: int, right: int) -> int:
    """Reference lookup using an explicit 111-to-000 binary rule string."""
    if rule_id < 0 or rule_id > 255:
        raise ValueError("ECA rule_id must be in [0, 255]")
    if left not in (0, 1) or center not in (0, 1) or right not in (0, 1):
        raise ValueError("neighborhood values must be binary")
    neighborhood = f"{left}{center}{right}"
    wolfram_order = ("111", "110", "101", "100", "011", "010", "001", "000")
    output_bits = f"{rule_id:08b}"
    return int(output_bits[wolfram_order.index(neighborhood)])


def step_reference(rule_id: int, state: npt.ArrayLike, boundary: Boundary) -> UInt8Array:
    current = _validate_reference_state(state)
    output = np.empty_like(current)
    for index in range(current.size):
        left = _reference_neighbor(current, index - 1, boundary)
        center = int(current[index])
        right = _reference_neighbor(current, index + 1, boundary)
        output[index] = _reference_rule_output(rule_id, left, center, right)
    return output


def simulate_reference(
    rule_id: int,
    initial: npt.ArrayLike,
    steps: int,
    boundary: Boundary = "periodic",
) -> UInt8Array:
    """Simple cell-by-cell simulator used as the reference implementation."""
    if steps < 0:
        raise ValueError("steps must be nonnegative")
    state = _validate_reference_state(initial)
    history = np.empty((steps + 1, state.size), dtype=np.uint8)
    history[0] = state
    for step in range(steps):
        state = step_reference(rule_id, state, boundary)
        history[step + 1] = state
    return history


def _vectorized_neighbors(state: UInt8Array, boundary: Boundary) -> tuple[UInt8Array, UInt8Array]:
    if boundary == "periodic":
        return np.roll(state, 1), np.roll(state, -1)
    if boundary == "fixed_zero":
        return (
            np.pad(state[:-1], (1, 0), constant_values=0),
            np.pad(state[1:], (0, 1), constant_values=0),
        )
    if boundary == "fixed_one":
        return (
            np.pad(state[:-1], (1, 0), constant_values=1),
            np.pad(state[1:], (0, 1), constant_values=1),
        )
    if boundary == "reflect":
        return (
            np.concatenate((state[:1], state[:-1])),
            np.concatenate((state[1:], state[-1:])),
        )
    raise ValueError(f"Unsupported boundary: {boundary}")


def step_vectorized(rule_id: int, state: npt.ArrayLike, boundary: Boundary) -> UInt8Array:
    _validate_rule(rule_id)
    current = _validate_state(state)
    left, right = _vectorized_neighbors(current, boundary)
    neighborhood = (left << 2) | (current << 1) | right
    return ((rule_id >> neighborhood) & 1).astype(np.uint8, copy=False)


def simulate_vectorized(
    rule_id: int,
    initial: npt.ArrayLike,
    steps: int,
    boundary: Boundary = "periodic",
) -> UInt8Array:
    """NumPy production simulator independent of the scalar update loop."""
    if steps < 0:
        raise ValueError("steps must be nonnegative")
    state = _validate_state(initial)
    history = np.empty((steps + 1, state.size), dtype=np.uint8)
    history[0] = state
    for step in range(steps):
        state = step_vectorized(rule_id, state, boundary)
        history[step + 1] = state
    return history
