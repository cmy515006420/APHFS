"""F0 programmatically regenerated Rule 54/110 canonical fixtures."""

from __future__ import annotations

from typing import Any

import numpy as np

from aphfs.constants import DEVELOPMENT_LABEL, ENGINEERING_FIXTURE_SCOPE
from aphfs.eca.core import simulate_reference, simulate_vectorized
from aphfs.provenance.hashing import sha256_bytes

FIXTURE_CITATIONS = {
    "rule54": "MartinezAdamatzkyMcIntosh2006",
    "rule110": "Cook2004",
}


def _seed_from_bits(bits: str, width: int) -> np.ndarray:
    seed = np.zeros(width, dtype=np.uint8)
    pattern = np.fromiter((int(bit) for bit in bits), dtype=np.uint8)
    start = (width - pattern.size) // 2
    seed[start : start + pattern.size] = pattern
    return seed


def run_f0(config: dict[str, Any]) -> dict[str, Any]:
    width = int(config["width"])
    steps = int(config["steps"])
    fixture_defs = {
        54: "001101001",
        110: "00010011011111",
    }
    fixtures = []
    all_match = True
    for rule_id, bits in fixture_defs.items():
        initial = _seed_from_bits(bits, width)
        reference = simulate_reference(rule_id, initial, steps, "periodic")
        regenerated = simulate_vectorized(rule_id, initial, steps, "periodic")
        exact = bool(np.array_equal(reference, regenerated))
        all_match = all_match and exact
        fixtures.append(
            {
                "rule_id": rule_id,
                "citation_key": FIXTURE_CITATIONS[f"rule{rule_id}"],
                "initial_program": bits,
                "fixture_sha256": sha256_bytes(regenerated.tobytes()),
                "exact_regeneration": exact,
            }
        )
    return {
        "label": DEVELOPMENT_LABEL,
        "engine_scope": ENGINEERING_FIXTURE_SCOPE,
        "sub_id": "F0",
        "status": "PASS" if all_match else "FAIL",
        "fixtures": fixtures,
        "catalogue_images_copied": False,
        "sealed_rule_labels_used_for_training": False,
        "interpretation": "KNOWN_STRUCTURE_FIXTURE_AUDIT_NOT_APHFS_DISCOVERY",
    }
