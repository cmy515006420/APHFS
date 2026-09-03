"""Frozen, exact, byte-stable signature serialization."""

from __future__ import annotations

import math
import struct
from collections.abc import Iterable
from dataclasses import asdict, dataclass

from aphfs.provenance.hashing import canonical_json_bytes, sha256_bytes


@dataclass(frozen=True)
class SignatureSpec:
    version: str
    probe_order: tuple[str, ...]
    summary_schema: tuple[str, ...]
    quantizer_boundaries: tuple[float, ...]
    boundary_tie_break: str = "upper"
    missing_value_code: int = -32768
    dtype: str = "int16"
    byte_order: str = "little"

    def validate(self) -> None:
        if self.version != "eca-signature-v1":
            raise ValueError("Unsupported signature version")
        if self.boundary_tie_break not in {"lower", "upper"}:
            raise ValueError("boundary_tie_break must be lower or upper")
        if self.dtype != "int16" or self.byte_order != "little":
            raise ValueError("v1 serialization is fixed to little-endian int16")
        if tuple(sorted(self.quantizer_boundaries)) != self.quantizer_boundaries:
            raise ValueError("quantizer boundaries must be sorted")


def _quantize(value: float | None, spec: SignatureSpec) -> int:
    if value is None or not math.isfinite(value):
        return spec.missing_value_code
    if spec.boundary_tie_break == "upper":
        return sum(value >= boundary for boundary in spec.quantizer_boundaries)
    return sum(value > boundary for boundary in spec.quantizer_boundaries)


def serialize_signature(values: Iterable[float | None], spec: SignatureSpec) -> bytes:
    spec.validate()
    quantized = tuple(_quantize(value, spec) for value in values)
    if len(quantized) != len(spec.probe_order) * len(spec.summary_schema):
        raise ValueError("Signature value count does not match probe order and summary schema")
    header = canonical_json_bytes(asdict(spec))
    payload = struct.pack("<" + "h" * len(quantized), *quantized)
    return b"APHFS-SIG\0" + struct.pack("<I", len(header)) + header + payload


def canonical_signature(values: Iterable[float | None], spec: SignatureSpec) -> str:
    return sha256_bytes(serialize_signature(values, spec))

