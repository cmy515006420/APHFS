"""Split-manifest isolation and frozen-configuration controls."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from aphfs.provenance.hashing import sha256_json


class ProtectedRoleAccessError(PermissionError):
    """Development code attempted to access a protected split."""


class FrozenConfigMutationError(RuntimeError):
    """A configuration changed after its hash was frozen."""


PROTECTED_ROLES = frozenset({"calibration", "locked"})


def derive_seed(master_seed: int, namespace: str, index: int) -> int:
    payload = {"master_seed": master_seed, "namespace": namespace, "index": index}
    return int(sha256_json(payload)[:16], 16) % (2**63 - 1)


def build_seed_manifest(role: str, master_seed: int, count: int) -> dict[str, Any]:
    """Build a seed manifest in memory.

    This development release intentionally refuses protected roles. A later,
    separately authorized release may wrap the same deterministic derivation in
    an author-executed commitment workflow.
    """
    if role in PROTECTED_ROLES:
        raise ProtectedRoleAccessError(f"Seed generation for role {role!r} is not authorized")
    if role != "development":
        raise ValueError(f"Unknown seed role: {role}")
    if count < 1:
        raise ValueError("count must be positive")
    seeds = [derive_seed(master_seed, role, index) for index in range(count)]
    body: dict[str, Any] = {
        "schema_version": "1",
        "role": role,
        "derivation": "sha256(master_seed, namespace, index) mod (2^63-1)",
        "master_seed": master_seed,
        "seeds": seeds,
    }
    body["commitment_sha256"] = sha256_json(body)
    return body


def load_development_manifest(path: Path) -> dict[str, Any]:
    lower_parts = {part.lower() for part in path.parts}
    if lower_parts & PROTECTED_ROLES:
        raise ProtectedRoleAccessError(f"Development code cannot access protected path: {path}")
    data = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    if data.get("role") != "development":
        raise ProtectedRoleAccessError("Development loader accepts only development manifests")
    return data


def validate_seed_disjointness(manifests: Iterable[dict[str, Any]]) -> None:
    seen: dict[int, str] = {}
    for manifest in manifests:
        role = str(manifest["role"])
        for seed in manifest["seeds"]:
            seed_int = int(seed)
            if seed_int in seen:
                raise ValueError(
                    f"Duplicate seed {seed_int} across roles {seen[seed_int]!r} and {role!r}"
                )
            seen[seed_int] = role


def validate_path_isolation(role_paths: dict[str, Path]) -> None:
    resolved = {role: path.resolve() for role, path in role_paths.items()}
    items = list(resolved.items())
    for index, (role_a, path_a) in enumerate(items):
        for role_b, path_b in items[index + 1 :]:
            if path_a == path_b or path_a in path_b.parents or path_b in path_a.parents:
                raise ValueError(f"Path overlap between {role_a!r} and {role_b!r}")


@dataclass(frozen=True)
class FrozenConfig:
    data: dict[str, Any]
    digest: str

    @classmethod
    def freeze(cls, data: dict[str, Any]) -> FrozenConfig:
        copied = json.loads(json.dumps(data))
        return cls(data=copied, digest=sha256_json(copied))

    def verify(self, current: dict[str, Any]) -> None:
        if sha256_json(current) != self.digest:
            raise FrozenConfigMutationError("Configuration changed after freeze")
