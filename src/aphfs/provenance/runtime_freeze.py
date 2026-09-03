"""Canonical runtime inventory and fail-closed freeze verification.

Every protected entry point imports this module.  No runner or packaging
script is allowed to maintain a second hashing implementation.
"""

from __future__ import annotations

import locale
import os
import platform
import sys
import time
from collections import Counter
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, cast

import numpy as np

from aphfs.provenance.hashing import sha256_file, sha256_json
from aphfs.schema.validation import load_json_object, validate_instance

RUNTIME_FREEZE_MISMATCH = "RUNTIME_FREEZE_MISMATCH"
RUNTIME_ENVIRONMENT_MISMATCH = "RUNTIME_ENVIRONMENT_MISMATCH"

_LOCKED_ISOLATED_ARGV = (
    ".venv-protected-freeze-v1/bin/python",
    "-I",
    "scripts/run_locked_audit_once.py",
)
_BOOTSTRAP_ENVIRONMENT_NAMES = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
)
_CRITICAL_IMPORT_PATHS = {
    "aphfs": "src/aphfs/__init__.py",
    "aphfs.pipelines.locked_execution": "src/aphfs/pipelines/locked_execution.py",
    "aphfs.provenance.amendment": "src/aphfs/provenance/amendment.py",
    "aphfs.provenance.runtime_freeze": "src/aphfs/provenance/runtime_freeze.py",
}


class RuntimeFreezeMismatch(PermissionError):
    """Raised before protected values are parsed or any benchmark is called."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"{RUNTIME_FREEZE_MISMATCH}: {detail}")
        self.code = RUNTIME_FREEZE_MISMATCH


class RuntimeEnvironmentMismatch(PermissionError):
    """Raised when the actual interpreter/runtime differs from the manifest."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"{RUNTIME_ENVIRONMENT_MISMATCH}: {detail}")
        self.code = RUNTIME_ENVIRONMENT_MISMATCH


@dataclass(frozen=True)
class RuntimeInventory:
    """Canonical path ledger and its category hashes."""

    rows: tuple[dict[str, str], ...]
    category_hashes: dict[str, str]
    runtime_inventory_sha256: str
    environment_sha256: str
    runtime_environment_manifest_sha256: str | None


def _safe_relative_pattern(pattern: str) -> None:
    path = Path(pattern)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Runtime allowlist pattern is not project-relative: {pattern}")


def _expand_patterns(project_root: Path, patterns: list[str]) -> list[Path]:
    expanded: set[Path] = set()
    for pattern in patterns:
        _safe_relative_pattern(pattern)
        matches = [path for path in project_root.glob(pattern) if path.is_file()]
        if not matches:
            raise FileNotFoundError(f"Runtime allowlist pattern matched no files: {pattern}")
        expanded.update(matches)
    return sorted(expanded)


def _normalize_numpy_config(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        return {
            str(child_key): _normalize_numpy_config(child_value, key=str(child_key))
            for child_key, child_value in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, list):
        return [_normalize_numpy_config(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [_normalize_numpy_config(item, key=key) for item in value]
    if "path" in key.lower() and isinstance(value, str) and value not in {"unknown", ""}:
        return Path(value).name
    return value


def _normalized_distribution_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _is_protected_environment_executable(
    executable: Path,
    prefix: Path,
) -> bool:
    """Accept a venv launcher even when its parent path has an OS alias.

    On macOS, ``/tmp`` and ``/private/tmp`` name the same directory.  Comparing
    their merely absolute spellings rejects a clean venv launched through the
    public ``/tmp`` alias.  Resolve the environment directory, but do not
    require the venv's Python symlink target itself to remain inside the venv.
    """
    return (
        executable.name == "python"
        and executable.parent.parent.resolve() == prefix.resolve()
        and prefix.resolve().name == ".venv-protected-freeze-v1"
    )


def _locked_distributions(project_root: Path) -> dict[str, str]:
    lock_path = project_root / "manifests/protected_runtime_requirements_v2.lock"
    locked: dict[str, str] = {}
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("==") != 1:
            raise ValueError(f"Protected runtime lock is not exact: {line}")
        name, version = line.split("==", maxsplit=1)
        normalized = _normalized_distribution_name(name)
        if normalized in locked:
            raise ValueError(f"Duplicate protected lock distribution: {normalized}")
        locked[normalized] = version
    return locked


def environment_fingerprint(project_root: Path) -> dict[str, Any]:
    """Return the exact, path-scrubbed protected scientific runtime manifest."""
    prefix = Path(sys.prefix).resolve()
    distribution_rows = sorted(
        (
            _normalized_distribution_name(str(distribution.metadata["Name"])),
            distribution.version,
        )
        for distribution in metadata.distributions()
        if distribution.metadata.get("Name")
        and Path(str(distribution.locate_file(""))).resolve().is_relative_to(prefix)
    )
    name_counts = Counter(name for name, _ in distribution_rows)
    duplicate_names = sorted(name for name, count in name_counts.items() if count != 1)
    distributions = sorted(set(distribution_rows))
    installed = {name: version for name, version in distributions}
    locked = _locked_distributions(project_root)
    missing = sorted(set(locked) - set(installed))
    extra = sorted(set(installed) - set(locked))
    version_mismatches = sorted(
        name
        for name in set(locked) & set(installed)
        if locked[name] != installed[name]
    )
    forbidden_names = {
        "artifact-tool-v2",
        "openpyxl",
        "pandas",
        "pdfplumber",
        "pillow",
        "pypdf",
        "python-docx",
        "python-pptx",
        "reportlab",
        "xlsxwriter",
    }
    executable = Path(sys.executable)
    executable_within_environment = _is_protected_environment_executable(
        executable,
        prefix,
    )
    numpy_config = cast(dict[str, Any], np.__config__.show(mode="dicts"))
    thread_names = (
        "OMP_NUM_THREADS",
        "MKL_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "NUMEXPR_NUM_THREADS",
    )
    deterministic_names = (
        "CUBLAS_WORKSPACE_CONFIG",
        "TF_DETERMINISTIC_OPS",
        "JAX_ENABLE_X64",
    )
    return {
        "schema_version": "2",
        "serialization_version": "APHFS_PROTECTED_RUNTIME_ENVIRONMENT_V2",
        "purpose": "PROTECTED_SCIENTIFIC_EXECUTION_ONLY",
        "cross_machine_policy": "EXACT_MATCH_REQUIRED_BEFORE_PROTECTED_VALUE_READ",
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "version_full": sys.version,
            "abi_flags": getattr(sys, "abiflags", ""),
            "cache_tag": getattr(sys.implementation, "cache_tag", None),
            "environment_name": prefix.name,
            "executable_environment_relative": "bin/python",
            "executable_sha256": sha256_file(executable.resolve()),
            "executable_within_environment": executable_within_environment,
        },
        "operating_system": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "kernel": platform.uname().release,
        },
        "installed_distributions": [
            {"name": name, "version": version} for name, version in distributions
        ],
        "distribution_count": len(distributions),
        "duplicate_distribution_names": duplicate_names,
        "forbidden_distribution_names_present": sorted(
            forbidden_names & set(installed)
        ),
        "lock_parity": {
            "matches": not (missing or extra or version_mismatches),
            "missing_from_environment": missing,
            "extra_in_environment": extra,
            "version_mismatches": version_mismatches,
        },
        "numpy": {
            "version": np.__version__,
            "build_configuration": _normalize_numpy_config(numpy_config),
        },
        "thread_environment": {name: os.environ.get(name) for name in thread_names},
        "locale": {
            "active": locale.setlocale(locale.LC_ALL, None),
            "preferred_encoding": locale.getpreferredencoding(False),
        },
        "timezone": {
            "TZ": os.environ.get("TZ"),
            "tzname": list(time.tzname),
            "daylight": bool(time.daylight),
        },
        "hash_environment": {"PYTHONHASHSEED": os.environ.get("PYTHONHASHSEED")},
        "determinism_environment": {
            name: os.environ.get(name) for name in deterministic_names
        },
        "cpu_count": os.cpu_count(),
        "pyproject_sha256": sha256_file(project_root / "pyproject.toml"),
        "protected_runtime_lock_sha256": sha256_file(
            project_root / "manifests/protected_runtime_requirements_v2.lock"
        ),
    }


def _customization_module_present(prefix: Path, filename: str) -> bool:
    return any(path.is_file() or path.is_symlink() for path in prefix.rglob(filename))


def environment_fingerprint_v3(project_root: Path) -> dict[str, Any]:
    """Return v2 identity plus isolated-bootstrap and import provenance.

    Paths are project-relative or environment-relative.  No host home or
    workspace path is serialized into the registered manifest.
    """
    fingerprint = environment_fingerprint(project_root)
    prefix = Path(sys.prefix).resolve()
    origins: dict[str, dict[str, str]] = {}
    for module_name, relative in _CRITICAL_IMPORT_PATHS.items():
        path = project_root / relative
        if not path.is_file() or path.is_symlink():
            raise RuntimeEnvironmentMismatch(
                f"critical import target is absent or symbolic: {module_name}"
            )
        origins[module_name] = {
            "path": relative,
            "sha256": sha256_file(path),
        }
    fingerprint.update(
        {
            "schema_version": "3",
            "serialization_version": "APHFS_PROTECTED_RUNTIME_ENVIRONMENT_V3",
            "python_flags": {
                "isolated": int(sys.flags.isolated),
                "ignore_environment": int(sys.flags.ignore_environment),
                "no_user_site": int(sys.flags.no_user_site),
                "safe_path": bool(sys.flags.safe_path),
            },
            "bootstrap_environment": {
                name.lower() + "_present": name in os.environ
                for name in _BOOTSTRAP_ENVIRONMENT_NAMES
            },
            "import_provenance": {
                "project_source_is_sys_path_zero": bool(sys.path)
                and Path(sys.path[0]).resolve() == (project_root / "src").resolve(),
                "critical_module_origins": origins,
                "sitecustomize_present": _customization_module_present(
                    prefix, "sitecustomize.py"
                ),
                "usercustomize_present": _customization_module_present(
                    prefix, "usercustomize.py"
                ),
            },
            "exact_command_sha256": sha256_json(
                {"cwd": "PROJECT_ROOT", "argv": list(_LOCKED_ISOLATED_ARGV)}
            ),
        }
    )
    return fingerprint


def compute_runtime_inventory(
    project_root: Path,
    allowlist_path: Path,
    runtime_environment_manifest_path: Path | None = None,
) -> RuntimeInventory:
    """Expand the canonical allowlist and hash every executable dependency."""
    allowlist = load_json_object(allowlist_path)
    allowlist_version = str(allowlist.get("schema_version", ""))
    if allowlist_version not in {"1", "2"}:
        raise RuntimeFreezeMismatch("unsupported runtime allowlist version")
    validate_instance(
        allowlist,
        project_root
        / "manifests/schema"
        / f"runtime_allowlist_v{allowlist_version}.schema.json",
        instance_name=allowlist_path.as_posix(),
    )
    categories = cast(dict[str, list[str]], allowlist["categories"])
    path_categories: dict[str, set[str]] = {}
    for category, patterns in categories.items():
        for path in _expand_patterns(project_root, patterns):
            relative = path.relative_to(project_root).as_posix()
            path_categories.setdefault(relative, set()).add(category)
    rows = tuple(
        {
            "path": relative,
            "sha256": sha256_file(project_root / relative),
            "categories": ",".join(sorted(category_names)),
        }
        for relative, category_names in sorted(path_categories.items())
    )
    category_hashes = {
        category: sha256_json(
            [
                {"path": row["path"], "sha256": row["sha256"]}
                for row in rows
                if category in row["categories"].split(",")
            ]
        )
        for category in sorted(categories)
    }
    registered_environment: dict[str, Any] | None = None
    if runtime_environment_manifest_path is not None:
        registered_environment = load_json_object(runtime_environment_manifest_path)
    use_v3 = (
        registered_environment is not None
        and registered_environment.get("schema_version") == "3"
    )
    try:
        actual_environment = (
            environment_fingerprint_v3(project_root)
            if use_v3
            else environment_fingerprint(project_root)
        )
    except (OSError, ValueError) as error:
        raise RuntimeEnvironmentMismatch(
            "protected runtime lock or environment inventory is malformed"
        ) from error
    runtime_environment_manifest_sha256: str | None = None
    if runtime_environment_manifest_path is not None:
        assert registered_environment is not None
        validate_instance(
            registered_environment,
            project_root
            / "manifests/schema"
            / (
                "runtime_environment_manifest_v3.schema.json"
                if use_v3
                else "runtime_environment_manifest_v2.schema.json"
            ),
            instance_name=runtime_environment_manifest_path.as_posix(),
        )
        if (
            actual_environment["duplicate_distribution_names"]
            or actual_environment["forbidden_distribution_names_present"]
            or not actual_environment["lock_parity"]["matches"]
            or not actual_environment["python"]["executable_within_environment"]
        ):
            raise RuntimeEnvironmentMismatch(
                "protected Python, unique distributions, forbidden-package exclusion, "
                "or lock parity failed"
            )
        if use_v3 and (
            actual_environment["python_flags"]
            != {
                "isolated": 1,
                "ignore_environment": 1,
                "no_user_site": 1,
                "safe_path": True,
            }
            or any(actual_environment["bootstrap_environment"].values())
            or actual_environment["import_provenance"]
            != {
                "project_source_is_sys_path_zero": True,
                "critical_module_origins": {
                    module_name: {
                        "path": relative,
                        "sha256": sha256_file(project_root / relative),
                    }
                    for module_name, relative in _CRITICAL_IMPORT_PATHS.items()
                },
                "sitecustomize_present": False,
                "usercustomize_present": False,
            }
            or actual_environment["exact_command_sha256"]
            != sha256_json(
                {"cwd": "PROJECT_ROOT", "argv": list(_LOCKED_ISOLATED_ARGV)}
            )
        ):
            raise RuntimeEnvironmentMismatch(
                "isolated flags, bootstrap environment, import provenance, "
                "or exact command differs"
            )
        if registered_environment != actual_environment:
            raise RuntimeEnvironmentMismatch(
                "actual interpreter, packages, BLAS/thread/locale, or platform differs"
            )
        runtime_environment_manifest_sha256 = sha256_file(
            runtime_environment_manifest_path
        )
    environment_sha256 = sha256_json(actual_environment)
    inventory_payload = {
        "allowlist_sha256": sha256_file(allowlist_path),
        "rows": list(rows),
        "environment_sha256": environment_sha256,
        "runtime_environment_manifest_sha256": (
            runtime_environment_manifest_sha256
        ),
    }
    return RuntimeInventory(
        rows=rows,
        category_hashes=category_hashes,
        runtime_inventory_sha256=sha256_json(inventory_payload),
        environment_sha256=environment_sha256,
        runtime_environment_manifest_sha256=(
            runtime_environment_manifest_sha256
        ),
    )


def freeze_record_payload_sha256(record: dict[str, Any]) -> str:
    """Hash a freeze record without its self-describing payload-hash field."""
    payload = {
        key: value
        for key, value in record.items()
        if key != "final_freeze_record_sha256"
    }
    return sha256_json(payload)


def build_freeze_record(
    *,
    project_root: Path,
    allowlist_path: Path,
    protocol_path: Path,
    config_path: Path,
    fidelity_path: Path,
    runtime_environment_manifest_path: Path,
    document_build_environment_manifest_path: Path,
    status: str,
    protected_execution_authorized: bool = False,
    source_candidate_record_sha256: str | None = None,
    author_final_freeze_approval_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a candidate or approved record from the canonical inventory."""
    inventory = compute_runtime_inventory(
        project_root,
        allowlist_path,
        runtime_environment_manifest_path,
    )
    category = inventory.category_hashes
    record: dict[str, Any] = {
        "schema_version": "5",
        "status": status,
        "protected_execution_authorized": protected_execution_authorized,
        "protected_roles_materialized": False,
        "source_candidate_record_sha256": source_candidate_record_sha256,
        "author_final_freeze_approval_sha256": (
            author_final_freeze_approval_sha256
        ),
        "runtime_allowlist_sha256": sha256_file(allowlist_path),
        "runtime_inventory_sha256": inventory.runtime_inventory_sha256,
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_sha256": sha256_file(fidelity_path),
        "source_sha256": category["source"],
        "script_sha256": category["scripts"],
        "schema_sha256": category["schemas"],
        "analysis_sha256": category["analysis"],
        "environment_sha256": inventory.environment_sha256,
        "runtime_environment_manifest_sha256": (
            inventory.runtime_environment_manifest_sha256
        ),
        "protected_runtime_environment_sha256": (
            inventory.runtime_environment_manifest_sha256
        ),
        "document_build_environment_sha256": sha256_file(
            document_build_environment_manifest_path
        ),
        "static_manifest_sha256": category["static_manifests"],
        "runtime_file_count": len(inventory.rows),
    }
    record["final_freeze_record_sha256"] = freeze_record_payload_sha256(record)
    validate_instance(
        record,
        project_root / "manifests/schema/final_freeze_record_v5.schema.json",
        instance_name="final freeze record",
    )
    return record


def verify_runtime_freeze(
    *,
    project_root: Path,
    allowlist_path: Path,
    freeze_record_path: Path,
    expected_freeze_file_sha256: str,
    protocol_path: Path,
    config_path: Path,
    fidelity_path: Path,
    runtime_environment_manifest_path: Path,
    allow_test_only_synthetic: bool = False,
) -> dict[str, Any]:
    """Verify the full runtime before any protected role values are parsed."""
    if sha256_file(freeze_record_path) != expected_freeze_file_sha256:
        raise RuntimeFreezeMismatch("final freeze record raw-file hash mismatch")
    record = load_json_object(freeze_record_path)
    validate_instance(
        record,
        project_root / "manifests/schema/final_freeze_record_v5.schema.json",
        instance_name=freeze_record_path.as_posix(),
    )
    status = str(record["status"])
    approved = (
        status == "FINAL_FREEZE_APPROVED"
        and bool(record["protected_execution_authorized"])
    )
    synthetic = (
        allow_test_only_synthetic
        and status == "TEST_ONLY_SYNTHETIC_FINAL_FREEZE_APPROVED"
    )
    if not (approved or synthetic):
        raise RuntimeFreezeMismatch("freeze record is not an approved execution record")
    if approved and (
        record.get("source_candidate_record_sha256") is None
        or record.get("author_final_freeze_approval_sha256") is None
    ):
        raise RuntimeFreezeMismatch(
            "approved freeze lacks candidate and author-approval provenance"
        )
    if record["final_freeze_record_sha256"] != freeze_record_payload_sha256(record):
        raise RuntimeFreezeMismatch("freeze record canonical payload hash mismatch")
    inventory = compute_runtime_inventory(
        project_root,
        allowlist_path,
        runtime_environment_manifest_path,
    )
    expected = {
        "runtime_allowlist_sha256": sha256_file(allowlist_path),
        "runtime_inventory_sha256": inventory.runtime_inventory_sha256,
        "protocol_sha256": sha256_file(protocol_path),
        "config_sha256": sha256_file(config_path),
        "fidelity_sha256": sha256_file(fidelity_path),
        "source_sha256": inventory.category_hashes["source"],
        "script_sha256": inventory.category_hashes["scripts"],
        "schema_sha256": inventory.category_hashes["schemas"],
        "analysis_sha256": inventory.category_hashes["analysis"],
        "environment_sha256": inventory.environment_sha256,
        "runtime_environment_manifest_sha256": sha256_file(
            runtime_environment_manifest_path
        ),
        "protected_runtime_environment_sha256": sha256_file(
            runtime_environment_manifest_path
        ),
        "static_manifest_sha256": inventory.category_hashes["static_manifests"],
        "runtime_file_count": len(inventory.rows),
    }
    mismatches = [
        key for key, value in expected.items() if record.get(key) != value
    ]
    if mismatches:
        raise RuntimeFreezeMismatch(
            "current runtime differs in " + ", ".join(sorted(mismatches))
        )
    return record
