"""Hard-fail JSON Schema validation at every execution boundary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError


class SchemaValidationError(ValueError):
    """An input or output violates its registered Draft 2020-12 schema."""


def load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SchemaValidationError(f"Expected a JSON object: {path}")
    return cast(dict[str, Any], value)


def validate_instance(
    instance: Any,
    schema: dict[str, Any] | Path,
    *,
    instance_name: str = "in-memory instance",
) -> None:
    schema_object = load_json_object(schema) if isinstance(schema, Path) else schema
    try:
        Draft202012Validator.check_schema(schema_object)
        Draft202012Validator(schema_object).validate(instance)
    except (SchemaError, ValidationError) as exc:
        path = "/".join(str(part) for part in getattr(exc, "absolute_path", ()))
        location = f" at {path}" if path else ""
        raise SchemaValidationError(
            f"Draft 2020-12 validation failed for {instance_name}{location}: {exc.message}"
        ) from exc


def validate_json_file(
    instance_path: Path,
    schema_path: Path,
) -> dict[str, Any]:
    instance = load_json_object(instance_path)
    schema = load_json_object(schema_path)
    validate_instance(instance, schema, instance_name=instance_path.as_posix())
    return instance
