"""Safe JSON/JSONL output helpers that refuse accidental overwrite."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any


class OutputExistsError(RuntimeError):
    """Raised when a supposedly immutable output already exists."""


def _claim_new_path(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8"):
            pass
    except FileExistsError as exc:
        raise OutputExistsError(f"Refusing to overwrite existing output: {path}") from exc


def write_json_new(path: Path, value: Any) -> None:
    _claim_new_path(path)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def write_jsonl_new(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    _claim_new_path(path)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(
                json.dumps(row, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
            )

