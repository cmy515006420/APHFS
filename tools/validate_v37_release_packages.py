#!/usr/bin/env python3
"""Fail-closed validation for the three APHFS Phase 3.7 local packages.

The validator is standard-library-only and imports the sibling builder by an
explicit file path so that ``python -I`` remains supported.  It never imports
``aphfs`` and never executes project code.  ZIPs are checked before manual
path-safe extraction into a new temporary directory.  Plain files and nested
ZIP/DOCX members are recursively inspected for secrets and private paths.
"""

from __future__ import annotations

import argparse
import ast
import binascii
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import struct
import tempfile
import unicodedata
import zipfile
from decimal import Decimal, localcontext
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

_BUILDER_PATH = Path(__file__).with_name("build_v37_release_packages.py")
if _BUILDER_PATH.is_symlink() or not _BUILDER_PATH.is_file():
    raise RuntimeError("sibling v3.7 package builder is missing or not a regular file")
_SPEC = importlib.util.spec_from_file_location("_aphfs_v37_release_builder", _BUILDER_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("cannot create isolated import spec for v3.7 package builder")
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)

ZIP_TIME = build.ZIP_TIME
GITHUB_NAME = build.GITHUB_NAME
BIORXIV_NAME = build.BIORXIV_NAME
REVIEW_NAME = build.REVIEW_NAME
SUPPLEMENTARY_REPRO_NAME = build.SUPPLEMENTARY_REPRO_NAME
FINAL_DOCX = build.FINAL_DOCX
FINAL_PDF = build.FINAL_PDF
BASELINE_PDF = build.BASELINE_PDF
TITLE = build.TITLE
RESULT_SHA256 = build.RESULT_SHA256
RECEIPT_SHA256 = build.RECEIPT_SHA256
CORE_SHA256 = build.CORE_SHA256
PROTOCOL_SHA256 = build.PROTOCOL_SHA256
CONFIG_SHA256 = build.CONFIG_SHA256
FIDELITY_SHA256 = build.FIDELITY_SHA256
AMENDMENT_V2_SHA256 = build.AMENDMENT_V2_SHA256
GRAMMAR_SHA256 = build.GRAMMAR_SHA256
V36_PDF_SHA256 = build.V36_PDF_SHA256
V36_DOCX_SHA256 = build.V36_DOCX_SHA256

MAX_MEMBER_BYTES = 140 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 650 * 1024 * 1024
MAX_NESTING = 6
HEX64 = re.compile(r"[0-9a-f]{64}")

PRIVATE_PATTERNS = (
    ("macOS/Linux home path", re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/")),
    ("macOS private temp path", re.compile(rb"/private/(?:tmp|var/folders)/")),
    ("local file URI", re.compile(rb"(?i)file://(?:/)?(?:Users|home)/")),
    ("Windows user path", re.compile(rb"(?i)[A-Z]:\\+Users\\+[A-Za-z0-9._-]+\\")),
)
SECRET_PATTERNS = (
    ("private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PGP private key", re.compile(rb"-----BEGIN PGP " rb"PRIVATE KEY BLOCK-----")),
    ("OpenAI-like token", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(rb"\bgh[opusr]_[A-Za-z0-9]{20,}\b")),
    ("GitHub fine-grained token", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS access key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "bearer credential",
        re.compile(rb"(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/-]{20,}"),
    ),
    (
        "credential assignment",
        re.compile(
            rb"(?i)(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|"
            rb"refresh[_-]?token)"
            rb"\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{20,}"
        ),
    ),
    (
        "session cookie",
        re.compile(rb"(?i)(?:cookie|set-cookie)\s*:\s*[^\r\n]{20,}"),
    ),
    (
        "generic signed URL query",
        re.compile(rb"(?i)[?&](?:sig|signature)=[A-Za-z0-9%+/=_-]{20,}"),
    ),
    (
        "signed URL",
        re.compile(rb"(?i)(?:X-Amz-Signature|X-Goog-Signature)=[0-9A-Za-z%]{20,}"),
    ),
    (
        "credentialed database URL",
        re.compile(
            rb"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?)://"
            rb"[^\s/:]+:[^\s/@]+@"
        ),
    ),
)

FORBIDDEN_CONTENT_FILENAMES = {
    "calibration_role_v1.json",
    "locked_role_v1.json",
    "locked_result_bundle_v1.json",
    "locked_execution_receipt_v1.json",
    "locked_execution_intent_v1.json",
    "calibration_execution_approval_v1.json",
    "locked_execution_approval_v1.json",
    "authorization_record.json",
}
ALLOWED_NESTED_ARCHIVE_NAMES = {
    SUPPLEMENTARY_REPRO_NAME,
    f"{GITHUB_NAME}.zip",
    f"{BIORXIV_NAME}.zip",
}

EXPECTED_ENDPOINTS = {
    "A0": (0, 256, "PASS"),
    "A1": (0, 64, "PASS"),
    "B0": (0, 64, "PASS"),
    "B1": (0, 64, "PASS"),
    "C": (0, 9, "PASS"),
    "D0": (0, 64, "PASS"),
    "D1": (0, 1, "PASS"),
    "D2-CERT": (0, 64, "NOT_CONTRADICTED_BY_LOCKED_AUDIT"),
    "D2-MEM": (0, 4, "PASS"),
    "E": (0, 64, "PASS"),
    "F0": (0, 64, "PASS"),
}
EXPECTED_COSTS = {
    "exhaustive": 132096,
    "fixed_order": 75080,
    "development_frozen_order": 89816,
    "adaptive_fidelity": 92592,
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_strict(path: Path) -> object:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_reject_duplicate_json_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite JSON constant: {value}")
        ),
    )


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def safe_rel(value: str) -> PurePosixPath:
    pure = build.safe_relative(value)
    if pure.name in FORBIDDEN_CONTENT_FILENAMES:
        raise ValueError(f"raw/private artifact filename is forbidden: {value}")
    name = pure.name.casefold()
    if name.endswith((".json", ".md", ".txt", ".html", ".yaml", ".yml")):
        if any(token in name for token in ("chat", "conversation", "prompt_log")):
            raise ValueError(f"chat/prompt transcript artifact is forbidden: {value}")
        if (
            any(token in name for token in ("approval", "authorization", "authorisation"))
            and not name.endswith(".schema.json")
        ):
            raise ValueError(f"private approval/authorization artifact is forbidden: {value}")
        if "protected_result" in name and not name.endswith(".schema.json"):
            raise ValueError(f"protected result container is forbidden: {value}")
        if re.search(r"(?:calibration|locked).*role|role.*manifest", name) and not name.endswith(
            ".schema.json"
        ):
            raise ValueError(f"raw role artifact is forbidden: {value}")
    if name.endswith(".zip") and pure.name not in ALLOWED_NESTED_ARCHIVE_NAMES:
        raise ValueError(f"unapproved/historical nested ZIP is forbidden: {value}")
    return pure


def iter_tree_files(root: Path) -> list[Path]:
    files: list[Path] = []
    seen: dict[str, str] = {}
    for current, directories, names in os.walk(root, followlinks=False):
        base = Path(current)
        directories[:] = sorted(directories)
        for name in directories:
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_rel(relative)
            if path.is_symlink():
                raise ValueError(f"symlink directory: {relative}")
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_rel(relative)
            key = collision_key(relative)
            if key in seen and seen[key] != relative:
                raise ValueError(f"case/Unicode collision: {seen[key]!r} / {relative!r}")
            seen[key] = relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"non-regular file: {relative}")
            if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
                raise ValueError(f"special file: {relative}")
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def directory_set(root: Path) -> set[str]:
    directories: set[str] = set()
    for current, names, _ in os.walk(root, followlinks=False):
        base = Path(current)
        for name in names:
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_rel(relative)
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"non-directory tree entry: {relative}")
            directories.add(relative)
    return directories


def expected_directory_set(expected: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in expected:
        parent = PurePosixPath(relative).parent
        while parent.as_posix() not in {"", "."}:
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def scan_plain_bytes(data: bytes, label: str) -> None:
    candidates = [data]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or (
        data and data.count(b"\x00") / len(data) > 0.15
    ):
        candidates.append(data.replace(b"\x00", b""))
    for candidate in candidates:
        for description, pattern in PRIVATE_PATTERNS + SECRET_PATTERNS:
            if pattern.search(candidate):
                raise ValueError(f"{label}: privacy/secret finding: {description}")


def checked_zip_infos(
    archive: zipfile.ZipFile,
    label: str,
    *,
    deterministic_outer: bool = False,
) -> list[zipfile.ZipInfo]:
    if archive.comment:
        raise ValueError(f"{label}: ZIP comment forbidden")
    infos = archive.infolist()
    raw_names: set[str] = set()
    collision_names: dict[str, str] = {}
    total = 0
    for info in infos:
        raw = info.filename
        relative = raw[:-1] if info.is_dir() and raw.endswith("/") else raw
        safe_rel(relative)
        scan_plain_bytes(raw.encode("utf-8", errors="strict"), f"{label}: member name")
        scan_plain_bytes(info.comment, f"{label}: member comment")
        scan_plain_bytes(info.extra, f"{label}: member extra field")
        if raw in raw_names:
            raise ValueError(f"{label}: duplicate ZIP member: {raw}")
        raw_names.add(raw)
        key = collision_key(relative)
        if key in collision_names and collision_names[key] != relative:
            raise ValueError(
                f"{label}: normalized/case-folded collision: "
                f"{collision_names[key]!r} / {relative!r}"
            )
        collision_names[key] = relative
        if info.flag_bits & 0x1:
            raise ValueError(f"{label}: encrypted ZIP member: {raw}")
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type == stat.S_IFLNK:
            raise ValueError(f"{label}: symlink ZIP member: {raw}")
        if info.is_dir() and file_type not in (0, stat.S_IFDIR):
            raise ValueError(f"{label}: invalid directory member type: {raw}")
        if not info.is_dir() and file_type not in (0, stat.S_IFREG):
            raise ValueError(f"{label}: special ZIP member: {raw}")
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(f"{label}: oversized member: {raw}")
        if info.compress_size and info.file_size / info.compress_size > 3000:
            raise ValueError(f"{label}: suspicious compression ratio: {raw}")
        total += info.file_size
        if total > MAX_UNCOMPRESSED_BYTES:
            raise ValueError(f"{label}: excessive total uncompressed size")
        if deterministic_outer:
            if info.date_time != ZIP_TIME or info.create_system != 3:
                raise ValueError(f"{label}: nondeterministic ZIP metadata: {raw}")
            if info.compress_type != zipfile.ZIP_STORED:
                raise ValueError(f"{label}: outer ZIP member is not stored: {raw}")
            if info.comment or info.extra:
                raise ValueError(f"{label}: outer ZIP member comment/extra field forbidden: {raw}")
            expected_mode = 0o755 if info.is_dir() else 0o644
            expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
            if file_type != expected_type or stat.S_IMODE(mode) != expected_mode:
                raise ValueError(f"{label}: unexpected permissions: {raw}")
    if deterministic_outer and [info.filename for info in infos] != sorted(
        info.filename for info in infos
    ):
        raise ValueError(f"{label}: ZIP members are not sorted")
    bad = archive.testzip()
    if bad is not None:
        raise ValueError(f"{label}: CRC failure: {bad}")
    return infos


def scan_zip_bytes(data: bytes, label: str, depth: int = 0) -> int:
    if depth > MAX_NESTING:
        raise ValueError(f"{label}: nested archive depth exceeds {MAX_NESTING}")
    count = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise ValueError(f"{label}: malformed nested ZIP/DOCX") from error
    with archive:
        for info in checked_zip_infos(archive, label):
            if info.is_dir():
                continue
            member = archive.read(info)
            member_label = f"{label}!/{info.filename}"
            scan_plain_bytes(member, member_label)
            count += 1
            if zipfile.is_zipfile(io.BytesIO(member)):
                count += scan_zip_bytes(member, member_label, depth + 1)
    return count


def scan_artifact(path: Path, label: str) -> int:
    if path.stat().st_size > MAX_MEMBER_BYTES:
        raise ValueError(f"{label}: file exceeds scan ceiling")
    data = path.read_bytes()
    scan_plain_bytes(data, label)
    if zipfile.is_zipfile(io.BytesIO(data)):
        return scan_zip_bytes(data, label)
    return 1


def png_integrity(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 45 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"invalid PNG signature: {path}")
    offset = 8
    dimensions: tuple[int, int] | None = None
    saw_idat = False
    saw_end = False
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError(f"truncated PNG chunk: {path}")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        actual_crc = binascii.crc32(kind + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"PNG CRC mismatch: {path}")
        if kind == b"IHDR":
            if length != 13 or dimensions is not None:
                raise ValueError(f"invalid PNG IHDR: {path}")
            dimensions = struct.unpack(">II", payload[:8])
            if dimensions[0] <= 0 or dimensions[1] <= 0:
                raise ValueError(f"invalid PNG dimensions: {path}")
        elif kind == b"IDAT":
            saw_idat = True
        elif kind == b"IEND":
            saw_end = True
            if end != len(data):
                raise ValueError(f"trailing bytes after PNG IEND: {path}")
            break
        offset = end
    if dimensions is None or not saw_idat or not saw_end:
        raise ValueError(f"incomplete PNG: {path}")
    return dimensions


def pdf_integrity(path: Path) -> None:
    data = path.read_bytes()
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-4096:]:
        raise ValueError(f"invalid PDF structure: {path}")


def svg_text(path: Path) -> str:
    try:
        root = ElementTree.fromstring(path.read_bytes())
    except ElementTree.ParseError as error:
        raise ValueError(f"malformed SVG: {path}") from error
    if not root.tag.endswith("svg"):
        raise ValueError(f"SVG root element missing: {path}")
    return " ".join(text.strip() for text in root.itertext() if text.strip())


def docx_text(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        infos = checked_zip_infos(archive, path.name)
        names = {info.filename for info in infos if not info.is_dir()}
        if "word/document.xml" not in names or "[Content_Types].xml" not in names:
            raise ValueError(f"DOCX core members missing: {path}")
        document = archive.read("word/document.xml")
    try:
        root = ElementTree.fromstring(document)
    except ElementTree.ParseError as error:
        raise ValueError(f"malformed DOCX document.xml: {path}") from error
    return re.sub(
        r"\s+",
        " ",
        " ".join(
            element.text
            for element in root.iter()
            if element.tag.endswith("}t") and element.text
        ),
    ).strip()


def assert_release_only_source(path: Path) -> None:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    except (SyntaxError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot parse release-only source: {path}") from error
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        if any(name == "aphfs" or name.startswith("aphfs.") for name in names):
            raise ValueError(f"release packager/validator imports aphfs: {path.name}")


def expected_for(kind: str) -> set[str]:
    if kind == "github":
        return build.expected_github()
    if kind == "biorxiv":
        return build.expected_biorxiv()
    if kind == "review":
        return build.expected_review()
    raise ValueError(f"unsupported package kind: {kind}")


def ledger_paths(kind: str) -> tuple[str, str, str]:
    base = "08_PACKAGE_AUDIT/" if kind == "review" else ""
    return (
        f"{base}FILE_MANIFEST.csv",
        f"{base}SHA256SUMS.txt",
        f"{base}PROJECT_TREE.txt",
    )


def validate_ledgers(root: Path, kind: str, expected: set[str]) -> dict[str, int]:
    manifest_rel, sums_rel, tree_rel = ledger_paths(kind)
    tree_lines = (root / tree_rel).read_text(encoding="utf-8").splitlines()
    if tree_lines != sorted(expected):
        raise ValueError(f"{kind}: PROJECT_TREE does not equal the exact allowlist")

    with (root / manifest_rel).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["relative_path", "size_bytes", "sha256", "license"]:
            raise ValueError(f"{kind}: manifest header mismatch")
        rows = list(reader)
    expected_manifest = expected - {manifest_rel, sums_rel}
    row_paths = [row["relative_path"] for row in rows]
    if len(row_paths) != len(set(row_paths)) or set(row_paths) != expected_manifest:
        raise ValueError(f"{kind}: manifest path set mismatch")
    for row in rows:
        relative = safe_rel(row["relative_path"]).as_posix()
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            declared_size = int(row["size_bytes"])
        except ValueError as error:
            raise ValueError(f"{kind}: invalid manifest size: {relative}") from error
        if declared_size != path.stat().st_size or row["sha256"] != sha256(path):
            raise ValueError(f"{kind}: manifest size/hash mismatch: {relative}")
        if row["license"] not in {"MIT", "CC-BY-4.0", "OFL-1.1"}:
            raise ValueError(f"{kind}: invalid manifest license: {relative}")

    sums: dict[str, str] = {}
    for line in (root / sums_rel).read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            raise ValueError(f"{kind}: malformed SHA256SUMS line")
        relative = safe_rel(match.group(2)).as_posix()
        if relative in sums:
            raise ValueError(f"{kind}: duplicate SHA256SUMS path: {relative}")
        sums[relative] = match.group(1)
    if set(sums) != expected - {sums_rel}:
        raise ValueError(f"{kind}: SHA256SUMS path set mismatch")
    for relative, digest in sums.items():
        if sha256(root.joinpath(*PurePosixPath(relative).parts)) != digest:
            raise ValueError(f"{kind}: SHA256SUMS mismatch: {relative}")
    return {"manifest_rows": len(rows), "sha256_rows": len(sums), "tree_rows": len(tree_lines)}


def validate_file_types(root: Path, files: list[Path]) -> dict[str, object]:
    pngs: dict[str, list[int]] = {}
    pdf_count = 0
    svg_count = 0
    docx_count = 0
    json_count = 0
    scanned_members = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        scanned_members += scan_artifact(path, relative)
        suffix = path.suffix.casefold()
        if suffix == ".pdf":
            pdf_integrity(path)
            pdf_count += 1
        elif suffix == ".png":
            pngs[relative] = list(png_integrity(path))
        elif suffix == ".svg":
            svg_text(path)
            svg_count += 1
        elif suffix == ".docx":
            text = docx_text(path)
            if "All-Possibility Hierarchical Filtering Simulation" not in text:
                raise ValueError(f"DOCX does not contain manuscript title: {relative}")
            docx_count += 1
        elif suffix == ".json":
            load_json_strict(path)
            json_count += 1
    return {
        "pdf_count": pdf_count,
        "svg_count": svg_count,
        "png_count": len(pngs),
        "docx_count": docx_count,
        "strict_json_count": json_count,
        "png_dimensions": pngs,
        "recursively_scanned_file_or_member_count": scanned_members,
    }


def validate_safe_evidence(root: Path) -> dict[str, object]:
    base = root / "safe_handoff/locked_audit_v2_4"
    summary_path = base / "LOCKED_RESULT_PUBLIC_SUMMARY_v2_4.json"
    summary = load_json_strict(summary_path)
    if not isinstance(summary, dict):
        raise ValueError("safe summary JSON root is not an object")
    if summary.get("source_result_sha256") != RESULT_SHA256:
        raise ValueError("safe summary result SHA-256 mismatch")
    if summary.get("source_receipt_sha256") != RECEIPT_SHA256:
        raise ValueError("safe summary receipt SHA-256 mismatch")
    required_flags = {
        "raw_role_values_included": False,
        "locked_role_rematerialized": False,
        "retry_performed": False,
        "calibration_rerun": False,
        "benchmark_engine_rerun_during_review": False,
        "independent_recomputation_status": "PASS",
    }
    for key, expected in required_flags.items():
        if summary.get(key) != expected:
            raise ValueError(f"safe summary flag mismatch: {key}")
    rows = summary.get("endpoints")
    if not isinstance(rows, list) or len(rows) != len(EXPECTED_ENDPOINTS):
        raise ValueError("safe summary endpoint count mismatch")
    observed: dict[str, tuple[object, object, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("endpoint"), str):
            raise ValueError("safe summary endpoint row malformed")
        observed[row["endpoint"]] = (
            row.get("numerator"),
            row.get("denominator"),
            row.get("status"),
        )
    if observed != EXPECTED_ENDPOINTS:
        raise ValueError(f"immutable aggregate endpoint drift: {observed}")
    d2 = next(row for row in rows if row["endpoint"] == "D2-CERT")
    if d2.get("withdrawal_triggered") is not False:
        raise ValueError("D2-CERT withdrawal flag drift")

    block_path = base / "recomputation_v1/LOCKED_BLOCK_RECOMPUTATION_LEDGER_v2_4.csv"
    with block_path.open(encoding="utf-8", newline="") as handle:
        block_rows = list(csv.DictReader(handle))
    if len(block_rows) != 718:
        raise ValueError("safe block recomputation ledger row-count drift")
    block_counts = {endpoint: 0 for endpoint in EXPECTED_ENDPOINTS}
    adverse_counts = {endpoint: 0 for endpoint in EXPECTED_ENDPOINTS}
    for row in block_rows:
        endpoint = row.get("endpoint")
        if endpoint not in EXPECTED_ENDPOINTS:
            raise ValueError(f"unknown endpoint in safe block ledger: {endpoint!r}")
        if row.get("source_result_sha256") != RESULT_SHA256:
            raise ValueError("safe block ledger result anchor drift")
        if row.get("recomputed_adverse") not in {"True", "False"}:
            raise ValueError("safe block ledger adverse flag is not Boolean text")
        block_counts[endpoint] += 1
        adverse_counts[endpoint] += int(row["recomputed_adverse"] == "True")
    expected_block_counts = {
        endpoint: denominator for endpoint, (_, denominator, _) in EXPECTED_ENDPOINTS.items()
    }
    if block_counts != expected_block_counts or any(adverse_counts.values()):
        raise ValueError(
            f"safe block-ledger aggregate drift: counts={block_counts} adverse={adverse_counts}"
        )

    cp_path = base / "recomputation_v1/LOCKED_CP_RECOMPUTATION_v2_4.csv"
    with cp_path.open(encoding="utf-8", newline="") as handle:
        cp_rows = list(csv.DictReader(handle))
    expected_cp_endpoints = {"A1", "B0", "B1", "D2-CERT", "E", "F0"}
    if {row.get("endpoint") for row in cp_rows} != expected_cp_endpoints:
        raise ValueError("safe Clopper--Pearson endpoint set drift")
    with localcontext() as context:
        context.prec = 60
        one_sided_upper = Decimal(1) - (
            Decimal("0.05").ln() / Decimal(64)
        ).exp()
        two_sided_upper = Decimal(1) - (
            Decimal("0.025").ln() / Decimal(64)
        ).exp()
    tolerance = Decimal("1e-27")
    for row in cp_rows:
        if row.get("events") != "0" or row.get("trials") != "64":
            raise ValueError("safe Clopper--Pearson event/trial count drift")
        if row.get("source_result_sha256") != RESULT_SHA256:
            raise ValueError("safe Clopper--Pearson result anchor drift")
        if abs(Decimal(row["one_sided_upper"]) - one_sided_upper) > tolerance:
            raise ValueError("independent one-sided Clopper--Pearson recomputation mismatch")
        if abs(Decimal(row["two_sided_upper"]) - two_sided_upper) > tolerance:
            raise ValueError("independent two-sided Clopper--Pearson recomputation mismatch")

    costs_path = base / "recomputation_v1/LOCKED_POLICY_COST_SUMMARY_v2_4.csv"
    with costs_path.open(encoding="utf-8", newline="") as handle:
        costs = list(csv.DictReader(handle))
    observed_costs = {
        row["policy"]: int(row["recomputed_total_cost_units"]) for row in costs
    }
    if observed_costs != EXPECTED_COSTS:
        raise ValueError(f"immutable policy cost drift: {observed_costs}")
    if any(row.get("source_result_sha256") != RESULT_SHA256 for row in costs):
        raise ValueError("policy-cost source result anchor drift")
    return {
        "result_sha256": RESULT_SHA256,
        "receipt_sha256": RECEIPT_SHA256,
        "endpoint_count": len(observed),
        "block_ledger_rows_independently_aggregated": len(block_rows),
        "clopper_pearson_rows_independently_recomputed": len(cp_rows),
        "policy_count": len(observed_costs),
        "raw_role_values_included": False,
    }


def validate_github(root: Path) -> dict[str, object]:
    readme = (root / "README_PREPUBLICATION.md").read_text(encoding="utf-8")
    readme_flat = re.sub(r"\s+", " ", readme)
    required = (
        "local pre-publication candidate",
        "No Git remote, repository URL, DOI",
        RESULT_SHA256,
        RECEIPT_SHA256,
        "no raw role values or protected result container",
        "PDF and SVG figures are canonical byte-reproducible outputs",
        "PNG files are renderer-dependent convenience previews",
    )
    missing = [token for token in required if token not in readme_flat]
    if missing:
        raise ValueError(f"GitHub README contract failed: {missing}")
    if (root / "README.md").read_bytes() != (root / "README_PREPUBLICATION.md").read_bytes():
        raise ValueError("README.md and README_PREPUBLICATION.md are not identical")
    template = (root / "README_PUBLIC_TEMPLATE.md").read_text(encoding="utf-8")
    if "VERIFIED_REPOSITORY_URL_TO_BE_INSERTED_AFTER_AUTHOR_AUTHORIZATION" not in template:
        raise ValueError("public README template lacks inactive URL placeholder")
    for label, text in (("README_PREPUBLICATION", readme), ("README_PUBLIC_TEMPLATE", template)):
        for token in (
            build.DATA_CODE_FUTURE_WORDING,
            "OpenAI ChatGPT (primarily GPT-5.6 Sol",
            "standard and reasoning settings available in the author's account",
            "OpenAI Codex",
            "Anthropic Claude (primarily Claude Opus 5 and Claude Fable 5.1)",
            "Google Gemini and xAI Grok were used only for limited exploratory critique",
            "reviewed the manuscript and reported results",
            "The author made the final scientific decisions and accepts responsibility",
            "did not conduct a repository-wide line-by-line review",
        ):
            if token not in text:
                raise ValueError(f"{label} lacks required public disclosure text: {token}")
        for stale in (
            "has not completed final item-by-item verification",
            "OpenAI GPT Pro/ChatGPT",
            "GPT-5.6 Thinking",
            "Anthropic Claude/Opus/Fable",
        ):
            if stale in text:
                raise ValueError(f"{label} retains stale AI disclosure: {stale}")
    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    if TITLE not in citation:
        raise ValueError("CITATION.cff title mismatch")
    if re.search(r"(?im)^\s*(?:doi|url|repository-code)\s*:", citation) or re.search(
        r"https?://", citation, re.I
    ):
        raise ValueError("CITATION.cff contains an unverified DOI/URL")

    provenance = load_json_strict(root / "BUILD_PROVENANCE.json")
    if not isinstance(provenance, dict):
        raise ValueError("public build provenance JSON root is not an object")
    if provenance.get("locked_result_sha256") != RESULT_SHA256 or provenance.get(
        "locked_receipt_sha256"
    ) != RECEIPT_SHA256:
        raise ValueError("public build provenance immutable-anchor mismatch")
    for flag in (
        "candidate_is_unpublished",
        "git_remote_created",
        "push_performed",
        "external_upload_performed",
        "scientific_result_changed",
    ):
        expected = flag == "candidate_is_unpublished"
        if provenance.get(flag) is not expected:
            raise ValueError(f"public build provenance flag mismatch: {flag}")
    expected_identity = {
        "frozen_eca_core_sha256": CORE_SHA256,
        "protected_protocol_v6_sha256": PROTOCOL_SHA256,
        "protected_benchmark_config_v3_sha256": CONFIG_SHA256,
        "protected_fidelity_contracts_v3_sha256": FIDELITY_SHA256,
        "finite_grammar_sha256": GRAMMAR_SHA256,
        "cumulative_non_scientific_amendment_v2_sha256": AMENDMENT_V2_SHA256,
    }
    if provenance.get("scientific_identity") != expected_identity:
        raise ValueError("public build provenance scientific identity mismatch")
    counters = provenance.get("scientific_execution_counts")
    if not isinstance(counters, dict) or any(value != 0 for value in counters.values()):
        raise ValueError("public build provenance has a nonzero scientific counter")

    allowlist = load_json_strict(root / "PUBLIC_ALLOWLIST.json")
    if not isinstance(allowlist, dict):
        raise ValueError("PUBLIC_ALLOWLIST JSON root is not an object")
    if allowlist.get("paths") != sorted(build.expected_github()):
        raise ValueError("PUBLIC_ALLOWLIST path set mismatch")
    if any(path.suffix.casefold() == ".zip" for path in iter_tree_files(root)):
        raise ValueError("GitHub candidate contains an unapproved nested ZIP")

    manuscript_tex = (root / "manuscript/main_v3_7.tex").read_text(encoding="utf-8")
    manuscript_flat = re.sub(r"\s+", " ", manuscript_tex)
    for token in (
        build.DATA_CODE_FUTURE_WORDING,
        "scientific_result_evidence_classes_v3_7",
        "constructed-workload conformance",
        "certificate-pipeline conformance",
        "OpenAI ChatGPT (primarily GPT-5.6 Sol",
        "Anthropic Claude (primarily Claude Opus 5 and Claude Fable 5.1)",
        "did not conduct a repository-wide line-by-line review",
    ):
        if token not in manuscript_flat:
            raise ValueError(f"public manuscript lacks required release text: {token}")
    for stale in (
        "locked_scientific_results_v3_4",
        "OpenAI GPT Pro/ChatGPT",
        "GPT-5.6 Thinking",
        "Anthropic Claude/Opus/Fable",
    ):
        if stale in manuscript_tex:
            raise ValueError(f"public manuscript retains stale release text: {stale}")

    actual_hashes = {
        "frozen_eca_core_sha256": sha256(root / "src/aphfs/eca/core.py"),
        "protected_protocol_v6_sha256": sha256(
            root / "configs/protected/protected_protocol_v6.json"
        ),
        "protected_benchmark_config_v3_sha256": sha256(
            root / "configs/protected/protected_benchmark_config_v3.json"
        ),
        "protected_fidelity_contracts_v3_sha256": sha256(
            root / "configs/protected/protected_fidelity_contracts_v3.json"
        ),
        "finite_grammar_sha256": sha256(root / "manifests/grammar/eca_v4_final_review.json"),
        "cumulative_non_scientific_amendment_v2_sha256": AMENDMENT_V2_SHA256,
    }
    if actual_hashes != expected_identity:
        raise ValueError("packaged frozen scientific source/config identity drift")

    evidence = validate_safe_evidence(root)
    components_path = root / "data/source/policy_cost_components_v2_6.csv"
    with components_path.open(encoding="utf-8", newline="") as handle:
        component_rows = list(csv.DictReader(handle))
    component_costs: dict[str, int] = {}
    component_names = (
        "candidate_evaluation_cost_units",
        "ordering_cost_units",
        "probe_cost_units",
        "reference_refinement_cost_units",
        "retry_or_other_cost_units",
    )
    for row in component_rows:
        policy = row.get("policy")
        if policy not in EXPECTED_COSTS or row.get("source_result_sha256") != RESULT_SHA256:
            raise ValueError("public policy-component row identity drift")
        recomputed = sum(int(row[name]) for name in component_names)
        declared = int(row["total_registered_cost_units"])
        if recomputed != declared or declared != EXPECTED_COSTS[policy]:
            raise ValueError(f"public policy-component sum drift: {policy}")
        component_costs[policy] = recomputed
    if component_costs != EXPECTED_COSTS:
        raise ValueError("public policy-component policy set drift")
    categories_path = root / "data/source/evidence_category_summary_v3_7.csv"
    with categories_path.open(encoding="utf-8", newline="") as handle:
        category_rows = list(csv.DictReader(handle))
    expected_categories = {
        "Analytical / deterministic / formula conformance": "A0;C;D0;D1;D2-MEM",
        "Constructed-workload conformance": "A1;B0;B1;E;F0",
        "Constructed closed-map certificate-pipeline conformance": "D2-CERT",
    }
    observed_categories = {
        row.get("public_label"): row.get("endpoints") for row in category_rows
    }
    if observed_categories != expected_categories:
        raise ValueError(f"public evidence-category source drift: {observed_categories}")
    if any(
        row.get("source_result_sha256") != RESULT_SHA256
        or row.get("categories_are_inferentially_interchangeable") != "False"
        for row in category_rows
    ):
        raise ValueError("public evidence-category identity/interchangeability drift")
    figure_svg = root / "figures/scientific_result_evidence_classes_v3_7.svg"
    accessible = svg_text(figure_svg)
    required_figure = (
        "Constructed-workload conformance",
        "A1, B0, B1, E, F0",
        "D2-CERT",
        "NOT_CONTRADICTED_BY_LOCKED_AUDIT",
    )
    if any(token not in accessible for token in required_figure):
        raise ValueError("Figure 3 SVG accessible text is incomplete")
    for stale in ("Finite-sample endpoints", "D2-CERT certificate withdrawal"):
        if stale in accessible:
            raise ValueError(f"Figure 3 retains stale label: {stale}")

    assert_release_only_source(root / "tools/build_v37_release_packages.py")
    assert_release_only_source(root / "tools/validate_v37_release_packages.py")
    return {
        "local_candidate": True,
        "git_remote_created": False,
        "external_upload": False,
        "safe_evidence": evidence,
        "policy_component_costs_independently_summed": component_costs,
        "evidence_categories": observed_categories,
        "canonical_vector_figures": 8,
        "renderer_dependent_png_previews": 4,
    }


def _validate_metadata(root: Path, prefix: str) -> dict[str, object]:
    metadata = (root / f"{prefix}biorxiv_metadata_v3_7.md").read_text(encoding="utf-8")
    screening = (root / f"{prefix}biorxiv_screening_note_v3_7.txt").read_text(
        encoding="utf-8"
    )
    checklist = (root / f"{prefix}biorxiv_upload_checklist_v3_7.md").read_text(
        encoding="utf-8"
    )
    for token in (TITLE, "Systems Biology", "New Results", "CC BY 4.0"):
        if token not in metadata:
            raise ValueError(f"bioRxiv metadata lacks required token: {token}")
    metadata_flat = re.sub(r"\s+", " ", metadata)
    for token in (
        build.DATA_CODE_FUTURE_WORDING,
        "OpenAI ChatGPT (primarily GPT-5.6 Sol",
        "OpenAI Codex",
        "Anthropic Claude (primarily Claude Opus 5 and Claude Fable 5.1)",
        "Google Gemini and xAI Grok were used only for limited exploratory critique",
    ):
        if token not in metadata_flat:
            raise ValueError(f"bioRxiv metadata lacks required public wording: {token}")
    if re.search(r"https?://(?:www\.)?github\.com/", metadata, re.I):
        raise ValueError("bioRxiv metadata contains an unverified GitHub URL")
    if re.search(r"(?im)^##\s+Subtitle\s*$", metadata):
        raise ValueError("bioRxiv metadata adds a forbidden independent subtitle")
    if len(screening.split()) < 150 or len(screening.split()) > 220:
        raise ValueError("bioRxiv screening note is outside the required 150--220 words")
    for token in ("Systems Biology", "New Results"):
        if token not in screening:
            raise ValueError(f"bioRxiv screening note lacks {token}")
    if "upload" not in checklist.casefold() or "author" not in checklist.casefold():
        raise ValueError("bioRxiv upload checklist lacks live author/upload boundary")
    return {
        "title": TITLE,
        "subject_area": "Systems Biology",
        "article_type": "New Results",
        "license": "CC BY 4.0",
        "screening_note_words": len(screening.split()),
    }


def _validate_nested_bytes(data: bytes, kind: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="aphfs-v37-nested-") as temporary:
        path = Path(temporary) / f"{kind}.zip"
        path.write_bytes(data)
        path.chmod(0o600)
        return validate_archive(path, kind)


def _read_archive_member(data: bytes, root_name: str, relative: str) -> bytes:
    target = f"{root_name}/{safe_rel(relative).as_posix()}"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = checked_zip_infos(archive, root_name, deterministic_outer=True)
        matches = [info for info in infos if not info.is_dir() and info.filename == target]
        if len(matches) != 1:
            raise ValueError(f"expected one nested member {target}, found {len(matches)}")
        return archive.read(matches[0])


def validate_biorxiv(root: Path) -> dict[str, object]:
    metadata = _validate_metadata(root, "03_SUBMISSION_METADATA/")
    pdf_integrity(root / f"01_MAIN_MANUSCRIPT/{FINAL_PDF}")
    if list((root / "01_MAIN_MANUSCRIPT").glob("*.tex")):
        raise ValueError("bioRxiv main-manuscript directory contains LaTeX source")
    nested_path = root / f"02_SUPPLEMENTARY_FILES/{SUPPLEMENTARY_REPRO_NAME}"
    nested_bytes = nested_path.read_bytes()
    nested_report = _validate_nested_bytes(nested_bytes, "github")
    nested_sha = sha256_bytes(nested_bytes)
    readme = (root / "00_README_FIRST.md").read_text(encoding="utf-8")
    for token in (
        "local candidate only",
        "has not been uploaded or submitted",
        nested_sha,
        "No remote, push, upload",
    ):
        if token not in readme:
            raise ValueError(f"bioRxiv README contract failed: {token}")
    return {
        "metadata": metadata,
        "supplementary_reproducibility_sha256": nested_sha,
        "supplementary_validation": nested_report,
        "uploaded": False,
    }


def validate_review(root: Path) -> dict[str, object]:
    baseline = root / f"05_V3_6_READONLY_BASELINE/{BASELINE_PDF}"
    if sha256(baseline) != V36_PDF_SHA256:
        raise ValueError("v3.6 read-only baseline PDF identity mismatch")
    baseline_docx = root / f"05_V3_6_READONLY_BASELINE/{build.BASELINE_DOCX}"
    if sha256(baseline_docx) != V36_DOCX_SHA256:
        raise ValueError("v3.6 read-only baseline DOCX identity mismatch")
    metadata = _validate_metadata(root, "02_RELEASE_METADATA/")
    for relative in build.AUDIT_FILES:
        packaged = root / f"03_FINAL_AUDITS/{PurePosixPath(relative).name}"
        text = packaged.read_text(encoding="utf-8")
        if len(text.strip()) < 80:
            raise ValueError(f"v3.7 audit is empty/too short: {relative}")

    github_path = root / f"07_LOCAL_RELEASE_PACKAGES/{GITHUB_NAME}.zip"
    biorxiv_path = root / f"07_LOCAL_RELEASE_PACKAGES/{BIORXIV_NAME}.zip"
    github_bytes = github_path.read_bytes()
    biorxiv_bytes = biorxiv_path.read_bytes()
    github_report = _validate_nested_bytes(github_bytes, "github")
    biorxiv_report = _validate_nested_bytes(biorxiv_bytes, "biorxiv")
    nested_github = _read_archive_member(
        biorxiv_bytes,
        BIORXIV_NAME,
        f"02_SUPPLEMENTARY_FILES/{SUPPLEMENTARY_REPRO_NAME}",
    )
    if nested_github != github_bytes:
        raise ValueError("bioRxiv supplementary archive is not byte-identical to GitHub candidate")

    manuscript_pairs = {
        f"01_FINAL_MANUSCRIPT/{FINAL_PDF}": f"manuscript/{FINAL_PDF}",
        f"01_FINAL_MANUSCRIPT/{FINAL_DOCX}": f"manuscript/{FINAL_DOCX}",
        "01_FINAL_MANUSCRIPT/main_v3_7.tex": "manuscript/main_v3_7.tex",
        "01_FINAL_MANUSCRIPT/supplement_v3_7.tex": "manuscript/supplement_v3_7.tex",
        "01_FINAL_MANUSCRIPT/references_v3_7.bib": "manuscript/references_v3_7.bib",
        "01_FINAL_MANUSCRIPT/main_v3_7.bbl": "manuscript/main_v3_7.bbl",
        "01_FINAL_MANUSCRIPT/placeins.sty": "manuscript/placeins.sty",
    }
    for review_relative, github_relative in manuscript_pairs.items():
        review_bytes = (root / review_relative).read_bytes()
        packaged_bytes = _read_archive_member(github_bytes, GITHUB_NAME, github_relative)
        if review_bytes != packaged_bytes:
            raise ValueError(f"review/GitHub manuscript byte mismatch: {github_relative}")
    for relative in build.FIGURE_FILES:
        review_bytes = (root / f"01_FINAL_MANUSCRIPT/{relative}").read_bytes()
        packaged_bytes = _read_archive_member(github_bytes, GITHUB_NAME, relative)
        if review_bytes != packaged_bytes:
            raise ValueError(f"review/GitHub figure byte mismatch: {relative}")
    biorxiv_pdf = _read_archive_member(
        biorxiv_bytes,
        BIORXIV_NAME,
        f"01_MAIN_MANUSCRIPT/{FINAL_PDF}",
    )
    if biorxiv_pdf != (root / f"01_FINAL_MANUSCRIPT/{FINAL_PDF}").read_bytes():
        raise ValueError("review/bioRxiv final manuscript PDF byte mismatch")
    for name in (
        "biorxiv_metadata_v3_7.md",
        "biorxiv_screening_note_v3_7.txt",
        "biorxiv_upload_checklist_v3_7.md",
    ):
        review_bytes = (root / f"02_RELEASE_METADATA/{name}").read_bytes()
        biorxiv_member = _read_archive_member(
            biorxiv_bytes,
            BIORXIV_NAME,
            f"03_SUBMISSION_METADATA/{name}",
        )
        if review_bytes != biorxiv_member:
            raise ValueError(f"review/bioRxiv metadata byte mismatch: {name}")
    readme = (root / "00_README_FIRST.md").read_text(encoding="utf-8")
    for token in (
        sha256_bytes(github_bytes),
        sha256_bytes(biorxiv_bytes),
        RESULT_SHA256,
        RECEIPT_SHA256,
    ):
        if token not in readme:
            raise ValueError(f"review README lacks package/immutable identity: {token}")
    return {
        "metadata": metadata,
        "github_sha256": sha256_bytes(github_bytes),
        "biorxiv_sha256": sha256_bytes(biorxiv_bytes),
        "nested_reproducibility_byte_identical": True,
        "github_validation": github_report,
        "biorxiv_validation": biorxiv_report,
        "manuscript_figure_metadata_cross_package_byte_parity": True,
        "old_review_zip_included": False,
    }


def validate_directory(root: Path, kind: str) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"validation root is not a regular directory: {root}")
    expected = expected_for(kind)
    files = iter_tree_files(root)
    actual = {path.relative_to(root).as_posix() for path in files}
    if actual != expected:
        raise ValueError(
            f"{kind} exact allowlist mismatch; missing={sorted(expected-actual)}; "
            f"extra={sorted(actual-expected)}"
        )
    actual_directories = directory_set(root)
    expected_directories = expected_directory_set(expected)
    if actual_directories != expected_directories:
        raise ValueError(
            f"{kind} directory allowlist mismatch; "
            f"missing={sorted(expected_directories-actual_directories)}; "
            f"extra={sorted(actual_directories-expected_directories)}"
        )
    ledger = validate_ledgers(root, kind, expected)
    file_types = validate_file_types(root, files)
    if kind == "github":
        semantic = validate_github(root)
    elif kind == "biorxiv":
        semantic = validate_biorxiv(root)
    else:
        semantic = validate_review(root)
    return {
        "status": "PASS",
        "kind": kind,
        "file_count": len(files),
        "exact_allowlist": True,
        "manifest_and_sha256": ledger,
        "file_integrity": file_types,
        "semantic_validation": semantic,
        "privacy_secret_scan": "PASS_RECURSIVE",
        "raw_role_or_protected_result_container_count": 0,
        "scientific_execution_performed": False,
        "external_upload_performed": False,
    }


def manual_extract(archive_path: Path, destination: Path, root_name: str) -> Path:
    with zipfile.ZipFile(archive_path) as archive:
        infos = checked_zip_infos(archive, archive_path.name, deterministic_outer=True)
        prefix = f"{root_name}/"
        if not infos or any(not info.filename.startswith(prefix) for info in infos):
            raise ValueError(f"archive does not have the single expected root {root_name}/")
        for info in infos:
            relative = info.filename[len(prefix) :]
            if not relative:
                continue
            if info.is_dir() and relative.endswith("/"):
                relative = relative[:-1]
            pure = safe_rel(relative)
            target = destination.joinpath(*pure.parts)
            try:
                target.relative_to(destination)
            except ValueError as error:
                raise ValueError(f"extraction target escapes destination: {relative}") from error
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as handle:
                handle.write(archive.read(info))
            target.chmod(0o644)
    return destination


def expected_archive_members(kind: str, root_name: str) -> set[str]:
    members = {f"{root_name}/"}
    for relative in expected_for(kind):
        pure = safe_rel(relative)
        parent = PurePosixPath(root_name)
        for part in pure.parts[:-1]:
            parent /= part
            members.add(parent.as_posix() + "/")
        members.add(f"{root_name}/{relative}")
    return members


def validate_archive(path: Path, kind: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"archive is missing or non-regular: {path}")
    if not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
        raise ValueError(f"archive is a special file: {path}")
    size_ceiling = {
        "github": build.MAX_GITHUB_BYTES,
        "biorxiv": build.MAX_BIORXIV_BYTES,
        "review": build.MAX_REVIEW_BYTES,
    }[kind]
    if path.stat().st_size > size_ceiling:
        raise ValueError(f"{kind} archive exceeds its configured size ceiling")
    root_name = {"github": GITHUB_NAME, "biorxiv": BIORXIV_NAME, "review": REVIEW_NAME}[kind]
    with zipfile.ZipFile(path) as archive:
        infos = checked_zip_infos(archive, path.name, deterministic_outer=True)
        actual_members = {info.filename for info in infos}
    expected_members = expected_archive_members(kind, root_name)
    if actual_members != expected_members:
        raise ValueError(
            f"{kind} archive member allowlist mismatch; "
            f"missing={sorted(expected_members-actual_members)}; "
            f"extra={sorted(actual_members-expected_members)}"
        )
    with tempfile.TemporaryDirectory(prefix="aphfs-v37-fresh-extract-") as temporary:
        extracted = Path(temporary) / root_name
        extracted.mkdir(mode=0o700)
        manual_extract(path, extracted, root_name)
        report = validate_directory(extracted, kind)
    report["archive_sha256"] = sha256(path)
    report["archive_size_bytes"] = path.stat().st_size
    report["fresh_extraction"] = "PASS_MANUAL_PATH_SAFE"
    report["crc"] = "PASS"
    report["deterministic_zip_metadata"] = "PASS"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    parser.add_argument("--kind", required=True, choices=("github", "biorxiv", "review"))
    args = parser.parse_args()
    try:
        supplied = args.path if args.path.is_absolute() else Path.cwd() / args.path
        if supplied.is_symlink():
            raise ValueError("validation target must not be a symlink")
        path = supplied.resolve(strict=True)
        report = (
            validate_directory(path, args.kind)
            if path.is_dir()
            else validate_archive(path, args.kind)
        )
        exit_code = 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        report = {
            "status": "FAIL",
            "kind": args.kind,
            "error": f"{type(error).__name__}: {error}",
        }
        exit_code = 1
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
