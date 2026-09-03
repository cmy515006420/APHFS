#!/usr/bin/env python3
"""Validate an exported APHFS public-repository tree without scientific execution.

Run this program against a clean ``git archive`` export, not directly against a
clone containing ``.git``.  The validator is deliberately standard-library
only.  It performs no network access, imports no ``aphfs`` module, invokes no
subprocess, and cannot run a benchmark, calibration, locked audit, role replay,
or role materialization.

The public URL is checked as a declared, exact value in the exported files.
Actual public reachability must additionally be established by an unauthenticated
fresh clone before the resulting verification record is accepted.
"""

from __future__ import annotations

import argparse
import binascii
import csv
import hashlib
import io
import json
import os
import re
import stat
import struct
import unicodedata
import zipfile
from decimal import Decimal, localcontext
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree

PUBLIC_REPOSITORY_URL = "https://github.com/cmy515006420/APHFS"

RESULT_SHA256 = "6fb3f08e48b4d3496e190fbc38b029ee7c15e327c504924f8c03b6e2083aec9c"
RECEIPT_SHA256 = "730bfe099a74b1ccfa281e653e9330bf91a5e73c30b24a58cf52dd88028c4766"
PROTOCOL_SHA256 = "5c28bab547056fb188e5e24c9ff3f26aefc5b85117aa01439e362c7f72ad8527"
CONFIG_SHA256 = "23da043818dd11ac5a47dfb6a94198af333aa3673d543381f5fcbb9b62a41ed9"
FIDELITY_SHA256 = "24c28988441d9f53beb7976b60e3807ea27e3f38104a99d51af09887a6d9f137"
CORE_SHA256 = "23946aea15d0a406c011ec2162a258f9bcf8702fcdc0ad4812f831b9064221e6"
GRAMMAR_SHA256 = "c4fd6f0e8fb6038db47d68f1bc1ddf2636e7947d323256d68c4e7ac8f9d6182c"

MAX_FILE_BYTES = 140 * 1024 * 1024
MAX_TOTAL_BYTES = 650 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 6
MAX_FILE_COUNT = 5000

EXPECTED_ENDPOINTS: dict[str, tuple[int, int, str]] = {
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

EXPECTED_EVIDENCE_CATEGORIES = {
    "Analytical / deterministic / formula conformance": "A0;C;D0;D1;D2-MEM",
    "Constructed-workload conformance": "A1;B0;B1;E;F0",
    "Constructed closed-map certificate-pipeline conformance": "D2-CERT",
}

PRIVATE_PATTERNS = (
    ("macOS/Linux home path", re.compile(rb"/(?:Users|home)/[A-Za-z0-9._-]+/")),
    ("macOS private temporary path", re.compile(rb"/private/(?:tmp|var/folders)/")),
    ("local file URI", re.compile(rb"(?i)file://(?:/)?(?:Users|home)/")),
    ("Windows user path", re.compile(rb"(?i)[A-Z]:\\+Users\\+[A-Za-z0-9._-]+\\")),
)

SECRET_PATTERNS = (
    ("private key", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "PGP private key",
        re.compile(rb"-----BEGIN PGP " rb"PRIVATE KEY BLOCK-----"),
    ),
    ("OpenAI-like token", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("GitHub classic token", re.compile(rb"\bgh[opusr]_[A-Za-z0-9]{20,}\b")),
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
            rb"refresh[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9._~+/-]{20,}"
        ),
    ),
    ("session cookie", re.compile(rb"(?i)(?:cookie|set-cookie)\s*:\s*[^\r\n]{20,}")),
    (
        "generic signed URL query",
        re.compile(rb"(?i)[?&](?:sig|signature)=[A-Za-z0-9%+/=_-]{20,}"),
    ),
    (
        "cloud signed URL",
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

FORBIDDEN_INSTANCE_BASENAMES = {
    "authorization_record.json",
    "calibration_execution_approval_v1.json",
    "calibration_role_v1.json",
    "locked_execution_approval_v1.json",
    "locked_execution_intent_v1.json",
    "locked_execution_receipt_v1.json",
    "locked_result_bundle_v1.json",
    "locked_role_v1.json",
}

FORBIDDEN_PUBLIC_STATUS_PHRASES = (
    "VERIFIED_REPOSITORY_URL_TO_BE_INSERTED_AFTER_AUTHOR_AUTHORIZATION",
    "PREPUBLICATION_LOCAL_CANDIDATE",
    "local pre-publication candidate",
    "No Git remote, repository URL, DOI",
    "No remote, push, or upload was created or performed",
    "A public repository URL will be added only after",
)

PUBLIC_STATUS_FILES = (
    "README.md",
    "README_PREPUBLICATION.md",
    "README_PUBLIC_TEMPLATE.md",
    "PACKAGE_PRIVACY_AUDIT.md",
    "PRIVACY.md",
    "SECURITY.md",
    "CITATION.cff",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_bytes(data: bytes, label: str) -> object:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid strict JSON: {label}") from error


def load_json(path: Path) -> object:
    return load_json_bytes(path.read_bytes(), path.as_posix())


def collision_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def safe_relative(value: str, *, inspect_artifact_name: bool = True) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError(f"unsafe relative path: {value!r}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe relative path: {value!r}")
    if pure.as_posix() != value:
        raise ValueError(f"non-canonical relative path: {value!r}")
    if re.match(r"^[A-Za-z]:", value):
        raise ValueError(f"drive-qualified path: {value!r}")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"non-NFC path: {value!r}")
    if inspect_artifact_name:
        validate_artifact_name(pure)
    return pure


def validate_artifact_name(path: PurePosixPath) -> None:
    lowered = path.as_posix().casefold()
    name = path.name.casefold()
    folded_parts = {part.casefold() for part in path.parts}
    if name in FORBIDDEN_INSTANCE_BASENAMES:
        raise ValueError(f"private/protected artifact instance is forbidden: {path}")
    if folded_parts & {".git", ".venv", "__pycache__"}:
        raise ValueError(f"repository/build internals are forbidden: {path}")
    if folded_parts & {"protected_roles", "raw_roles", "private", "secrets"}:
        raise ValueError(f"private/protected directory is forbidden: {path}")
    if name.endswith((".pem", ".key", ".p12", ".pfx")) or name.startswith(".env"):
        raise ValueError(f"credential-bearing filename is forbidden: {path}")
    is_schema = name.endswith(".schema.json")
    if not is_schema:
        if re.search(r"(?:calibration|locked)[_-]?role|role[_-]?manifest", name):
            raise ValueError(f"raw role/role-manifest instance is forbidden: {path}")
        if "protected_result" in name or "result_bundle_actual" in name:
            raise ValueError(f"protected result container is forbidden: {path}")
    if not is_schema and name.endswith((".json", ".md", ".txt", ".yaml", ".yml")):
        if any(token in name for token in ("chat", "conversation", "prompt_log")):
            raise ValueError(f"chat/prompt transcript is forbidden: {path}")
        if any(token in name for token in ("approval", "authorization", "authorisation")):
            raise ValueError(f"private approval/authorization instance is forbidden: {path}")
    if "/protected_roles/" in f"/{lowered}/":
        raise ValueError(f"raw protected-role path is forbidden: {path}")


def iter_regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    seen: dict[str, str] = {}
    total = 0
    for current, directories, names in os.walk(root, followlinks=False):
        base = Path(current)
        directories[:] = sorted(directories)
        for name in directories:
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"non-directory or symlink directory: {relative}")
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            key = collision_key(relative)
            if key in seen and seen[key] != relative:
                raise ValueError(f"case/Unicode path collision: {seen[key]!r} / {relative!r}")
            seen[key] = relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"non-regular file: {relative}")
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"special file: {relative}")
            if metadata.st_size > MAX_FILE_BYTES:
                raise ValueError(f"file exceeds size ceiling: {relative}")
            total += metadata.st_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("repository exceeds total size ceiling")
            files.append(path)
            if len(files) > MAX_FILE_COUNT:
                raise ValueError("repository exceeds file-count ceiling")
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def directory_set(root: Path) -> set[str]:
    result: set[str] = set()
    for current, directories, _ in os.walk(root, followlinks=False):
        base = Path(current)
        for name in directories:
            path = base / name
            relative = path.relative_to(root).as_posix()
            safe_relative(relative)
            if path.is_symlink() or not path.is_dir():
                raise ValueError(f"non-directory tree entry: {relative}")
            result.add(relative)
    return result


def expected_directories(files: set[str]) -> set[str]:
    result: set[str] = set()
    for relative in files:
        parent = PurePosixPath(relative).parent
        while parent.as_posix() not in {"", "."}:
            result.add(parent.as_posix())
            parent = parent.parent
    return result


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


def checked_zip_infos(archive: zipfile.ZipFile, label: str) -> list[zipfile.ZipInfo]:
    if archive.comment:
        raise ValueError(f"{label}: ZIP comment is forbidden")
    raw_names: set[str] = set()
    normalized_names: dict[str, str] = {}
    total = 0
    infos = archive.infolist()
    for info in infos:
        raw = info.filename
        relative = raw[:-1] if info.is_dir() and raw.endswith("/") else raw
        safe_relative(relative)
        scan_plain_bytes(raw.encode("utf-8", errors="strict"), f"{label}: member name")
        scan_plain_bytes(info.comment, f"{label}: member comment")
        scan_plain_bytes(info.extra, f"{label}: member extra")
        if raw in raw_names:
            raise ValueError(f"{label}: duplicate member: {raw}")
        raw_names.add(raw)
        key = collision_key(relative)
        if key in normalized_names and normalized_names[key] != relative:
            raise ValueError(
                f"{label}: case/Unicode member collision: {normalized_names[key]!r} / {relative!r}"
            )
        normalized_names[key] = relative
        if info.flag_bits & 0x1:
            raise ValueError(f"{label}: encrypted member: {raw}")
        mode = (info.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(mode)
        if file_type == stat.S_IFLNK:
            raise ValueError(f"{label}: symlink member: {raw}")
        if info.is_dir() and file_type not in (0, stat.S_IFDIR):
            raise ValueError(f"{label}: invalid directory member type: {raw}")
        if not info.is_dir() and file_type not in (0, stat.S_IFREG):
            raise ValueError(f"{label}: special member: {raw}")
        if info.file_size > MAX_FILE_BYTES:
            raise ValueError(f"{label}: oversized member: {raw}")
        if info.compress_size and info.file_size / info.compress_size > 3000:
            raise ValueError(f"{label}: suspicious compression ratio: {raw}")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError(f"{label}: excessive uncompressed size")
    bad = archive.testzip()
    if bad is not None:
        raise ValueError(f"{label}: CRC failure: {bad}")
    return infos


def scan_zip_bytes(data: bytes, label: str, depth: int = 0) -> int:
    if depth > MAX_ARCHIVE_DEPTH:
        raise ValueError(f"{label}: archive nesting exceeds {MAX_ARCHIVE_DEPTH}")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        raise ValueError(f"{label}: malformed ZIP/DOCX") from error
    count = 0
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
    data = path.read_bytes()
    scan_plain_bytes(data, label)
    if zipfile.is_zipfile(io.BytesIO(data)):
        return 1 + scan_zip_bytes(data, label)
    return 1


def png_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 45 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"invalid PNG signature: {path.name}")
    offset = 8
    dimensions: tuple[int, int] | None = None
    saw_data = False
    saw_end = False
    while offset + 12 <= len(data):
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError(f"truncated PNG: {path.name}")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        if (binascii.crc32(kind + payload) & 0xFFFFFFFF) != expected_crc:
            raise ValueError(f"PNG CRC mismatch: {path.name}")
        if kind == b"IHDR":
            if length != 13 or dimensions is not None:
                raise ValueError(f"invalid PNG IHDR: {path.name}")
            dimensions = struct.unpack(">II", payload[:8])
        elif kind == b"IDAT":
            saw_data = True
        elif kind == b"IEND":
            saw_end = True
            if end != len(data):
                raise ValueError(f"trailing bytes after PNG IEND: {path.name}")
            break
        offset = end
    if dimensions is None or min(dimensions) <= 0 or not saw_data or not saw_end:
        raise ValueError(f"incomplete PNG: {path.name}")
    return dimensions


def validate_basic_file_types(root: Path, files: list[Path]) -> dict[str, object]:
    counts = {"json": 0, "pdf": 0, "png": 0, "svg": 0, "docx": 0}
    dimensions: dict[str, list[int]] = {}
    scanned = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        scanned += scan_artifact(path, relative)
        suffix = path.suffix.casefold()
        if suffix == ".json":
            load_json(path)
            counts["json"] += 1
        elif suffix == ".pdf":
            data = path.read_bytes()
            if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-4096:]:
                raise ValueError(f"invalid PDF structure: {relative}")
            counts["pdf"] += 1
        elif suffix == ".png":
            dimensions[relative] = list(png_dimensions(path))
            counts["png"] += 1
        elif suffix == ".svg":
            try:
                root_element = ElementTree.fromstring(path.read_bytes())
            except ElementTree.ParseError as error:
                raise ValueError(f"malformed SVG: {relative}") from error
            if not root_element.tag.endswith("svg"):
                raise ValueError(f"SVG root missing: {relative}")
            counts["svg"] += 1
        elif suffix == ".docx":
            with zipfile.ZipFile(path) as archive:
                names = {info.filename for info in checked_zip_infos(archive, relative)}
                if "word/document.xml" not in names or "[Content_Types].xml" not in names:
                    raise ValueError(f"DOCX core members missing: {relative}")
            counts["docx"] += 1
    return {
        "type_counts": counts,
        "png_dimensions": dimensions,
        "recursively_scanned_file_or_member_count": scanned,
    }


def validate_allowlist_and_ledgers(root: Path, files: list[Path]) -> dict[str, int]:
    actual = {path.relative_to(root).as_posix() for path in files}
    allowlist_object = load_json(root / "PUBLIC_ALLOWLIST.json")
    if not isinstance(allowlist_object, dict) or not isinstance(
        allowlist_object.get("paths"), list
    ):
        raise ValueError("PUBLIC_ALLOWLIST.json does not contain a paths list")
    raw_allowlist = allowlist_object["paths"]
    if not all(isinstance(value, str) for value in raw_allowlist):
        raise ValueError("PUBLIC_ALLOWLIST.json contains a non-string path")
    allowlist = [safe_relative(value).as_posix() for value in raw_allowlist]
    if len(allowlist) != len(set(allowlist)) or allowlist != sorted(allowlist):
        raise ValueError("PUBLIC_ALLOWLIST paths are duplicate or unsorted")
    if set(allowlist) != actual:
        raise ValueError(
            "exact public allowlist mismatch; "
            f"missing={sorted(set(allowlist) - actual)}; extra={sorted(actual - set(allowlist))}"
        )
    observed_directories = directory_set(root)
    required_directories = expected_directories(actual)
    if observed_directories != required_directories:
        raise ValueError(
            "directory allowlist mismatch; "
            f"missing={sorted(required_directories - observed_directories)}; "
            f"extra={sorted(observed_directories - required_directories)}"
        )

    tree_lines = (root / "PROJECT_TREE.txt").read_text(encoding="utf-8").splitlines()
    if tree_lines != sorted(actual):
        raise ValueError("PROJECT_TREE.txt does not equal the exact public file set")

    with (root / "FILE_MANIFEST.csv").open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["relative_path", "size_bytes", "sha256", "license"]:
            raise ValueError("FILE_MANIFEST.csv header mismatch")
        rows = list(reader)
    expected_manifest = actual - {"FILE_MANIFEST.csv", "SHA256SUMS.txt"}
    row_paths = [safe_relative(row["relative_path"]).as_posix() for row in rows]
    if len(row_paths) != len(set(row_paths)) or set(row_paths) != expected_manifest:
        raise ValueError("FILE_MANIFEST.csv path set mismatch")
    for row, relative in zip(rows, row_paths, strict=True):
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            declared_size = int(row["size_bytes"])
        except ValueError as error:
            raise ValueError(f"invalid manifest size: {relative}") from error
        if declared_size != path.stat().st_size or row["sha256"] != sha256(path):
            raise ValueError(f"manifest size/hash mismatch: {relative}")
        if row["license"] not in {"MIT", "CC-BY-4.0", "OFL-1.1"}:
            raise ValueError(f"unexpected manifest license: {relative}")

    sums: dict[str, str] = {}
    for line in (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if match is None:
            raise ValueError("malformed SHA256SUMS.txt line")
        relative = safe_relative(match.group(2)).as_posix()
        if relative in sums:
            raise ValueError(f"duplicate SHA256SUMS entry: {relative}")
        sums[relative] = match.group(1)
    if set(sums) != actual - {"SHA256SUMS.txt"}:
        raise ValueError("SHA256SUMS.txt path set mismatch")
    for relative, digest in sums.items():
        if sha256(root.joinpath(*PurePosixPath(relative).parts)) != digest:
            raise ValueError(f"SHA256SUMS mismatch: {relative}")
    return {
        "allowlist_rows": len(allowlist),
        "tree_rows": len(tree_lines),
        "manifest_rows": len(rows),
        "sha256_rows": len(sums),
    }


def normalized_docx_text_and_links(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        infos = checked_zip_infos(archive, path.name)
        names = {info.filename for info in infos if not info.is_dir()}
        if "word/document.xml" not in names:
            raise ValueError(f"DOCX document.xml missing: {path.name}")
        parts = [archive.read("word/document.xml")]
        relation = "word/_rels/document.xml.rels"
        if relation in names:
            parts.append(archive.read(relation))
    combined = b" ".join(parts).decode("utf-8", errors="strict")
    try:
        document = ElementTree.fromstring(parts[0])
    except ElementTree.ParseError as error:
        raise ValueError(f"malformed DOCX document.xml: {path.name}") from error
    visible = " ".join(
        element.text for element in document.iter() if element.tag.endswith("}t") and element.text
    )
    return re.sub(r"\s+", " ", visible + " " + combined).strip()


def validate_public_status(root: Path) -> dict[str, object]:
    readme = (root / "README.md").read_text(encoding="utf-8")
    citation = (root / "CITATION.cff").read_text(encoding="utf-8")
    provenance = load_json(root / "BUILD_PROVENANCE.json")
    if not isinstance(provenance, dict):
        raise ValueError("BUILD_PROVENANCE.json root is not an object")

    for relative in PUBLIC_STATUS_FILES:
        path = root / relative
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for phrase in FORBIDDEN_PUBLIC_STATUS_PHRASES:
            if phrase in text:
                raise ValueError(f"contradictory prepublication text in {relative}: {phrase}")

    if PUBLIC_REPOSITORY_URL not in readme or "public" not in readme.casefold():
        raise ValueError("README.md lacks the exact verified public repository URL/state")
    citation_url = re.compile(
        rf"(?m)^repository-code:\s*['\"]?{re.escape(PUBLIC_REPOSITORY_URL)}(?:\.git)?['\"]?\s*$"
    )
    if citation_url.search(citation) is None:
        raise ValueError("CITATION.cff lacks exact repository-code URL")

    expected_public_fields: dict[str, object] = {
        "candidate_is_unpublished": False,
        "external_upload_performed": True,
        "git_remote_created": True,
        "push_performed": True,
        "repository_url": PUBLIC_REPOSITORY_URL,
        "repository_visibility": "public",
        "scientific_result_changed": False,
    }
    for key, expected in expected_public_fields.items():
        actual = provenance.get(key)
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(f"BUILD_PROVENANCE public-state mismatch: {key}")
    biorxiv_upload = provenance.get("biorxiv_upload_performed")
    if biorxiv_upload is not None and biorxiv_upload is not False:
        raise ValueError("BUILD_PROVENANCE incorrectly represents a bioRxiv upload")

    counts = provenance.get("scientific_execution_counts")
    if not isinstance(counts, dict):
        raise ValueError("BUILD_PROVENANCE scientific_execution_counts missing")
    protected_actions = (
        "benchmark",
        "calibration",
        "locked_audit",
        "new_protected_computation",
        "retuning",
        "role_rematerialization",
        "role_replay",
    )
    for key in protected_actions:
        value = counts.get(key)
        if type(value) is not int or value != 0:
            raise ValueError(f"BUILD_PROVENANCE reports a prohibited scientific action: {key}")

    source_files = sorted((root / "manuscript").glob("main*.tex"))
    if len(source_files) != 1:
        raise ValueError("expected exactly one manuscript/main*.tex source")
    source_text = source_files[0].read_text(encoding="utf-8")
    if PUBLIC_REPOSITORY_URL not in source_text:
        raise ValueError("final manuscript LaTeX lacks the exact public repository URL")
    for phrase in FORBIDDEN_PUBLIC_STATUS_PHRASES:
        if phrase in source_text:
            raise ValueError(f"final manuscript LaTeX retains prepublication text: {phrase}")

    docx_files = sorted((root / "manuscript").glob("*.docx"))
    if len(docx_files) != 1:
        raise ValueError("expected exactly one final manuscript DOCX")
    docx_text = normalized_docx_text_and_links(docx_files[0])
    if PUBLIC_REPOSITORY_URL not in docx_text:
        raise ValueError("final manuscript DOCX lacks the exact public repository URL")
    for phrase in FORBIDDEN_PUBLIC_STATUS_PHRASES:
        if phrase in docx_text:
            raise ValueError(f"final manuscript DOCX retains prepublication text: {phrase}")

    return {
        "repository_url": PUBLIC_REPOSITORY_URL,
        "repository_visibility_declared": "public",
        "readme_public_state": True,
        "citation_repository_code": True,
        "build_provenance_public_state": True,
        "manuscript_url_parity": True,
        "biorxiv_upload_performed": False,
    }


def validate_immutable_anchors(root: Path) -> dict[str, str]:
    file_anchors = {
        "protocol": (
            root / "configs/protected/protected_protocol_v6.json",
            PROTOCOL_SHA256,
        ),
        "config": (
            root / "configs/protected/protected_benchmark_config_v3.json",
            CONFIG_SHA256,
        ),
        "fidelity": (
            root / "configs/protected/protected_fidelity_contracts_v3.json",
            FIDELITY_SHA256,
        ),
        "eca_core": (root / "src/aphfs/eca/core.py", CORE_SHA256),
        "grammar": (root / "manifests/grammar/eca_v4_final_review.json", GRAMMAR_SHA256),
    }
    for label, (path, expected) in file_anchors.items():
        if sha256(path) != expected:
            raise ValueError(f"immutable {label} SHA-256 mismatch")

    provenance = load_json(root / "BUILD_PROVENANCE.json")
    if not isinstance(provenance, dict):
        raise ValueError("BUILD_PROVENANCE root is not an object")
    if provenance.get("locked_result_sha256") != RESULT_SHA256:
        raise ValueError("BUILD_PROVENANCE locked-result anchor mismatch")
    if provenance.get("locked_receipt_sha256") != RECEIPT_SHA256:
        raise ValueError("BUILD_PROVENANCE locked-receipt anchor mismatch")
    scientific = provenance.get("scientific_identity")
    if not isinstance(scientific, dict):
        raise ValueError("BUILD_PROVENANCE scientific_identity missing")
    provenance_anchors = {
        "protected_protocol_v6_sha256": PROTOCOL_SHA256,
        "protected_benchmark_config_v3_sha256": CONFIG_SHA256,
        "protected_fidelity_contracts_v3_sha256": FIDELITY_SHA256,
        "frozen_eca_core_sha256": CORE_SHA256,
        "finite_grammar_sha256": GRAMMAR_SHA256,
    }
    for key, expected in provenance_anchors.items():
        if scientific.get(key) != expected:
            raise ValueError(f"BUILD_PROVENANCE scientific-identity mismatch: {key}")
    return {
        "locked_result_sha256": RESULT_SHA256,
        "locked_receipt_sha256": RECEIPT_SHA256,
        "protocol_sha256": PROTOCOL_SHA256,
        "config_sha256": CONFIG_SHA256,
        "fidelity_sha256": FIDELITY_SHA256,
        "eca_core_sha256": CORE_SHA256,
        "grammar_sha256": GRAMMAR_SHA256,
    }


def validate_safe_aggregate_evidence(root: Path) -> dict[str, object]:
    base = root / "safe_handoff/locked_audit_v2_4"
    summary = load_json(base / "LOCKED_RESULT_PUBLIC_SUMMARY_v2_4.json")
    if not isinstance(summary, dict):
        raise ValueError("locked public summary root is not an object")
    expected_flags: dict[str, object] = {
        "source_result_sha256": RESULT_SHA256,
        "source_receipt_sha256": RECEIPT_SHA256,
        "raw_role_values_included": False,
        "locked_role_rematerialized": False,
        "retry_performed": False,
        "calibration_rerun": False,
        "benchmark_engine_rerun_during_review": False,
        "independent_recomputation_status": "PASS",
    }
    for key, expected in expected_flags.items():
        if summary.get(key) != expected:
            raise ValueError(f"locked public summary identity/flag mismatch: {key}")
    endpoint_rows = summary.get("endpoints")
    if not isinstance(endpoint_rows, list) or len(endpoint_rows) != len(EXPECTED_ENDPOINTS):
        raise ValueError("locked public summary endpoint count mismatch")
    observed: dict[str, tuple[object, object, object]] = {}
    for row in endpoint_rows:
        if not isinstance(row, dict) or not isinstance(row.get("endpoint"), str):
            raise ValueError("malformed locked public summary endpoint row")
        observed[row["endpoint"]] = (
            row.get("numerator"),
            row.get("denominator"),
            row.get("status"),
        )
    if observed != EXPECTED_ENDPOINTS:
        raise ValueError(f"immutable endpoint aggregate drift: {observed}")
    d2 = next(row for row in endpoint_rows if row.get("endpoint") == "D2-CERT")
    if d2.get("withdrawal_triggered") is not False:
        raise ValueError("D2-CERT withdrawal flag drift")

    block_path = base / "recomputation_v1/LOCKED_BLOCK_RECOMPUTATION_LEDGER_v2_4.csv"
    with block_path.open(encoding="utf-8", newline="") as handle:
        blocks = list(csv.DictReader(handle))
    if len(blocks) != 718:
        raise ValueError("safe block ledger must contain exactly 718 rows")
    block_counts = {endpoint: 0 for endpoint in EXPECTED_ENDPOINTS}
    adverse_counts = {endpoint: 0 for endpoint in EXPECTED_ENDPOINTS}
    for row in blocks:
        endpoint = row.get("endpoint")
        if endpoint not in EXPECTED_ENDPOINTS:
            raise ValueError(f"unknown endpoint in safe block ledger: {endpoint!r}")
        if row.get("source_result_sha256") != RESULT_SHA256:
            raise ValueError("safe block ledger result anchor mismatch")
        if row.get("recomputed_adverse") not in {"True", "False"}:
            raise ValueError("safe block ledger has a non-Boolean adverse value")
        block_counts[endpoint] += 1
        adverse_counts[endpoint] += int(row["recomputed_adverse"] == "True")
    expected_block_counts = {
        endpoint: denominator for endpoint, (_, denominator, _) in EXPECTED_ENDPOINTS.items()
    }
    if block_counts != expected_block_counts or any(adverse_counts.values()):
        raise ValueError("safe block-ledger independent aggregation mismatch")

    cp_path = base / "recomputation_v1/LOCKED_CP_RECOMPUTATION_v2_4.csv"
    with cp_path.open(encoding="utf-8", newline="") as handle:
        cp_rows = list(csv.DictReader(handle))
    expected_cp = {"A1", "B0", "B1", "D2-CERT", "E", "F0"}
    if {row.get("endpoint") for row in cp_rows} != expected_cp or len(cp_rows) != 6:
        raise ValueError("safe Clopper-Pearson endpoint set mismatch")
    with localcontext() as context:
        context.prec = 60
        one_sided = Decimal(1) - (Decimal("0.05").ln() / Decimal(64)).exp()
        two_sided = Decimal(1) - (Decimal("0.025").ln() / Decimal(64)).exp()
    tolerance = Decimal("1e-27")
    for row in cp_rows:
        if row.get("events") != "0" or row.get("trials") != "64":
            raise ValueError("safe Clopper-Pearson count mismatch")
        if row.get("source_result_sha256") != RESULT_SHA256:
            raise ValueError("safe Clopper-Pearson result anchor mismatch")
        if abs(Decimal(row["one_sided_upper"]) - one_sided) > tolerance:
            raise ValueError("one-sided Clopper-Pearson recomputation mismatch")
        if abs(Decimal(row["two_sided_upper"]) - two_sided) > tolerance:
            raise ValueError("two-sided Clopper-Pearson recomputation mismatch")

    costs_path = base / "recomputation_v1/LOCKED_POLICY_COST_SUMMARY_v2_4.csv"
    with costs_path.open(encoding="utf-8", newline="") as handle:
        costs = list(csv.DictReader(handle))
    observed_costs = {row["policy"]: int(row["recomputed_total_cost_units"]) for row in costs}
    if observed_costs != EXPECTED_COSTS:
        raise ValueError(f"immutable policy-cost aggregate drift: {observed_costs}")
    if any(row.get("source_result_sha256") != RESULT_SHA256 for row in costs):
        raise ValueError("policy-cost result anchor mismatch")

    failure_path = base / "LOCKED_FAILURE_INDETERMINATE_LEDGER_v2_4.csv"
    with failure_path.open(encoding="utf-8", newline="") as handle:
        failures = list(csv.DictReader(handle))
    if failures:
        raise ValueError("released failure/indeterminate ledger unexpectedly contains rows")

    categories_path = root / "data/source/evidence_category_summary_v3_7.csv"
    with categories_path.open(encoding="utf-8", newline="") as handle:
        categories = list(csv.DictReader(handle))
    observed_categories = {row.get("public_label"): row.get("endpoints") for row in categories}
    if observed_categories != EXPECTED_EVIDENCE_CATEGORIES:
        raise ValueError("public evidence-category mapping drift")
    if any(
        row.get("source_result_sha256") != RESULT_SHA256
        or row.get("categories_are_inferentially_interchangeable") != "False"
        for row in categories
    ):
        raise ValueError("public evidence-category identity/interchangeability drift")

    return {
        "endpoint_count": len(observed),
        "block_rows_independently_aggregated": len(blocks),
        "clopper_pearson_rows_independently_recomputed": len(cp_rows),
        "policy_costs_independently_checked": observed_costs,
        "evidence_categories": observed_categories,
        "raw_role_values_included": False,
    }


def validate(root: Path) -> dict[str, object]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("validation root must be a regular directory")
    files = iter_regular_files(root)
    ledger_report = validate_allowlist_and_ledgers(root, files)
    type_report = validate_basic_file_types(root, files)
    public_report = validate_public_status(root)
    anchor_report = validate_immutable_anchors(root)
    evidence_report = validate_safe_aggregate_evidence(root)
    return {
        "status": "PASS",
        "validator": "APHFS_PUBLIC_REPOSITORY_VALIDATOR_V1",
        "root": root.name,
        "file_count": len(files),
        "exact_allowlist_manifest_sha256_tree": ledger_report,
        "file_and_recursive_privacy_integrity": type_report,
        "public_repository_status": public_report,
        "immutable_anchors": anchor_report,
        "safe_aggregate_evidence": evidence_report,
        "privacy_secret_local_path_scan": "PASS_RECURSIVE",
        "raw_role_or_protected_result_container_count": 0,
        "aphfs_imported": False,
        "scientific_execution_performed": False,
        "network_access_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, type=Path)
    args = parser.parse_args()
    try:
        supplied = args.path if args.path.is_absolute() else Path.cwd() / args.path
        if supplied.is_symlink():
            raise ValueError("validation target must not be a symlink")
        root = supplied.resolve(strict=True)
        report = validate(root)
        exit_code = 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        report = {
            "status": "FAIL",
            "validator": "APHFS_PUBLIC_REPOSITORY_VALIDATOR_V1",
            "error": f"{type(error).__name__}: {error}",
            "aphfs_imported": False,
            "scientific_execution_performed": False,
            "network_access_performed": False,
        }
        exit_code = 1
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
