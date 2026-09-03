"""APHFS development-only command line."""

from __future__ import annotations

import argparse
from pathlib import Path

from aphfs.benchmarks.runner import run_development_all
from aphfs.constants import DEVELOPMENT_LABEL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aphfs")
    subparsers = parser.add_subparsers(dest="command", required=True)
    dev_all = subparsers.add_parser("dev-all", help="run authorized development-only diagnostics")
    dev_all.add_argument("--config", type=Path, required=True)
    dev_all.add_argument(
        "--proposed-protocol",
        type=Path,
        default=Path("configs/proposed_locked/protocol_v2.json"),
    )
    dev_all.add_argument(
        "--development-seeds",
        type=Path,
        default=Path("manifests/development_seeds/seeds_v1.json"),
    )
    dev_all.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/development/reproduction_run"),
    )
    dev_all.add_argument(
        "--preflight-output",
        type=Path,
        default=Path("outputs/preflight/reproduction_run"),
    )
    dev_all.add_argument(
        "--grammar-manifest",
        type=Path,
        default=Path("manifests/grammar/eca_reproduction.json"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "dev-all":
        raise AssertionError("unreachable")
    project_root = Path.cwd().resolve()
    manifest = run_development_all(
        project_root=project_root,
        config_path=args.config,
        proposed_protocol_path=args.proposed_protocol,
        development_seed_path=args.development_seeds,
        output_directory=args.output,
        preflight_directory=args.preflight_output,
        grammar_manifest_path=args.grammar_manifest,
    )
    print(DEVELOPMENT_LABEL)
    print(f"development run written: {manifest['run_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
