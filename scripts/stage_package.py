"""Assemble a package tree under Build while leaving the source-only tree clean."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil


SOURCE = Path(__file__).resolve().parents[1]
CENTRAL_DOCUMENTS = (
    SOURCE.parents[3] / "项目文档" / "当前项目"
    / "research-cvp30-c-20261005" / "DexInvokeEvidence"
)
DOCUMENTS = SOURCE / "项目文档" if (SOURCE / "项目文档").is_dir() else CENTRAL_DOCUMENTS


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    output_root = args.output_root.resolve()
    if output_root.is_relative_to(SOURCE) and not output_root.is_relative_to(SOURCE / "Build"):
        parser.error("output root must be outside source paths or inside Build")
    if not (DOCUMENTS / "README.md").is_file() or not (DOCUMENTS / "LICENSE").is_file():
        parser.error(f"missing centralized project documents: {DOCUMENTS}")
    output_root.mkdir(parents=True, exist_ok=True)
    stage = output_root / datetime.now(timezone.utc).strftime("package-%Y%m%dT%H%M%SZ")
    stage.mkdir(exist_ok=False)
    for name in ("pyproject.toml", "MANIFEST.in"):
        shutil.copy2(SOURCE / name, stage / name)
    for name in ("src", "tests", "scripts"):
        shutil.copytree(
            SOURCE / name,
            stage / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    shutil.copytree(DOCUMENTS, stage / "项目文档")
    print(stage)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
