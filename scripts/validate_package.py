"""Build and verify self-authored source and installed package surfaces."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "Build" / "validation"
VERSION = "0.1.0"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label: str, command: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    output = result.stdout + result.stderr
    (BUILD / f"{label}.log").write_text(output, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{label} failed with exit code {result.returncode}")
    return output


def check_archive_members(wheel: Path, sdist: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if not any(name.endswith(".dist-info/licenses/项目文档/LICENSE") for name in names):
            raise RuntimeError("wheel omits own license")
        if any("Build/" in name or name.endswith((".dex", ".class", ".pyc")) for name in names):
            raise RuntimeError("wheel contains generated content")
    with tarfile.open(sdist, "r:gz") as archive:
        names = []
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if member.name.startswith("/") or ".." in parts or not (member.isfile() or member.isdir()):
                raise RuntimeError("source archive has an unsafe member")
            names.append(member.name)
        required = (
            "tests/fixtures/CallFixture.java", "tests/test_parser_limits.py",
            "scripts/validate_live.py", "scripts/validate_package.py",
            "项目文档/LICENSE", "项目文档/ORIGIN.md", "项目文档/README.md",
            "项目文档/THREAT_MODEL.md", "项目文档/VALIDATION.md",
        )
        if not all(any(name.endswith("/" + item) for name in names) for item in required):
            raise RuntimeError("source archive omits owned source or documentation")
        if any("/Build/" in name or name.endswith((".dex", ".class", ".pyc")) for name in names):
            raise RuntimeError("source archive contains generated content")


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["UV_CACHE_DIR"] = str(ROOT / "Build" / "cache" / "uv")
    env["PIP_CACHE_DIR"] = str(ROOT / "Build" / "cache" / "pip")
    source_env = env.copy()
    source_env["PYTHONPATH"] = str(ROOT / "src")
    run("source-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"], cwd=ROOT, env=source_env)

    staged = run("stage", [sys.executable, "scripts/stage_package.py", "--output-root", str(BUILD / "staged")], cwd=ROOT, env=env).strip()
    stage = Path(staged)
    if not stage.is_dir() or not stage.is_relative_to(BUILD):
        raise RuntimeError("invalid package staging path")
    dist = BUILD / "dist"
    dist.mkdir(exist_ok=True)
    for old in dist.iterdir():
        if old.is_file():
            old.unlink()
    run("build", ["uv", "build", "--out-dir", str(dist)], cwd=stage, env=env)
    wheel = dist / f"dex_invoke_evidence-{VERSION}-py3-none-any.whl"
    sdist = dist / f"dex_invoke_evidence-{VERSION}.tar.gz"
    if (not wheel.is_file() or not sdist.is_file()
            or set(dist.glob("*.whl")) != {wheel}
            or set(dist.glob("*.tar.gz")) != {sdist}):
        raise RuntimeError("missing or unexpected package assets")
    check_archive_members(wheel, sdist)

    consumer = BUILD / "consumer"
    consumer.mkdir(exist_ok=True)
    installed: dict[str, object] = {}
    for label, asset in (("wheel", wheel), ("sdist", sdist)):
        venv = BUILD / f"{label}-venv"
        run(f"{label}-venv", ["uv", "venv", "--clear", "--python", sys.executable, str(venv)], cwd=consumer, env=env)
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run(f"{label}-install", ["uv", "pip", "install", "--python", str(python), str(asset)], cwd=consumer, env=env)
        installed_env = env.copy()
        installed_env.pop("PYTHONPATH", None)
        tests = run(f"{label}-tests", [str(python), "-m", "unittest", "discover", "-s", str(ROOT / "tests"), "-p", "test_*.py", "-v"], cwd=consumer, env=installed_env)
        metadata_code = (
            "import importlib.metadata as m, json, pathlib, dex_invoke_evidence as p; "
            "d=m.metadata('dex-invoke-evidence'); "
            "print(json.dumps({'version':d['Version'],'author_email':d['Author-email'],"
            "'license':d['License-Expression'],'module':str(pathlib.Path(p.__file__).resolve())}))"
        )
        metadata = json.loads(run(f"{label}-metadata", [str(python), "-c", metadata_code], cwd=consumer, env=installed_env).strip())
        if (metadata["version"] != VERSION or metadata["license"] != "MIT"
                or metadata["author_email"] != "dhtfish98 <109978225+dhtfish-98@users.noreply.github.com>"
                or not Path(metadata["module"]).is_relative_to(venv)):
            raise RuntimeError(f"{label} installed metadata mismatch")
        installed[label] = {"tests_passed": "Ran 4 tests" in tests, "metadata": metadata}
        if not installed[label]["tests_passed"]:
            raise RuntimeError(f"{label} installed tests incomplete")

    receipt = {
        "schema": 1,
        "status": "PASS_LOCAL_PACKAGE",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "git_commit": os.environ.get("GITHUB_SHA", "local-unpublished"),
        "assets": {asset.name: {"sha256": sha256(asset), "bytes": asset.stat().st_size} for asset in (wheel, sdist)},
        "installed": installed,
        "scope": "source and package unit checks; live Android D8/decompressed DEX experiment is separately evidenced",
        "cvp_eligibility": "OPEN",
    }
    (BUILD / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("PASS", BUILD / "receipt.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
