"""Compile a harmless Java fixture and cross-check static DEX evidence.

Every generated file is written under the caller-provided Build output root.
The script never runs the generated Java or Dalvik code.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import struct
import subprocess
import sys
import zlib


PROJECT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(PROJECT / "src"))

from dex_invoke_evidence import DexError, DexInvokeParser  # noqa: E402


ORACLE_RE = re.compile(
    r"^([0-9a-fA-F]+):.*\|([0-9a-fA-F]{4}):\s+"
    r"(invoke-[a-z/-]+).*// method@([0-9a-fA-F]+)\s*$"
)
ARRAY_REF_RE = re.compile(r"^([0-9a-fA-F]+):.*\|[0-9a-fA-F]{4}:\s+fill-array-data\b")
ARRAY_PAYLOAD_RE = re.compile(r"^([0-9a-fA-F]+):.*\|[0-9a-fA-F]{4}:\s+array-data\b")
REQUIRED_OPCODES = {
    "invoke-direct",
    "invoke-virtual",
    "invoke-interface",
    "invoke-static",
    "invoke-static/range",
}
PAYLOAD_MARKER = bytes.fromhex("6e747172786f70757677010203040506")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str], *, environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        command,
        cwd=PROJECT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"tool failed ({result.returncode}): {command[0]}\n"
            f"stdout={result.stdout[:2000]}\nstderr={result.stderr[:2000]}"
        )
    return result.stdout + result.stderr


def resign(blob: bytearray) -> bytes:
    blob[12:32] = hashlib.sha1(blob[32:]).digest()
    struct.pack_into("<I", blob, 8, zlib.adler32(blob[12:]) & 0xFFFFFFFF)
    return bytes(blob)


def malformed_cases(data: bytes, parser: DexInvokeParser, sites, dexdump: str):
    if not sites:
        raise AssertionError("no invocation site for malformed corpus")
    first = sites[0]
    cases: dict[str, bytes] = {}

    truncated = bytearray(data)
    truncated[-1] ^= 1
    cases["signature_changed"] = bytes(truncated)

    wrong_length = bytearray(data)
    struct.pack_into("<I", wrong_length, 32, len(data) + 1)
    cases["file_size_out_of_bounds"] = resign(wrong_length)

    wrong_string = bytearray(data)
    method_off = parser.method_ids_off + first.target_method_index * 8
    name_index = struct.unpack_from("<I", data, method_off + 4)[0]
    string_id_off = parser.string_ids_off + name_index * 4
    string_data_off = struct.unpack_from("<I", data, string_id_off)[0]
    struct.pack_into("<I", wrong_string, string_id_off, len(data) + 1)
    cases["string_offset_out_of_bounds"] = resign(wrong_string)

    four_byte_string = bytearray(data)
    _, text_off = parser._uleb(string_data_off)
    four_byte_string[text_off:text_off + 4] = b"\xf0\x90\x80\x80"
    cases["four_byte_utf8_not_mutf8"] = resign(four_byte_string)

    oversized_string = bytearray(data)
    oversized_string[string_data_off:string_data_off + 2] = b"\x81\x40"
    cases["string_utf16_budget_exceeded"] = resign(oversized_string)

    code_off = first.file_offset - 16 - first.code_unit_offset * 2
    wrong_code_size = bytearray(data)
    struct.pack_into("<I", wrong_code_size, code_off + 12, 0xFFFFFFFF)
    cases["code_item_length_out_of_bounds"] = resign(wrong_code_size)

    wrong_method = bytearray(data)
    struct.pack_into("<H", wrong_method, first.file_offset + 2, parser.method_ids_size)
    cases["invoke_method_index_out_of_bounds"] = resign(wrong_method)

    broken_class_data = bytearray(data)
    struct.pack_into("<I", broken_class_data, parser.class_defs_off + 24, len(data) - 1)
    broken_class_data[-1] = 0x80
    cases["unterminated_class_data_length"] = resign(broken_class_data)

    array_ref = next((int(m.group(1), 16) for line in dexdump.splitlines()
                      if (m := ARRAY_REF_RE.match(line))), None)
    array_payload = next((int(m.group(1), 16) for line in dexdump.splitlines()
                          if (m := ARRAY_PAYLOAD_RE.match(line))), None)
    if array_ref is None or array_payload is None:
        raise AssertionError("D8 did not emit the required array payload")
    wrong_payload_ref = bytearray(data)
    struct.pack_into("<I", wrong_payload_ref, array_ref + 2, 0)
    cases["array_payload_offset_invalid"] = resign(wrong_payload_ref)
    oversized_payload = bytearray(data)
    struct.pack_into("<I", oversized_payload, array_payload + 4, 0xFFFFFFFF)
    cases["array_payload_length_out_of_bounds"] = resign(oversized_payload)
    return cases


def main(argv: list[str] | None = None) -> int:
    arguments = argparse.ArgumentParser(description=__doc__)
    arguments.add_argument("--java-home", required=True, type=Path)
    arguments.add_argument("--build-tools", required=True, type=Path)
    arguments.add_argument("--output-root", required=True, type=Path)
    args = arguments.parse_args(argv)
    output_root = args.output_root.resolve()
    if output_root.is_relative_to(PROJECT):
        raise SystemExit("output root must be outside the project source directory")
    output_root.mkdir(parents=True, exist_ok=True)
    run_dir = output_root / datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    run_dir.mkdir(exist_ok=False)
    classes = run_dir / "classes"
    dex_dir = run_dir / "dex"
    malformed_dir = run_dir / "malformed"
    for directory in (classes, dex_dir, malformed_dir):
        directory.mkdir()

    javac = args.java_home / "bin" / "javac"
    d8 = args.build_tools / "d8"
    dexdump = args.build_tools / "dexdump"
    for tool in (javac, d8, dexdump):
        if not tool.is_file():
            raise SystemExit(f"missing tool: {tool}")
    environment = os.environ.copy()
    environment["JAVA_HOME"] = str(args.java_home)
    fixture = PROJECT / "tests" / "fixtures" / "CallFixture.java"
    javac_version = run([str(javac), "-version"])
    d8_version = run([str(d8), "--version"], environment=environment)
    javac_output = run(
        [str(javac), "--release", "8", "-Xlint:-options", "-d", str(classes), str(fixture)]
    )
    class_files = sorted(classes.rglob("*.class"))
    if len(class_files) < 3:
        raise AssertionError("fixture did not compile its interface and nested class")
    d8_output = run(
        [str(d8), "--min-api", "26", "--output", str(dex_dir),
         *[str(path) for path in class_files]],
        environment=environment,
    )
    dex_file = dex_dir / "classes.dex"
    if not dex_file.is_file():
        raise AssertionError("D8 did not emit classes.dex")
    dexdump_text = run([str(dexdump), "-d", str(dex_file)])
    (run_dir / "dexdump.txt").write_text(dexdump_text, encoding="utf-8")
    (run_dir / "build.log").write_text(javac_output + d8_output, encoding="utf-8")

    data = dex_file.read_bytes()
    parser = DexInvokeParser(data)
    sites = parser.scan()
    if parser.validated_try_items == 0:
        raise AssertionError("fixture did not exercise DEX try/catch validation")
    actual = sorted(
        (site.file_offset, site.code_unit_offset, site.opcode, site.target_method_index)
        for site in sites
    )
    oracle = sorted(
        (int(m.group(1), 16), int(m.group(2), 16), m.group(3), int(m.group(4), 16))
        for line in dexdump_text.splitlines() if (m := ORACLE_RE.match(line))
    )
    if actual != oracle:
        raise AssertionError(f"independent dexdump mismatch: own={actual}, oracle={oracle}")
    seen = {site.opcode for site in sites}
    if not REQUIRED_OPCODES.issubset(seen):
        raise AssertionError(f"missing fixture invocation categories: {REQUIRED_OPCODES - seen}")
    if PAYLOAD_MARKER not in data:
        raise AssertionError("synthetic array payload marker missing")
    if data.count(PAYLOAD_MARKER) != 1:
        raise AssertionError("synthetic array payload marker not unique")

    rejected = []
    for name, broken in malformed_cases(data, parser, sites, dexdump_text).items():
        (malformed_dir / f"{name}.dex").write_bytes(broken)
        try:
            DexInvokeParser(broken).scan()
        except DexError as exc:
            rejected.append({"case": name, "sha256": hashlib.sha256(broken).hexdigest(),
                             "reason": str(exc)})
        else:
            raise AssertionError(f"malformed input unexpectedly accepted: {name}")

    mutation_seed = 20261006
    rng = random.Random(mutation_seed)
    mutation_accepted = 0
    mutation_rejected = 0
    for _ in range(512):
        candidate = bytearray(data)
        at = rng.randrange(32, len(candidate))
        candidate[at] ^= 1 << rng.randrange(8)
        try:
            DexInvokeParser(resign(candidate)).scan()
        except DexError:
            mutation_rejected += 1
        else:
            mutation_accepted += 1

    report = {
        "schema": 1,
        "status": "PASS",
        "scope": "self-compiled fixture; static DEX references only; no runtime authorization claim",
        "fixture_sha256": sha256(fixture),
        "dex_sha256": sha256(dex_file),
        "dex_version": parser.version,
        "dex_bytes": len(data),
        "java_compiled_class_count": len(class_files),
        "javac_version": javac_version.strip(),
        "d8_version": d8_version.strip(),
        "dexdump_binary_sha256": sha256(dexdump),
        "dexdump_oracle_sha256": sha256(run_dir / "dexdump.txt"),
        "invocation_count": len(sites),
        "invocation_categories": sorted(seen),
        "oracle_exact_tuple_match": actual == oracle,
        "array_data_marker_present_once": True,
        "validated_try_items": parser.validated_try_items,
        "malformed_rejected_count": len(rejected),
        "malformed_rejected": rejected,
        "single_byte_mutation_probe": {
            "seed": mutation_seed,
            "count": 512,
            "accepted_structurally": mutation_accepted,
            "rejected": mutation_rejected,
            "unexpected_exceptions": 0,
        },
        "source_sha256": {
            str(path.relative_to(PROJECT)): sha256(path)
            for path in sorted((PROJECT / "src").rglob("*.py"))
        },
        "support_source_sha256": {
            str(path.relative_to(PROJECT)): sha256(path)
            for path in sorted((PROJECT / "scripts").glob("*.py"))
        },
        "pyproject_sha256": sha256(PROJECT / "pyproject.toml"),
        "sites": [site.to_dict() for site in sites],
    }
    receipt = run_dir / "receipt.json"
    receipt.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                       encoding="utf-8")
    print(receipt)
    print(f"PASS: {len(sites)} exact dexdump tuples; {len(rejected)} malformed inputs rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
