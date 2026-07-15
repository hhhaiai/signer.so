#!/usr/bin/env python3
"""Cross-ABI proof for the 0x8746c sensor/display orchestration subpipeline."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM = (AUDIT / "disasm-8746c-8f56c.txt").read_text(errors="replace").lower()
X86 = (AUDIT / "disasm-x86-88475-93f86.txt").read_text(
    errors="replace").lower()
TRACE = (AUDIT / "unidbg-detector-scratch-two-sensor-loop-raw.log").read_text(
    errors="replace")
BOUNDARY_TRACE = (
    AUDIT / "unidbg-detector-scratch-128-sensor-boundary-raw.log"
).read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.S | re.M) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def require_order(text: str, needles: list[str], label: str) -> None:
    offset = 0
    for needle in needles:
        found = text.find(needle, offset)
        if found < 0:
            raise AssertionError(f"missing/out-of-order {label}: {needle}")
        offset = found + len(needle)


def first_trace_run() -> str:
    marker = "detector-scratch stage=producer-entry"
    if marker not in TRACE:
        raise AssertionError("two-sensor trace lacks producer entry")
    run = TRACE.split(marker, 1)[1]
    return run.split("detector-scratch stage=producer-return", 1)[0]


def main() -> None:
    require(ARM,
            r"8cc38:.*mov\s+w3,\s*#0xffffffff.*"
            r"8cc60:.*bl\s+c0180",
            "ARM64 getSensorList(-1)")
    require(ARM,
            r"8da3c:.*ldr\s+x2,\s*\[x8\].*"
            r"8da60:.*bl\s+a8978",
            "ARM64 sensor-list size reader")
    require(ARM,
            r"8e348:.*sub\s+x8,\s*x29,\s*#0x234.*"
            r"8e34c:.*ldur\s+w3,\s*\[x8,\s*#-256\].*"
            r"8e358:.*bl\s+a948c",
            "ARM64 indexed sensor read")
    require(X86,
            r"91510:.*call\s+b278e",
            "x86_64 getSensorList")
    require(X86,
            r"91bc8:.*call\s+a469c",
            "x86_64 size reader")
    require(X86,
            r"93c9b:.*mov\s+rcx,.*\[rbp-0x190\].*"
            r"93ca9:.*call\s+a4cd9",
            "x86_64 indexed sensor read")
    print("cross-ABI sensor-list, size and indexed get loop inputs: PASS")

    # Numeric address order is not runtime order in the flattened ARM64 CFG,
    # so prove the getter and acquisition call sites independently.  Runtime
    # order is checked against the observation-only trace below.
    require(ARM,
            r"8bf3c:.*8bf44:.*ldr\s+x2,\s*\[x8\].*"
            r"8bf60:.*bl\s+bea74",
            "ARM64 Sensor.getName")
    require(ARM,
            r"8ad10:.*8ad18:.*ldr\s+x2,\s*\[x8\].*"
            r"8ad3c:.*bl\s+92b24",
            "ARM64 name UTF acquisition")
    require(ARM,
            r"8ca50:.*8ca58:.*ldr\s+x2,\s*\[x8\].*"
            r"8ca74:.*bl\s+bf5fc",
            "ARM64 Sensor.getVendor")
    require(ARM,
            r"8ec08:.*8ec10:.*ldr\s+x2,\s*\[x8\].*"
            r"8ec34:.*bl\s+92b24",
            "ARM64 vendor UTF acquisition")
    require(ARM,
            r"8bc94:.*ldr\s+x1,\s*\[x8\].*"
            r"8bca0:.*ldr\s+x2,\s*\[x8\].*"
            r"8bcac:.*ldr\s+x3,\s*\[x8\].*"
            r"8bcb8:.*ldr\s+x4,\s*\[x8\].*"
            r"8bccc:.*bl\s+8f56c",
            "ARM64 UTF pair append")
    require(X86, r"91cb6:.*call\s+b1a13", "x86_64 Sensor.getName")
    require(X86, r"91eea:.*call\s+b20c2", "x86_64 Sensor.getVendor")
    if len(re.findall(r"call\s+96ae0\b", X86)) != 2:
        raise AssertionError("x86_64 must have two UTF acquisitions")
    require(X86, r"92f15:.*call\s+93f86", "x86_64 UTF pair append")
    print("cross-ABI name/vendor UTF acquisition and pair append: PASS")

    require(ARM,
            r"8bcd0:.*ldur\s+w8,\s*\[x8,\s*#-256\].*"
            r"8bd04:.*add\s+w8,\s*w8,\s*#0x1.*"
            r"8bd18:.*stur\s+w8,\s*\[x29,\s*#-148\]",
            "ARM64 post-appender index increment")
    require(ARM,
            r"8ec88:.*ldur\s+x8,\s*\[x8,\s*#-256\].*"
            r"8ecbc:.*ldr\s+w14,\s*\[x8\].*"
            r"8ecd4:.*cmp\s+w27,\s*w14.*"
            r"8ece0:.*csel\s+x6,\s*x16,\s*x15,\s*lt.*"
            r"8ecf0:.*stur\s+w27,\s*\[x8,\s*#-256\]",
            "ARM64 signed index/count loop gate")
    require(X86,
            r"92fd0:.*mov\s+r10,.*\[rbp-0x190\].*"
            r"92fd7:.*inc\s+r10d.*"
            r"92fda:.*mov\s+dword ptr \[rbp-0x1b4\],\s*r10d",
            "x86_64 post-appender index increment")
    require(X86,
            r"91244:.*mov\s+rax,.*\[rbp-0x1a8\].*"
            r"9124e:.*cmp\s+ecx,\s*dword ptr \[rax\].*"
            r"91264:.*cmovl\s+rdx,\s*rax",
            "x86_64 signed index/count loop gate")
    print("cross-ABI post-appender increment and signed index<count gate: PASS")

    require(ARM,
            r"8a82c:.*ldr\s+x1,\s*\[x8\].*"
            r"8a840:.*ldur\s+x2,\s*\[x8,\s*#-256\].*"
            r"8a848:.*bl\s+95020",
            "ARM64 name UTF release")
    require(ARM,
            r"8d0f4:.*ldr\s+x1,\s*\[x8\].*"
            r"8d108:.*ldur\s+x2,\s*\[x8,\s*#-256\].*"
            r"8d110:.*bl\s+95020",
            "ARM64 vendor UTF release")
    if len(re.findall(r"ldr\s+x8,\s*\[x8,\s*#184\]\s*\n\s*"
                      r"[0-9a-f]+:.*blr\s+x8", ARM)) != 7:
        raise AssertionError("ARM64 must have seven DeleteLocalRef sites")
    if len(re.findall(r"call\s+qword ptr \[rax\+0xb8\]", X86)) != 7:
        raise AssertionError("x86_64 must have seven DeleteLocalRef sites")
    if len(re.findall(r"call\s+98081\b", X86)) != 2:
        raise AssertionError("x86_64 must have two UTF release sites")
    print("cross-ABI two UTF releases and seven local-ref cleanup sites: PASS")

    run = first_trace_run()
    require_order(run, [
        "stage=size-return status=0x0 value=2/0x2",
        "stage=get-entry caller=libsigner.so+0x8e35c status=0x0",
        "index=0",
        "stage=sensor-pair-entry caller=libsigner.so+0x8bcd0",
        "count=0",
        "stage=sensor-pair-return status=0x0",
        "count=1",
        "stage=get-entry caller=libsigner.so+0x8e35c status=0x0",
        "index=1",
        "stage=sensor-pair-entry caller=libsigner.so+0x8bcd0",
        "count=1",
        "stage=sensor-pair-return status=0x0",
        "count=2",
        "stage=sensor-utf-release caller=libsigner.so+0x8a84c",
        "stage=sensor-utf-release caller=libsigner.so+0x8d114",
        "stage=delete-local-ref pc=libsigner.so+0x8e158",
        "stage=delete-local-ref pc=libsigner.so+0x8dbfc",
        "stage=delete-local-ref pc=libsigner.so+0x8cd38",
        "stage=delete-local-ref pc=libsigner.so+0x8c22c",
        "stage=delete-local-ref pc=libsigner.so+0x8dde0",
        "stage=system-resources-entry",
        "stage=display-metrics-entry",
        "name=widthPixels",
        "name=heightPixels",
        "stage=delete-local-ref pc=libsigner.so+0x8c754",
        "stage=delete-local-ref pc=libsigner.so+0x8b53c",
    ], "two-sensor observation")
    if run.count("stage=get-entry ") != 2:
        raise AssertionError("first run must fetch two sensors")
    if run.count("stage=sensor-pair-entry ") != 2:
        raise AssertionError("first run must append two pairs")
    if run.count("stage=sensor-utf-release ") != 2:
        raise AssertionError("first run must release only the final two UTF pointers")
    if run.count("stage=delete-local-ref ") != 7:
        raise AssertionError("first run must execute seven terminal local-ref deletes")
    between = run.split("count=1", 1)[1].split("count=2", 1)[0]
    if "sensor-utf-release" in between or "delete-local-ref" in between:
        raise AssertionError("first sensor temporaries unexpectedly cleaned before index 1")
    print("two-sensor execution proves overwrite-without-per-iteration cleanup: PASS")

    require_order(BOUNDARY_TRACE, [
        "stage=size-return status=0x0 value=128/0x80",
        "index=126",
        "first=sensor-126",
        "count=127",
        "index=127",
        "first=sensor-127",
        "stage=sensor-pair-return status=0x26",
        "count=127",
        "stage=sensor-utf-release caller=libsigner.so+0x8a84c",
        "stage=sensor-utf-release caller=libsigner.so+0x8d114",
        "stage=delete-local-ref pc=libsigner.so+0x8e158",
        "stage=delete-local-ref pc=libsigner.so+0x8dbfc",
        "stage=delete-local-ref pc=libsigner.so+0x8cd38",
        "stage=delete-local-ref pc=libsigner.so+0x8c22c",
        "stage=delete-local-ref pc=libsigner.so+0x8dde0",
        "stage=producer-return status=0x26",
        "width-height-pair=0x0/0x0 string-count=127",
    ], "128-sensor capacity boundary")
    if BOUNDARY_TRACE.count("stage=get-entry ") != 128:
        raise AssertionError("capacity run must fetch all 128 sensor objects")
    if BOUNDARY_TRACE.count("stage=sensor-pair-entry ") != 128:
        raise AssertionError("capacity run must attempt 128 pair appends")
    if BOUNDARY_TRACE.count("stage=sensor-utf-release ") != 2:
        raise AssertionError("capacity run must release only final UTF pointers")
    if BOUNDARY_TRACE.count("stage=delete-local-ref ") != 5:
        raise AssertionError(
            "capacity failure must perform five sensor refs and skip display refs")
    if "stage=system-resources-entry" in BOUNDARY_TRACE:
        raise AssertionError("status 0x26 must skip Resources.getSystem")
    if "stage=display-metrics-entry" in BOUNDARY_TRACE:
        raise AssertionError("status 0x26 must skip getDisplayMetrics")
    print("128-sensor run proves count 127, status 0x26 and display skip: PASS")

    require(CPP,
            r"struct RecoveredDetectorSensorDisplayOperations8746c\s*\{",
            "C++ operation surface")
    require(CPP,
            r"runRecoveredDetectorSensorDisplayPipeline8746c\(",
            "C++ sensor/display pipeline")
    require(CPP,
            r"std::int32_t sensorCount = 0;.*"
            r"for \(std::int32_t index = 0; status == 0 && index < sensorCount;",
            "C++ signed-jint sensor loop")
    require(CPP,
            r"releaseStringUtfChars\(.*sensorName.*sensorNameChars.*"
            r"releaseStringUtfChars\(.*sensorVendor.*sensorVendorChars.*"
            r"deleteLocalReference\(operations\.context, sensorManager\).*"
            r"deleteLocalReference\(operations\.context, sensorList\).*"
            r"deleteLocalReference\(operations\.context, sensor\).*"
            r"deleteLocalReference\(operations\.context, sensorName\).*"
            r"deleteLocalReference\(operations\.context, sensorVendor\)",
            "C++ terminal sensor cleanup order")
    require(CPP,
            r'getIntField\(.*"widthPixels".*getIntField\(.*"heightPixels"',
            "C++ display field order")
    require(CPP,
            r"bool recoveredDetectorSensorDisplayPipeline8746cRegression\(\)",
            "C++ direct regression")
    require(CPP,
            r"for \(const std::int32_t count : \{0, -1\}\)",
            "C++ empty and negative-size regressions")
    require(CPP,
            r"const std::array<SensorFailureCase8746c, 9> sensorFailures",
            "C++ per-stage sensor failure regressions")
    require(CPP,
            r'state\.failEvent = "append-1";.*'
            r"state\.failStatus = 0x26;",
            "C++ appender capacity-status regression")
    require(CPP,
            r"runRecoveredDetectorScratchProducer8746c\(.*"
            r"runRecoveredDetectorProperties8746c\(.*"
            r"if \(propertyStatus != 0\) return propertyStatus;.*"
            r"runRecoveredDetectorSensorDisplayPipeline8746c\(",
            "C++ property-before-sensor producer composition")
    require(CPP,
            r"bool recoveredDetectorScratchProducer8746cRegression\(\).*"
            r"if \(!recoveredDetectorScratchProducer8746cRegression\(\)\)",
            "C++ composed producer regression and top-level guard")
    require(CPP,
            r"if \(!recoveredDetectorSensorDisplayPipeline8746cRegression\(\)\)",
            "top-level regression guard")
    require(COVERAGE,
            r"`0x8746c\.\.0x8f56c`.*\*\*recovered\*\*",
            "producer recovered coverage")
    print("C++ success/failure model, cleanup quirk and recovered coverage: PASS")


if __name__ == "__main__":
    main()
