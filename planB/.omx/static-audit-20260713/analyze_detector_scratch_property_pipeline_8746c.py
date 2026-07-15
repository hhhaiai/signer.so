#!/usr/bin/env python3
"""Cross-ABI and observation-only proof for 0x8746c property materialization."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM = (AUDIT / "disasm-8746c-8f56c.txt").read_text(errors="replace").lower()
X86 = (AUDIT / "disasm-x86-88475-93f86.txt").read_text(
    errors="replace").lower()
TRACE = (AUDIT / "unidbg-detector-scratch-unique-properties-raw.log").read_text(
    errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


@dataclass(frozen=True)
class Stage:
    property_name: str
    scratch_offset: int
    arm_call: int
    arm_string: int
    arm_key: int
    x86_call: int
    x86_string: int
    x86_key: int
    published_before_call: int | None


STAGES = (
    Stage("ro.bootloader", 0x48, 0x8D278, 0x143668, 0x37,
          0x92636, 0x13C038, 0x52, None),
    Stage("ro.product.manufacturer", 0x08, 0x8B244, 0x143690, 0xA0,
          0x90DC2, 0x13C060, 0xB5, 0x48),
    Stage("ro.product.model", 0x18, 0x8DD00, 0x1436B0, 0x5A,
          0x8EBD4, 0x13C080, 0x99, 0x08),
    Stage("ro.product.device", 0x20, 0x8C0E8, 0x143720, 0xF7,
          0x8E7DF, 0x13C0F0, 0x39, 0x18),
    Stage("ro.build.display.id", 0x28, 0x8EEA8, 0x143900, 0x26,
          0x92231, 0x13C2D0, 0xBA, 0x20),
    Stage("ro.product.name", 0x00, 0x8B5B8, 0x143790, 0xD4,
          0x93DAF, 0x13C160, 0x18, 0x28),
    Stage("ro.build.host", 0x58, 0x8E95C, 0x143648, 0x15,
          0x8F311, 0x13C018, 0x49, 0x00),
    Stage("ro.build.fingerprint", 0x30, 0x8D2FC, 0x1437C0, 0xD4,
          0x8FD4D, 0x13C190, 0xFC, 0x58),
    Stage("ro.build.type", 0x38, 0x8B7AC, 0x144800, 0x05,
          0x8FF6F, 0x13D2A0, 0x2B, 0x30),
    Stage("ro.product.brand", 0x10, 0x8D9B0, 0x143700, 0xB4,
          0x92BC0, 0x13C0D0, 0x11, 0x38),
    Stage("ro.build.user", 0x50, 0x8B368, 0x144810, 0xB4,
          0x8DF5B, 0x13D2B0, 0x69, 0x10),
    Stage("ro.hardware", 0x40, 0x8B9A8, 0x143628, 0x4A,
          0x8D9FF, 0x13BFF8, 0x2E, 0x50),
    Stage("ro.product.cpu.abilist", 0x68, 0x8BD74, 0x144820, 0x45,
          0x8E3CB, 0x13D2C0, 0x47, 0x40),
)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def elf_vma_bytes(path: Path, address: int, size: int) -> bytes:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise AssertionError(f"expected little-endian ELF64: {path}")
    section_offset = struct.unpack_from("<Q", data, 0x28)[0]
    section_entry_size = struct.unpack_from("<H", data, 0x3A)[0]
    section_count = struct.unpack_from("<H", data, 0x3C)[0]
    for index in range(section_count):
        entry = section_offset + index * section_entry_size
        section_address = struct.unpack_from("<Q", data, entry + 0x10)[0]
        file_offset = struct.unpack_from("<Q", data, entry + 0x18)[0]
        section_size = struct.unpack_from("<Q", data, entry + 0x20)[0]
        if section_address <= address and address + size <= section_address + section_size:
            start = file_offset + address - section_address
            return data[start:start + size]
    raise AssertionError(f"VMA 0x{address:x}+0x{size:x} is not file-backed in {path}")


def verify_encoded_string(path: Path, address: int, key: int,
                          plaintext: str) -> None:
    decoded = plaintext.encode("ascii") + b"\0"
    expected = bytes(byte ^ key for byte in decoded)
    actual = elf_vma_bytes(path, address, len(expected))
    if actual != expected:
        raise AssertionError(
            f"encoded string mismatch {path.name}@0x{address:x}: "
            f"actual={actual.hex()} expected={expected.hex()}")


def arm_window(call: int, before: int = 0x40) -> str:
    lines = ARM.splitlines()
    call_pattern = re.compile(rf"^\s*{call:x}:.*\bbl\s+d4678\b")
    for index, line in enumerate(lines):
        if call_pattern.search(line):
            return "\n".join(lines[max(0, index - before):index + 2])
    raise AssertionError(f"ARM64 property call 0x{call:x} not found")


def x86_window(call: int, before: int = 24) -> str:
    lines = X86.splitlines()
    call_pattern = re.compile(rf"^\s*{call:x}:.*\bcall\s+c1a02\b")
    for index, line in enumerate(lines):
        if call_pattern.search(line):
            return "\n".join(lines[max(0, index - before):index + 2])
    raise AssertionError(f"x86_64 property call 0x{call:x} not found")


def arm_publish_pattern(offset: int) -> str:
    if offset == 0:
        return r"str\s+x9,\s*\[x8\]"
    return rf"str\s+x9,\s*\[x8,\s*#{offset}\]"


def x86_publish_pattern(offset: int) -> str:
    if offset == 0:
        return r"mov\s+qword ptr \[rax\],\s*rcx"
    return rf"mov\s+qword ptr \[rax\+0x{offset:x}\],\s*rcx"


def main() -> None:
    if len(re.findall(r"\bbl\s+d4678\b", ARM)) != 13:
        raise AssertionError("ARM64 must contain thirteen property dispatch calls")
    if len(re.findall(r"\bcall\s+c1a02\b", X86)) != 13:
        raise AssertionError("x86_64 must contain thirteen property dispatch calls")
    if len(re.findall(r"\bbl\s+139e20\s+<malloc@plt>", ARM)) != 13:
        raise AssertionError("ARM64 must contain thirteen malloc calls")
    if len(re.findall(r"\bcall\s+132850\s+<malloc@plt>", X86)) != 13:
        raise AssertionError("x86_64 must contain thirteen malloc calls")
    print("thirteen dispatcher and thirteen malloc sites per ABI: PASS")

    for stage in STAGES:
        verify_encoded_string(ARM_SO, stage.arm_string, stage.arm_key,
                              stage.property_name)
        verify_encoded_string(X86_SO, stage.x86_string, stage.x86_key,
                              stage.property_name)
        arm = arm_window(stage.arm_call)
        x86 = x86_window(stage.x86_call)
        require(arm, rf"adr\s+x0,\s*{stage.arm_string:x}\b",
                f"ARM64 {stage.property_name} address")
        require(x86, rf"#\s*{stage.x86_string:x}\b",
                f"x86_64 {stage.property_name} address")
        if stage.published_before_call is not None:
            require(arm, arm_publish_pattern(stage.published_before_call),
                    f"ARM64 prior publication +0x{stage.published_before_call:x}")
            require(x86, x86_publish_pattern(stage.published_before_call),
                    f"x86_64 prior publication +0x{stage.published_before_call:x}")
    print("thirteen XOR-decoded names and cross-ABI call sites: PASS")
    print("twelve publish-previous-stage edges before calls 2..13: PASS")

    require(ARM,
            r"8d248:.*sub\s+x9,\s*x8,\s*#0x60.*"
            r"8d254:.*mov\s+x1,\s*x9.*"
            r"8d268:.*stur\s+q0,\s*\[x8,\s*#-20\].*"
            r"8d26c:.*stp\s+q0,\s*q0,\s*\[x8,\s*#-80\].*"
            r"8d270:.*stp\s+q0,\s*q0,\s*\[x8,\s*#-48\].*"
            r"8d274:.*stur\s+q0,\s*\[x8,\s*#-96\].*"
            r"8d278:.*bl\s+d4678",
            "ARM64 zeroed 0x60-byte shared property buffer")
    require(X86,
            r"9260a:.*lea\s+r15,\s*\[rax-0x60\].*"
            r"92611:.*xorps\s+xmm0,\s*xmm0.*"
            r"92614:.*movups\s+xmmword ptr \[rax-0x14\],\s*xmm0.*"
            r"92618:.*movaps\s+xmmword ptr \[rax-0x20\],\s*xmm0.*"
            r"9261c:.*movaps\s+xmmword ptr \[rax-0x30\],\s*xmm0.*"
            r"92620:.*movaps\s+xmmword ptr \[rax-0x40\],\s*xmm0.*"
            r"92624:.*movaps\s+xmmword ptr \[rax-0x50\],\s*xmm0.*"
            r"92628:.*movaps\s+xmmword ptr \[rax-0x60\],\s*xmm0.*"
            r"92633:.*mov\s+rsi,\s*r15.*92636:.*call\s+c1a02",
            "x86_64 zeroed 0x60-byte shared property buffer")
    require(ARM, r"8ae80:.*str\s+x9,\s*\[x8,\s*#104\]",
            "ARM64 final +0x68 publication")
    require(X86, r"9080c:.*mov\s+qword ptr \[rax\+0x68\],\s*rcx",
            "x86_64 final +0x68 publication")
    print("shared 0x60 stack buffer and final +0x68 publication: PASS")

    arm_failure_blocks = {
        0x8AAAC: 0x40,
        0x8AE34: 0x38,
        0x8B2C0: 0x08,
        0x8B750: 0x18,
        0x8BA18: 0x30,
        0x8CDAC: 0x10,
        0x8CF60: 0x50,
        0x8D658: 0x20,
        0x8DEE4: 0x28,
        0x8E0A4: 0x68,
        0x8E240: 0x58,
        0x8E290: 0x48,
    }
    for status_address, offset in arm_failure_blocks.items():
        pattern = (r"str\s+xzr,\s*\[x0\]" if offset == 0 else
                   rf"str\s+xzr,\s*\[x0,\s*#{offset}\]")
        require(ARM,
                rf"{status_address:x}:.*mov\s+w12,\s*#0x2.*{pattern}",
                f"ARM64 status-2 clear +0x{offset:x}")
    require(ARM,
            r"8e88c:.*mov\s+w12,\s*#0x2.*8e8c4:.*b\s+8dcc4",
            "ARM64 status-2 branch for +0x0")
    require(ARM, r"8dcc8:.*str\s+xzr,\s*\[x0\]",
            "ARM64 failure clear +0x0")
    if len(re.findall(r"mov\s+w12,\s*#0x2\b", ARM)) != 13:
        raise AssertionError("ARM64 must contain thirteen property status-2 blocks")

    x86_failure_clears = {
        0x8D769: 0x18,
        0x8E24E: 0x38,
        0x8E343: 0x50,
        0x8E622: 0x40,
        0x8F3CF: 0x28,
        0x8F3E0: 0x58,
        0x8F432: 0x30,
        0x8F8A8: 0x00,
        0x90799: 0x48,
        0x916A4: 0x20,
        0x922D7: 0x68,
        0x9337F: 0x08,
        0x93969: 0x10,
    }
    for address, offset in x86_failure_clears.items():
        suffix = "" if offset == 0 else f"\\+0x{offset:x}"
        require(X86,
                rf"{address:x}:.*and\s+qword ptr \[rax{suffix}\],\s*0x0",
                f"x86_64 failure clear +0x{offset:x}")
    require(X86,
            r"939d1:.*push\s+0x2.*939d3:.*pop\s+rdx.*"
            r"939d4:.*mov\s+dword ptr \[rbp-0x34\],\s*edx",
            "x86_64 common status-2 publication")
    print("thirteen allocation failures clear the current field and return 2: PASS")

    observed_calls = re.findall(
        r"stage=property-entry caller=libsigner\.so\+0x([0-9a-f]+) "
        r"name=([^ ]+) output=([^\s]+)", TRACE)
    if len(observed_calls) < len(STAGES):
        raise AssertionError("unique-property trace lacks one complete producer run")
    first_run = observed_calls[:len(STAGES)]
    expected_run = [
        (f"{stage.arm_call + 4:x}", stage.property_name, first_run[0][2])
        for stage in STAGES
    ]
    if first_run != expected_run:
        raise AssertionError(
            f"unexpected observed property order/output reuse: {first_run}")
    expected_fields = (
        "stage=all-fields"
        " +0x00=TRACE_PRODUCT_NAME"
        " +0x08=TRACE_MANUFACTURER"
        " +0x10=TRACE_BRAND"
        " +0x18=TRACE_MODEL"
        " +0x20=TRACE_DEVICE"
        " +0x28=TRACE_DISPLAY_ID"
        " +0x30=TRACE_FINGERPRINT"
        " +0x38=TRACE_BUILD_TYPE"
        " +0x40=TRACE_HARDWARE"
        " +0x48=TRACE_BOOTLOADER"
        " +0x50=TRACE_BUILD_USER"
        " +0x58=TRACE_HOST"
        " +0x68=TRACE_ABILIST"
    )
    if expected_fields not in TRACE:
        raise AssertionError("unique-property scratch mapping missing")
    print("observation-only order, shared output pointer and 13 scratch fields: PASS")

    for stage in STAGES:
        require(CPP,
                rf'\{{"{re.escape(stage.property_name)}",\s*0x{stage.scratch_offset:02x}\}}',
                f"C++ descriptor {stage.property_name}")
    require(CPP,
            r"operations\.readProperty\(\s*descriptor\.propertyName,\s*"
            r"propertyValue\.data\(\)\)",
            "caller-supplied property reader")
    require(CPP, r"operations\.allocate\(length \+ 1\)",
            "caller-supplied allocator")
    require(CPP, r"if \(allocation == nullptr\).*return 2;",
            "C++ allocation failure status")
    require(CPP, r"bool recoveredDetectorProperties8746cRegression\(\)",
            "C++ property regression")
    require(CPP, r"if \(!recoveredDetectorProperties8746cRegression\(\)\)",
            "top-level property regression guard")
    require(CPP, r"struct RecoveredDetectorInputProfile8746c\s*\{",
            "caller-supplied detector profile")
    require(CPP,
            r"RecoveredDetectorMissingPropertyPolicy8746c::Reject",
            "reject-missing default policy")
    require(CPP,
            r"bool displayMetricsProvided = false;.*"
            r"bool sensorListProvided = false;",
            "explicit display and sensor-list presence")
    require(CPP,
            r"materializeRecoveredDetectorInputProfile8746c\(",
            "caller profile materializer")
    require(CPP,
            r"destroyRecoveredDetectorInputProfileScratch8746c\(",
            "all-field adapter cleanup")
    require(CPP,
            r"if \(!recoveredDetectorInputProfile8746cRegression\(\)\)",
            "top-level caller profile regression guard")
    if "TRACE_PRODUCT_NAME" in CPP or "bullhead" in CPP[:12000]:
        raise AssertionError("recovered property pipeline must not embed trace/device values")
    print("C++ caller inputs, all 13 descriptors and failure regressions: PASS")


if __name__ == "__main__":
    main()
