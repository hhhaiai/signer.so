#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARM_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARM_DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
ARM_FRAMES = Path(__file__).with_name("arm64-eh-frame.txt")
SOURCE = ROOT / "native-reimplementation/recovered_primitives.cpp"
INVENTORY = Path(__file__).with_name("arm64-function-inventory.csv")


def require(condition: bool, description: str) -> None:
    if not condition:
        raise SystemExit(f"missing proof: {description}")


def body(text: str, start: int, end: int) -> str:
    selected: list[str] = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and start <= int(match.group(1), 16) < end:
            selected.append(line)
    require(bool(selected), f"disassembly body {start:#x}..{end:#x}")
    return "\n".join(selected)


def decoded(blob: bytes, vma: int, length: int, key: int) -> bytes:
    # Both target data segments use a +0x8000 VMA/file-offset delta.
    raw = blob[vma - 0x8000 : vma - 0x8000 + length]
    require(len(raw) == length, f"bytes at VMA {vma:#x}")
    return bytes(value ^ key for value in raw)


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def objdump(path: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/objdump", *arguments, str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm_text = ARM_DISASSEMBLY.read_text(errors="replace")
    x86_text = objdump(X86_SO, "-d")
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = objdump(X86_SO, "--dwarf=frames")
    arm_blob = ARM_SO.read_bytes()
    x86_blob = X86_SO.read_bytes()
    source = SOURCE.read_text()

    arm_to_array = body(arm_text, 0x93FD0, 0x94BC0)
    x86_to_array = body(x86_text, 0x97673, 0x97D1E)
    arm_unsigned = body(arm_text, 0x917A8, 0x91D2C)
    x86_unsigned = body(x86_text, 0x95BF1, 0x9604F)
    arm_caller = body(arm_text, 0x91D2C, 0x9279C)
    x86_caller = body(x86_text, 0x9604F, 0x9685C)

    for marker, description in [
        ("pc=00093fd0...00094bc0", "ARM64 toByteArray FDE"),
        ("pc=000917a8...00091d2c", "ARM64 unsigned-byte FDE"),
    ]:
        require(marker in arm_frames, description)
    for marker, description in [
        ("pc=00097673...00097d1e", "x86_64 toByteArray FDE"),
        ("pc=00095bf1...0009604f", "x86_64 unsigned-byte FDE"),
    ]:
        require(marker in x86_frames, description)

    expected_constants = {
        "arm_method": (
            decoded(arm_blob, 0x144948, 12, 0xE2), b"toByteArray\0"),
        "arm_signature": (
            decoded(arm_blob, 0x144954, 5, 0xB6), b"()[B\0"),
        "x86_method": (
            decoded(x86_blob, 0x13D3E8, 12, 0xC6), b"toByteArray\0"),
        "x86_signature": (
            decoded(x86_blob, 0x13D3F4, 5, 0x1C), b"()[B\0"),
    }
    for name, (actual, expected) in expected_constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI BigInteger.toByteArray constants: PASS")

    for pattern, description in [
        (r"943d0:.*\[x8, #0xf8\].*943d4:.*blr", "ARM GetObjectClass"),
        (r"94834:.*\[x8, #0x108\].*94838:.*blr", "ARM GetMethodID"),
        (r"945cc:.*\[x8, #0x110\].*945d0:.*blr", "ARM CallObjectMethod"),
        (r"944f0:.*\[x8, #0xb8\].*944f4:.*blr", "ARM DeleteLocalRef"),
        (r"943f0:.*0x92a20.*945f0:.*0x92a20.*94854:.*0x92a20",
         "ARM three exception consumes"),
        (r"94b84:.*#0x3\b.*94b94:.*str\s+w10", "ARM null-object status 3"),
        (r"94a3c:.*#0x12\b.*94b4c:.*#0x12\b",
         "ARM class/method status 18"),
        (r"943b8:.*#0x1c\b", "ARM call/null-result status 28"),
        (r"945d4:.*ldr.*945d8:.*str\s+x0, \[x8\]",
         "ARM returned byte-array publication"),
        (r"94ad0:.*str\s+xzr, \[x8\]", "ARM failure output clear"),
        (r"94814:.*0x144948.*9481c:.*0x144954",
         "ARM method/signature pointers"),
    ]:
        require_pattern(arm_to_array, pattern, description)

    for pattern, description in [
        (r"97938:.*\*0xf8", "x86 GetObjectClass"),
        (r"97b31:.*\*0x108", "x86 GetMethodID"),
        (r"97a43:.*\*0x110", "x86 CallObjectMethod"),
        (r"979ca:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"9794e:.*0x96a44.*97a5e:.*0x96a44.*97b47:.*0x96a44",
         "x86 three exception consumes"),
        (r"97d01:.*\$0x3", "x86 null-object status 3"),
        (r"97cd4:.*\$0x12", "x86 class/method status 18"),
        (r"97921:.*\$0x1c", "x86 call/null-result status 28"),
        (r"97a49:.*97a4e:.*movq\s+%rax, \(%rcx\)",
         "x86 returned byte-array publication"),
        (r"97c87:.*97c8c:.*andq\s+\$0x0, \(%rax\)",
         "x86 failure output clear"),
        (r"97b23:.*0x13d3e8.*97b2a:.*0x13d3f4",
         "x86 method/signature pointers"),
    ]:
        require_pattern(x86_to_array, pattern, description)
    print("cross-ABI toByteArray JNI/status/output ownership: PASS")

    for pattern, description in [
        (r"91824:.*0x93fd0", "ARM toByteArray helper call"),
        (r"91c48:.*0x95110", "ARM GetByteArrayElements helper call"),
        (r"91b6c:.*0x95834", "ARM ReleaseByteArrayElements helper call"),
        (r"91b48:.*#0x1c\b.*91b58:.*str\s+w10",
         "ARM zero-length status 28"),
        (r"91bb0:.*ldrb.*91bb4:.*cmp.*91bbc:.*cset.*91bc0:.*sub.*91bc4:.*sxtw",
         "ARM leading-zero removal and signed widening"),
        (r"91bc8:.*91bd0:.*str\s+x0, \[x8\].*91bd8:.*calloc",
         "ARM output length and calloc(length,1)"),
        (r"91bf4:.*cmp\s+x0, #0x0.*91c2c:.*str\s+x0, \[x8\]",
         "ARM allocation publication and null test"),
        (r"91a98:.*ldp\s+x0, x2.*91aa0:.*add\s+x1, x9, x8.*91aa4:.*memcpy",
         "ARM memcpy(elements+skip,length)"),
        (r"91ca4:.*#0x2\b.*91cb4:.*str\s+w10",
         "ARM allocation-failure status 2"),
        (r"91a6c:.*91a7c:.*str\s+xzr.*91a80:.*91a88:.*str\s+xzr",
         "ARM clears both outputs on failure"),
        (r"91b60:.*91b6c:.*0x95834", "ARM element release block"),
        (r"91adc:.*91ae8:.*\[x8, #0xb8\].*91aec:.*blr",
         "ARM byte-array local-ref delete block"),
        (r"91d28:.*__stack_chk_fail", "ARM stack-canary exit"),
    ]:
        require_pattern(arm_unsigned, pattern, description)

    for pattern, description in [
        (r"95c67:.*0x97673", "x86 toByteArray helper call"),
        (r"95f82:.*0x9811d", "x86 GetByteArrayElements helper call"),
        (r"95ed2:.*0x98686", "x86 ReleaseByteArrayElements helper call"),
        (r"95eb5:.*\$0x1c", "x86 zero-length status 28"),
        (r"95ef5:.*cmpb\s+\$0x0.*95ef8:.*sete.*95f03:.*subl.*95f05:.*movslq",
         "x86 leading-zero removal and signed widening"),
        (r"95f08:.*95f0d:.*movq\s+%rdi, \(%rax\).*95f15:.*\$0x1.*95f18:.*calloc",
         "x86 output length and calloc(length,1)"),
        (r"95f2a:.*95f2f:.*movq\s+%rcx, \(%rax\).*95f37:.*testq",
         "x86 allocation publication and null test"),
        (r"95e26:.*movzbl.*95e2e:.*addq.*95e33:.*movq.*95e3d:.*memcpy",
         "x86 memcpy(elements+skip,length)"),
        (r"95fcf:.*\$0x2", "x86 allocation-failure status 2"),
        (r"95e0c:.*andq\s+\$0x0.*95e15:.*95e1a:.*andq\s+\$0x0",
         "x86 clears both outputs on failure"),
        (r"95ec3:.*95ed2:.*0x98686", "x86 element release block"),
        (r"95e54:.*95e61:.*\*0xb8", "x86 byte-array local-ref delete block"),
        (r"9604a:.*__stack_chk_fail", "x86 stack-canary exit"),
    ]:
        require_pattern(x86_unsigned, pattern, description)

    require_pattern(arm_caller, r"924f0:.*0x917a8",
                    "ARM unsigned-byte caller edge")
    require_pattern(x86_caller, r"965fa:.*0x95bf1",
                    "x86 unsigned-byte caller edge")
    print("cross-ABI unsigned-byte allocation/copy/cleanup envelope: PASS")

    for required in [
        "runRecoveredJniToByteArray93fd0",
        '"toByteArray"',
        '"()[B"',
        "recoveredJniToByteArray93fd0Regression",
        "runRecoveredBigIntegerUnsignedBytes917a8",
        "recoveredBigIntegerUnsignedBytes917a8Regression",
        "elementLength == 0",
        "elements + skipLeadingZero",
        "static_cast<std::int32_t>(reducedLength)",
        "*outputLength = 0;",
        "*outputData = 0;",
        '"JNI BigInteger.toByteArray helper 0x93fd0 regression failed',
        '"BigInteger unsigned-byte materializer 0x917a8 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    rows = inventory_rows()
    require(rows[0x93FD0]["status"] == "recovered",
            "0x93fd0 recovered coverage")
    require(rows[0x917A8]["status"] == "recovered",
            "0x917a8 recovered coverage")
    require(rows[0x93FD0]["reachable"] == "no",
            "0x93fd0 non-JNI-reachable classification")
    require(rows[0x917A8]["reachable"] == "no",
            "0x917a8 non-JNI-reachable classification")
    print("C++ regressions and two-FDE recovered coverage: PASS")


if __name__ == "__main__":
    main()
