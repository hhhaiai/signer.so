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
    raw = blob[vma - 0x8000 : vma - 0x8000 + length]
    require(len(raw) == length, f"bytes at VMA {vma:#x}")
    return bytes(value ^ key for value in raw)


def require_pattern(text: str, pattern: str, description: str) -> None:
    require(re.search(pattern, text, re.MULTILINE | re.DOTALL) is not None,
            description)


def objdump(path: Path, *arguments: str) -> str:
    return subprocess.run(
        ["/usr/bin/objdump", *arguments, str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


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

    arm_function = body(arm_text, 0xBA914, 0xBB5A0)
    x86_function = body(x86_text, 0xAF3E2, 0xAFB26)
    arm_caller = body(arm_text, 0x1DDE0, 0x1E578)
    x86_caller = body(x86_text, 0x22CF9, 0x2335E)

    require("pc=000ba914...000bb5a0" in arm_frames, "ARM64 FDE")
    require("pc=000af3e2...000afb26" in x86_frames, "x86_64 FDE")
    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 caller FDE")
    require("pc=00022cf9...0002335e" in x86_frames,
            "x86_64 caller FDE")

    constants = {
        "arm_method": (
            decoded(arm_blob, 0x1453B0, 15, 0x87),
            b"getPackageInfo\0",
        ),
        "arm_signature": (
            decoded(arm_blob, 0x1453C0, 54, 0x34),
            b"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\0",
        ),
        "x86_method": (
            decoded(x86_blob, 0x13DE50, 15, 0xCB),
            b"getPackageInfo\0",
        ),
        "x86_signature": (
            decoded(x86_blob, 0x13DE60, 54, 0xE9),
            b"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\0",
        ),
    }
    for name, (actual, expected) in constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI PackageManager.getPackageInfo constants: PASS")

    for pattern, description in [
        (r"ba938:.*cmp\s+x3, #0x0.*ba96c:.*ccmp\s+x2, #0x0",
         "ARM PackageManager/packageName null gates"),
        (r"bb1d0:.*\[x8, #0xf8\].*bb1d4:.*blr", "ARM GetObjectClass"),
        (r"bb1f0:.*0x92a20", "ARM class exception consumer"),
        (r"bad08:.*0x1453b0.*bad10:.*0x1453c0",
         "ARM method/signature pointers"),
        (r"bad28:.*\[x8, #0x108\].*bad2c:.*blr", "ARM GetMethodID"),
        (r"bad48:.*0x92a20", "ARM method exception consumer"),
        (r"bae5c:.*ldp\s+x2, x1.*bae68:.*ldr\s+x3.*"
         r"bae6c:.*ldr\s+w4.*bae70:.*\[x8, #0x110\].*bae74:.*blr",
         "ARM PackageManager/method/packageName/flags CallObjectMethod"),
        (r"bae78:.*ldr\s+x8.*bae7c:.*str\s+x0, \[x8\]",
         "ARM PackageInfo publication"),
        (r"bae94:.*0x92a20", "ARM call exception consumer"),
        (r"bb390:.*ldr\s+x8, \[x8\].*bb398:.*cmp\s+x8, #0x0",
         "ARM null PackageInfo result check"),
        (r"bb4a0:.*\[x8, #0xb8\].*bb4a4:.*blr", "ARM DeleteLocalRef"),
        (r"bb4c0:.*ldr\s+w8, \[x8\].*bb540:.*cmp\s+w8, #0x0",
         "ARM final status check"),
        (r"bb1b8:.*str\s+xzr, \[x8\]", "ARM nonzero-status output clear"),
        (r"bb004:.*#0x3\b", "ARM null-input status 3"),
        (r"baf80:.*#0x12\b.*bafc4:.*#0x12\b",
         "ARM class/method status 18"),
        (r"bacf4:.*#0x23\b", "ARM call/null-result status 35"),
        (r"bad00:.*0x1469c0.*bad14:.*stlrb.*bb01c:.*0x1469c0",
         "ARM method once-lock acquire/release"),
        (r"bafe8:.*0x1469c4.*baff8:.*stlrb.*bb3c0:.*0x1469c4",
         "ARM signature once-lock acquire/release"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"af43b:.*testq\s+%rcx.*af45e:.*testq\s+%rdx",
         "x86 packageName/PackageManager null gates"),
        (r"af94c:.*\*0xf8", "x86 GetObjectClass"),
        (r"af962:.*0x96a44", "x86 class exception consumer"),
        (r"af6bb:.*0x13de50.*af6c2:.*0x13de60",
         "x86 method/signature pointers"),
        (r"af6c9:.*\*0x108", "x86 GetMethodID"),
        (r"af6df:.*0x96a44", "x86 method exception consumer"),
        (r"af780:.*%rsi.*af785:.*%rdx.*af78a:.*%rcx.*"
         r"af78f:.*%r8d.*af796:.*\*0x110",
         "x86 PackageManager/method/packageName/flags CallObjectMethod"),
        (r"af7a2:.*movq\s+%rax, \(%rcx\)", "x86 PackageInfo publication"),
        (r"af7b2:.*0x96a44", "x86 call exception consumer"),
        (r"afa54:.*movq.*afa59:.*cmpq\s+\$0x0, \(%rax\)",
         "x86 null PackageInfo result check"),
        (r"afab0:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"afb01:.*cmpl\s+\$0x0, \(%rax\)", "x86 final status check"),
        (r"af92f:.*andq\s+\$0x0, \(%rax\)",
         "x86 nonzero-status output clear"),
        (r"af886:.*\$0x3", "x86 null-input status 3"),
        (r"af817:.*\$0x12.*af863:.*\$0x12",
         "x86 class/method status 18"),
        (r"af69c:.*\$0x23", "x86 call/null-result status 35"),
        (r"af6a3:.*0x13f048.*af899:.*cmpxchgb.*0x13f048",
         "x86 method once-lock acquire/release"),
        (r"af872:.*0x13f04a.*afa7f:.*cmpxchgb.*0x13f04a",
         "x86 signature once-lock acquire/release"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(
        arm_caller,
        r"1e3b8:.*ldp\s+x2, x3.*1e3bc:.*x5.*1e3c0:.*x0, x23.*"
        r"1e3c8:.*x1, x22.*1e3cc:.*#0x40.*1e3d4:.*0xba914",
        "ARM legacy six-argument forwarding and flag 0x40",
    )
    require_pattern(
        arm_caller,
        r"1e470:.*ldp\s+x2, x3.*1e474:.*x5.*1e478:.*x0, x23.*"
        r"1e47c:.*x1, x22.*1e480:.*#0x8000000.*1e484:.*0xba914",
        "ARM API-28 six-argument forwarding and flag 0x08000000",
    )
    require_pattern(
        x86_caller,
        r"231a6:.*%rdx.*231ab:.*%rcx.*231b4:.*%rdi.*231b7:.*%rsi.*"
        r"231ba:.*\$0x40.*231be:.*%r9.*231c3:.*0xaf3e2",
        "x86 legacy six-argument forwarding and flag 0x40",
    )
    require_pattern(
        x86_caller,
        r"2327e:.*%rdx.*23283:.*%rcx.*2328c:.*%rdi.*2328f:.*%rsi.*"
        r"23292:.*\$0x8000000.*23298:.*%r9.*2329d:.*0xaf3e2",
        "x86 API-28 six-argument forwarding and flag 0x08000000",
    )
    print("cross-ABI getPackageInfo JNI/status/ownership flow: PASS")

    for required in [
        "RecoveredJniGetPackageInfoOperationsBa914",
        "runRecoveredJniGetPackageInfoBa914",
        "recoveredJniGetPackageInfoBa914Regression",
        '"getPackageInfo",',
        '"(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;"',
        "operations.callObjectMethod(",
        "packageManagerObject, methodId, packageNameObject, flags",
        "operations.deleteLocalRef(jniEnvironment, packageManagerClass);",
        "if (*status != 0) *outputPackageInfo = 0;",
        "status = 0x55;",
        "state.objectResult = 0;",
        "state.exceptions[2] = 1;",
        "0x08000000U",
        '"JNI PackageManager.getPackageInfo reader 0xba914 regression failed',
    ]:
        require(required in source, f"C++ source token {required}")

    row = inventory_rows()[0xBA914]
    require(row["status"] == "recovered", "0xba914 recovered coverage")
    require(row["reachable"] == "yes", "0xba914 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
