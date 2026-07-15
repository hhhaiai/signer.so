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
    # All four target data segments use a +0x8000 VMA/file-offset delta.
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

    arm_generate = body(arm_text, 0xA0640, 0xA1230)
    x86_generate = body(x86_text, 0x9FC58, 0xA0319)
    arm_orchestrator = body(arm_text, 0x91428, 0x917A8)
    x86_orchestrator = body(x86_text, 0x958B5, 0x95BF1)

    require("pc=000a0640...000a1230" in arm_frames,
            "ARM64 generateKeyPair FDE")
    require("pc=00091428...000917a8" in arm_frames,
            "ARM64 key-pair orchestrator FDE")
    require("pc=0009fc58...000a0319" in x86_frames,
            "x86_64 generateKeyPair FDE")
    require("pc=000958b5...00095bf1" in x86_frames,
            "x86_64 key-pair orchestrator FDE")

    expected_constants = {
        "arm_generate_name": (
            decoded(arm_blob, 0x144D00, 16, 0x22),
            b"generateKeyPair\0"),
        "arm_generate_signature": (
            decoded(arm_blob, 0x144D10, 26, 0x7C),
            b"()Ljava/security/KeyPair;\0"),
        "arm_provider": (
            decoded(arm_blob, 0x144880, 16, 0xD4),
            b"AndroidKeyStore\0"),
        "x86_generate_name": (
            decoded(x86_blob, 0x13D7A0, 16, 0x82),
            b"generateKeyPair\0"),
        "x86_generate_signature": (
            decoded(x86_blob, 0x13D7B0, 26, 0xDB),
            b"()Ljava/security/KeyPair;\0"),
        "x86_provider": (
            decoded(x86_blob, 0x13D320, 16, 0x6E),
            b"AndroidKeyStore\0"),
    }
    for name, (actual, expected) in expected_constants.items():
        require(actual == expected, f"{name}: {actual!r}")
    print("cross-ABI generateKeyPair/signature/provider constants: PASS")

    for pattern, description in [
        (r"a0b74:.*\[x8, #0xf8\].*a0b78:.*blr", "ARM GetObjectClass"),
        (r"a0dc4:.*\[x8, #0x108\].*a0dc8:.*blr", "ARM GetMethodID"),
        (r"a0a20:.*\[x8, #0x110\].*a0a24:.*blr", "ARM CallObjectMethod"),
        (r"a1130:.*\[x8, #0xb8\].*a1134:.*blr", "ARM DeleteLocalRef"),
        (r"a0a44:.*0x92a20.*a0b94:.*0x92a20.*a0de4:.*0x92a20",
         "ARM three exception consumes"),
        (r"a0c9c:.*#0x3\b", "ARM null-object status 3"),
        (r"a0b4c:.*#0x12\b.*a1108:.*#0x12\b",
         "ARM class/method status 18"),
        (r"a0a08:.*#0x1c\b", "ARM call/null-result status 28"),
        (r"a0a2c:.*str\s+x0, \[x8\]", "ARM returned output publication"),
        (r"a0ef8:.*str\s+xzr, \[x8\]", "ARM failure output clear"),
    ]:
        require_pattern(arm_generate, pattern, description)

    for pattern, description in [
        (r"a001a:.*\*0xf8", "x86 GetObjectClass"),
        (r"a0102:.*\*0x108", "x86 GetMethodID"),
        (r"9ff3e:.*\*0x110", "x86 CallObjectMethod"),
        (r"a02a3:.*\*0xb8", "x86 DeleteLocalRef"),
        (r"9ff59:.*0x96a44.*a0030:.*0x96a44.*a011a:.*0x96a44",
         "x86 three exception consumes"),
        (r"a00a6:.*\$0x3", "x86 null-object status 3"),
        (r"9ffe2:.*\$0x12.*a0280:.*\$0x12",
         "x86 class/method status 18"),
        (r"9ff20:.*\$0x1c", "x86 call/null-result status 28"),
        (r"9ff49:.*movq\s+%rax, \(%rcx\)", "x86 returned output publication"),
        (r"a0182:.*andq\s+\$0x0, \(%rax\)", "x86 failure output clear"),
    ]:
        require_pattern(x86_generate, pattern, description)
    print("cross-ABI generateKeyPair JNI/status/output ownership: PASS")

    for pattern, description in [
        (r"91660:.*bl\s+0x139800", "ARM byte-lock CAS"),
        (r"916c0:.*0x144000.*916cc:.*\[x8, #0x880\].*916dc:.*#0x85c",
         "ARM provider XOR-once publication"),
        (r"91720:.*stlrb\s+wzr", "ARM provider lock release"),
        (r"9171c:.*0x144880.*9172c:.*bl\s+0xa4450",
         "ARM KeyStore.getInstance(provider)"),
        (r"916e4:.*916f0:.*mov\s+x3, xzr.*916f8:.*bl\s+0xa5308",
         "ARM KeyStore.load(null)"),
        (r"91690:.*9169c:.*bl\s+0xa0640", "ARM generateKeyPair forwarding"),
        (r"916a0:.*ldr\s+w8, \[x23\].*916fc:.*ldr\s+w8, \[x23\].*91730:.*ldr\s+w8, \[x23\]",
         "ARM status check after every helper"),
        (r"91760:.*str\s+xzr.*9176c:.*str\s+xzr",
         "ARM clears both outputs on failure"),
    ]:
        require_pattern(arm_orchestrator, pattern, description)

    for pattern, description in [
        (r"95a04:.*cmpxchgb.*0x13ef92", "x86 byte-lock CAS"),
        (r"95a9d:.*0x13d320.*95ab2:.*0x13ef93", "x86 provider XOR-once publication"),
        (r"95b33:.*0x13ef92", "x86 provider lock release"),
        (r"95b46:.*0x13d320.*95b52:.*callq\s+0xa1e5d",
         "x86 KeyStore.getInstance(provider)"),
        (r"95ac1:.*95ad5:.*xorl\s+%ecx, %ecx.*95ad7:.*callq\s+0xa283d",
         "x86 KeyStore.load(null)"),
        (r"95a21:.*95a37:.*callq\s+0x9fc58", "x86 generateKeyPair forwarding"),
        (r"95a78:.*cmpl\s+\$0x0.*95b18:.*cmpl\s+\$0x0.*95b93:.*cmpl\s+\$0x0",
         "x86 status check after every helper"),
        (r"95bba:.*andq\s+\$0x0.*95bc3:.*andq\s+\$0x0",
         "x86 clears both outputs on failure"),
    ]:
        require_pattern(x86_orchestrator, pattern, description)
    print("cross-ABI AndroidKeyStore/load/generate failure envelope: PASS")

    for required in [
        "runRecoveredJniGenerateKeyPairA0640",
        '"generateKeyPair"',
        '"()Ljava/security/KeyPair;"',
        "recoveredJniGenerateKeyPairA0640Regression",
        "kRecoveredAndroidKeyStoreEncoded91428",
        "acquireRecoveredAndroidKeyStoreString91428",
        "runRecoveredAndroidKeyStoreKeyPair91428WithState",
        "runRecoveredAndroidKeyStoreKeyPair91428",
        "recoveredAndroidKeyStoreKeyPair91428Regression",
        "*outputKeyStore = 0;",
        "*outputKeyPair = 0;",
    ]:
        require(required in source, f"C++ source token {required}")

    rows = inventory_rows()
    require(rows[0xA0640]["status"] == "recovered",
            "0xa0640 recovered coverage")
    require(rows[0x91428]["status"] == "recovered",
            "0x91428 recovered coverage")
    require(rows[0xA0640]["reachable"] == "no",
            "0xa0640 non-JNI-reachable classification")
    require(rows[0x91428]["reachable"] == "no",
            "0x91428 non-JNI-reachable classification")
    print("C++ regressions and two-FDE recovered coverage: PASS")


if __name__ == "__main__":
    main()
