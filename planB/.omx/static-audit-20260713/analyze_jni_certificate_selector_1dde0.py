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


def direct_targets(text: str) -> list[int]:
    result: list[int] = []
    for line in text.splitlines():
        match = re.search(r"\b(?:bl|callq)\s+0x([0-9a-f]+)", line)
        if match:
            result.append(int(match.group(1), 16))
    return result


def inventory_rows() -> dict[int, dict[str, str]]:
    with INVENTORY.open(newline="") as handle:
        return {int(row["start"], 16): row for row in csv.DictReader(handle)}


def main() -> None:
    arm_text = ARM_DISASSEMBLY.read_text(errors="replace")
    x86_text = objdump(X86_SO, "-d")
    arm_frames = ARM_FRAMES.read_text(errors="replace")
    x86_frames = objdump(X86_SO, "--dwarf=frames")
    source = SOURCE.read_text()

    arm_function = body(arm_text, 0x1DDE0, 0x1E578)
    x86_function = body(x86_text, 0x22CF9, 0x2335E)
    arm_caller = body(arm_text, 0x1E578, 0x1F058)
    x86_caller = body(x86_text, 0x2335E, 0x23D51)

    require("pc=0001dde0...0001e578" in arm_frames, "ARM64 parent FDE")
    require("pc=00022cf9...0002335e" in x86_frames, "x86_64 parent FDE")
    require("pc=0001e578...0001f058" in arm_frames, "ARM64 caller FDE")
    require("pc=0002335e...00023d51" in x86_frames,
            "x86_64 caller FDE")

    arm_expected = {
        0xB3230, 0xB3BF4, 0xB8830, 0xB9424, 0xBA914,
        0xC2B78, 0xC375C, 0xC4064, 0x139DF0,
    }
    x86_expected = {
        0xAAE64, 0xAB508, 0xADF2E, 0xAE5F4, 0xAF3E2,
        0xB3FF9, 0xB46D8, 0xB4DAD, 0x132820,
    }
    require(set(direct_targets(arm_function)) == arm_expected,
            "ARM exact direct helper/stack-fail target set")
    require(set(direct_targets(x86_function)) == x86_expected,
            "x86 exact direct helper/stack-fail target set")
    print("cross-ABI exact direct helper set and parent FDEs: PASS")

    for pattern, description in [
        (r"1de1c:.*x3.*1de24:.*x22, x1.*1de2c:.*x23, x0.*"
         r"1de40:.*x2.*1de44:.*0xb3230",
         "ARM status/JNIEnv/Context getPackageName entry"),
        (r"1de38:.*stp\s+xzr, xzr, \[x29, #-0x18\].*"
         r"1de3c:.*stp\s+xzr, xzr, \[x29, #-0x28\]",
         "ARM four local-reference zero initialization"),
        (r"1de60:.*cmp\s+w24, #0x1b.*1de70:.*csel.*gt",
         "ARM API <=27 versus >=28 selection"),
        (r"1e408:.*x3.*1e414:.*x2.*1e418:.*0xb3bf4.*"
         r"1e41c:.*ldr\s+w8, \[x23\].*1e420:.*cmp\s+w8, #0x0",
         "ARM getPackageManager and status short-circuit"),
        (r"1e3b8:.*ldp\s+x2, x3.*1e3cc:.*#0x40.*"
         r"1e3d0:.*strb\s+wzr.*1e3d4:.*0xba914.*"
         r"1e3d8:.*ldr\s+w8, \[x23\].*1e3e8:.*cmp\s+w8, #0x0",
         "ARM legacy getPackageInfo, false publication and status gate"),
        (r"1e470:.*ldp\s+x2, x3.*1e480:.*#0x8000000.*"
         r"1e484:.*0xba914.*1e488:.*ldr\s+w8, \[x23\].*"
         r"1e498:.*cmp\s+w8, #0x0",
         "ARM API-28 getPackageInfo and status gate"),
        (r"1e368:.*x2.*1e374:.*x3.*1e378:.*0xb8830",
         "ARM legacy PackageInfo.signatures terminal output"),
        (r"1e43c:.*x2.*1e440:.*x3.*1e44c:.*0xb9424.*"
         r"1e450:.*ldr\s+w8, \[x23\].*1e454:.*cmp\s+w8, #0x0",
         "ARM PackageInfo.signingInfo and status gate"),
        (r"1e1dc:.*x2.*1e1e8:.*x3.*1e1ec:.*0xc4064.*"
         r"1e1f0:.*ldr\s+w8, \[x23\].*1e1f4:.*cmp\s+w8, #0x0",
         "ARM hasMultipleSigners and status gate"),
        (r"1e2c8:.*ldr\s+x8, \[sp, #0x40\].*1e2d8:.*ldrb\s+w8.*"
         r"1e2e4:.*ldur\s+x8, \[x29, #-0x28\].*1e2e8:.*str\s+x8",
         "ARM boolean branch and SigningInfo cleanup transfer"),
        (r"1e210:.*x2.*1e21c:.*x3.*1e220:.*0xc375c",
         "ARM certificate-history terminal output"),
        (r"1e4b8:.*x2.*1e4c4:.*x3.*1e4c8:.*0xc2b78",
         "ARM APK-content-signers terminal output"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"22d46:.*%rcx.*22d4b:.*\(%rcx\).*22d4f:.*%rax.*"
         r"22d66:.*\(%rax\).*22d6f:.*0xaae64",
         "x86 four local refs and getPackageName entry"),
        (r"22d74:.*\$0x1c.*22d8c:.*cmovgeq",
         "x86 API <=27 versus >=28 selection"),
        (r"231f4:.*%rdi.*231fb:.*%rsi.*231fe:.*%rdx.*"
         r"23203:.*%rcx.*23208:.*0xab508.*2320d:.*cmpl\s+\$0x0",
         "x86 getPackageManager and status short-circuit"),
        (r"2319e:.*movq.*231a3:.*movb\s+\$0x0.*231ba:.*\$0x40.*"
         r"231c3:.*0xaf3e2.*231c8:.*cmpl\s+\$0x0",
         "x86 legacy getPackageInfo, false publication and status gate"),
        (r"2327e:.*%rdx.*23283:.*%rcx.*23292:.*\$0x8000000.*"
         r"2329d:.*0xaf3e2.*232a2:.*cmpl\s+\$0x0",
         "x86 API-28 getPackageInfo and status gate"),
        (r"2315f:.*%rdx.*2316b:.*%rcx.*23170:.*0xadf2e",
         "x86 legacy PackageInfo.signatures terminal output"),
        (r"23239:.*%rdx.*23248:.*%rcx.*2324d:.*0xae5f4.*"
         r"23252:.*cmpl\s+\$0x0",
         "x86 PackageInfo.signingInfo and status gate"),
        (r"23001:.*%rdx.*23010:.*%rcx.*23015:.*0xb4dad.*"
         r"2301a:.*cmpl\s+\$0x0",
         "x86 hasMultipleSigners and status gate"),
        (r"230e7:.*cmpb\s+\$0x0.*230ef:.*movq.*230f4:.*movq.*"
         r"2310d:.*cmoveq",
         "x86 boolean branch and SigningInfo cleanup transfer"),
        (r"2303f:.*%rdi.*23043:.*%rsi.*23046:.*%rdx.*"
         r"2304b:.*%rcx.*23050:.*0xb46d8",
         "x86 certificate-history terminal output"),
        (r"232ce:.*%rdi.*232d2:.*%rsi.*232d5:.*%rdx.*"
         r"232da:.*%rcx.*232df:.*0xb3ff9",
         "x86 APK-content-signers terminal output"),
    ]:
        require_pattern(x86_function, pattern, description)

    for text, patterns, abi in [
        (arm_function, [
            r"1e4e0:.*ldur\s+x8, \[x29, #-0x28\].*1e4f0:.*str\s+x8",
            r"1e390:.*ldr\s+x8, \[x22\].*1e398:.*ldr\s+x1, \[sp, #0x30\].*1e3a0:.*blr",
            r"1e238:.*ldur\s+x8, \[x29, #-0x20\].*1e240:.*str\s+x8",
            r"1e304:.*ldr\s+x8, \[x22\].*1e30c:.*ldr\s+x1, \[sp, #0x28\].*1e314:.*blr",
            r"1e32c:.*ldur\s+x8, \[x29, #-0x18\].*1e340:.*str\s+x8",
            r"1e518:.*ldr\s+x8, \[x22\].*1e520:.*ldr\s+x1, \[sp, #0x20\].*1e528:.*blr",
            r"1e28c:.*ldur\s+x8, \[x29, #-0x10\].*1e2a0:.*str\s+x8",
            r"1e264:.*ldr\s+x8, \[x22\].*1e26c:.*ldr\s+x1, \[sp, #0x18\].*1e274:.*blr",
        ], "ARM"),
        (x86_function, [
            r"232ec:.*movq\s+0x50.*232f1:.*0x40",
            r"2317d:.*\(%r12\).*23184:.*0x40.*23189:.*\*0xb8",
            r"2305d:.*0x50.*23063:.*0x58.*23068:.*0x38",
            r"23116:.*\(%r12\).*2311d:.*0x38.*23122:.*\*0xb8",
            r"23130:.*0x58.*23136:.*0x60.*2313b:.*0x30",
            r"23320:.*\(%r12\).*23327:.*0x30.*2332c:.*\*0xb8",
            r"230b8:.*0x60.*230be:.*0x68.*230c3:.*0x28",
            r"23097:.*\(%r12\).*2309e:.*0x28.*230a3:.*\*0xb8",
        ], "x86"),
    ]:
        for index, pattern in enumerate(patterns):
            require_pattern(text, pattern, f"{abi} cleanup block {index + 1}")
    print("cross-ABI status branching and SigningInfo->PackageInfo->"
          "PackageManager->packageName cleanup blocks: PASS")

    require_pattern(
        arm_caller,
        r"1e5ac:.*x4.*1e5b0:.*x5.*1e5d8:.*sturb\s+wzr.*"
        r"1e5dc:.*stp\s+xzr, xzr.*1e5e4:.*stur\s+xzr.*"
        r"1e5ec:.*0x1dde0",
        "ARM caller-owned boolean/Signature-array output forwarding",
    )
    require_pattern(
        x86_caller,
        r"233a6:.*%r8.*233ae:.*%r9.*233b6:.*\(%r9\).*"
        r"233e6:.*movb\s+\$0x0.*23403:.*0x22cf9",
        "x86 caller-owned boolean/Signature-array output forwarding",
    )
    print("cross-ABI caller six-argument/output contract: PASS")

    required_tokens = [
        "RecoveredJniCertificateSelectorOperations1dde0",
        "runRecoveredJniCertificateSelector1dde0",
        "recoveredJniCertificateSelector1dde0Regression",
        "if (androidApi < 28)",
        "*outputHasMultipleSigners = 0;",
        "0x40U",
        "0x08000000U",
        "operations.getLegacySignatures(",
        "operations.getSigningInfo(",
        "operations.hasMultipleSigners(",
        "operations.getApkContentsSigners(",
        "operations.getSigningCertificateHistory(",
        "cleanupLocalReference(signingInfo);",
        "cleanupLocalReference(packageInfo);",
        "cleanupLocalReference(packageManager);",
        "cleanupLocalReference(packageName);",
        '"JNI certificate-array selector 0x1dde0 regression failed',
    ]
    for token in required_tokens:
        require(token in source, f"C++ source token {token}")
    require_pattern(
        source,
        r"cleanupLocalReference\(signingInfo\);.*"
        r"cleanupLocalReference\(packageInfo\);.*"
        r"cleanupLocalReference\(packageManager\);.*"
        r"cleanupLocalReference\(packageName\);",
        "C++ cleanup order",
    )

    row = inventory_rows()[0x1DDE0]
    require(row["status"] == "recovered", "0x1dde0 recovered coverage")
    require(row["reachable"] == "yes", "0x1dde0 JNI-reachable classification")
    print("C++ regression and recovered JNI coverage: PASS")


if __name__ == "__main__":
    main()
