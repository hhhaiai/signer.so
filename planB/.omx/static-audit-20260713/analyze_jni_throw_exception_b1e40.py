#!/usr/bin/env python3
"""Cross-ABI static proof for the JNI ThrowNew helper at ARM64 0xb1e40."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / ".omx/static-audit-20260713"
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
ARMV7_SO = ROOT / "adjust-android-signature-3.67.0/jni/armeabi-v7a/libsigner.so"
X86_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86/libsigner.so"
ARM64_DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace").lower()
X86_64_DISASM = (AUDIT / "x86_64-full-objdump.txt").read_text(
    errors="replace").lower()
X86_64_EH = (AUDIT / "x86_64-eh-frame.txt").read_text(
    errors="replace").lower()
ARM = ARM64_DISASM[
    ARM64_DISASM.index("  b1e40:"):ARM64_DISASM.index("  b21b4:")
]
X64 = X86_64_DISASM[
    X86_64_DISASM.index("   aa064:"):X86_64_DISASM.index("   aa362:")
]
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace").lower()
CPP_WINDOW = CPP[
    CPP.index("krecoveredjnithrowexceptionclassencodedb1e40"):
    CPP.index("struct recoveredjniintfieldoperationsb21b4")
]
COVERAGE = (ROOT / "native-reimplementation/SO_FUNCTION_COVERAGE.md").read_text(
    errors="replace").lower()


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: {pattern}")


def main() -> None:
    plain = b"java/lang/Exception\0"
    arm_cipher = ARM64_SO.read_bytes()[0x13D0F0:0x13D0F0 + len(plain)]
    x64_cipher = X86_64_SO.read_bytes()[0x135B90:0x135B90 + len(plain)]
    armv7_cipher = ARMV7_SO.read_bytes()[0x112370:0x112370 + len(plain)]
    x86_cipher = X86_SO.read_bytes()[0x130100:0x130100 + len(plain)]
    if bytes(value ^ 0x50 for value in arm_cipher) != plain:
        raise AssertionError("ARM64 class ciphertext/key mismatch")
    if bytes(value ^ 0xF6 for value in x64_cipher) != plain:
        raise AssertionError("x86_64 class ciphertext/key mismatch")
    if bytes(value ^ 0x52 for value in armv7_cipher) != plain:
        raise AssertionError("ARMv7 class ciphertext/key mismatch")
    if bytes(value ^ 0x95 for value in x86_cipher) != plain:
        raise AssertionError("x86 class ciphertext/key mismatch")
    print("four-ABI XOR-once java/lang/Exception plaintext: PASS")

    require(ARM,
            r"b1ee8:.*adr\s+x22,\s*0x1450f0.*"
            r"b203c:.*ldrb\s+w8,\s*\[x22,\s*#0x10\].*"
            r"b204c:.*eor\s+w8,\s*w8,\s*w12.*"
            r"b2068:.*movi\s+v1\.16b,\s*#0x50.*"
            r"b2088:.*eor\s+v0\.16b,\s*v0\.16b,\s*v1\.16b.*"
            r"b2098:.*strb\s+w10,\s*\[x8,\s*#0x96d\]",
            "ARM64 20-byte XOR decode and initialized publication")
    require(ARM,
            r"b20b0:.*stlrb\s+wzr,\s*\[x8\].*"
            r"b2164:.*mov\s+w0,\s*wzr.*"
            r"b2168:.*mov\s+w1,\s*#0x1.*"
            r"b2170:.*adr\s+x2,\s*0x14696c.*"
            r"b2174:.*bl\s+0x139800",
            "ARM64 acquire CAS and release unlock")
    require(ARM,
            r"b20a8:.*mov\s+x0,\s*x20.*"
            r"b20ac:.*mov\s+x1,\s*x22.*"
            r"b20b8:.*ldr\s+x8,\s*\[x8,\s*#0x30\].*"
            r"b20c8:.*bl\s+0x92a20",
            "ARM64 FindClass and exception consumer")
    require(ARM,
            r"b20f8:.*ldur\s+w8,\s*\[x29,\s*#-0x4\].*"
            r"b210c:.*str\s+w10,\s*\[x8\]",
            "ARM64 status 18 publication")
    require(ARM,
            r"b2114:.*ldr\s+x8,\s*\[x20\].*"
            r"b2120:.*ldr\s+x2,\s*\[sp,\s*#0x10\].*"
            r"b2124:.*ldr\s+x8,\s*\[x8,\s*#0x70\].*"
            r"b2128:.*blr\s+x8",
            "ARM64 ThrowNew(message)")
    require(ARM,
            r"b2014:.*ldr\s+x8,\s*\[x20\].*"
            r"b201c:.*mov\s+x1,\s*x24.*"
            r"b2020:.*ldr\s+x8,\s*\[x8,\s*#0xb8\].*"
            r"b2024:.*blr\s+x8",
            "ARM64 DeleteLocalRef")
    print("ARM64 once init, FindClass, status, ThrowNew and cleanup: PASS")

    require(X86_64_EH, r"pc=000aa064\.\.\.000aa362",
            "x86_64 equivalent FDE")
    require(X64,
            r"aa1d4:.*movaps.*# 0x13db90.*"
            r"aa1db:.*xorps.*"
            r"aa1ff:.*movb\s+\$0x1.*# 0x13f01f.*"
            r"aa331:.*xorl\s+%eax,\s*%eax.*"
            r"aa336:.*cmpxchgb.*# 0x13f01e",
            "x86_64 XOR-once state")
    require(X64,
            r"aa18a:.*callq\s+\*0xb8\(%rax\).*"
            r"aa21b:.*leaq.*# 0x13db90.*"
            r"aa222:.*callq\s+\*0x30\(%rax\).*"
            r"aa231:.*callq\s+0x96a44.*"
            r"aa2a6:.*movl\s+\$0x12,\s*\(%rax\).*"
            r"aa2cd:.*callq\s+\*0x70\(%rax\)",
            "x86_64 JNI flow and status parity")
    print("x86_64 FDE and JNI behavior parity: PASS")

    for symbol in (
            "recoveredjnithrowexceptionclassstateb1e40",
            "acquirerecoveredjnithrowexceptionclassb1e40",
            "recoveredjnithrowexceptionoperationsb1e40",
            "runrecoveredjnithrowexceptionb1e40withstate",
            "runrecoveredjnithrowexceptionb1e40",
            "recoveredjnithrowexceptionb1e40regression"):
        require(CPP_WINDOW, rf"\b{symbol}\b", f"C++ symbol {symbol}")
    require(CPP_WINDOW,
            r"operations\.findclass.*operations\.consumeexception.*"
            r"if \(exceptionclass == 0 \|\| classexception\).*"
            r"\*status = 18.*operations\.thrownew.*"
            r"if \(exceptionclass != 0\).*operations\.deletelocalref",
            "C++ status/throw/cleanup flow")
    require(CPP,
            r"if \(!recoveredjnithrowexceptionb1e40regression\(\)\)",
            "top-level regression guard")
    require(COVERAGE,
            r"`0xb1e40\.\.0xb21b4`.*jni java/lang/exception thrownew helper.*"
            r"\*\*recovered\*\*",
            "recovered coverage row")
    print("C++ implementation, regression and coverage: PASS")


if __name__ == "__main__":
    main()
