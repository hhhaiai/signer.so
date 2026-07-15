#!/usr/bin/env python3
"""Cross-ABI proof for the filtered detector stages at 0x13dc8/0x14078."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ARM64_SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"
X86_64_SO = ROOT / "adjust-android-signature-3.67.0/jni/x86_64/libsigner.so"
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


def find_objdump() -> str:
    candidates = [
        os.environ.get("GNU_OBJDUMP"),
        "/opt/homebrew/opt/binutils/bin/objdump",
        "/opt/homebrew/Cellar/binutils/2.46.0/bin/objdump",
        shutil.which("gobjdump"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise SystemExit("GNU objdump not found; set GNU_OBJDUMP")


def run_objdump(objdump: str, args: list[str], binary: Path) -> str:
    result = subprocess.run(
        [objdump, *args, str(binary)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.lower()


def disassemble(objdump: str, binary: Path, start: int, stop: int) -> str:
    return run_objdump(objdump, [
        "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}"
    ], binary)


def data_bytes(
        objdump: str, binary: Path, address: int, count: int) -> bytes:
    dump = run_objdump(objdump, [
        "-s",
        f"--start-address=0x{address:x}",
        f"--stop-address=0x{address + count:x}",
    ], binary)
    match = re.search(
        rf"^\s*{address:x}\s+((?:[0-9a-f]{{8}}\s*)+)",
        dump,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"missing data at 0x{address:x}")
    hexadecimal = re.sub(r"\s+", "", match.group(1))[:count * 2]
    return bytes.fromhex(hexadecimal)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise AssertionError(f"missing {label}: /{pattern}/")


def require_token_order(text: str, tokens: list[str], label: str) -> None:
    positions = [text.find(token) for token in tokens]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise AssertionError(f"invalid {label} order: {tokens}")


def stage_events(filter_success: bool, match_count: int, correction: int) -> list[str]:
    events = ["filter"]
    if filter_success:
        events.append("count")
        if match_count != 0:
            events.append(f"correction-{correction:02x}")
        events.append("timing-15000")
    else:
        events.append("correction-32")
    events.extend(("final-mask", "free", "return-status-zero"))
    return events


def main() -> None:
    objdump = find_objdump()
    arm_packed = disassemble(objdump, ARM64_SO, 0x13DC8, 0x14078)
    arm_loopback = disassemble(objdump, ARM64_SO, 0x14078, 0x14338)
    x86_packed = disassemble(objdump, X86_64_SO, 0x1668D, 0x168BD)
    x86_loopback = disassemble(objdump, X86_64_SO, 0x168BD, 0x16AF8)

    arm_threshold = struct.unpack(
        "<d", data_bytes(objdump, ARM64_SO, 0x2F48, 8)
    )[0]
    x86_threshold = struct.unpack(
        "<d", data_bytes(objdump, X86_64_SO, 0x4108, 8)
    )[0]
    if arm_threshold != 15000.0 or x86_threshold != 15000.0:
        raise AssertionError((arm_threshold, x86_threshold))

    for pattern, label in (
        (r"bl\s+(?:0x)?34f9c", "ARM64 packed stage filter"),
        (r"bl\s+(?:0x)?34bf4", "ARM64 packed counter"),
        (r"tst\s+w0,\s*#0xffff", "ARM64 packed uint16 gate"),
        (r"mov\s+w1,\s*#0x4.*bl\s+(?:0x)?13548c", "ARM64 correction 0x04"),
        (r"orr\s+x8,\s*x8,\s*#0x1.*str\s+x8,\s*\[x19,\s*#224\]", "ARM64 packed flag bit zero"),
        (r"fmov\s+d0,\s*d8.*bl\s+(?:0x)?d184", "ARM64 packed timing"),
        (r"bl\s+(?:0x)?14380", "ARM64 packed failure correction 0x32"),
        (r"mov\s+x9,\s*#0x10.*movk\s+x9,\s*#0x4,\s*lsl\s*#48.*orr\s+x8,\s*x8,\s*x9", "ARM64 packed final mask"),
        (r"bl\s+(?:0x)?139de0", "ARM64 packed temporary free"),
        (r"cmp\s+w8,\s*#0x0.*cset\s+w0,\s*eq", "ARM64 packed status return"),
    ):
        require(arm_packed, pattern, label)

    for pattern, label in (
        (r"bl\s+(?:0x)?34f9c", "ARM64 loopback stage filter"),
        (r"bl\s+(?:0x)?34954", "ARM64 loopback counter"),
        (r"tst\s+w0,\s*#0xffff", "ARM64 loopback uint16 gate"),
        (r"mov\s+w1,\s*#0xa.*bl\s+(?:0x)?13548c", "ARM64 correction 0x0a"),
        (r"orr\s+x8,\s*x8,\s*#0x1.*str\s+x8,\s*\[x19,\s*#224\]", "ARM64 loopback flag bit zero"),
        (r"fmov\s+d0,\s*d8.*bl\s+(?:0x)?d184", "ARM64 loopback timing"),
        (r"bl\s+(?:0x)?143b4", "ARM64 loopback failure correction 0x32"),
        (r"mov\s+x9,\s*#0x400.*movk\s+x9,\s*#0x4,\s*lsl\s*#48.*orr\s+x8,\s*x8,\s*x9", "ARM64 loopback final mask"),
        (r"bl\s+(?:0x)?139de0", "ARM64 loopback temporary free"),
        (r"cmp\s+w8,\s*#0x0.*cset\s+w0,\s*eq", "ARM64 loopback status return"),
    ):
        require(arm_loopback, pattern, label)

    for pattern, label in (
        (r"callq?\s+(?:0x)?32f48", "x86_64 packed stage filter"),
        (r"callq?\s+(?:0x)?32c82", "x86_64 packed counter"),
        (r"testw?\s+%ax,\s*%ax", "x86_64 packed uint16 gate"),
        (r"pushq?\s+\$0x4.*callq?\s+(?:0x)?12f5ad", "x86_64 correction 0x04"),
        (r"orb\s+\$0x1,\s*0xe0\(%rax\)", "x86_64 packed flag bit zero"),
        (r"callq?\s+(?:0x)?11519", "x86_64 packed timing"),
        (r"callq?\s+(?:0x)?16b2e", "x86_64 packed failure correction 0x32"),
        (r"movabsq?\s+\$0x4000000000010,\s*%rax", "x86_64 packed final mask"),
        (r"callq?\s+(?:0x)?132810 <free@plt>", "x86_64 packed temporary free"),
        (r"cmpl?\s+\$0x0,\s*0x3c\(%rsp\).*sete\s+%al", "x86_64 packed status return"),
    ):
        require(x86_packed, pattern, label)

    for pattern, label in (
        (r"callq?\s+(?:0x)?32f48", "x86_64 loopback stage filter"),
        (r"callq?\s+(?:0x)?32a17", "x86_64 loopback counter"),
        (r"testw?\s+%ax,\s*%ax", "x86_64 loopback uint16 gate"),
        (r"pushq?\s+\$0xa.*callq?\s+(?:0x)?12f5ad", "x86_64 correction 0x0a"),
        (r"orb\s+\$0x1,\s*0xe0\(%rax\)", "x86_64 loopback flag bit zero"),
        (r"callq?\s+(?:0x)?11519", "x86_64 loopback timing"),
        (r"callq?\s+(?:0x)?16b47", "x86_64 loopback failure correction 0x32"),
        (r"movabsq?\s+\$0x4000000000400,\s*%rax", "x86_64 loopback final mask"),
        (r"callq?\s+(?:0x)?132810 <free@plt>", "x86_64 loopback temporary free"),
        (r"cmpl?\s+\$0x0,\s*0x3c\(%rsp\).*sete\s+%al", "x86_64 loopback status return"),
    ):
        require(x86_loopback, pattern, label)

    assert stage_events(True, 0, 0x04) == [
        "filter", "count", "timing-15000",
        "final-mask", "free", "return-status-zero",
    ]
    assert stage_events(True, 1, 0x04) == [
        "filter", "count", "correction-04", "timing-15000",
        "final-mask", "free", "return-status-zero",
    ]
    assert stage_events(False, 0, 0x04) == [
        "filter", "correction-32", "final-mask", "free",
        "return-status-zero",
    ]
    assert stage_events(True, 1, 0x0A)[2] == "correction-0a"

    for symbol in (
        "RecoveredDetectorRecordStageMemoryOperations13dc8",
        "runRecoveredPackedTransitionRecordStage13dc8",
        "runRecoveredLoopbackRecordStage14078",
        "recoveredDetectorRecordStages13dc814078Regression",
    ):
        require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

    packed_start = CPP.index(
        "bool runRecoveredPackedTransitionRecordStage13dc8(\n"
        "        RecoveredDetectorRecord34f9c* const* inputRecords,\n"
        "        std::uint64_t inputCount,\n"
        "        RecoveredArm64NativeContext* context,\n"
        "        const ProtectedRealtimeSyscallSamples& timingSamples,\n"
        "        const RecoveredDetectorRecordStageMemoryOperations13dc8& operations)"
    )
    packed_end = CPP.index("\n}\n", packed_start) + 3
    packed_cpp = CPP[packed_start:packed_end]
    require_token_order(
        packed_cpp,
        [
            "runRecoveredDetectorRecordFilter34f9c(",
            "runRecoveredDetectorRecordPackedTransitionCount34bf4(",
            "applyProtectedCorrectionAndFlagBit0(context, 0x04)",
            "applyProtectedTimingComparison(context, 15000.0, timingSamples)",
            "applyProtectedCorrection32First(context)",
            "applyProtectedContextMask0004000000000010(context)",
            "operations.release(filteredRecords)",
            "return status == 0",
        ],
        "C++ packed stage",
    )

    loopback_start = CPP.index(
        "bool runRecoveredLoopbackRecordStage14078(\n"
        "        RecoveredDetectorRecord34f9c* const* inputRecords,\n"
        "        std::uint64_t inputCount,\n"
        "        RecoveredArm64NativeContext* context,\n"
        "        const ProtectedRealtimeSyscallSamples& timingSamples,\n"
        "        const RecoveredDetectorRecordStageMemoryOperations13dc8& operations)"
    )
    loopback_end = CPP.index("\n}\n", loopback_start) + 3
    loopback_cpp = CPP[loopback_start:loopback_end]
    require_token_order(
        loopback_cpp,
        [
            "runRecoveredDetectorRecordFilter34f9c(",
            "runRecoveredDetectorRecordCrossMatchCount34954(",
            "applyProtectedCorrectionAndFlagBit0(context, 0x0a)",
            "applyProtectedTimingComparison(context, 15000.0, timingSamples)",
            "applyProtectedCorrection32Second(context)",
            "applyProtectedContextMask0004000000000400(context)",
            "operations.release(filteredRecords)",
            "return status == 0",
        ],
        "C++ loopback stage",
    )

    require(
        GENERATOR,
        r"0x013DC8:.*packed-transition filtered record stage.*recovered",
        "0x13dc8 coverage entry",
    )
    require(
        GENERATOR,
        r"0x014078:.*fixed-loopback filtered record stage.*recovered",
        "0x14078 coverage entry",
    )

    print("ARM64 0x13dc8 / x86_64 0x1668d packed stage: PASS")
    print("ARM64 0x14078 / x86_64 0x168bd loopback stage: PASS")
    print("shared 15000ms threshold and success/failure ordering: PASS")
    print("corrections 04/0a/32 and final masks: PASS")


if __name__ == "__main__":
    main()
