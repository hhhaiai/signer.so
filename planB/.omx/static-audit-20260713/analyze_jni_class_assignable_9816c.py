#!/usr/bin/env python3
from __future__ import annotations

import csv
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
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
    source = SOURCE.read_text()

    arm_function = body(arm_text, 0x9816C, 0x9885C)
    x86_function = body(x86_text, 0x9A484, 0x9A9A6)
    arm_caller = body(arm_text, 0x91D2C, 0x9279C)
    x86_caller = body(x86_text, 0x9604F, 0x9685C)

    require("pc=0009816c...0009885c" in arm_frames, "ARM64 FDE")
    require("pc=0009a484...0009a9a6" in x86_frames, "x86_64 FDE")

    for pattern, description in [
        (r"9818c:.*cmp\s+x3, #0x0.*9819c:.*ccmp\s+x2, #0x0",
         "ARM object/class-name null gate"),
        (r"98454:.*\[x8, #0xf8\].*98458:.*blr",
         "ARM GetObjectClass"),
        (r"98464:.*0x92a20", "ARM object-class exception consumer"),
        (r"98690:.*\[x8, #0x30\].*98694:.*blr", "ARM FindClass"),
        (r"986a0:.*0x92a20", "ARM target-class exception consumer"),
        (r"987ac:.*\[x8, #0x58\].*987b0:.*blr",
         "ARM IsAssignableFrom"),
        (r"987b4:.*tst\s+w0, #0xff.*987bc:.*cset.*987c4:.*strb",
         "ARM normalized jboolean publication"),
        (r"987c8:.*0x92a20", "ARM assignability exception consumer"),
        (r"98548:.*\[x8, #0xb8\].*9854c:.*blr",
         "ARM object-class DeleteLocalRef"),
        (r"985e4:.*\[x8, #0xb8\].*985e8:.*blr",
         "ARM target-class DeleteLocalRef"),
        (r"98748:.*#0x3\b.*9875c:.*str\s+w12",
         "ARM null-input status 3"),
        (r"98510:.*#0x12\b.*98664:.*#0x12\b",
         "ARM acquisition status 18"),
        (r"98440:.*#0x1c\b", "ARM assignability-exception status 28"),
        (r"98768:.*9877c:.*strb\s+wzr", "ARM failure output clear"),
        (r"98784:.*ldr\s+w8.*9878c:.*cmp\s+w8, #0x0",
         "ARM final incoming-status gate"),
    ]:
        require_pattern(arm_function, pattern, description)

    for pattern, description in [
        (r"9a4ce:.*testq\s+%rcx.*9a4fb:.*testq\s+%rdx",
         "x86 object/class-name null gate"),
        (r"9a692:.*\*0xf8", "x86 GetObjectClass"),
        (r"9a6a7:.*0x96a44", "x86 object-class exception consumer"),
        (r"9a845:.*\*0x30", "x86 FindClass"),
        (r"9a84e:.*0x96a44", "x86 target-class exception consumer"),
        (r"9a924:.*\*0x58", "x86 IsAssignableFrom"),
        (r"9a927:.*testb.*9a92e:.*setne", "x86 normalized jboolean publication"),
        (r"9a934:.*0x96a44", "x86 assignability exception consumer"),
        (r"9a746:.*\*0xb8", "x86 object-class DeleteLocalRef"),
        (r"9a7d5:.*\*0xb8", "x86 target-class DeleteLocalRef"),
        (r"9a8c2:.*\$0x3", "x86 null-input status 3"),
        (r"9a71c:.*\$0x12.*9a822:.*\$0x12",
         "x86 acquisition status 18"),
        (r"9a67a:.*\$0x1c", "x86 assignability-exception status 28"),
        (r"9a8d3:.*9a8d8:.*\$0x0", "x86 failure output clear"),
        (r"9a8e6:.*9a8eb:.*cmpl\s+\$0x0",
         "x86 final incoming-status gate"),
    ]:
        require_pattern(x86_function, pattern, description)

    require_pattern(arm_caller, r"9255c:.*0x9816c", "ARM caller edge")
    require_pattern(x86_caller, r"9664f:.*0x9a484", "x86 caller edge")
    print("cross-ABI JNI class-assignability flow: PASS")

    for required in [
        "RecoveredJniClassAssignableOperations9816c",
        "runRecoveredJniClassAssignable9816c",
        "recoveredJniClassAssignable9816cRegression",
        "operations.getObjectClass(jniEnvironment, object)",
        "operations.findClass(jniEnvironment, className)",
        "operations.isAssignableFrom(",
        "operations.deleteLocalRef(jniEnvironment, objectClass);",
        "operations.deleteLocalRef(jniEnvironment, targetClass);",
        "if (*status != 0) *output = 0;",
        '"JNI class-assignability helper 0x9816c regression failed',
    ]:
        require(required in source, f"C++ source token {required}")
    require_pattern(
        source,
        r"deleteLocalRef\(jniEnvironment, objectClass\);.*"
        r"deleteLocalRef\(jniEnvironment, targetClass\);",
        "C++ object-class then target-class cleanup order",
    )

    rows = inventory_rows()
    row = rows[0x9816C]
    require(row["status"] == "recovered", "0x9816c recovered coverage")
    require(row["reachable"] == "no", "0x9816c non-JNI classification")
    print("C++ regression, ownership order and recovered coverage: PASS")


if __name__ == "__main__":
    main()
