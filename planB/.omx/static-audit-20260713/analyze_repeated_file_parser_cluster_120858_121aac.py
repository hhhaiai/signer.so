#!/usr/bin/env python3
"""Prove the repeated file-list parser cluster from 0x120858 through 0x121aac."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()


def body(start: int, end: int) -> str:
    lines: list[str] = []
    for line in DISASM.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match is not None and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, label: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


ranges = {
    "seq_raw": body(0x120858, 0x120AFC),
    "destroy_b": body(0x120AFC, 0x120C68),
    "append_b": body(0x120C68, 0x120DE8),
    "tagged": body(0x120DE8, 0x120FFC),
    "seq_tagged": body(0x120FFC, 0x121260),
    "destroy_c": body(0x121260, 0x1213CC),
    "append_c": body(0x1213CC, 0x12154C),
    "framed": body(0x12154C, 0x12183C),
    "seq_framed": body(0x12183C, 0x121AAC),
    "aggregate": body(0x121AAC, 0x121ADC),
}

for text, pattern, label in (
    (ranges["seq_raw"], r"120a00:.*bl\s+0x11f89c", "raw size read"),
    (ranges["seq_raw"], r"120a40:.*bl\s+0x1206d0", "raw nested reader"),
    (ranges["seq_raw"], r"120a7c:.*add\s+w26, w8, #0x4", "raw offset advance"),
    (ranges["seq_raw"], r"120a88:.*mov\s+w8, #0x8", "raw overshoot status"),
    (ranges["destroy_b"], r"120c34:.*ldr\s+x9, \[x20, #0x10\]", "B next +0x10"),
    (ranges["destroy_b"], r"120c10:.*ldr\s+x0, \[x20, #0x8\]", "B payload +0x08"),
    (ranges["destroy_b"], r"120c14:.*bl\s+0x139de0", "B payload free"),
    (ranges["destroy_b"], r"120c1c:.*bl\s+0x139de0", "B node free"),
    (ranges["append_b"], r"120c90:.*mov\s+w1, #0x18", "B node size"),
    (ranges["append_b"], r"120cb0:.*bl\s+0x139e50", "B calloc"),
    (ranges["append_b"], r"120d08:.*add\s+x10, x0, #0x10", "B next address"),
    (ranges["tagged"], r"120e14:.*bl\s+0x120c68", "tagged append"),
    (ranges["tagged"], r"120e84:.*sub\s+w22, w22, #0x4", "tagged size-4"),
    (ranges["tagged"], r"120f84:.*bl\s+0x11f89c", "tag read"),
    (ranges["tagged"], r"120f44:.*str\s+w22, \[x21, #0x4\]", "payload length +4"),
    (ranges["tagged"], r"120f48:.*bl\s+0x139e50", "tagged payload calloc"),
    (ranges["tagged"], r"120f60:.*str\s+x0, \[x21, #0x8\]", "tagged payload +8"),
    (ranges["tagged"], r"120fa8:.*bl\s+0x11f89c", "tagged payload read"),
    (ranges["seq_tagged"], r"121190:.*bl\s+0x120de8", "tagged sequence nested reader"),
    (ranges["seq_tagged"], r"1211cc:.*add\s+w20, w8, #0x4", "tagged sequence advance"),
    (ranges["seq_tagged"], r"1211d4:.*mov\s+w8, #0x8", "tagged overshoot status"),
    (ranges["destroy_c"], r"12135c:.*ldr\s+x9, \[x20, #0x10\]", "C next +0x10"),
    (ranges["destroy_c"], r"121388:.*ldr\s+x0, \[x20, #0x8\]", "C payload +0x08"),
    (ranges["append_c"], r"1213f4:.*mov\s+w1, #0x18", "C node size"),
    (ranges["append_c"], r"121414:.*bl\s+0x139e50", "C calloc"),
    (ranges["append_c"], r"12146c:.*add\s+x10, x0, #0x10", "C next address"),
    (ranges["framed"], r"121578:.*bl\s+0x1213cc", "framed append"),
    (ranges["framed"], r"121708:.*bl\s+0x11f89c", "framed first header"),
    (ranges["framed"], r"121758:.*bl\s+0x11f89c", "framed second header"),
    (ranges["framed"], r"12179c:.*add\s+x8, x23, #0x8", "framed length+8"),
    (ranges["framed"], r"121788:.*mov\s+w8, #0x8", "framed mismatch status"),
    (ranges["framed"], r"1217c4:.*bl\s+0x139e50", "framed payload calloc"),
    (ranges["framed"], r"121804:.*bl\s+0x11f89c", "framed payload read"),
    (ranges["seq_framed"], r"1219cc:.*bl\s+0x12154c", "framed sequence nested reader"),
    (ranges["seq_framed"], r"121a58:.*add\s+w8, w8, #0x4", "framed sequence advance"),
    (ranges["seq_framed"], r"1219f0:.*mov\s+w8, #0x8", "framed overshoot status"),
    (ranges["aggregate"], r"121abc:.*add\s+x0, x0, #0x20", "third owner offset"),
    (ranges["aggregate"], r"121ac0:.*bl\s+0x120afc", "third destructor"),
    (ranges["aggregate"], r"121ac4:.*add\s+x0, x19, #0x10", "second owner offset"),
    (ranges["aggregate"], r"121ac8:.*bl\s+0x1203e4", "second destructor"),
    (ranges["aggregate"], r"121ad8:.*b\s+0x11fb60", "first destructor tail call"),
):
    require(text, pattern, label)

for symbol in (
    "runRecoveredFileListSizedPayloadSequence120858",
    "runRecoveredFileListDestroy120afc",
    "runRecoveredFileListAppend120c68",
    "runRecoveredFileListTaggedPayloadRead120de8",
    "runRecoveredFileListTaggedPayloadSequence120ffc",
    "runRecoveredFileListDestroy121260",
    "runRecoveredFileListAppend1213cc",
    "runRecoveredFileListRecordRead12154c",
    "runRecoveredFileListRecordSequence12183c",
    "runRecoveredThreeFileListDestroy121aac",
    "recoveredFileListRepeatedParserCluster120858121aacRegression",
):
    require(CPP, rf"\b{symbol}\b", f"C++ {symbol}")

for address in (
    "0x120858", "0x120AFC", "0x120C68", "0x120DE8", "0x120FFC",
    "0x121260", "0x1213CC", "0x12154C", "0x12183C", "0x121AAC",
):
    require(GENERATOR, rf"{address}:.*recovered", f"{address} coverage entry")

print("REPEATED_FILE_PARSER_CLUSTER_120858_121AAC_STATIC_OK")
