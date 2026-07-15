#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
ARM = (AUDIT / "disasm-f328-fce0.txt").read_text(errors="replace")
X64 = (AUDIT / "disasm-x86_64-130fb-13920.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace"
)


def ordered(text: str, needles: tuple[str, ...]) -> None:
    cursor = 0
    for needle in needles:
        cursor = text.index(needle, cursor) + len(needle)


for needle in (
    "f3a8: 9404aa9a     \tbl\t0x139e10 <memset@plt>",
    "f3bc: 9401e02c     \tbl\t0x8746c",
    "faa8: 94003d6c     \tbl\t0x1f058",
    "fb8c: 94003fd6     \tbl\t0x1fae4",
    "faf0: 9400555e     \tbl\t0x25068",
    "f8a8: 94005d4e     \tbl\t0x26de0",
    "f850: 94007372     \tbl\t0x2c618",
    "fb24: 9400745e     \tbl\t0x2cc9c",
    "fa18: 94004887     \tbl\t0x21c34",
    "f810: 94000134     \tbl\t0xfce0",
    "fb58: 94000bb6     \tbl\t0x12a30",
    "fc90: 94000cdc     \tbl\t0x13000",
    "fc98: 9401ffab     \tbl\t0x8fb44",
):
    assert needle in ARM, needle

for address, immediate in (
    ("fc0c", "#0x1"),
    ("fc64", "#0x2"),
    ("f8e0", "#0x3"),
    ("f90c", "#0x8"),
    ("f984", "#0x28"),
    ("f9dc", "#0x2c"),
    ("fa7c", "#0x1f"),
):
    assert f"{address}:" in ARM and immediate in ARM[ARM.index(f"{address}:"):][:120]

ordered(
    X64,
    (
        "13176:",  # memset
        "1318a:",  # initial local-object producer
        "138de:",  # unconditional fallback-mask stage at exit
        "138eb:",  # unconditional local-object destructor
        "13903:",  # result load
    ),
)

for needle in (
    "runRecoveredEnvironmentStageDispatcherF328(",
    "operations.stage1f058(&probeStatus);",
    "probeStatus > 2",
    "probeStatus > 5",
    "operations.stage2c618(jniEnvironment)",
    "operations.stage2cc9c(jniEnvironment)",
    "operations.stageFce0(status, scratch.data(), context)",
    "operations.stage12a30(scratch.data(), context);",
    "applyProtectedContextFallbackMaskStage(context);",
    "operations.stage8fb44(scratch.data());",
    "recoveredEnvironmentF328Regression()",
):
    assert needle in CPP, needle

assert "stageF328" not in CPP
print("arm64/x86_64 environment stage 0xf328 direct-orchestration evidence: PASS")
