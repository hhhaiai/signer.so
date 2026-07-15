#!/usr/bin/env python3
"""Interpret the flattened container parser cluster and verify owned C++."""

from __future__ import annotations

import importlib.util
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DISASM = (ROOT / ".omx/libsigner-arm64-objdump.txt").read_text(
    errors="replace"
)
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()

spec = importlib.util.spec_from_file_location(
    "arm64_vm_base", HERE / "analyze_environment_dispatcher_143e8.py"
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

instructions: dict[int, tuple[str, str]] = {}
for line in DISASM.splitlines():
    match = re.match(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)\s*"
        r"(.*?)(?:\s+//.*)?$",
        line,
    )
    if match is not None:
        instructions[int(match.group(1), 16)] = (
            match.group(2),
            match.group(3).strip(),
        )
module.ins = instructions


class ClusterVm(module.VM):
    def __init__(
        self,
        start: int,
        total_size: int,
        values: list[int],
        statuses: dict[int, int] | None = None,
    ) -> None:
        super().__init__()
        self.pc = start
        self.r[0] = 0x100000
        self.r[1] = 0x110000
        self.r[2] = total_size
        self.r[3] = 0x120000
        self.store(0x100000, 0, 4)
        self.values = list(values)
        self.statuses = statuses or {}
        self.call_log: list[tuple[int, tuple[int, ...]]] = []
        self.node = 0x200000

    def call(self, target: int) -> None:
        arguments = tuple(self.reg(f"x{index}") for index in range(5))
        self.call_log.append((target, arguments))
        if target == 0x1222A8:
            self.set("x0", self.node)
            return
        if target == 0x11F89C:
            destination = self.reg("x1")
            size = self.reg("x2")
            count = self.reg("w3")
            value = self.values.pop(0) if self.values else 0
            self.store(destination, value, min(size * count, 8))
            self.set("w0", 1)
            return
        if target in {
            0x121ADC,
            0x12183C,
            0x122090,
            0x12243C,
            0x122D24,
            0x12014C,
            0x120858,
            0x120FFC,
        }:
            status = self.statuses.get(target, 0)
            if status != 0:
                self.store(self.reg("x0"), status, 4)
            self.set("w0", 0)
            return
        if target == 0x139DF0:
            raise AssertionError("unexpected stack-check failure")
        raise AssertionError(f"unexpected call target {target:#x}")


def run_case(
    start: int,
    total_size: int,
    values: list[int],
    statuses: dict[int, int] | None = None,
) -> tuple[list[tuple[int, tuple[int, ...]]], int]:
    vm = ClusterVm(start, total_size, values, statuses)
    vm.run()
    return vm.call_log, vm.load(0x100000, 4)


calls, status = run_case(0x12243C, 24, [4, 4, 4])
assert status == 0
assert [target for target, _ in calls] == [
    0x1222A8,
    0x11F89C,
    0x121ADC,
    0x11F89C,
    0x12183C,
    0x11F89C,
    0x122090,
]
assert calls[2][1][1:4] == (0x200000, 4, 0x120000)
assert calls[4][1][1:4] == (0x200030, 4, 0x120000)
assert calls[6][1][1:4] == (0x200040, 4, 0x120000)

calls, status = run_case(0x12243C, 7, [4])
assert status == 8
assert [target for target, _ in calls] == [0x1222A8, 0x11F89C]

calls, status = run_case(0x12243C, 24, [4, 4, 4], {0x12183C: 6})
assert status == 6
assert [target for target, _ in calls][-1] == 0x12183C

calls, status = run_case(0x122D24, 12, [4, 0])
assert status == 0
assert [target for target, _ in calls] == [
    0x11F89C,
    0x12243C,
    0x11F89C,
    0x12243C,
]

calls, status = run_case(0x122D24, 9, [4, 0])
assert status == 8
assert [target for target, _ in calls].count(0x12243C) == 2

calls, status = run_case(0x122FE8, 8, [4])
assert status == 0
assert [target for target, _ in calls] == [0x11F89C, 0x122D24]

calls, status = run_case(0x122FE8, 7, [4])
assert status == 8
assert [target for target, _ in calls] == [0x11F89C]

calls, status = run_case(0x123288, 28, [4, 4, 0x11223344, 0x55667788, 0])
assert status == 0
assert [target for target, _ in calls] == [
    0x11F89C,
    0x12014C,
    0x11F89C,
    0x120858,
    0x11F89C,
    0x11F89C,
    0x11F89C,
    0x120FFC,
]
assert calls[1][1][1:4] == (0x110000, 4, 0x120000)
assert calls[3][1][1:4] == (0x110010, 4, 0x120000)
assert calls[4][1][1] == 0x110020
assert calls[5][1][1] == 0x110024
assert calls[7][1][1:4] == (0x110028, 0, 0x120000)

for symbol in (
    "runRecoveredContainerNodeParser12243c",
    "runRecoveredContainerNodeSequence122d24",
    "runRecoveredContainerNodeSequenceWrapper122fe8",
    "runRecoveredThreeListTwoFieldParser123288",
    "recoveredContainerParserCluster12243c123288Regression",
):
    assert re.search(rf"\b{symbol}\b", CPP), symbol

for address in ("0x12243C", "0x122D24", "0x122FE8", "0x123288"):
    assert re.search(rf"{address}:.*recovered", GENERATOR), address

print("CONTAINER_PARSER_CLUSTER_12243C_123288_STATIC_VM_OK")
