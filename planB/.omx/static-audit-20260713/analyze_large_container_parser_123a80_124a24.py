#!/usr/bin/env python3
"""Interpret the flattened 0x68 large-container parser layer."""

from __future__ import annotations

import importlib.util
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()
GENERATOR = (HERE / "generate_arm64_function_inventory.py").read_text()

spec = importlib.util.spec_from_file_location(
    "container_vm", HERE / "analyze_container_parser_cluster_12243c_123288.py"
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LargeVm(module.ClusterVm):
    def call(self, target: int) -> None:
        arguments = tuple(self.reg(f"x{index}") for index in range(5))
        self.call_log.append((target, arguments))
        if target == 0x1238EC:
            self.set("x0", 0x300000)
            return
        if target == 0x11F89C:
            destination = self.reg("x1")
            size = self.reg("x2")
            count = self.reg("w3")
            value = self.values.pop(0) if self.values else 0
            self.store(destination, value, min(size * count, 8))
            self.set("w0", 1)
            return
        if target in {0x123288, 0x12183C, 0x122090, 0x123A80, 0x124774}:
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
    inner_values: tuple[int, int] = (0, 0),
) -> tuple[list[tuple[int, tuple[int, ...]]], int]:
    vm = LargeVm(start, total_size, values)
    vm.pc = start
    vm.store(0x300020, inner_values[0], 4)
    vm.store(0x300024, inner_values[1], 4)
    vm.run()
    return vm.call_log, vm.load(0x100000, 4)


calls, status = run_case(0x123A80, 32, [4, 7, 9, 4, 4], (7, 9))
assert status == 0
assert [target for target, _ in calls] == [
    0x1238EC,
    0x11F89C,
    0x123288,
    0x11F89C,
    0x11F89C,
    0x11F89C,
    0x12183C,
    0x11F89C,
    0x122090,
]
assert calls[2][1][1:4] == (0x300000, 4, 0x120000)
assert calls[3][1][1] == 0x300038
assert calls[4][1][1] == 0x30003C
assert calls[6][1][1:4] == (0x300040, 4, 0x120000)
assert calls[8][1][1:4] == (0x300050, 4, 0x120000)

calls, status = run_case(0x123A80, 32, [4, 7, 10], (7, 9))
assert status == 9
assert [target for target, _ in calls][-1] == 0x11F89C

calls, status = run_case(0x124774, 12, [4, 0])
assert status == 0
assert [target for target, _ in calls] == [
    0x11F89C, 0x123A80, 0x11F89C, 0x123A80
]

calls, status = run_case(0x124774, 9, [4, 0])
assert status == 8
assert [target for target, _ in calls].count(0x123A80) == 2

calls, status = run_case(0x124A24, 8, [4])
assert status == 0
assert [target for target, _ in calls] == [0x11F89C, 0x124774]

calls, status = run_case(0x124A24, 12, [4])
assert status == 8
assert [target for target, _ in calls] == [0x11F89C, 0x124774]

for symbol in (
    "runRecoveredLargeContainerParser123a80",
    "runRecoveredLargeContainerSequence124774",
    "runRecoveredLargeContainerSequenceWrapper124a24",
    "recoveredLargeContainerParserCluster123a80124a24Regression",
):
    assert re.search(rf"\b{symbol}\b", CPP), symbol

for address in ("0x123A80", "0x124774", "0x124A24"):
    assert re.search(rf"{address}:.*recovered", GENERATOR), address

print("LARGE_CONTAINER_PARSER_123A80_124A24_STATIC_VM_OK")
