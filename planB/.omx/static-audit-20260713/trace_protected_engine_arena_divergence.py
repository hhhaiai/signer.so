#!/usr/bin/env python3
"""Trace the text-only protected-engine VM at the device-observed arena sites.

The target ELF is not loaded or executed.  This imports the checked-in
instruction interpreter and records the same helper-call arguments observed by
device-reference/frida/protected-engine-trace.js.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / ".omx/static-audit-20260713/analyze_protected_engine_full.py"
REPORT = ROOT / ".omx/static-audit-20260713/arm64-arena-divergence-static.jsonl"
STOP_PC = 0x106D00


def load_analyzer():
    spec = importlib.util.spec_from_file_location("protected_engine_static", ANALYZER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


engine = load_analyzer()


class ArenaTraceVm(engine.ProtectedEngineVm):
    READER_SITES = {
        0xF5D1C: "f5d1c-source-read",
        0xF58B0: "f58b0-lane-copy-read",
    }
    WRITER_SITES = {
        0xF237C: "f237c-target-writer",
        0xF5114: "f5114-writer",
        0xF5D30: "f5d30-writer",
        0xF58C4: "f58c4-writer",
    }

    def __init__(self, rand_values):
        super().__init__(rand_values)
        self.events: List[Dict[str, Any]] = []

    def arena_label(self, address: int) -> str:
        if address == self.memory.read(self.work_address + 0x08, 8):
            return "shared"
        for index in range(16):
            if address == self.memory.read(self.work_address + 0x20 + index * 8, 8):
                return f"lane{index}"
        return f"arena@{address:#x}"

    @staticmethod
    def arena_state(arena) -> Dict[str, Any]:
        base = arena.frame_bases[-1]
        return {
            "capacity": arena.capacity,
            "length": arena.length,
            "depth": len(arena.frame_bases),
            "base": base,
            "frameLength": engine.u32(arena.length - base),
        }

    def work_state(self) -> Dict[str, Any]:
        evaluation = self.stacks[self.memory.read(self.work_address + 0x00, 8)]
        counters = self.counters[self.memory.read(self.work_address + 0x10, 8)]
        auxiliary = self.stacks[self.memory.read(self.work_address + 0x18, 8)]
        return {
            "evaluationTop": [f"0x{value:08x}" for value in reversed(evaluation.values[-24:])],
            "counterHead": [f"0x{value:08x}" for value in counters.values[:24]],
            "auxiliaryTop": [f"0x{value:08x}" for value in reversed(auxiliary.values[-24:])],
        }

    def helper_call(self, target: int) -> None:
        if target == self.HELPER_ARENA_READ and self.pc in self.READER_SITES:
            address = self.read_reg("x0")
            offset = self.read_reg("w1")
            arena = self.arenas[address]
            absolute = engine.u32(arena.frame_bases[-1] + offset)
            value = arena.read(offset)
            event = {
                "executed": self.executed,
                "pc": f"0x{self.pc:08x}",
                "site": self.READER_SITES[self.pc],
                "kind": "read",
                "arena": self.arena_label(address),
                "arenaState": self.arena_state(arena),
                "relativeOffset": f"0x{offset:08x}",
                "absoluteOffset": f"0x{absolute:08x}",
                "value": f"0x{value:08x}",
                "work": self.work_state(),
            }
            self.events.append(event)

        if target == self.HELPER_ARENA_WRITE:
            address = self.read_reg("x1")
            offset = self.read_reg("w2")
            value = self.read_reg("w3")
            arena = self.arenas[address]
            arena_label = self.arena_label(address)
            absolute = engine.u32(arena.frame_bases[-1] + offset)
            if self.pc in self.WRITER_SITES or 0x40 <= absolute <= 0x43 or arena_label == "lane2":
                self.events.append({
                    "executed": self.executed,
                    "pc": f"0x{self.pc:08x}",
                    "site": self.WRITER_SITES.get(self.pc, "other-target-writer"),
                    "kind": "write",
                    "arena": arena_label,
                    "arenaState": self.arena_state(arena),
                    "relativeOffset": f"0x{offset:08x}",
                    "absoluteOffset": f"0x{absolute:08x}",
                    "value": f"0x{value:08x}",
                    "existingValue": f"0x{arena.read(offset):08x}",
                    "work": self.work_state(),
                })

        super().helper_call(target)

    def run_to_stop(self, max_instructions: int = 20_000_000) -> None:
        while not self.returned and self.pc != STOP_PC:
            assert self.executed < max_instructions, (self.pc, self.executed)
            self.execute_one()
        assert self.pc == STOP_PC, (self.pc, self.executed, self.returned)


def main() -> None:
    descriptors, _expected, rand_values = engine.pixel_descriptors()
    vm = ArenaTraceVm(rand_values)
    vm.setup(descriptors)
    vm.run_to_stop()
    REPORT.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in vm.events))
    print(REPORT)
    print(f"events={len(vm.events)} executed={vm.executed} pc={vm.pc:#x}")
    for event in vm.events:
        if event["site"] in ("f5d1c-source-read", "f5d30-writer", "f5114-writer", "f58b0-lane-copy-read"):
            print(json.dumps(event, sort_keys=True))


if __name__ == "__main__":
    main()
