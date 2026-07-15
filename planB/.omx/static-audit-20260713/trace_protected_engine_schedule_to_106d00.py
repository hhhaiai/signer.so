#!/usr/bin/env python3
"""Trace the static protected-engine schedule up to ARM64 PC 0x106d00.

This script imports the text-only interpreter in analyze_protected_engine_full.py.
It never loads or executes libsigner.so.  The report records the recent PC path,
evaluation/auxiliary stack events, counter-chain events, and the origin of every
live stack/counter word when the fixed-frame builder is selected.
"""

from __future__ import annotations

import importlib.util
import sys
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, NamedTuple, Optional


ROOT = Path(__file__).resolve().parents[2]
ANALYZER = ROOT / ".omx/static-audit-20260713/analyze_protected_engine_full.py"
REPORT = ROOT / ".omx/static-audit-20260713/arm64-schedule-to-106d00.md"
TARGET_PC = 0x106D00


def load_analyzer():
    spec = importlib.util.spec_from_file_location("protected_engine_static", ANALYZER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


engine = load_analyzer()


class Origin(NamedTuple):
    value: int
    definition_pc: int
    parent_pc: Optional[int] = None


class ScheduleTraceVm(engine.ProtectedEngineVm):
    def __init__(self, rand_values):
        super().__init__(rand_values)
        self.pc_history: Deque[int] = deque(maxlen=300)
        self.eval_events: Deque[str] = deque(maxlen=160)
        self.aux_events: Deque[str] = deque(maxlen=200)
        self.counter_events: Deque[str] = deque(maxlen=100)
        self.control_transfers: Deque[str] = deque(maxlen=400)
        self.stack_origins: Dict[int, List[Origin]] = {}
        self.counter_origins: Dict[int, List[Origin]] = {}
        self.evaluation_stack = 0
        self.auxiliary_stack = 0
        self.counter_chain = 0

    def setup(self, descriptors, status_value=0):
        super().setup(descriptors, status_value)
        self.evaluation_stack = self.memory.read(self.work_address + 0x00, 8)
        self.counter_chain = self.memory.read(self.work_address + 0x10, 8)
        self.auxiliary_stack = self.memory.read(self.work_address + 0x18, 8)
        self.stack_origins = {
            self.evaluation_stack: [],
            self.auxiliary_stack: [],
        }
        self.counter_origins = {self.counter_chain: []}

    def stack_label(self, address: int) -> str:
        if address == self.evaluation_stack:
            return "evaluation"
        if address == self.auxiliary_stack:
            return "auxiliary"
        return f"stack@{address:#x}"

    def record_stack(self, address: int, message: str) -> None:
        target = self.aux_events if address == self.auxiliary_stack else self.eval_events
        target.append(f"{self.executed:08d} pc={self.pc:#08x} {message}")

    @staticmethod
    def format_origin(origin: Origin) -> str:
        parent = "" if origin.parent_pc is None else f" parent={origin.parent_pc:#x}"
        return f"value={origin.value:#010x} def={origin.definition_pc:#x}{parent}"

    def helper_call(self, target: int) -> None:
        push_targets = (self.HELPER_STACK_PUSH, self.HELPER_STACK_PUSH_ALIAS)
        pop_targets = (self.HELPER_STACK_POP, self.HELPER_STACK_POP_ALIAS)

        if target in push_targets:
            address = self.read_reg("x1")
            value = engine.u32(self.read_reg("w2"))
            origins = self.stack_origins.setdefault(address, [])
            origins.append(Origin(value, self.pc))
            super().helper_call(target)
            self.record_stack(
                address,
                f"{self.stack_label(address)} push {value:#010x}; depth={len(origins)}",
            )
            return

        if target in pop_targets:
            address = self.read_reg("x1")
            origins = self.stack_origins.setdefault(address, [])
            origin = origins.pop() if origins else None
            super().helper_call(target)
            value = engine.u32(self.read_reg("w0"))
            detail = "unknown-origin" if origin is None else self.format_origin(origin)
            self.record_stack(
                address,
                f"{self.stack_label(address)} pop -> {value:#010x}; {detail}; depth={len(origins)}",
            )
            return

        if target in (self.HELPER_STACK_DUPLICATE, self.HELPER_STACK_REQUIRE):
            address = self.read_reg("x1")
            index = self.read_reg("w2") if target == self.HELPER_STACK_DUPLICATE else 0
            origins = self.stack_origins.setdefault(address, [])
            parent = origins[-1 - index] if len(origins) > index else None
            super().helper_call(target)
            if parent is not None:
                origins.append(Origin(parent.value, self.pc, parent.definition_pc))
            self.record_stack(
                address,
                f"{self.stack_label(address)} duplicate index={index}; depth={len(origins)}",
            )
            return

        if target == self.HELPER_STACK_SWAP:
            address = self.read_reg("x1")
            index = self.read_reg("w2")
            origins = self.stack_origins.setdefault(address, [])
            super().helper_call(target)
            if len(origins) > index:
                origins[-1], origins[-1 - index] = origins[-1 - index], origins[-1]
            self.record_stack(
                address,
                f"{self.stack_label(address)} swap index={index}; depth={len(origins)}",
            )
            return

        if target == self.HELPER_COUNTER_PUSH:
            address = self.read_reg("x1")
            value = engine.u32(self.read_reg("w2"))
            origins = self.counter_origins.setdefault(address, [])
            origins.insert(0, Origin(value, self.pc))
            super().helper_call(target)
            self.counter_events.append(
                f"{self.executed:08d} pc={self.pc:#08x} counter push {value:#010x}; depth={len(origins)}"
            )
            return

        if target == self.HELPER_COUNTER_DECREMENT:
            address = self.read_reg("x0")
            origins = self.counter_origins.setdefault(address, [])
            before = origins[0] if origins else None
            super().helper_call(target)
            value = engine.u32(self.read_reg("w0"))
            if origins and value == 0:
                origins.pop(0)
            detail = "unknown-origin" if before is None else self.format_origin(before)
            self.counter_events.append(
                f"{self.executed:08d} pc={self.pc:#08x} counter decrement -> {value:#010x}; {detail}; depth={len(origins)}"
            )
            return

        super().helper_call(target)

    def execute_one(self) -> None:
        old_pc = self.pc
        instruction = self.instructions[old_pc]
        self.pc_history.append(old_pc)
        super().execute_one()
        if self.pc != old_pc + 4:
            self.control_transfers.append(
                f"{self.executed:08d} {old_pc:#08x} -> {self.pc:#08x}  "
                f"{instruction.mnemonic} {instruction.operands}"
            )

    def run_to_target(self, max_instructions: int = 20_000_000) -> None:
        while not self.returned and self.pc != TARGET_PC:
            assert self.executed < max_instructions, (self.pc, self.executed)
            self.execute_one()
        assert self.pc == TARGET_PC, (self.pc, self.executed, self.returned)


def bullet_origins(origins: List[Origin]) -> List[str]:
    if not origins:
        return ["- empty"]
    result = []
    for index, origin in enumerate(reversed(origins)):
        parent = "" if origin.parent_pc is None else f", duplicated-from `{origin.parent_pc:#x}`"
        result.append(
            f"- top+{index}: `{origin.value:#010x}`, definition `{origin.definition_pc:#x}`{parent}"
        )
    return result


def main() -> None:
    descriptors, _expected, rand_values = engine.pixel_descriptors()
    vm = ScheduleTraceVm(rand_values)
    vm.setup(descriptors)
    vm.run_to_target()
    assert vm.status is not None

    evaluation = vm.stacks[vm.evaluation_stack].values
    auxiliary = vm.stacks[vm.auxiliary_stack].values
    counters = vm.counters[vm.counter_chain].values
    shared = vm.arenas[vm.memory.read(vm.work_address + 0x08, 8)]
    lane0 = vm.arenas[vm.memory.read(vm.work_address + 0x20, 8)]
    lines = [
        "# ARM64 protected-engine schedule trace to `0x106d00`",
        "",
        "This report was generated by a text-only interpreter over the checked-in",
        "`llvm-objdump` listing. The target ELF was not loaded or executed.",
        "",
        "## Stop state",
        "",
        f"- executed instructions before target: **{vm.executed:,}**",
        f"- current PC: `{vm.pc:#x}`",
        f"- status: `{vm.status.value}`",
        f"- evaluation-stack depth: `{len(evaluation)}`",
        f"- auxiliary-stack depth: `{len(auxiliary)}`",
        f"- counter-chain depth: `{len(counters)}`",
        f"- evaluation-stack top words: `{[hex(v) for v in reversed(evaluation[-12:])]}`",
        f"- auxiliary-stack top words: `{[hex(v) for v in reversed(auxiliary[-12:])]}`",
        f"- counter-chain head words: `{[hex(v) for v in counters[:12]]}`",
        f"- shared words 0x40..0x43: `{[hex(shared.read(i)) for i in range(0x40, 0x44)]}`",
        f"- lane-0 words 0..3: `{[hex(lane0.read(i)) for i in range(4)]}`",
        "",
        "## Live auxiliary-stack word origins",
        "",
        *bullet_origins(vm.stack_origins[vm.auxiliary_stack]),
        "",
        "## Live evaluation-stack word origins",
        "",
        *bullet_origins(vm.stack_origins[vm.evaluation_stack]),
        "",
        "## Live counter-chain origins",
        "",
        *bullet_origins(vm.counter_origins[vm.counter_chain]),
        "",
        "## Static interpretation of the selection chain",
        "",
        "1. `0x11a110` materializes auxiliary schedule token `0x301`; the common",
        "   push at `0x119e84` stores it, and `0xf23a4` later pops the same token.",
        "2. The dispatcher compares the token at `0xf3b4c`. Because it equals",
        "   `0x301`, `b.hs 0xf560c` is taken and the retained `NE` flag is false,",
        "   so `0xf5610 b.ne 0xf23c8` falls through into the `0x301` handler.",
        "3. Immediately before the copy/build continuation, the evaluation stack",
        "   receives `0x20` at `0x101c18`, `0x18` at `0x101c68`, and lane `2` at",
        "   `0x101c80`. They are popped as `{lane=2, sourceOffset=0x18, wordCount=0x20}`",
        "   at `0x101c94`, `0x101cb4`, and `0x101cd0`.",
        "4. `0x101ce4..0x101d00` pops then pushes lane 2's frame. The loop at",
        "   `0x101d14..0x101d4c` copies 32 shared-arena words from offsets",
        "   `0x18..0x37` into lane-2 offsets `0..31`. The unsigned completion",
        "   branch at `0x101d1c` then reaches `0x106d00`.",
        "5. At the stop point, the auxiliary stack, evaluation stack, and counter",
        "   chain are all empty. Therefore no live residual token directly chooses",
        "   `0x106d00`; the selection is the already-consumed fixed token `0x301`.",
        "6. x86_64 independently contains token materialization `0x112098`, compare",
        "   `0xe5fa0`, and the corresponding fixed-frame builder at `0xfc546`.",
        "   This rules out an ARM64-only condition-code or branch-direction error.",
        "",
        "## Recent auxiliary-stack events",
        "",
        "```text",
        *vm.aux_events,
        "```",
        "",
        "## Recent counter-chain events",
        "",
        "```text",
        *vm.counter_events,
        "```",
        "",
        "## Recent evaluation-stack events",
        "",
        "```text",
        *vm.eval_events,
        "```",
        "",
        "## Recent non-sequential control transfers",
        "",
        "```text",
        *vm.control_transfers,
        "```",
        "",
        "## Immediate predecessor PC chain",
        "",
        "```text",
        *[f"{pc:#08x}" for pc in vm.pc_history],
        f"{TARGET_PC:#08x}  <stop before execution>",
        "```",
        "",
    ]
    REPORT.write_text("\n".join(lines))
    print(REPORT)
    print(f"executed={vm.executed} status={vm.status.value} pc={vm.pc:#x}")


if __name__ == "__main__":
    main()
