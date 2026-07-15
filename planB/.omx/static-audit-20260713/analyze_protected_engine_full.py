#!/usr/bin/env python3
"""Static ARM64 interpreter for libsigner.so 0xf1ec8..0x11ba78.

The target ELF is never loaded or executed.  Instructions are parsed from the
checked-in llvm-objdump text and the 17 direct callees are replaced with the
source-level container semantics already recovered in recovered_primitives.cpp.
"""

from __future__ import annotations

import dataclasses
import re
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[2]
OBJDUMP = ROOT / ".omx/libsigner-arm64-objdump.txt"
START = 0xF1EC8
END = 0x11BA78


def u32(value: int) -> int:
    return value & 0xFFFFFFFF


def u64(value: int) -> int:
    return value & 0xFFFFFFFFFFFFFFFF


def split_operands(text: str) -> List[str]:
    result: List[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        result.append(tail)
    return result


def parse_immediate(text: str) -> int:
    text = text.strip()
    if text.startswith("#"):
        text = text[1:]
    return int(text, 0)


@dataclasses.dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    parts: Tuple[str, ...]


def load_instructions() -> Dict[int, Instruction]:
    instructions: Dict[int, Instruction] = {}
    pattern = re.compile(
        r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([^\s]+)\s*(.*?)\s*$")
    for line in OBJDUMP.read_text().splitlines():
        match = pattern.match(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if START <= address < END:
            operands = match.group(3).split("//", 1)[0].rstrip()
            instructions[address] = Instruction(
                address, match.group(2), operands,
                tuple(split_operands(operands)))
    assert len(instructions) == 42732, len(instructions)
    return instructions


class Memory:
    def __init__(self) -> None:
        self.bytes: Dict[int, int] = {}
        self.next_heap = 0x10000000

    def allocate(self, size: int, alignment: int = 16) -> int:
        address = (self.next_heap + alignment - 1) & -alignment
        self.next_heap = address + max(size, 1)
        for index in range(size):
            self.bytes[address + index] = 0
        return address

    def read(self, address: int, size: int) -> int:
        value = 0
        for index in range(size):
            value |= self.bytes.get(u64(address + index), 0) << (index * 8)
        return value

    def write(self, address: int, size: int, value: int) -> None:
        for index in range(size):
            self.bytes[u64(address + index)] = (value >> (index * 8)) & 0xFF

    def write_bytes(self, address: int, data: bytes) -> None:
        for index, value in enumerate(data):
            self.bytes[u64(address + index)] = value


@dataclasses.dataclass
class Arena:
    capacity: int = 0x100
    words: List[int] = dataclasses.field(
        default_factory=lambda: [0] * 0x100)
    length: int = 0
    frame_bases: List[int] = dataclasses.field(default_factory=lambda: [0])

    def write(self, status: "Status", offset: int, value: int) -> None:
        index = u32(self.frame_bases[len(self.frame_bases) - 1] + offset)
        while index >= self.capacity:
            self.capacity = u32(self.capacity + 128)
            self.words.extend([0] * 128)
        self.words[index] = u32(value)
        if self.length <= index:
            self.length = index + 1

    def read(self, offset: int) -> int:
        index = u32(self.frame_bases[len(self.frame_bases) - 1] + offset)
        return self.words[index] if index < self.capacity else 0

    def push_frame(self, status: "Status") -> None:
        self.frame_bases.append(self.length)

    def pop_frame(self, status: "Status") -> None:
        if len(self.frame_bases) == 0:
            status.value = 7
            return
        new_depth = len(self.frame_bases) - 1
        self.length = self.frame_bases[new_depth]
        self.frame_bases = self.frame_bases[:new_depth]

    def current_frame_length(self) -> int:
        return u32(self.length - self.frame_bases[len(self.frame_bases) - 1])


@dataclasses.dataclass
class WordStack:
    values: List[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CounterChain:
    values: List[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Status:
    memory: Memory
    address: int

    @property
    def value(self) -> int:
        return self.memory.read(self.address, 4)

    @value.setter
    def value(self, value: int) -> None:
        self.memory.write(self.address, 4, u32(value))


class ProtectedEngineVm:
    HELPER_STACK_PUSH = 0x138A70
    HELPER_STACK_POP = 0x138B74
    HELPER_ARENA_READ = 0x138744
    HELPER_STACK_DUPLICATE = 0x138C8C
    HELPER_ARENA_WRITE = 0x138318
    HELPER_STACK_SWAP = 0x138E60
    HELPER_STACK_REQUIRE = 0x138E58
    HELPER_FRAME_PUSH = 0x138560
    HELPER_FRAME_POP = 0x138660
    HELPER_COUNTER_DECREMENT = 0x137A78
    HELPER_COUNTER_PUSH = 0x137980
    HELPER_FRAME_LENGTH = 0x138728
    HELPER_STACK_PUSH_ALIAS = 0x137898
    HELPER_STACK_EMPTY_ALIAS = 0x13789C
    HELPER_STACK_POP_ALIAS = 0x1378A0
    RAND_PLT = 0x13A020
    STACK_CHK_FAIL_PLT = 0x139DF0

    def __init__(self, rand_values: Sequence[int]) -> None:
        self.instructions = load_instructions()
        self.memory = Memory()
        self.regs = [0] * 31
        self.sp = 0
        self.pc = START
        self.n = False
        self.z = False
        self.c = False
        self.v = False
        self.arenas: Dict[int, Arena] = {}
        self.stacks: Dict[int, WordStack] = {}
        self.counters: Dict[int, CounterChain] = {}
        self.status: Optional[Status] = None
        self.rand_values = [u32(value) for value in rand_values]
        self.rand_index = 0
        self.call_counts: Dict[int, int] = {}
        self.executed = 0
        self.returned = False
        self.work_address = 0
        self.memory_operand_cache: Dict[
            str, Tuple[str, Optional[str], Optional[str], bool]] = {}
        self.branch_target_cache: Dict[str, int] = {}

    def read_reg(self, name: str) -> int:
        name = name.strip()
        if name in ("xzr", "wzr"):
            return 0
        if name == "sp":
            return self.sp
        if len(name) < 2 or name[0] not in "wx" or not name[1:].isdigit():
            raise AssertionError(f"unsupported register {name!r} at {self.pc:#x}")
        value = self.regs[int(name[1:])]
        return value if name[0] == "x" else value & 0xFFFFFFFF

    def write_reg(self, name: str, value: int) -> None:
        name = name.strip()
        if name in ("xzr", "wzr"):
            return
        if name == "sp":
            self.sp = u64(value)
            return
        if len(name) < 2 or name[0] not in "wx" or not name[1:].isdigit():
            if name.startswith("q"):
                return
            raise AssertionError(f"unsupported register {name!r} at {self.pc:#x}")
        index = int(name[1:])
        self.regs[index] = u64(value) if name[0] == "x" else u32(value)

    def register_width(self, name: str) -> int:
        return 64 if name.startswith("x") or name == "sp" else 32

    def eval_value(self, operand: str) -> int:
        operand = operand.strip()
        if operand.startswith("#"):
            return parse_immediate(operand)
        return self.read_reg(operand)

    def apply_modifier(self, value: int, modifier: Optional[str]) -> int:
        if modifier is None:
            return value
        modifier = modifier.strip()
        if modifier.startswith("lsl"):
            return value << parse_immediate(modifier.split(None, 1)[1])
        if modifier.startswith("uxtw"):
            parts = modifier.split(None, 1)
            shift = parse_immediate(parts[1]) if len(parts) == 2 else 0
            return (value & 0xFFFFFFFF) << shift
        raise AssertionError(f"unsupported modifier {modifier!r} at {self.pc:#x}")

    def memory_address(self, operand: str) -> Tuple[int, Optional[str]]:
        cached = self.memory_operand_cache.get(operand)
        if cached is None:
            original = operand
            operand = operand.strip()
            pre_index = operand.endswith("!")
            if pre_index:
                operand = operand[:-1]
            assert operand.startswith("[") and operand.endswith("]"), (
                self.pc, operand)
            fields = split_operands(operand[1:-1])
            cached = (
                fields[0], fields[1] if len(fields) >= 2 else None,
                fields[2] if len(fields) >= 3 else None, pre_index)
            self.memory_operand_cache[original] = cached
        base_name, offset_operand, modifier, pre_index = cached
        address = self.read_reg(base_name)
        if offset_operand is not None:
            offset = self.eval_value(offset_operand)
            address = u64(address + self.apply_modifier(offset, modifier))
        if pre_index:
            self.write_reg(base_name, address)
        return address, base_name if pre_index else None

    def set_sub_flags(self, left: int, right: int, width: int) -> None:
        mask = (1 << width) - 1
        sign = 1 << (width - 1)
        left &= mask
        right &= mask
        result = (left - right) & mask
        self.z = result == 0
        self.n = (result & sign) != 0
        self.c = left >= right
        self.v = ((left ^ right) & (left ^ result) & sign) != 0

    def set_add_flags(self, left: int, right: int, width: int) -> None:
        mask = (1 << width) - 1
        sign = 1 << (width - 1)
        left &= mask
        right &= mask
        total = left + right
        result = total & mask
        self.z = result == 0
        self.n = (result & sign) != 0
        self.c = total > mask
        self.v = ((~(left ^ right) & (left ^ result)) & sign) != 0

    def branch_condition(self, mnemonic: str) -> bool:
        return {
            "b.eq": self.z,
            "b.ne": not self.z,
            "b.hs": self.c,
            "b.hi": self.c and not self.z,
            "b.ge": self.n == self.v,
        }[mnemonic]

    def condition_true(self, condition: str) -> bool:
        return {
            "eq": self.z,
            "ne": not self.z,
            "hs": self.c,
            "lo": not self.c,
            "hi": self.c and not self.z,
            "ge": self.n == self.v,
        }[condition]

    def branch_target(self, operand: str) -> int:
        cached = self.branch_target_cache.get(operand)
        if cached is not None:
            return cached
        match = re.search(r"0x([0-9a-f]+)", operand)
        assert match is not None, operand
        target = int(match.group(1), 16)
        self.branch_target_cache[operand] = target
        return target

    def raw_status(self, address: int) -> Status:
        assert self.status is not None
        assert address == self.status.address, (self.pc, address, self.status.address)
        return self.status

    def helper_call(self, target: int) -> None:
        self.call_counts[target] = self.call_counts.get(target, 0) + 1
        status = self.status
        assert status is not None

        if target in (self.HELPER_STACK_PUSH, self.HELPER_STACK_PUSH_ALIAS):
            stack = self.stacks[self.read_reg("x1")]
            stack.values.append(u32(self.read_reg("w2")))
            return
        if target in (self.HELPER_STACK_POP, self.HELPER_STACK_POP_ALIAS):
            stack = self.stacks[self.read_reg("x1")]
            if not stack.values:
                status.value = 3
                self.write_reg("w0", 0)
            else:
                self.write_reg("w0", stack.values.pop())
            return
        if target == self.HELPER_STACK_EMPTY_ALIAS:
            stack = self.stacks[self.read_reg("x0")]
            self.write_reg("w0", 1 if not stack.values else 0)
            return
        if target == self.HELPER_ARENA_READ:
            arena = self.arenas[self.read_reg("x0")]
            self.write_reg("w0", arena.read(self.read_reg("w1")))
            return
        if target == self.HELPER_ARENA_WRITE:
            self.raw_status(self.read_reg("x0"))
            arena = self.arenas[self.read_reg("x1")]
            arena.write(status, self.read_reg("w2"), self.read_reg("w3"))
            return
        if target == self.HELPER_STACK_DUPLICATE:
            stack = self.stacks[self.read_reg("x1")]
            index = self.read_reg("w2")
            if len(stack.values) <= index:
                status.value = 4
            else:
                stack.values.append(stack.values[-1 - index])
            return
        if target == self.HELPER_STACK_REQUIRE:
            stack = self.stacks[self.read_reg("x1")]
            if len(stack.values) <= 0:
                status.value = 4
            else:
                stack.values.append(stack.values[-1])
            return
        if target == self.HELPER_STACK_SWAP:
            stack = self.stacks[self.read_reg("x1")]
            index = self.read_reg("w2")
            if len(stack.values) <= index:
                status.value = 4
            else:
                selected = -1 - index
                stack.values[-1], stack.values[selected] = (
                    stack.values[selected], stack.values[-1])
            return
        if target == self.HELPER_FRAME_PUSH:
            self.arenas[self.read_reg("x1")].push_frame(status)
            return
        if target == self.HELPER_FRAME_POP:
            self.arenas[self.read_reg("x1")].pop_frame(status)
            return
        if target == self.HELPER_FRAME_LENGTH:
            self.write_reg(
                "w0", self.arenas[self.read_reg("x0")].current_frame_length())
            return
        if target == self.HELPER_COUNTER_PUSH:
            chain = self.counters[self.read_reg("x1")]
            chain.values.insert(0, u32(self.read_reg("w2")))
            return
        if target == self.HELPER_COUNTER_DECREMENT:
            chain = self.counters[self.read_reg("x0")]
            assert chain.values, (self.pc, "counter underflow")
            value = u32(chain.values[0] - 1)
            chain.values[0] = value
            if value == 0:
                chain.values.pop(0)
            self.write_reg("w0", value)
            return
        if target == self.RAND_PLT:
            assert self.rand_index < len(self.rand_values), (
                self.pc, self.rand_index, len(self.rand_values))
            self.write_reg("w0", self.rand_values[self.rand_index])
            self.rand_index += 1
            return
        if target == self.STACK_CHK_FAIL_PLT:
            raise AssertionError(f"stack protector failure at {self.pc:#x}")
        raise AssertionError(f"unknown direct call {target:#x} at {self.pc:#x}")

    def setup(self, descriptors: Sequence[bytes], status_value: int = 0) -> None:
        assert len(descriptors) <= 16
        status_address = self.memory.allocate(4, 4)
        self.status = Status(self.memory, status_address)
        self.status.value = status_value

        work = self.memory.allocate(0xA0)
        self.work_address = work
        evaluation_stack = self.memory.allocate(16)
        shared_arena = self.memory.allocate(32)
        counter_chain = self.memory.allocate(8)
        auxiliary_stack = self.memory.allocate(16)
        self.stacks[evaluation_stack] = WordStack()
        self.arenas[shared_arena] = Arena()
        self.counters[counter_chain] = CounterChain()
        self.stacks[auxiliary_stack] = WordStack()
        self.memory.write(work + 0x00, 8, evaluation_stack)
        self.memory.write(work + 0x08, 8, shared_arena)
        self.memory.write(work + 0x10, 8, counter_chain)
        self.memory.write(work + 0x18, 8, auxiliary_stack)
        for index in range(16):
            arena_address = self.memory.allocate(32)
            self.arenas[arena_address] = Arena()
            self.memory.write(work + 0x20 + index * 8, 8, arena_address)

        descriptor_addresses: List[int] = []
        for data in descriptors:
            data_address = self.memory.allocate(len(data), 4)
            self.memory.write_bytes(data_address, data)
            descriptor = self.memory.allocate(16)
            self.memory.write(descriptor, 4, len(data))
            self.memory.write(descriptor + 8, 8, data_address)
            descriptor_addresses.append(descriptor)

        old_sp = 0x70000000
        self.sp = old_sp
        for index, descriptor in enumerate(descriptor_addresses[5:]):
            self.memory.write(old_sp + index * 8, 8, descriptor)

        self.write_reg("x0", status_address)
        self.write_reg("x1", work)
        self.write_reg("w2", len(descriptor_addresses))
        for index, descriptor in enumerate(descriptor_addresses[:5], 3):
            self.write_reg(f"x{index}", descriptor)

        thread_pointer = 0x71000000
        self.memory.write(thread_pointer + 0x28, 8, 0x1122334455667788)
        self.write_reg("x30", 0xDEAD0000)
        self.thread_pointer = thread_pointer

    def execute_one(self) -> None:
        instruction = self.instructions.get(self.pc)
        assert instruction is not None, f"no instruction at {self.pc:#x}"
        mnemonic = instruction.mnemonic
        operands = instruction.parts
        next_pc = self.pc + 4

        if mnemonic == "mov":
            self.write_reg(operands[0], self.eval_value(operands[1]))
        elif mnemonic == "movk":
            destination = operands[0]
            width = self.register_width(destination)
            shift = 0
            if len(operands) == 3:
                assert operands[2].startswith("lsl")
                shift = parse_immediate(operands[2].split(None, 1)[1])
            mask = (1 << width) - 1
            lane_mask = u64(0xFFFF << shift) & mask
            value = (self.read_reg(destination) & ~lane_mask) | (
                (parse_immediate(operands[1]) & 0xFFFF) << shift)
            self.write_reg(destination, value)
        elif mnemonic in ("add", "sub"):
            left = self.eval_value(operands[1])
            right = self.eval_value(operands[2])
            modifier = operands[3] if len(operands) == 4 else None
            right = self.apply_modifier(right, modifier)
            value = left + right if mnemonic == "add" else left - right
            self.write_reg(operands[0], value)
        elif mnemonic in ("and", "orr", "eor"):
            left = self.eval_value(operands[1])
            right = self.eval_value(operands[2])
            modifier = operands[3] if len(operands) == 4 else None
            right = self.apply_modifier(right, modifier)
            if mnemonic == "and":
                value = left & right
            elif mnemonic == "orr":
                value = left | right
            else:
                value = left ^ right
            self.write_reg(operands[0], value)
        elif mnemonic in ("lsl", "lsr"):
            value = self.eval_value(operands[1])
            shift = self.eval_value(operands[2])
            width = self.register_width(operands[0])
            shift &= width - 1
            if mnemonic == "lsl":
                value <<= shift
            else:
                value = (value & ((1 << width) - 1)) >> shift
            self.write_reg(operands[0], value)
        elif mnemonic == "mvn":
            width = self.register_width(operands[0])
            self.write_reg(
                operands[0], ~self.eval_value(operands[1]) & ((1 << width) - 1))
        elif mnemonic == "mul":
            self.write_reg(
                operands[0], self.eval_value(operands[1]) * self.eval_value(operands[2]))
        elif mnemonic == "msub":
            value = self.eval_value(operands[3]) - (
                self.eval_value(operands[1]) * self.eval_value(operands[2]))
            self.write_reg(operands[0], value)
        elif mnemonic == "udiv":
            numerator = self.eval_value(operands[1])
            denominator = self.eval_value(operands[2])
            self.write_reg(operands[0], 0 if denominator == 0 else numerator // denominator)
        elif mnemonic in ("cmp", "cmn"):
            left = self.eval_value(operands[0])
            right = self.eval_value(operands[1])
            width = self.register_width(operands[0])
            if mnemonic == "cmp":
                self.set_sub_flags(left, right, width)
            else:
                self.set_add_flags(left, right, width)
        elif mnemonic == "cset":
            self.write_reg(operands[0], int(self.condition_true(operands[1])))
        elif mnemonic == "rev":
            value = self.eval_value(operands[1]) & 0xFFFFFFFF
            self.write_reg(operands[0], int.from_bytes(value.to_bytes(4, "little"), "big"))
        elif mnemonic in ("ldr", "ldur", "ldrb", "ldrh", "ldursw"):
            address, _ = self.memory_address(operands[1])
            destination = operands[0]
            if mnemonic == "ldrb":
                size = 1
            elif mnemonic == "ldrh":
                size = 2
            elif mnemonic == "ldursw":
                size = 4
            else:
                size = 8 if destination.startswith("x") else 4
            value = self.memory.read(address, size)
            if mnemonic == "ldursw" and value & 0x80000000:
                value -= 1 << 32
            self.write_reg(destination, value)
        elif mnemonic in ("str", "stur"):
            address, _ = self.memory_address(operands[1])
            source = operands[0]
            size = 8 if source.startswith("x") else 4
            self.memory.write(address, size, self.read_reg(source))
        elif mnemonic in ("stp", "ldp"):
            address, _ = self.memory_address(operands[2])
            first, second = operands[0], operands[1]
            size = 16 if first.startswith("q") else 8
            if mnemonic == "stp":
                first_value = 0 if first.startswith("q") else self.read_reg(first)
                second_value = 0 if second.startswith("q") else self.read_reg(second)
                self.memory.write(address, size, first_value)
                self.memory.write(address + size, size, second_value)
            else:
                self.write_reg(first, self.memory.read(address, size))
                self.write_reg(second, self.memory.read(address + size, size))
        elif mnemonic == "mrs":
            assert operands[1] == "TPIDR_EL0"
            self.write_reg(operands[0], self.thread_pointer)
        elif mnemonic == "b":
            next_pc = self.branch_target(operands[0])
        elif mnemonic in ("b.eq", "b.ne", "b.hs", "b.hi", "b.ge"):
            if self.branch_condition(mnemonic):
                next_pc = self.branch_target(operands[0])
        elif mnemonic in ("cbz", "cbnz"):
            is_zero = self.eval_value(operands[0]) == 0
            if is_zero == (mnemonic == "cbz"):
                next_pc = self.branch_target(operands[1])
        elif mnemonic in ("tbz", "tbnz"):
            bit = parse_immediate(operands[1])
            is_zero = ((self.eval_value(operands[0]) >> bit) & 1) == 0
            if is_zero == (mnemonic == "tbz"):
                next_pc = self.branch_target(operands[2])
        elif mnemonic == "bl":
            target = self.branch_target(operands[0])
            self.write_reg("x30", next_pc)
            self.helper_call(target)
        elif mnemonic == "ret":
            self.returned = True
        else:
            raise AssertionError(
                f"unsupported {mnemonic} {instruction.operands} at {self.pc:#x}")

        self.pc = next_pc
        self.executed += 1

    def run(self, max_instructions: int = 20_000_000) -> None:
        while not self.returned:
            assert self.executed < max_instructions, (self.pc, self.executed)
            self.execute_one()

    def output(self) -> bytes:
        lane0 = self.arenas[self.memory.read(self.work_address + 0x20, 8)]
        lane1 = self.arenas[self.memory.read(self.work_address + 0x28, 8)]
        byte_length = lane1.read(0)
        assert byte_length % 4 == 0, byte_length
        return b"".join(
            lane0.read(index).to_bytes(4, "big")
            for index in range(byte_length // 4))


CODEWORD_BASIS = (
    0x0002, 0x0022, 0x0220, 0x2220, 0x8200, 0x0A00, 0x0120, 0xA221,
    0x0401, 0xA42A, 0xB20A, 0x1839, 0xB824, 0x0668, 0xCD15, 0xD0AA,
)


def encode_correction(code: int) -> int:
    source = u32(code * 2 + 3) & 0xFFFF
    output = 0
    for bit in range(16):
        if source & (1 << bit):
            output ^= CODEWORD_BASIS[15 - bit]
    return output


class BionicRandom:
    def __init__(self, seed: int) -> None:
        self.state = [0] * 31
        self.state[0] = u32(seed)
        for index in range(1, 31):
            previous = self.state[index - 1]
            if previous & 0x80000000:
                previous -= 1 << 32
            high = int(previous / 127773)
            low = previous - high * 127773
            value = 16807 * low - 2836 * high
            if value <= 0:
                value += 0x7FFFFFFF
            self.state[index] = u32(value)
        self.front = 3
        self.rear = 0
        for _ in range(310):
            self.next()

    def next(self) -> int:
        self.state[self.front] = u32(
            self.state[self.front] + self.state[self.rear])
        value = (self.state[self.front] >> 1) & 0x7FFFFFFF
        self.front = (self.front + 1) % 31
        self.rear = (self.rear + 1) % 31
        return value


def native_halfwords(values: Iterable[int]) -> bytes:
    return b"".join(struct.pack("<H", value & 0xFFFF) for value in values)


def pixel_descriptors() -> Tuple[List[bytes], bytes, List[int]]:
    corrections = [0x2B, 0x36, 0x25, 0x05]
    slots = [encode_correction(0x40 + (index & 7)) for index in range(64)]
    for index, code in enumerate(corrections):
        slots[index] = encode_correction(code)
    descriptor1 = native_halfwords(slots)
    certificate = bytes.fromhex(
        "164a86faf30e412b59223a36ccbe0f6e46e40958")
    # Native context descriptor 3 is the final 16-byte context+0xe0 flag
    # field, not a Boolean.  The isolated Pixel 8 reference run reaches the
    # engine with 0x1ffdffffffffffbf.  ARM64 0xf1fb0..0xf1fb8 loads each
    # little-endian word and REV32s it into lane 2, producing the independently
    # observed [0xbfffffff, 0xfffffd1f, 0, 0].
    flags = struct.pack("<Q", 0x1FFDFFFFFFFFFFBF) + bytes(8)
    basis = native_halfwords(CODEWORD_BASIS)
    field2 = bytes((0, 1, 2, 3))
    plaintext = (
        b"0123456789abcdef"
        b"abc123"
        b"CN"
        b"2026-07-10T00:00:00.000+0800"
        b"Pixel 9 Pro"
        b"phone"
        b"sandbox"
        b"11111111-1111-1111-1111-111111111111"
        b"android"
        b"15"
        b"1400000"
        b"session"
        b"android4.38.5"
        b"93.67.0"
    )
    assert len(plaintext) == 154
    descriptors = [
        descriptor1,
        certificate,
        flags,
        basis,
        field2,
        len(plaintext).to_bytes(4, "big"),
        plaintext,
        bytes(4),
        b"",
    ]
    expected = bytes.fromhex(
        "3b273362218b186a73e7349775b93f11"
        "51da6894512660bd1e9809e7c17c3898"
        "a2d0c5508f89e6c3022e6c8f7b442797"
        "abef7d1d32d8a04d887d2d1bf24b19b1"
        "f9ab2e878f79e9e4403f2fbb71ee5609"
        "443039c0ce6fc355892096d63e697e9c"
        "a2794cf0628c4403e0d6e9e452c356cb"
        "f881e5aebd431e2b583b6d923875d3eb"
        "9b3b2de520ab291ca72a1f1cd661d6af"
        "510d952d14921db3ae61537b5fccc21e"
        "45554bf72a6d107816fbbf28ebd8f6f7")
    random = BionicRandom(1760000000)
    rand_values = [random.next() for _ in range(8)]
    return descriptors, expected, rand_values


def main() -> None:
    descriptors, expected, rand_values = pixel_descriptors()
    vm = ProtectedEngineVm(rand_values)
    vm.setup(descriptors)
    vm.run()
    assert vm.status is not None
    actual = vm.output() if vm.status.value == 0 else b""
    assert vm.status.value == 0, (
        f"status={vm.status.value} pc={vm.pc:#x} executed={vm.executed}")
    assert vm.rand_index == 8, vm.rand_index
    assert actual == expected, (
        len(actual), actual.hex(), len(expected), expected.hex())
    print(
        "arm64 protected engine 0xf1ec8 full static VM Pixel vector: PASS")
    print(f"executed_instructions={vm.executed}")
    print(f"direct_calls={sum(vm.call_counts.values())}")
    print(f"output_bytes={len(actual)}")


if __name__ == "__main__":
    main()
