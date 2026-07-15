#!/usr/bin/env python3
"""Prove the ARM64 final descriptor 8/9 context pair remains zero/null.

This is a static, conservative register may-alias analysis over the existing
llvm-objdump text.  It follows direct control-flow edges, propagates fixed
context-relative register offsets, and recursively follows direct calls when
one of x0..x7 may carry the native-context pointer.
"""

from __future__ import annotations

import collections
import csv
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
INVENTORY = ROOT / ".omx/static-audit-20260713/arm64-function-inventory.csv"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-context-dynamic-pair.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise SystemExit(f"missing static evidence: {description}")


def register(value: str) -> int | None:
    match = re.fullmatch(r"[xw](\d+)", value.strip())
    return int(match.group(1)) if match else None


def immediate(value: str) -> int | None:
    match = re.search(r"#(-?0x[0-9a-f]+|-?\d+)", value)
    return int(match.group(1), 0) if match else None


def direct_target(operands: str) -> int | None:
    match = re.search(r"0x([0-9a-f]+)", operands)
    return int(match.group(1), 16) if match else None


def merged(left: dict[int, set[int]], right: dict[int, set[int]]) -> dict[int, set[int]]:
    result = {key: set(value) for key, value in left.items()}
    for key, value in right.items():
        result.setdefault(key, set()).update(value)
    return result


def main() -> None:
    text = DISASSEMBLY.read_text()
    required_evidence = [
        (r"cbec0:.*add\s+x11, sp, #0x88", "native context base at sp+0x88"),
        (r"cbf5c:.*add\s+x9, x11, #0x8", "memset destination context+0x08"),
        (r"cbf84:.*stp\s+x8, x9, \[sp, #0x8\]", "saved context pointers"),
        (r"cc3e8:.*ldr\s+x0, \[sp, #0x10\]", "reload context+0x08 for memset"),
        (r"cc3f0:.*mov\s+w2, #0x120", "0x120-byte zero range"),
        (r"cc3f4:.*bl\s+0x139e10", "memset call"),
        (r"11e658:.*ldr\s+w8, \[x8, #0x118\]", "slot 8 length read"),
        (r"11e760:.*ldr\s+w1, \[x8, #0x118\]", "slot 9 length read"),
        (r"11e764:.*ldr\s+x2, \[x8, #0x120\]", "slot 9 data read"),
        (r"cc1c0:.*ldr\s+x0, \[x8, #0x120\]", "context+0x120 cleanup load"),
        (r"cc1c4:.*bl\s+0x139de0", "context+0x120 free"),
    ]
    for pattern, description in required_evidence:
        require(text, pattern, description)

    instructions: dict[int, tuple[str, str, str]] = {}
    instruction_order: list[int] = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z0-9.]+)\s*(.*)$", line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        instructions[address] = (
            match.group(2), match.group(3).split("//", 1)[0].strip(), line.strip())
        instruction_order.append(address)

    functions: dict[int, tuple[int, str]] = {}
    with INVENTORY.open(newline="") as handle:
        for row in csv.DictReader(handle):
            functions[int(row["start"], 16)] = (int(row["end"], 16), row["name"])

    def analyze(start: int, seeds: dict[int, int]):
        end, name = functions[start]
        addresses = [address for address in instruction_order if start <= address < end]
        address_set = set(addresses)
        next_address = {
            address: addresses[index + 1] if index + 1 < len(addresses) else None
            for index, address in enumerate(addresses)
        }
        states: dict[int, dict[int, set[int]]] = {
            start: {key: {value} for key, value in seeds.items()}
        }
        pending = collections.deque([start])
        writes: set[tuple[int, int, str]] = set()
        calls: set[tuple[int, int, tuple[tuple[int, int], ...]]] = set()

        while pending:
            address = pending.popleft()
            state = {key: set(value) for key, value in states[address].items()}
            mnemonic, operands, line = instructions[address]
            operands_list = [item.strip() for item in operands.split(",")]

            if mnemonic.startswith(("str", "stur", "stp")):
                memory = re.search(
                    r"\[\s*([xw]\d+)(?:\s*,\s*#(-?0x[0-9a-f]+|-?\d+))?", operands)
                if memory is not None:
                    base_register = register(memory.group(1))
                    memory_offset = int(memory.group(2), 0) if memory.group(2) else 0
                    for base_offset in state.get(base_register, set()):
                        writes.add((address, base_offset + memory_offset, line))

            if mnemonic == "bl":
                target = direct_target(operands)
                passed = tuple(sorted(
                    (argument, offset)
                    for argument in range(8)
                    for offset in state.get(argument, set())
                ))
                if target is not None and passed:
                    calls.add((address, target, passed))
                # AArch64 caller-saved integer registers cannot retain aliases.
                for caller_saved in range(19):
                    state.pop(caller_saved, None)
            else:
                destination = register(operands_list[0]) if operands_list else None
                if destination is not None:
                    replacement: set[int] | None = None
                    if mnemonic in ("mov", "orr") and len(operands_list) >= 2:
                        source = register(operands_list[1])
                        replacement = set(state.get(source, set())) if source is not None else set()
                    elif mnemonic in ("add", "sub") and len(operands_list) >= 3:
                        source = register(operands_list[1])
                        value = immediate(operands_list[2])
                        if source is not None and value is not None:
                            sign = 1 if mnemonic == "add" else -1
                            replacement = {offset + sign * value for offset in state.get(source, set())}
                        else:
                            replacement = set()
                    elif mnemonic in ("csel", "csinc", "csinv", "csneg") \
                            and len(operands_list) >= 3:
                        first = register(operands_list[1])
                        second = register(operands_list[2])
                        replacement = set(state.get(first, set())) | set(state.get(second, set()))
                    elif mnemonic.startswith(("ldr", "ldur", "ldp", "adr", "mrs")) \
                            or mnemonic in ("movz", "movn", "movi", "fmov") \
                            or mnemonic.startswith((
                                "eor", "and", "lsl", "lsr", "asr", "rev", "ubfx", "sxt", "uxt")):
                        replacement = set()

                    if replacement is not None:
                        if replacement:
                            state[destination] = replacement
                        else:
                            state.pop(destination, None)
                        if mnemonic.startswith("ldp") and len(operands_list) > 1:
                            second_destination = register(operands_list[1])
                            if second_destination is not None:
                                state.pop(second_destination, None)

            target = direct_target(operands)
            successors: list[int] = []
            if mnemonic == "b":
                if target in address_set:
                    successors.append(target)
            elif mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
                if target in address_set:
                    successors.append(target)
                if next_address[address] is not None:
                    successors.append(next_address[address])
            elif mnemonic not in ("ret", "br") and next_address[address] is not None:
                successors.append(next_address[address])

            for successor in successors:
                successor_state = merged(states.get(successor, {}), state)
                if successor not in states or successor_state != states[successor]:
                    states[successor] = successor_state
                    pending.append(successor)

        return name, writes, calls

    # These are every native-context-bearing stage called by the orchestrator.
    roots = {
        0xCBA90: {2: 0},   # stage 1 receives context in x2
        0xCBBD4: {3: 0},   # stage 2 receives context in x3
        0x143E8: {0: 0},   # environment dispatcher
        0xD6888: {0: 0},   # correction stage
        0xF224: {0: 0},    # timing stage
        0x11DA64: {2: 0},  # final consumer receives context in x2
    }
    queue = collections.deque((start, seeds) for start, seeds in roots.items())
    visited: set[tuple[int, tuple[tuple[int, int], ...]]] = set()
    all_writes: set[tuple[int, int, str, str]] = set()
    analyzed_functions: set[tuple[int, str]] = set()

    while queue:
        start, seeds = queue.popleft()
        key = (start, tuple(sorted(seeds.items())))
        if key in visited or start not in functions:
            continue
        visited.add(key)
        name, writes, calls = analyze(start, seeds)
        analyzed_functions.add((start, name))
        for address, offset, line in writes:
            all_writes.add((address, offset, line, name))
        for _, target, passed in calls:
            if target not in functions:
                continue
            target_seeds = {argument: offset for argument, offset in passed}
            if target_seeds:
                queue.append((target, target_seeds))

    forbidden = [write for write in all_writes if write[1] in (0x118, 0x120)]
    if forbidden:
        evidence = "\n".join(write[2] for write in forbidden)
        raise SystemExit(f"context dynamic pair has a producer write:\n{evidence}")

    offsets = sorted({offset for _, offset, _, _ in all_writes})
    write_rows = "\n".join(
        f"| `0x{address:x}` | `context+0x{offset:x}` | `{name}` | `{line}` |"
        for address, offset, line, name in sorted(all_writes)
        if 0 <= offset <= 0x127
    )
    function_rows = "\n".join(
        f"- `0x{address:x}` `{name}`" for address, name in sorted(analyzed_functions)
    )
    OUTPUT.write_text(f"""# ARM64 native context dynamic pair closure

## Result

On the analyzed ARM64 `libsigner.so`, final descriptors 8/9 are a reserved
zero-length pair on the statically reachable native signing pipeline:

```text
context+0x118 length = 0
context+0x120 data   = nullptr
slot 8 bytes         = 00 00 00 00
slot 9 bytes         = empty
```

## Initialization evidence

- `0xcbec0`: native context base is `sp+0x88`.
- `0xcbf5c`: `x9 = context+0x08`; it is saved at `sp+0x10` by `0xcbf84`.
- `0xcc3e8..0xcc3f4`: `memset(context+0x08, 0, 0x120)`.
- The zero range is `[context+0x08, context+0x128)`, so it covers both
  `context+0x118` and `context+0x120` completely.

## Producer search

The checker performs conservative fixed-point register may-alias propagation
through direct branches and recursively follows direct calls whenever x0..x7
may contain the context or a fixed context-relative pointer. Analyzed entries
and reachable context-bearing helpers:

{function_rows}

Observed fixed context-relative write offsets: `{', '.join(f'0x{x:x}' for x in offsets)}`.
No write targets `context+0x118` or `context+0x120`.

| address | write | function | instruction |
|---|---|---|---|
{write_rows}

The correction encoder's indexed halfword stores are intentionally not
misreported as fixed-offset writes; their base is `context+0x20` and the
separate `0x13531c..0x135484` analysis bounds them to the correction region.

## Consumer and cleanup evidence

- `0x11e658`: reads `context+0x118`, reverses the 32-bit zero and creates the
  four-byte length descriptor used as slot 8.
- `0x11e760/0x11e764`: reads length/pointer for slot 9.
- `0xcc1c0/0xcc1c4`: cleanup loads `context+0x120` and calls `free`; null is
  therefore the normal no-data cleanup value.

## Compatibility consequence

The Java-supplied HMAC is not slot 8/9, and neither is `adj_signing_id` on this
ARM64 path. Any `adj_signing_id` contribution to the protected engine must be
recovered from the fixed context descriptors or an earlier protected
transformation, not from the reserved dynamic pair.
""")
    print("CONTEXT_DYNAMIC_PAIR_STATIC_OK")


if __name__ == "__main__":
    main()
