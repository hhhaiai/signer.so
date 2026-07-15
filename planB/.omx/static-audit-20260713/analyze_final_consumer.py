#!/usr/bin/env python3
"""Build a bounded CFG summary for the arm64 final-result consumer.

The source objdump file contains the next function after the consumer.  This
script deliberately excludes everything after the stack-check call at 0x11ea74.
It only parses text; it never loads or executes libsigner.so.
"""

from __future__ import annotations

import pathlib
import re


START = 0x11DA64
END = 0x11EA74
HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE / "arm64-final-consumer-disasm.txt"
OUTPUT = HERE / "arm64-final-consumer-cfg.md"

INSTRUCTION = re.compile(
    r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)(?:\s+(.*?))?(?:\s+//.*)?$"
)
TARGET = re.compile(r"0x([0-9a-f]+)")
def parse() -> list[dict[str, object]]:
    instructions: list[dict[str, object]] = []
    for line in SOURCE.read_text(errors="replace").splitlines():
        match = INSTRUCTION.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        if START <= address <= END:
            instructions.append(
                {
                    "address": address,
                    "mnemonic": match.group(2),
                    "operands": (match.group(3) or "").strip(),
                    "line": line.strip(),
                }
            )
    return instructions


def branch_target(instruction: dict[str, object]) -> int | None:
    mnemonic = str(instruction["mnemonic"])
    if mnemonic == "bl" or not (mnemonic == "b" or mnemonic.startswith("b.")):
        return None
    match = TARGET.search(str(instruction["operands"]))
    return int(match.group(1), 16) if match else None


def main() -> None:
    instructions = parse()
    by_address = {int(item["address"]): item for item in instructions}
    addresses = sorted(by_address)
    next_address = {address: addresses[index + 1] for index, address in enumerate(addresses[:-1])}

    leaders = {START}
    for instruction in instructions:
        address = int(instruction["address"])
        mnemonic = str(instruction["mnemonic"])
        target = branch_target(instruction)
        if target is not None and START <= target <= END:
            leaders.add(target)
        if (mnemonic == "b" or mnemonic.startswith("b.") or mnemonic == "ret") and address in next_address:
            leaders.add(next_address[address])
    leaders = sorted(leaders)

    blocks: list[tuple[int, list[dict[str, object]]]] = []
    for index, leader in enumerate(leaders):
        limit = leaders[index + 1] if index + 1 < len(leaders) else END + 4
        body = [item for item in instructions if leader <= int(item["address"]) < limit]
        if body:
            blocks.append((leader, body))

    calls: list[tuple[int, str]] = []
    edges: list[tuple[int, int, str]] = []
    for index, (leader, body) in enumerate(blocks):
        for instruction in body:
            if instruction["mnemonic"] == "bl":
                calls.append((int(instruction["address"]), str(instruction["operands"])))
        last = body[-1]
        mnemonic = str(last["mnemonic"])
        target = branch_target(last)
        if target is not None and START <= target <= END:
            edges.append((leader, target, "branch" if mnemonic == "b" else mnemonic))
        if mnemonic.startswith("b.") and index + 1 < len(blocks):
            edges.append((leader, blocks[index + 1][0], "fallthrough"))
        elif mnemonic not in {"b", "ret"} and index + 1 < len(blocks):
            edges.append((leader, blocks[index + 1][0], "fallthrough"))

    lines = [
        "# arm64 final consumer bounded CFG",
        "",
        "## Scope",
        "",
        f"- Included: `0x{START:x}..0x{END:x}`.",
        "- `0x11ea70` is the normal `ret`; `0x11ea74` is the stack-check failure call.",
        "- Excluded: the next function beginning at `0x11ea78`.",
        f"- Parsed instructions: **{len(instructions)}**; basic blocks: **{len(blocks)}**; CFG edges: **{len(edges)}**.",
        "",
        "## Direct calls",
        "",
        "| call site | target |",
        "|---:|---|",
    ]
    lines.extend(f"| `0x{address:x}` | `{target}` |" for address, target in calls)
    lines.extend(
        [
            "",
            "## Original-context offsets referenced",
            "",
            "The prologue keeps the original context in x19 and saves it at sp+0x70 before opaque register rotation.",
            "",
            "`+0x20`, `+0x30`, `+0x50`, `+0xe0`, `+0xf0`, `+0x118` (length), `+0x120` (data pointer)",
            "",
            "## Basic blocks",
            "",
            "Each row records the terminal instruction and statically visible successors.",
            "",
            "| block | instruction range | terminal | successors | direct calls |",
            "|---:|---:|---|---|---|",
        ]
    )
    outgoing: dict[int, list[tuple[int, str]]] = {}
    for source, target, kind in edges:
        outgoing.setdefault(source, []).append((target, kind))
    for leader, body in blocks:
        block_calls = [
            f"0x{int(item['address']):x}->{item['operands']}"
            for item in body
            if item["mnemonic"] == "bl"
        ]
        successors = ", ".join(
            f"0x{target:x} ({kind})" for target, kind in outgoing.get(leader, [])
        )
        lines.append(
            f"| `0x{leader:x}` | `0x{int(body[0]['address']):x}..0x{int(body[-1]['address']):x}` "
            f"| `{body[-1]['mnemonic']} {body[-1]['operands']}` | {successors or '-'} "
            f"| {', '.join(block_calls) or '-'} |"
        )

    OUTPUT.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
