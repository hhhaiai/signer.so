#!/usr/bin/env python3
"""Summarize the protected arm64 helper ranges from objdump text only."""

from __future__ import annotations

from collections import Counter
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
SOURCE = HERE.parent / "libsigner-arm64-objdump.txt"
OUTPUT = HERE / "arm64-opaque-helper-summary.md"

RANGES = {
    "metadata preparation 0xa334": (0xA334, 0xAF3C),
    "metadata builder/orchestrator 0xaf3c": (0xAF3C, 0xCDE4),
    "protected crypto/data engine 0xf1ec8": (0xF1EC8, 0x11BA78),
    "generic range/byte adapter 0x11ba78": (0x11BA78, 0x11D40C),
    "result concatenation wrapper 0x11d798": (0x11D798, 0x11DA64),
}

INSTRUCTION = re.compile(
    r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+([a-z.]+)(?:\s+(.*))?$"
)


def instructions() -> list[tuple[int, str, str]]:
    result = []
    for line in SOURCE.read_text(errors="replace").splitlines():
        match = INSTRUCTION.match(line)
        if match:
            result.append((int(match.group(1), 16), match.group(2), match.group(3) or ""))
    return result


def direct_calls(items: list[tuple[int, str, str]]) -> Counter[str]:
    return Counter(operands for _, mnemonic, operands in items if mnemonic == "bl")


def main() -> None:
    all_instructions = instructions()
    recovered_container_lines: list[str] = []
    if OUTPUT.exists():
        current = OUTPUT.read_text(errors="replace")
        start = current.find("## Recovered protected-engine container vocabulary")
        end = current.find("## Recovered 32-bit materialization runs", start)
        if start >= 0 and end > start:
            recovered_container_lines = current[start:end].strip().splitlines()
    lines = [
        "# Arm64 protected helper static summary",
        "",
        "This report parses the existing objdump text. It does not load or execute libsigner.so.",
        "",
        "## Function boundaries and direct calls",
        "",
    ]
    for name, (start, end) in RANGES.items():
        items = [item for item in all_instructions if start <= item[0] < end]
        calls = direct_calls(items)
        lines.extend(
            [
                f"### {name}",
                "",
                f"- Strict range: `0x{start:x}..0x{end - 4:x}`",
                f"- Instructions: **{len(items)}**",
                f"- Direct calls: **{sum(calls.values())}**, unique targets: **{len(calls)}**",
                "",
                "| count | target |",
                "|---:|---|",
            ]
        )
        lines.extend(f"| {count} | `{target}` |" for target, count in calls.most_common())
        lines.append("")

    lines.extend(
        [
            "## Static classification",
            "",
            "- `0xaf3c` calls metadata builder `0x9954c` exactly four times and also calls `0xa334`; these ranges belong to parameter/metadata construction, not a second final cipher.",
            "- `0x11d798` calls `0x11ba78` twice with callback addresses `0x11d528` and `0x11d40c`, allocates `combined_length + 1`, and returns the concatenated buffer through output pointers.",
            "- Callback `0x11d528` contains the explicit `memcpy` append path; callback `0x11d40c` accumulates/advances a destination pointer. These are generic output adapters.",
            "- `0xf1ec8..0x11ba74` is the only remaining large protected crypto/data engine. It contains the recovered AES, SHA-256, HMAC, correction and IV regions.",
            "- The engine has exactly two direct `rand@plt` call sites (`0x11a62c`, `0x11a64c`); the state machine loops over those sites to produce the four IV words. No second random/nonce call family is present in this engine.",
            "",
        ]
    )
    if recovered_container_lines:
        lines.extend(recovered_container_lines)
        lines.append("")
    lines.extend(
        [
            "## Recovered 32-bit materialization runs",
            "",
            "### Final HMAC key at 0xf9014..0xf9298",
            "",
            "```text",
            "caab8344 4a214639 2abb96b6 42306155",
            "29a770c6 3c163c1c 7528673e 0671728f",
            "```",
            "",
            "### Field-4 SHA source words at 0xf97c8..0xf9a3c",
            "",
            "```text",
            "018a6c12 190ae32c ce07f549 3186d96f",
            "cb061855 af48c173 9da54cdc 06cf339e",
            "```",
            "",
            "Each word XOR `0xcccccccc` gives the recovered custom SHA-256 initial state.",
            "",
            "A scan of immediate 32-bit writes through engine writer `0x138a70` finds exactly three runs of at least eight consecutive non-small words: the HMAC key at `0xf9014`, the field-4 SHA source state at `0xf97c8`, and the run beginning `a6c52aab 77ab6249 ...` at `0xfb7b8`.",
            "",
            "The `0xfb7b8` run is later reused with logical indices `0x41..0x48` in the correction/environment construction region, so it is not a second final HMAC/AES key. This scan only rules out a second directly materialized eight-word key run; a key derived algebraically inside opaque states still requires data-flow proof.",
            "",
            "## GCM-looking string fragment correction",
            "",
            "The bytes rendered by strings as `=gcm` or `=gcmj` are the low bytes of the opaque 64-bit control-state constant:",
            "",
            "```text",
            "0x9224eb6a6d63673d",
            "```",
            "",
            "Cross-ABI evidence:",
            "",
            "- arm64 `0x6dcd8..0x6dce8`: materializes the constant and compares it as a state value.",
            "- x86_64 `0x5e946`: `movabs 0x9224eb6a6d63673d`, followed by a state comparison.",
            "- x86 `0x5938d` and `0x5df6d`: compares/XORs the two 32-bit halves `0x6d63673d` and `0x9224eb6a`.",
            "- armv7 string hits contain the same two words in mixed ARM/Thumb code/data alignment.",
            "",
            "Therefore these string hits are not evidence of an AES-GCM algorithm name or metadata value.",
            "",
            "## Current second-envelope verdict",
            "",
            "No second final-envelope key materialization, nonce generator, tag-length branch, metadata builder value or output-concatenation layout was found in these bounded helpers. The remaining uncertainty is reachability and full semantic naming inside the 42,732-instruction protected engine at `0xf1ec8..0x11ba74`.",
        ]
    )
    OUTPUT.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
