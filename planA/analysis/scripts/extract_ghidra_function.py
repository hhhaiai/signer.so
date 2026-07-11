#!/usr/bin/python3
"""Extract one balanced C-like function from a Ghidra text export."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


def _function_start(source: str, function_name: str) -> tuple[int, int]:
    pattern = re.compile(
        rf"(?m)^[^\n{{;]*\b{re.escape(function_name)}\s*\([^;]*?(?=\n?\s*\{{)"
    )
    match = pattern.search(source)
    if match is None:
        raise ValueError(f"function {function_name!r} not found")

    declaration_start = match.start()
    line_start = source.rfind("\n", 0, declaration_start) + 1
    cursor = line_start
    while cursor > 0:
        previous_end = cursor - 1
        previous_start = source.rfind("\n", 0, previous_end) + 1
        line = source[previous_start:previous_end].strip()
        if line == "" or line.startswith("//"):
            cursor = previous_start
            continue
        break
    return cursor, match.end()


def _balanced_end(source: str, opening: int) -> int:
    depth = 0
    state = "code"
    quote = ""
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state == "string":
            if char == "\\":
                index += 1
            elif char == quote:
                state = "code"
        else:
            if char == "/" and next_char == "/":
                state = "line-comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block-comment"
                index += 1
            elif char in ('"', "'"):
                state = "string"
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index + 1
                if depth < 0:
                    break
        index += 1
    raise ValueError("function body has unbalanced braces")


def extract_function(source: str, function_name: str) -> str:
    start, after_signature = _function_start(source, function_name)
    opening = source.find("{", after_signature)
    if opening < 0:
        raise ValueError(f"function {function_name!r} has no body")
    end = _balanced_end(source, opening)
    return source[start:end].strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("function")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        extracted = extract_function(args.source.read_text(encoding="utf-8"), args.function)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(extracted, encoding="utf-8")
        else:
            sys.stdout.write(extracted)
    except (OSError, ValueError) as exc:
        print(f"extract_ghidra_function: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
