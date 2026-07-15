#!/usr/bin/env python3
"""Verify the ARM64 0xaf3c result/metadata transaction without executing it."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
DISASSEMBLY = HERE.parent / "libsigner-arm64-objdump.txt"
OUTPUT = HERE / "arm64-native-result-builder-transaction.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    full_text = DISASSEMBLY.read_text(errors="replace")
    lines = []
    for line in full_text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and 0xAF3C <= int(match.group(1), 16) < 0xCDE4:
            lines.append(line)
    text = "\n".join(lines)
    checks = [
        (r"afb4:.*bl\s+0x9548c.*afb8:.*ldr\s+w8, \[x19\].*afdc:.*cmp\s+w8, #0x0.*aff4:.*csel\s+x23, x16, x9, eq", "NewByteArray status split"),
        (r"bd18:.*ldr\s+x2, \[x8\].*bd34:.*bl\s+0x95680.*bd38:.*ldr\s+w8, \[x21\].*bd50:.*cmp\s+w8, #0x0.*be60:.*csel\s+x9, x9, x8, eq", "SetByteArrayRegion status split"),
        (r"b6d4:.*mov\s+x9, #0x8d82.*b6e4:.*movk\s+x9, #0x3dea, lsl #32.*b6ec:.*movk\s+x9, #0x43c0, lsl #48.*b6f4:.*cmp\s+x8, x10", "NewByteArray failure converges to rollback state"),
        (r"b404:.*mov\s+x9, #0x8d82.*b414:.*movk\s+x9, #0x3dea, lsl #32.*b41c:.*movk\s+x9, #0x43c0, lsl #48.*b424:.*cmp\s+x8, x10", "SetByteArrayRegion failure converges to rollback state"),
        (r"c518:.*add\s+x3, x3, #0xea8.*add\s+x4, x4, #0xeb4.*c544:.*bl\s+0x9954c.*c548:.*ldr\s+w8, \[x21\].*c560:.*cmp\s+w8, #0x0.*c670:.*csel\s+x9, x8, x9, eq", "headers_id put and status split"),
        (r"c7c8:.*add\s+x3, x3, #0xed0.*add\s+x4, x4, #0xea0.*c7f4:.*bl\s+0x9954c.*c7f8:.*ldr\s+w8, \[x21\].*c810:.*cmp\s+w8, #0x0.*c920:.*csel\s+x9, x8, x9, eq", "adj_signing_id put and status split"),
        (r"bfd0:.*add\s+x3, x3, #0xeb8.*add\s+x4, x4, #0xec8.*bffc:.*bl\s+0x9954c.*c000:.*ldr\s+w8, \[x21\].*c018:.*cmp\s+w8, #0x0.*c118:.*csel\s+x9, x8, x27, eq", "native_version put and asymmetric status split"),
        (r"c678:.*add\s+x3, x3, #0xee0.*add\s+x4, x4, #0xeec.*c6a4:.*bl\s+0x9954c.*c6a8:.*ldr\s+w8, \[x21\].*c6c0:.*cmp\s+w8, #0x0.*c7c0:.*csel\s+x9, x8, x13, eq", "algorithm put and final status split"),
        (r"b50c:.*mov\s+x9, #0x8d82.*b51c:.*movk\s+x9, #0x3dea, lsl #32.*b524:.*movk\s+x9, #0x43c0, lsl #48.*b52c:.*cmp\s+x8, x10", "headers_id failure to rollback"),
        (r"b684:.*mov\s+x9, #0x8d82.*b694:.*movk\s+x9, #0x3dea, lsl #32.*b69c:.*movk\s+x9, #0x43c0, lsl #48.*b6a4:.*cmp\s+x8, x10", "adj_signing_id failure to rollback"),
        (r"b244:.*mov\s+x9, #0x8d82.*b250:.*movk\s+x9, #0x3dea, lsl #32.*b254:.*movk\s+x9, #0x43c0, lsl #48.*b258:.*b\.eq\s+0xb14c", "algorithm failure to rollback"),
        (r"b1c0:.*cmp\s+x8, x27.*b1c4:.*movk\s+x9, #0xa70c, lsl #16.*b1c8:.*movk\s+x9, #0x3dea, lsl #32.*b1cc:.*movk\s+x9, #0x43c0, lsl #48.*b1d0:.*b\.eq\s+0xb14c", "native_version failure to rollback"),
        (r"b4ac:.*cmp\s+x8, x9.*b4b0:.*b\.eq\s+0xc250.*c250:.*bl\s+0xa334", "common rollback state calls metadata cleanup"),
        (r"b4e4:.*mov\s+x9, #0xeef5.*b4f4:.*movk\s+x9, #0xa55b, lsl #32.*b4fc:.*movk\s+x9, #0x4c81, lsl #48.*b504:.*cmp\s+x8, x10", "algorithm success selects final return state"),
        (r"b744:.*mov\s+x10, #0xeef5.*b750:.*movk\s+x10, #0xa55b, lsl #32.*b754:.*movk\s+x10, #0x4c81, lsl #48.*b760:.*b\s+0xcdb8.*cdb8:.*ldp\s+x20, x19", "success state returns without rollback"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text(
        """# ARM64 `0xaf3c` native result-builder transaction

This report reads only the existing ARM64 objdump. It does not load or execute
`libsigner.so`.

## Confirmed success order

The flattened state transitions recover this runtime order; call-site address
order is not runtime order:

```text
NewByteArray                         0xafb4
SetByteArrayRegion                  0xbd34
Map.put(headers_id, 9)              0xc544
Map.put(adj_signing_id, 1400000)    0xc7f4
Map.put(native_version, 3.67.0)     0xbffc
Map.put(algorithm, adj8)            0xc6a4
return                              0xcdb8
```

The key/value addresses at the four calls are direct evidence:

| call | key/value VMAs | decoded pair |
|---:|---|---|
| `0xc544` | `0x142ea8`, `0x142eb4` | `headers_id=9` |
| `0xc7f4` | `0x142ed0`, `0x142ea0` | `adj_signing_id=1400000` |
| `0xbffc` | `0x142eb8`, `0x142ec8` | `native_version=3.67.0` |
| `0xc6a4` | `0x142ee0`, `0x142eec` | `algorithm=adj8` |

## Failure and rollback behavior

- `NewByteArray` failure state `0x73a9e0897a6e742c` and
  `SetByteArrayRegion` failure state `0x2773b06d406c84a3` converge to
  `0x43c03deaa70c8d82`, dispatched at `0xc250`.
- `headers_id` and `adj_signing_id` put failures also converge directly to
  the same rollback state.
- `native_version` failure is selected through `x27`; `0xb1c4..0xb1cc`
  constructs the same common rollback state before the conditional dispatcher
  jump at `0xb1d0`. It does not branch to `0xbaac`.
- Any nonzero status after a metadata put reaches `0xc250`, which
  calls `0xa334`. That cleanup clears `context+0x18` and removes all four
  metadata keys. A cleanup failure may overwrite the transaction status.
- Final success selects state `0x4c81a55be310eef5` and returns at `0xcdb8`
  without calling rollback.

## Lazy decode calls are synchronization, not fallible metadata producers

The calls to `0x139800` are byte compare-and-swap operations used to guard
one-time XOR decoding of static key/value buffers. They return the previous
guard byte and choose decode-versus-wait paths; they do not allocate and do
not introduce an additional transaction status code.
""",
        encoding="utf-8",
    )
    print("NATIVE_RESULT_BUILDER_TRANSACTION_STATIC_OK")


if __name__ == "__main__":
    main()
