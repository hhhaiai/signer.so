#!/usr/bin/env python3
"""Verify the ARM64 JNI Map.put helper status and local-reference lifecycle."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
DISASSEMBLY = HERE.parent / "libsigner-arm64-objdump.txt"
OUTPUT = HERE / "arm64-map-put-cleanup.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    text = DISASSEMBLY.read_text(errors="replace")
    checks = [
        (r"99570:.*cmp\s+x1, #0x0.*9957c:.*cmp\s+x4, #0x0.*99580:.*ccmp\s+x3, #0x0.*99598:.*ccmp\s+x2, #0x0", "env/map/key/value validation"),
        (r"9a7c4:.*mov\s+w8, #0x3.*9a7d0:.*stur\s+xzr, \[x29, #-0x30\]", "invalid-argument status 3"),
        (r"9a688:.*ldr\s+x8, \[x22\].*9a694:.*ldr\s+x8, \[x8, #0xf8\].*9a6a4:.*bl\s+0x92a20", "GetObjectClass"),
        (r"99a8c:.*adr\s+x8, 0x1468a4.*99a9c:.*adr\s+x2, 0x144a50.*99aa4:.*adr\s+x3, 0x144a60.*99ab4:.*ldr\s+x8, \[x8, #0x108\]", "GetMethodID put lookup"),
        (r"99a60:.*mov\s+w8, #0x12.*99d58:.*str\s+w11, \[x9\]", "class/method failure status 18"),
        (r"99f00:.*ldr\s+x8, \[x22\].*99f0c:.*ldr\s+x8, \[x8, #0x538\].*99f20:.*bl\s+0x92a20", "key NewStringUTF"),
        (r"99dd8:.*ldr\s+x8, \[x22\].*99de4:.*ldr\s+x8, \[x8, #0x538\].*99df4:.*bl\s+0x92a20", "value NewStringUTF"),
        (r"99da4:.*ldr\s+w8, \[sp, #0x34\].*99da8:.*mov\s+w11, #0x22.*99dc0:.*str\s+w11, \[x9\]", "key-string failure status 34"),
        (r"9a41c:.*mov\s+w8, #0x22.*9a424:.*stur\s+w8, \[x29, #-0x44\]", "value-string failure status 34"),
        (r"9a4c4:.*ldr\s+x8, \[x22\].*9a4cc:.*ldp\s+x2, x1, \[sp, #0x38\].*9a4d4:.*ldr\s+x8, \[x8, #0x110\].*9a4e8:.*bl\s+0x92a20", "CallObjectMethod Map.put"),
        (r"9a600:.*mov\s+w8, #0x1c.*9a604:.*stur\s+w8, \[x29, #-0x44\]", "put invocation exception status 28"),
        (r"99c0c:.*ldr\s+x8, \[x22\].*99c14:.*ldr\s+x1, \[sp, #0x50\].*99c18:.*ldr\s+x8, \[x8, #0xb8\]", "key-string cleanup"),
        (r"9a038:.*ldr\s+x8, \[x22\].*9a040:.*ldr\s+x1, \[sp, #0x48\].*9a044:.*ldr\s+x8, \[x8, #0xb8\]", "returned-object cleanup"),
        (r"9a7ec:.*ldr\s+x8, \[x22\].*9a7f4:.*ldr\s+x1, \[sp, #0x20\].*9a7f8:.*ldr\s+x8, \[x8, #0xb8\]", "value-string cleanup"),
        (r"9a8fc:.*ldr\s+x8, \[x22\].*9a904:.*ldr\s+x1, \[sp, #0x28\].*9a908:.*ldr\s+x8, \[x8, #0xb8\]", "class cleanup"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text(
        """# ARM64 `Map.put` status and cleanup model

`0x9954c..0x9aa58` implements JNI `Map.put(String,String)` with method name
`put` and signature `(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`.

## Status mapping

| stage | status |
|---|---:|
| null env/map/key/value | `3` |
| `GetObjectClass` exception/null | `18` |
| `GetMethodID` exception/null | `18` |
| key `NewStringUTF` exception/null | `34` |
| value `NewStringUTF` exception/null | `34` |
| `CallObjectMethod(Map.put)` pending exception | `28` |
| success | incoming status unchanged |

## Reference cleanup

The helper conditionally deletes every reference that it actually creates:

- class returned by `GetObjectClass`;
- key `jstring`;
- value `jstring`;
- previous Map value returned by `Map.put`, when non-null.

Unlike `0x9aa5c Map.remove`, this helper's four `DeleteLocalRef` argument slots
are populated by the corresponding live JNI references; no opaque-anchor
deletion was found in this function.
""",
        encoding="utf-8",
    )
    print("MAP_PUT_CLEANUP_STATIC_OK")


if __name__ == "__main__":
    main()
