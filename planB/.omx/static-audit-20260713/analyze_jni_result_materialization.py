#!/usr/bin/env python3
"""Verify and document the ARM64 nSign Java byte[] materialization path."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
DISASSEMBLY = HERE.parent / "libsigner-arm64-objdump.txt"
OUTPUT = HERE / "arm64-jni-result-materialization.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    text = DISASSEMBLY.read_text(errors="replace")
    checks = [
        (r"aec8:.*str\s+xzr, \[x21, #0x18\]", "a334 clears context+0x18"),
        (r"aecc:.*bl\s+0x9aa5c.*aee4:.*bl\s+0x9aa5c.*aefc:.*bl\s+0x9aa5c.*af38:.*b\s+0x9aa5c", "four Map.remove calls"),
        (r"9b3ac:.*adr\s+x2, 0x144a9c.*9b3b4:.*adr\s+x3, 0x144ab0.*9b3c4:.*ldr\s+x8, \[x8, #0x108\]", "remove method lookup"),
        (r"9afc0:.*ldr\s+x8, \[x8, #0x110\]", "CallObjectMethod"),
        (r"9b474:.*ldr\s+x8, \[x8, #0x538\]", "NewStringUTF"),
        (r"af7c:.*add\s+x3, x2, #0x18.*afb4:.*bl\s+0x9548c", "af3c passes context+0x18 to byte-array constructor"),
        (r"954c4:.*ldr\s+x8, \[x8, #0x580\].*954d8:.*blr\s+x8.*9555c:.*str\s+x0, \[x19\]", "NewByteArray and output store"),
        (r"95618:.*str\s+xzr, \[x19\].*95638:.*mov\s+w8, #0x1f.*95648:.*str\s+w8, \[x21\]", "NewByteArray failure clears output and writes status 31"),
        (r"bd18:.*ldp\s+x8, x4, \[sp, #0x8\].*bd28:.*ldr\s+x2, \[x8\].*bd34:.*bl\s+0x95680", "af3c copies native bytes to created array"),
        (r"9578c:.*ldr\s+x8, \[x8, #0x680\].*95794:.*blr\s+x8", "SetByteArrayRegion"),
        (r"957c0:.*str\s+w28, \[x9\].*957cc:.*mov\s+w28, #0x20", "SetByteArrayRegion exception status 32"),
        (r"95800:.*mov\s+w28, #0x3", "null target array status 3"),
        (r"11ea38:.*ldr\s+w8, \[x8\].*11ea44:.*cmp\s+w8, #0x0.*11ea48:.*cset\s+w0, eq", "final consumer succeeds iff status is zero"),
        (r"cc1c8:.*ldr\s+x8, \[sp, #0xa0\].*cc1d8:.*str\s+x8, \[sp, #0x78\].*cc450:.*ldr\s+x0, \[sp, #0x78\]", "orchestrator returns context+0x18"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text(
        """# ARM64 JNI result materialization

## Confirmed call chain

```text
0x11da64 final consumer
  -> 0xa334 removes temporary/native metadata and clears context+0x18
  -> protected engine produces native result bytes
  -> 0xaf3c materializes those bytes as a Java byte[] at context+0x18
       0x9548c: NewByteArray(length)
       0x95680: SetByteArrayRegion(array, 0, length, nativeBytes)
  -> 0xcbe98 returns context+0x18
```

## `0xa334` is cleanup, not the byte-array constructor

- `0xaec8`: `str xzr, [x21,#0x18]` clears `context+0x18`.
- `0xaecc/0xaee4/0xaefc/0xaf38`: four calls/tail-call to `0x9aa5c`.
- `0x9aa5c` resolves `Map.remove(Object)` using the decoded strings
  `remove` and `(Ljava/lang/Object;)Ljava/lang/Object;`, creates a Java string
  through JNI vtable offset `0x538`, invokes the object method through offset
  `0x110`, and deletes local references through offset `0xb8`.
- The four decoded keys are `headers_id`, `native_version`,
  `adj_signing_id`, and `algorithm`.

## Java byte-array creation

`0xaf3c(status, env, context, nativeLength, nativeBytes)` computes
`context+0x18` at `0xaf7c` and passes that address to `0x9548c`.

`0x9548c` calls `NewByteArray(length)` at JNI vtable offset `0x580` and stores
the returned reference through the supplied output pointer. A pending exception
or a null return writes status `31` and clears the output. A preexisting nonzero
status is preserved but also clears the newly-created output reference.

## Java byte-array copy

At `0xbd18..0xbd34`, `0xaf3c` loads the reference from `context+0x18` and calls
`0x95680(status, env, array, 0, nativeLength, nativeBytes)`.

- null target array -> status `3`, no JNI call;
- non-null target -> `SetByteArrayRegion` at JNI vtable offset `0x680`;
- pending exception after the copy -> status `32`;
- successful copy -> status unchanged.

## Final native/JNI return semantics

- `0x11ea38..0x11ea48`: final consumer returns true exactly when status is zero.
- `0xcc1c8..0xcc1d8`: the orchestrator loads `context+0x18` into its return slot.
- `0xcc450`: the JNI-facing return value is that slot.

Thus a successful result is a non-null Java `byte[]` containing the exact
native envelope bytes. Array creation failure clears the reference. A copy
exception leaves the allocated reference in `context+0x18`, but status `32`
and the pending Java exception mean there is no normal Java return. The
standalone null-target status `3` is not reached through the normal `0xaf3c`
chain because `0x9548c` converts a null allocation to status `31` first.
`0xcc47c` is not a second result materializer.
""",
        encoding="utf-8",
    )
    print("JNI_RESULT_MATERIALIZATION_STATIC_OK")


if __name__ == "__main__":
    main()
