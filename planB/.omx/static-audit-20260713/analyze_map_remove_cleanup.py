#!/usr/bin/env python3
"""Verify Map.remove JNI failure/status/cleanup behavior across ARM64 and x86_64."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ARM64 = HERE.parent / "libsigner-arm64-objdump.txt"
X86_64 = HERE / "x86_64-full-objdump.txt"
OUTPUT = HERE / "arm64-map-remove-cleanup.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    arm64 = ARM64.read_text(errors="replace")
    x86 = X86_64.read_text(errors="replace")

    arm_checks = [
        (r"9aa7c:.*cmp\s+x1, #0x0.*9aa88:.*cmp\s+x3, #0x0.*9aa90:.*ccmp\s+x2, #0x0", "env/key/map validation"),
        (r"9aed4:.*mov\s+w8, #0x3.*9aee0:.*stur\s+xzr, \[x29, #-0x30\]", "invalid-argument status 3"),
        (r"9b150:.*ldr\s+x8, \[x21\].*9b15c:.*ldr\s+x8, \[x8, #0xf8\].*9b16c:.*bl\s+0x92a20", "GetObjectClass and exception check"),
        (r"9ae78:.*mov\s+w8, #0x12.*9aea0:.*ldur\s+x9, \[x29, #-0x30\].*9aecc:.*str\s+w11, \[x9\]", "class/method failure status 18"),
        (r"9b39c:.*adr\s+x8, 0x1468ac.*9b3ac:.*adr\s+x2, 0x144a9c.*9b3b4:.*adr\s+x3, 0x144ab0.*9b3c4:.*ldr\s+x8, \[x8, #0x108\]", "GetMethodID remove lookup"),
        (r"9b468:.*ldr\s+x8, \[x21\].*9b474:.*ldr\s+x8, \[x8, #0x538\].*9b484:.*bl\s+0x92a20", "NewStringUTF and exception check"),
        (r"9aef8:.*ldr\s+w8, \[sp, #0x2c\].*9af0c:.*movk\s+x8, #0x335e.*9af10:.*str\s+w11, \[x9\]", "NewStringUTF failure status 34"),
        (r"9afb4:.*ldr\s+x8, \[x21\].*9afc0:.*ldr\s+x8, \[x8, #0x110\].*9afcc:.*mov\s+x19, x0.*9afd4:.*bl\s+0x92a20", "CallObjectMethod and returned object"),
        (r"9b060:.*mov\s+x10, #0xe452.*9b068:.*mov\s+w11, #0x1c.*9b07c:.*str\s+w11, \[x9\]", "CallObjectMethod exception status 28"),
        (r"9b304:.*ldr\s+x8, \[x21\].*9b30c:.*ldr\s+x1, \[sp, #0x40\].*9b310:.*ldr\s+x8, \[x8, #0xb8\]", "key-string DeleteLocalRef"),
        (r"9af28:.*ldr\s+x8, \[x21\].*9af30:.*ldr\s+x1, \[sp, #0x20\].*9af34:.*ldr\s+x8, \[x8, #0xb8\]", "opaque-anchor DeleteLocalRef"),
        (r"9b36c:.*cmp\s+x23, #0x0.*9b394:.*str\s+x23, \[sp, #0x20\]", "opaque-anchor cleanup setup"),
        (r"9af8c:.*ldur\s+x9, \[x29, #-0x8\].*9afa8:.*stur\s+x9, \[x29, #-0x18\].*9b540:.*ldr\s+x8, \[x21\].*9b548:.*ldr\s+x1, \[sp, #0x18\].*9b54c:.*ldr\s+x8, \[x8, #0xb8\]", "class DeleteLocalRef"),
        (r"aeb4:.*ldp\s+x20, x21, \[sp\].*aec8:.*str\s+xzr, \[x21, #0x18\].*aecc:.*bl\s+0x9aa5c.*aee4:.*bl\s+0x9aa5c.*aefc:.*bl\s+0x9aa5c.*af38:.*b\s+0x9aa5c", "a334 unconditional four removals"),
    ]
    for pattern, description in arm_checks:
        require(arm64, pattern, description)

    x86_checks = [
        (r"9be80:.*xorl\s+%ecx, %ecx.*9be8a:.*pushq\s+\$0x3", "x86_64 status 3"),
        (r"9be40:.*pushq\s+\$0x12", "x86_64 status 18"),
        (r"9bea0:.*movl\s+\$0x22, \(%rax\)", "x86_64 status 34"),
        (r"9bfaa:.*movl\s+\$0x1c, \(%rax\)", "x86_64 status 28"),
        (r"9c17c:.*testq\s+%r13, %r13.*9c19a:.*movq\s+%r13, 0x50\(%rsp\)", "x86_64 opaque-anchor cleanup setup"),
        (r"9bec9:.*callq\s+\*0xb8\(%rax\)", "x86_64 opaque-anchor DeleteLocalRef"),
    ]
    for pattern, description in x86_checks:
        require(x86, pattern, description)

    # The ARM64 CallObjectMethod result is kept only in x19. There is no store
    # of x19 into any DeleteLocalRef argument slot and no later x19 use except
    # moving it into a dispatcher scratch register on the exception path.
    body_match = re.search(r"(?ms)^\s*9aa5c:.*?(?=^\s*9b684:)", arm64)
    if body_match is None:
        raise SystemExit("missing ARM64 Map.remove helper body")
    x19_lines = [line for line in body_match.group(0).splitlines() if re.search(r"\bx19\b", line)]
    expected_x19_addresses = {"9aa74", "9ab7c", "9afcc", "9b074", "9b664"}
    actual_x19_addresses = {
        match.group(1)
        for line in x19_lines
        if (match := re.match(r"\s*([0-9a-f]+):", line))
    }
    if actual_x19_addresses != expected_x19_addresses:
        raise SystemExit(f"unexpected CallObjectMethod-result flow: {sorted(actual_x19_addresses)}")

    OUTPUT.write_text(
        """# ARM64 `Map.remove` status and cleanup model

## Function and arguments

`0x9aa5c..0x9b680` implements the equivalent of:

```text
removeFromMap(status, env, map, keyCString)
```

Entry validation requires non-null `env`, `map`, and `keyCString`.

## Failure status mapping

| stage | ARM64 evidence | native status |
|---|---:|---:|
| invalid env/map/key | `0x9aed4` | `3` |
| `GetObjectClass` exception/null | `0x9ae78 -> 0x9aea0` | `18` |
| `GetMethodID(remove, signature)` exception/null | `0x9ae78 -> 0x9aea0` | `18` |
| `NewStringUTF(key)` exception/null | `0x9aef8..0x9af10` | `34` |
| `CallObjectMethod(Map.remove)` pending exception | `0x9b060..0x9b07c` | `28` |

A successful call leaves the incoming status word unchanged. Later failures
overwrite an earlier nonzero status because the helper does not short-circuit
on the incoming status value.

## JNI references

- class reference: deleted when non-null;
- key `jstring`: deleted when it was created, including the unusual case where
  `NewStringUTF` returned non-null while an exception was reported;
- `Map.remove` return object: stored in `x19` at `0x9afcc`, but never passed to
  `DeleteLocalRef` and never otherwise consumed;
- opaque anchor: `x23` is initialized from the flattened initial-state constant,
  saved at `0x9b394`, and passed to `DeleteLocalRef` at `0x9af28..0x9af38` on
  paths that created a key string. The corresponding x86_64 function stores
  `%r13` and performs the same vtable `+0xb8` call. This is not the
  `CallObjectMethod` result.

The opaque-anchor deletion is documented as an observed target behavior, not
executed by the platform-neutral C++ model. A real JNI adapter should expose it
as a compatibility observation until isolated ART testing establishes whether
release ART ignores, warns on, or rejects the invalid local-reference value.

## `0xa334` caller behavior

`0xa334` clears `context+0x18`, then unconditionally invokes `0x9aa5c` four
times for:

```text
headers_id
adj_signing_id
native_version
algorithm
```

There is no status check between the calls. A later remove failure can overwrite
an earlier failure code; a later successful remove leaves an earlier failure
unchanged.
""",
        encoding="utf-8",
    )
    print("MAP_REMOVE_CLEANUP_STATIC_OK")


if __name__ == "__main__":
    main()
