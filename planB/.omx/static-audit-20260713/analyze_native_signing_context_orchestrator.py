#!/usr/bin/env python3
"""Verify ARM64/x86_64 signing-context orchestration without executing the SO."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ARM64 = HERE.parent / "libsigner-arm64-objdump.txt"
X86_64 = HERE / "x86_64-full-objdump.txt"
OUTPUT = HERE / "arm64-native-signing-context-orchestrator.md"


def function_slice(text: str, start: int, end: int) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and start <= int(match.group(1), 16) < end:
            lines.append(line)
    return "\n".join(lines)


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.S) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    arm64_full = ARM64.read_text(errors="replace")
    x86_full = X86_64.read_text(errors="replace")
    clock = function_slice(arm64_full, 0xCC47C, 0xCC604)
    orchestrator = function_slice(arm64_full, 0xCBE98, 0xCC47C)
    x86_clock = function_slice(x86_full, 0xBB5B8, 0xBB6AB)

    clock_checks = [
        (clock, r"cc49c:.*mov\s+w0, wzr.*cc4a4:.*bl\s+0x139eb0", "ARM64 clock_gettime(CLOCK_REALTIME)"),
        (clock, r"cc4a8:.*ldr\s+d0, \[sp, #0x10\].*cc4e4:.*ldr\s+d1, \[sp, #0x8\].*cc550:.*fmadd\s+d1, d1, d2, d0", "ARM64 seconds/nanoseconds millisecond conversion"),
        (clock, r"cc500:.*cmp\s+x19, #0x0.*cc52c:.*cmp\s+w0, #0x0", "ARM64 null status and syscall result splits"),
        (clock, r"cc58c:.*movi\s+d0, #0+.*cc598:.*str\s+w16, \[x19\]", "ARM64 failure status 14"),
        (clock, r"cc5a8:.*movi\s+d0, #0+", "ARM64 failure with null status returns zero"),
        (clock, r"cc5c0:.*fmov\s+d0, d1", "ARM64 success returns milliseconds"),
        (x86_clock, r"bb5d3:.*xorl\s+%edi, %edi.*bb5d8:.*callq\s+0x1328e0", "x86_64 clock_gettime(CLOCK_REALTIME)"),
        (x86_clock, r"bb5dd:.*cvtsi2sdq.*bb5e8:.*divsd.*bb5f0:.*mulsd.*bb633:.*addsd", "x86_64 millisecond conversion"),
        (x86_clock, r"bb671:.*movl\s+\$0xe, \(%rbx\).*bb677:.*xorpd", "x86_64 failure status 14"),
        (x86_clock, r"bb680:.*movapd\s+%xmm1, %xmm0", "x86_64 success return"),
    ]
    for text, pattern, description in clock_checks:
        require(text, pattern, description)

    orchestrator_checks = [
        (r"cbeec:.*ldp\s+x10, x8, \[x0, #0x18\].*cbef8:.*ldr\s+x13, \[x0\].*cbf18:.*ldp\s+x8, x9, \[x0, #0x8\]", "five input descriptor fields"),
        (r"cbf10:.*ldr\s+w12, \[x8\].*cbf24:.*cmp\s+w12, #0x1.*cbf2c:.*ccmp\s+x10, #0x0.*cbf54:.*ccmp\s+x9, #0x0.*cbf6c:.*ccmp\s+x8, #0x0.*cbf8c:.*ccmp\s+x13, #0x0", "API and four non-null input gate"),
        (r"cc160:.*mov\s+x10, #0x2ff4.*cc174:.*cmp\s+x8, x10.*cc17c:.*b\s+0xcc43c.*cc180:.*str\s+xzr, \[sp, #0x78\].*cc194:.*b\s+0xcbfc8", "invalid/clock-failure null return"),
        (r"cc3bc:.*add\s+x0, sp, #0x84.*cc3c0:.*bl\s+0xcc47c.*cc3c4:.*ldr\s+w8, \[sp, #0x84\].*cc3cc:.*cmp\s+w8, #0x0", "clock helper gate"),
        (r"cc3e8:.*ldr\s+x0, \[sp, #0x10\].*cc3f0:.*mov\s+w2, #0x120.*cc3f4:.*bl\s+0x139e10", "memset context+8 for 0x120 bytes"),
        (r"cc3fc:.*str\s+d8, \[sp, #0x88\].*cc404:.*str\s+w8, \[sp, #0x94\].*cc40c:.*str\s+x8, \[sp, #0x98\]", "timing/API/Map context fields"),
        (r"cc410:.*bl\s+0x134a1c.*cc418:.*mov\s+w8, #0x14", "descriptor/correction initialization"),
        (r"cc384:.*bl\s+0xd466c.*cc398:.*bl\s+0x1e578.*cc39c:.*ldr\s+w8, \[sp, #0x84\].*cc3b4:.*csel", "certificate stage status split"),
        (r"cc1e4:.*str\s+wzr, \[sp, #0x84\]", "certificate failure status reset"),
        (r"cc230:.*bl\s+0xcba90.*cc254:.*bl\s+0xcbbd4.*cc25c:.*bl\s+0x143e8.*cc264:.*bl\s+0xd6888.*cc26c:.*bl\s+0xf224.*cc28c:.*bl\s+0x11da64", "fixed context-stage and final-consumer order"),
        (r"cc294:.*tst\s+w0, #0x1.*cc2a4:.*csel.*cc308:.*str\s+wzr, \[sp, #0x84\].*cc358:.*ldr\s+x8, \[x8, #0x108\]", "both final-consumer results converge to cleanup"),
        (r"cc198:.*ldr\s+x0, \[sp, #0x40\].*cc19c:.*bl\s+0x139de0.*cc1b4:.*str\s+xzr, \[x8, #0x108\]", "conditional +0x108 free and clear"),
        (r"cc1fc:.*ldr\s+x0, \[sp, #0x38\].*cc200:.*bl\s+0x139de0.*cc218:.*str\s+xzr, \[x8, #0x110\].*cc2ac:.*ldr\s+x8, \[x8, #0x110\]", "conditional +0x110 load/free/clear blocks"),
        (r"cc1bc:.*ldr\s+x0, \[x8, #0x120\].*cc1c4:.*bl\s+0x139de0.*cc1c8:.*ldr\s+x8, \[sp, #0xa0\].*cc1d8:.*str\s+x8, \[sp, #0x78\]", "unconditional +0x120 free and +0x18 result extraction"),
        (r"cc450:.*ldr\s+x0, \[sp, #0x78\].*cc474:.*ret", "orchestrator return"),
    ]
    for pattern, description in orchestrator_checks:
        require(orchestrator, pattern, description)

    OUTPUT.write_text(
        """# ARM64 native signing-context orchestrator

This report reads existing ARM64/x86_64 objdump text only. It does not load or
execute `libsigner.so`.

## `0xcc47c` realtime helper

ARM64 `0xcc47c..0xcc600` and x86_64 `0xbb5b8..0xbb6a6` are equivalent:

```text
clock_gettime(CLOCK_REALTIME, &timespec)
success -> seconds * 1000.0 + nanoseconds / 1000000.0
failure + non-null status -> *status = 14, return 0.0
failure + null status     -> return 0.0 without a write
```

There is no `-ENOSYS`/`gettimeofday` fallback here. That fallback belongs to
the separate `0xd184` helper.

## `0xcbe98` loaded-input contract

The outer 0x28-byte descriptor is assumed accessible. Native code
unconditionally dereferences its four pointer slots before checking their
pointee values:

| descriptor offset | loaded value |
|---:|---|
| `+0x00` | `JNIEnv*` |
| `+0x08` | pointer to Java Context reference |
| `+0x10` | pointer to Java Map reference |
| `+0x18` | pointer to supplied Java-HMAC byte-array reference |
| `+0x20` | pointer to Android API integer |

The post-dereference gate accepts only:

```text
androidApi >= 1
JNIEnv != null
Context != null
Map != null
supplied Java HMAC != null
```

An invalid loaded value returns null. It is not safe to pass a null outer
descriptor or null pointer slot, because those are dereferenced before the
gate.

## Valid-path order

```text
0xcc47c CLOCK_REALTIME helper
memset(context+0x08, 0, 0x120)
store timing at +0x00, API at +0x0c, Map at +0x10
0x134a1c descriptor/correction initialization
zero 20-byte context+0xf0 region
0xd466c
0x1e578 certificate/digest stage
  nonzero status -> reset status to zero and continue
0xcba90 native context init stage 1
0xcbbd4 native context init stage 2
0x143e8 environment dispatcher
0xd6888 post-environment stage
0xf224 timing correction gate
0x11da64 final consumer
```

The final consumer's boolean result only selects the flattened cleanup entry;
both values converge to the same ownership cleanup. `0xcbe98` returns the
reference stored at context `+0x18`.

## Cleanup order

```text
if context+0x108 != null: free and clear it
if context+0x110 != null: free and clear it
free(context+0x120) unconditionally
return context+0x18
```

The C++ model is `modelRecoveredSigningContextOrchestrator()`, and the exact
clock helper is `recoveredSigningContextClockMilliseconds()`.
""",
        encoding="utf-8",
    )
    print("NATIVE_SIGNING_CONTEXT_ORCHESTRATOR_STATIC_OK")


if __name__ == "__main__":
    main()
