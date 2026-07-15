#!/usr/bin/env python3
"""Check the recovered descriptor/timing/return spine of ARM64 nSign."""

from __future__ import annotations

import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ASM = (HERE / "disasm-cc604-cd934.txt").read_text()
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text()


def require(pattern: str, label: str) -> None:
    if re.search(pattern, ASM, re.MULTILINE) is None:
        raise AssertionError(f"missing {label}: {pattern}")


# Export arguments saved by the prologue.
require(r"cc62c:.*stur\s+w5, \[x29, #-0x6c\]", "API save")
require(r"cc634:.*stp\s+x3, x4, \[x29, #-0x80\]", "Map/HMAC save")
require(r"cc63c:.*stp\s+x0, x2, \[x29, #-0x90\]", "env/context save")

# Five 16-byte wrappers plus the 0x30 descriptor and one output wrapper.
for address in ("ccd40", "ccd50", "ccd60", "ccd70", "ccd7c", "ccd88",
                "ccd98"):
    require(rf"{address}:.*sub\s+", f"dynamic wrapper allocation {address}")
require(r"ccda8:.*stur\s+x12, \[x8, #-0x10\]", "context wrapper")
require(r"ccdb0:.*stur\s+x23, \[x9, #-0x10\]", "Map wrapper")
require(r"ccdb4:.*stur\s+x8, \[x10, #-0x10\]", "HMAC wrapper")
require(r"ccdbc:.*stur\s+w8, \[x11, #-0x10\]", "API wrapper")
require(r"ccde4:.*stp\s+x1, x8, \[x25, #-0x30\]", "descriptor +0/+8")
require(r"ccdfc:.*stp\s+x9, x8, \[x25, #-0x20\]", "descriptor +10/+18")
require(r"ccdc8:.*stur\s+x26, \[x25, #-0x10\]", "descriptor +20")

require(r"ccdc0:.*bl\s+0xd4908", "periodic timer")
require(r"cd2dc:.*adr\s+x13, 0x1457c0", "environment key decode")
require(r"cd2e0:.*mov\s+w12, #0x28", "environment XOR byte")
require(r"cce40:.*bl\s+0xaebf8", "environment Map copy")
require(r"cccb8:.*ldrb\s+w8, \[x24\]", "environment value compare")
require(r"cccbc:.*ldrb\s+w9, \[x19\]", "sandbox literal compare")
require(r"cd4b8:.*bl\s+0xcc47c", "first realtime sample")
require(r"cd570:.*tst\s+w9, #0x1", "first clock status merge")
require(r"cd770:.*ldur\s+x0, \[x29, #-0x58\]", "descriptor argument")
require(r"cd774:.*bl\s+0xcbe98", "signing-context call")
require(r"cd77c:.*stur\s+x0, \[x29, #-0x98\]", "saved jbyteArray")
require(r"cd784:.*str\s+wzr, \[x27\]", "status reset")
require(r"cd788:.*bl\s+0xcc47c", "second realtime sample")
require(r"cd7b4:.*orr\s+w8, w8, w9", "second status merge")
require(r"cd84c:.*tst\s+w8, #0x1", "final auxiliary flag branch")
require(r"cd904:.*ldur\s+x0, \[x29, #-0x98\]", "saved result return")

for symbol in ("RecoveredNsignKnownInput", "RecoveredNsignKnownOutput",
               "modelRecoveredNsignKnownOrchestration",
               "RecoveredNsignDescriptorCC604",
               "RecoveredNsignOperationsCC604",
               "runRecoveredNsignOrchestratorCC604",
               "recoveredNsignOrchestratorCC604Regression"):
    if re.search(rf"\b{symbol}\b", CPP) is None:
        raise AssertionError(f"missing C++ {symbol}")

(HERE / "arm64-nsign-jni-orchestrator.md").write_text("""# ARM64 nSign JNI orchestrator

## Scope and status

- export/FDE: `0xcc604..0xcd934`
- status: **recovered**
- the flattened FDE has been interpreted end-to-end with stubbed callees;
  descriptor values, exact environment comparison, conditional timestamp
  logging, independent clock-status decisions and JNI return are closed

## JNI arguments

| register | Java/native meaning | prologue evidence |
|---|---|---|
| `x0` | `JNIEnv*` | `0xcc63c`, stack `-0x90` |
| `x1` | helper object/class, not forwarded | unused by descriptor |
| `x2` | Android `Context` | `0xcc63c`, stack `-0x88` |
| `x3` | Java Map/Object | `0xcc634`, stack `-0x80` |
| `x4` | supplied Java-HMAC `byte[]` | `0xcc634`, stack `-0x78` |
| `w5` | Android API | `0xcc62c`, stack `-0x6c` |

## Dynamic wrappers and descriptor

`0xccd3c..0xccd9c` carves five 16-byte value wrappers, a 0x30-byte
descriptor, and a separate output wrapper from the stack.  The descriptor
passed to `0xcbe98` is:

| descriptor offset | value |
|---:|---|
| `+0x00` | `JNIEnv*` value |
| `+0x08` | pointer to Context wrapper |
| `+0x10` | pointer to Map wrapper |
| `+0x18` | pointer to supplied-HMAC wrapper |
| `+0x20` | pointer to API wrapper |

This matches `0xcbe98`'s pre-validation unconditional pointer-slot
dereferences.

## Observable order

1. `0xccdc0`: run one-shot periodic timer helper `0xd4908`.
2. Decode Map key `environment` (`0x1457c0`, XOR `0x28`) and reference value
   `sandbox` (`0x1457d0`, XOR `0x1a`), then `0xcce40` reads the Map value
   through `0xaebf8` and the byte loop at `0xcccb8` compares it with
   `sandbox`.
3. Set the environment auxiliary bit unless Map copy succeeded with a non-null
   C string exactly equal to `sandbox` (case-sensitive, NUL-terminated).
4. `0xcd4b8`: first `CLOCK_REALTIME` sample. Log `Signing all the parameters
   begin` only when both the environment bit and current status are zero.
5. `0xcd774`: call `0xcbe98` with the descriptor and save returned
   `jbyteArray` at stack `-0x98`.
6. Clear the outer status, then `0xcd788` takes the second realtime sample.
7. Log `Signing all the parameters end  ` only when the environment bit and
   second-clock status are both zero. The first-clock failure is deliberately
   not carried into this decision.
8. `0xcd904` returns the saved `jbyteArray` on every branch.

Therefore neither outer clock failure clears or replaces the result produced
by `0xcbe98`.  The inner clock in `0xcbe98` remains different: its failure
returns null before context processing.

## C++

`runRecoveredNsignOrchestratorCC604()` is the callback-driven execution form.
`recoveredNsignOrchestratorCC604Regression()` covers exact sandbox, mismatch,
Map failure, first/second clock failure, null environment and null result.
`analyze_nsign_jni_orchestrator_full.py` interprets the complete ARM64 FDE and
proves the same matrix without loading the shared object.
""")

print("NSIGN_JNI_ORCHESTRATOR_STATIC_OK")
