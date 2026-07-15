#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEXT = (Path(__file__).resolve().parent /
        "disasm-11d798-11da64.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")


def require(pattern, description):
    if re.search(pattern, TEXT, re.S) is None:
        raise AssertionError(description)


# ABI capture: x0 status, x1 env, x2 map, x3 output**, x4 length*.
require(r"11d7b8:.*stp\s+x3, x4, \[sp, #0x10\].*"
        r"11d7c0:.*stur\s+x2, \[x29, #-0x28\].*"
        r"11d7c8:.*str\s+x1, \[sp, #0x30\].*"
        r"11d830:.*mov\s+x23, x0", "five-argument ABI capture")

# The opaque dispatcher reaches the counting pass with callback 0x11d40c and
# the copying pass with callback 0x11d528. Both receive the same status/env/map
# and the same 24-byte sink at fp-0x20.
require(r"11da00:.*sub\s+x4, x29, #0x20.*"
        r"11da04:.*mov\s+x0, x23.*"
        r"11da08:.*ldr\s+x1, \[sp, #0x30\].*"
        r"11da10:.*adr\s+x3, 0x11d40c.*"
        r"11da14:.*ldur\s+x2, \[x29, #-0x28\].*"
        r"11da18:.*bl\s+0x11ba78", "counting walker call")
require(r"11d968:.*sub\s+x4, x29, #0x20.*"
        r"11d96c:.*mov\s+x0, x23.*"
        r"11d970:.*ldr\s+x1, \[sp, #0x30\].*"
        r"11d978:.*adr\s+x3, 0x11d528.*"
        r"11d97c:.*ldur\s+x2, \[x29, #-0x28\].*"
        r"11d980:.*bl\s+0x11ba78", "copying walker call")

# Allocation is exactly calloc(countedLength + 1, 1). Null writes status 2.
require(r"11d9d0:.*ldur\s+x8, \[x29, #-0x20\].*"
        r"11d9d4:.*mov\s+w1, #0x1.*"
        r"11d9d8:.*add\s+x0, x8, #0x1.*"
        r"11d9dc:.*bl\s+0x139e50", "calloc length plus one")
require(r"11d93c:.*mov\s+w8, #0x2.*11d940:.*str\s+w8, \[x23\]",
        "allocation failure status 2")

# Success writes one NUL byte, then publishes pointer and explicit length.
require(r"11d948:.*ldp\s+x28, x8, \[sp, #0x20\].*"
        r"11d95c:.*sub\s+x20, x8, #0x1.*"
        r"11d960:.*strb\s+wzr, \[x28\], #0x1", "terminator write")
require(r"11d994:.*ldur\s+x8, \[x29, #-0x10\].*"
        r"11d998:.*ldr\s+x11, \[sp, #0x10\].*"
        r"11d99c:.*ldur\s+x10, \[x29, #-0x20\].*"
        r"11d9a0:.*str\s+x8, \[x11\].*"
        r"11d9a4:.*ldr\s+x8, \[sp, #0x18\].*"
        r"11d9a8:.*str\s+x10, \[x8\]", "deferred output publication")

# There is no free call in the FDE, so an allocated buffer remains owned when
# the second walker reports an error.
if re.search(r"\bbl\s+0x139e[0-9a-f]+.*free", TEXT):
    raise AssertionError("unexpected free in materializer")

for needle in (
        "RecoveredMapPlaintextMaterializationInput11d798",
        "RecoveredMapPlaintextMaterializationOutput11d798",
        "modelRecoveredMapPlaintextMaterialization11d798(",
        "input.firstWalkerStatus != 0",
        "input.secondWalkerStatus != 0",
        "input.countedLength + 1",
        "return {2, true, allocationSize",
        "input.countedLength};"):
    assert needle in CPP, needle

print("arm64 Map plaintext materializer 0x11d798 evidence: PASS")
