#!/usr/bin/env python3
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
TEXT = (AUDIT / "disasm-11ba78-11d40c.txt").read_text(errors="replace")
SO = ROOT / "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so"


def require(pattern, description):
    if re.search(pattern, TEXT, re.S) is None:
        raise AssertionError(description)


# Protected 100-key table entry and the only Map operations used by the body.
require(r"11bb34:.*adr\s+x20, 0x145a30", "100-key table base")
require(r"11cf60:.*sub\s+x4, x29, #0x14.*"
        r"11cf64:.*mov\s+x0, x25.*"
        r"11cf68:.*ldr\s+x1, \[sp, #0x58\].*"
        r"11cf6c:.*ldr\s+x2, \[sp, #0x40\].*"
        r"11cf70:.*ldur\s+x3, \[x29, #-0x40\].*"
        r"11cf74:.*bl\s+0xacd90", "containsKey call ABI")
require(r"11d2d8:.*sub\s+x4, x29, #0x20.*"
        r"11d2dc:.*mov\s+x0, x25.*"
        r"11d2e0:.*ldr\s+x1, \[sp, #0x58\].*"
        r"11d2e4:.*ldr\s+x2, \[sp, #0x40\].*"
        r"11d2e8:.*ldur\s+x3, \[x29, #-0x40\].*"
        r"11d2ec:.*bl\s+0xadbf4", "Map.get call ABI")

# The caller-supplied sink callback receives status, JNIEnv, native key,
# selected Java value and the opaque sink pointer. Full instruction
# interpretation proves a present Map key reaches the callback even when
# Map.get returned null.
require(r"11c418:.*mov\s+x0, x25.*"
        r"11c420:.*ldp\s+x8, x4, \[sp, #0x8\].*"
        r"11c428:.*ldur\s+x3, \[x29, #-0x20\].*"
        r"11c42c:.*mov\s+x1, x25.*"
        r"11c430:.*ldur\s+x2, \[x29, #-0x40\].*"
        r"11c434:.*blr\s+x8", "selected-value callback ABI")

# JNI local reference cleanup uses DeleteLocalRef at vtable offset 0xb8.
require(r"11d12c:.*ldr\s+x0, \[sp, #0x58\].*"
        r"11d130:.*ldr\s+x1, \[sp, #0x28\].*"
        r"11d134:.*ldr\s+x8, \[x0\].*"
        r"11d138:.*ldr\s+x8, \[x8, #0xb8\].*"
        r"11d13c:.*blr\s+x8", "DeleteLocalRef cleanup")

# The one native scratch allocation copies the complete 1362-byte decoded CSV
# plus NUL. It is unconditionally freed at the single normal epilogue.
require(r"11d048:.*sub\s+x8, x26, x20.*"
        r"11d04c:.*add\s+x0, x8, #0x1.*"
        r"11d054:.*bl\s+0x139e20", "whole-table malloc length plus one")
require(r"11d3cc:.*ldur\s+x0, \[x29, #-0x30\].*"
        r"11d3d0:.*bl\s+0x139de0", "unconditional native scratch free")

# Validate the decoded table remains exactly 100 comma-separated keys.
image = SO.read_bytes()
phoff = struct.unpack_from("<Q", image, 32)[0]
entsize = struct.unpack_from("<H", image, 54)[0]
count = struct.unpack_from("<H", image, 56)[0]
raw = None
for index in range(count):
    fields = struct.unpack_from(
        "<IIQQQQQQ", image, phoff + index * entsize)
    if fields[0] == 1 and fields[3] <= 0x145A30 < fields[3] + fields[5]:
        start = fields[2] + 0x145A30 - fields[3]
        encoded = image[start:start + 1363]
        raw = bytes(value ^ 0x52 for value in encoded)
        break
assert raw is not None and raw[-1] == 0
keys = raw[:-1].decode("ascii").split(",")
assert len(keys) == 100 and keys[0] == "ad_impressions_count"
assert keys[-1] == "native_version" and "adj_signing_id" not in keys

print("arm64 JNI Map selected-value walker 0x11ba78 boundary evidence: PASS")
