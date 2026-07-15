#!/usr/bin/env python3
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = Path(__file__).resolve().parent
TEXT = (AUDIT / "disasm-927c4-92b24.txt").read_text(errors="replace")
CPP = (ROOT / "native-reimplementation/recovered_primitives.cpp").read_text(
    errors="replace")

body_match = re.search(
    r"\n\s*92a20:.*?(?=\n\s*92b20:.*?\n)", TEXT, re.DOTALL)
assert body_match is not None
body = body_match.group(0)

checks = (
    (r"92a38:.*ldr\s+x8, \[x0\].*"
     r"92a4c:.*ldr\s+x8, \[x8, #0x78\].*"
     r"92a54:.*blr\s+x8", "ExceptionOccurred"),
    (r"92a88:.*cmp\s+x0, #0x0.*92a98:.*csel\s+x24, x23, x22, ne",
     "null/non-null state split"),
    (r"92ac8:.*ldr\s+x8, \[x19\].*"
     r"92ad0:.*ldr\s+x8, \[x8, #0x80\].*"
     r"92ad4:.*blr\s+x8", "ExceptionDescribe"),
    (r"92ad8:.*ldr\s+x8, \[x19\].*"
     r"92ae0:.*ldr\s+x8, \[x8, #0x88\].*"
     r"92ae4:.*blr\s+x8", "ExceptionClear"),
    (r"92b04:.*cmp\s+x20, #0x0.*"
     r"92b10:.*cset\s+w0, ne", "boolean return"),
)
for pattern, label in checks:
    assert re.search(pattern, body, re.DOTALL), label

for needle in (
        "struct RecoveredJniExceptionOperations92a20",
        "runRecoveredJniExceptionConsumer92a20(",
        "operations.exceptionOccurred(jniEnvironment)",
        "operations.exceptionDescribe(jniEnvironment)",
        "operations.exceptionClear(jniEnvironment)",
        "return exception != 0 ? 1U : 0U;"):
    assert needle in CPP, needle

print("arm64 JNI exception consumer 0x92a20 evidence: PASS")
