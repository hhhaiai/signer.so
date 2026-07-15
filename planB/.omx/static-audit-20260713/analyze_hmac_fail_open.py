#!/usr/bin/env python3
"""Prove expected-HMAC stage failures are skipped rather than aborting nSign."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-hmac-fail-open.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    text = DISASSEMBLY.read_text()
    checks = [
        (r"ebd0:.*stur\s+wzr, \[x29, #-0x64\]", "integrity stage starts failed"),
        (r"ee84:.*bl\s+0xc8ec0.*eeac:.*tst\s+w0, #0x1", "key resolver status gate"),
        (r"f0a4:.*bl\s+0xca648.*f0c4:.*tst\s+w0, #0x1", "Mac producer status gate"),
        (r"ecc8:.*mov\s+w1, #0x7.*eccc:.*bl\s+0x13548c", "only mismatch emits correction 0x07"),
        (r"ece4:.*mov\s+w8, #0x1.*ece8:.*stur\s+w8, \[x29, #-0x64\]", "mismatch still completes stage"),
        (r"eeec:.*mov\s+w8, #0x1.*eef0:.*stur\s+w8, \[x29, #-0x64\]", "match completes stage"),
        (r"f1b0:.*ldr\s+w8, \[sp, #0xc\].*f1b8:.*and\s+w0, w8, #0x1", "stage boolean return"),
        (r"cbd44:.*bl\s+0xe6c0.*cbd48:.*tst\s+w0, #0x1", "stage caller observes false"),
        (r"cc254:.*bl\s+0xcbbd4.*cc258:.*add\s+x0, sp, #0x88.*cc25c:.*bl\s+0x143e8", "upper orchestrator ignores cbbd4 return and continues"),
        (r"cc28c:.*bl\s+0x11da64", "final consumer remains reachable after stage call"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    stage = "\n".join(
        line for line in text.splitlines()
        if re.match(r"^\s*([0-9a-f]+):", line)
        and 0xE6C0 <= int(re.match(r"^\s*([0-9a-f]+):", line).group(1), 16) < 0xF1C8
    )
    stores = re.findall(r"^\s*[0-9a-f]+:.*stur\s+w(?:zr|\d+), \[x29, #-0x64\]", stage, re.MULTILINE)
    if len(stores) != 3:
        raise SystemExit(f"unexpected integrity-result stores: {len(stores)}")
    corrections = re.findall(r"^\s*[0-9a-f]+:.*bl\s+0x13548c", stage, re.MULTILINE)
    if len(corrections) != 1:
        raise SystemExit(f"unexpected correction calls inside e6c0: {len(corrections)}")

    OUTPUT.write_text("""# ARM64 expected Java-HMAC fail-open propagation

## Result

`0xe6c0` initializes its stage result to false. Only a completed match or a
completed mismatch sets that result to true. A mismatch emits correction
`0x07`; resolver, Java-object, Mac producer or byte-array-copy failure leaves
the stage false and does not emit `0x07`.

`0xcbbd4` observes the boolean and can leave its integrity sub-stage early.
However, the upper signing orchestrator calls `0xcbbd4` at `0xcc254` and does
not inspect `w0`; it immediately continues with the environment dispatcher at
`0xcc25c`, later reaching final consumer `0x11da64` at `0xcc28c`.

Therefore the native behavior is:

```text
expected-HMAC infrastructure failure
  -> skip integrity verdict/correction 0x07
  -> continue native signing pipeline
```

It is not, by itself:

```text
expected-HMAC infrastructure failure -> JNI null signature
```

This is a fail-open integrity stage. The ordinary Java wrapper often prevents
entry into native code when its own key/HMAC operation throws, but a faithful
native reimplementation must still preserve the native call-level behavior.
""")
    print("HMAC_FAIL_OPEN_STATIC_OK")


if __name__ == "__main__":
    main()
