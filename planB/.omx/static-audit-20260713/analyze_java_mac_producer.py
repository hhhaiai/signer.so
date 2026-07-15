#!/usr/bin/env python3
"""Close Java Mac HmacSHA256 orchestration and reference cleanup on ARM64."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
DISASSEMBLY = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = ROOT / ".omx/static-audit-20260713/arm64-java-mac-producer.md"


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE | re.DOTALL) is None:
        raise SystemExit(f"missing static evidence: {description}")


def main() -> None:
    text = DISASSEMBLY.read_text()
    checks = [
        (r"aa4d4:.*adr\s+x11, 0x144fe0", "Mac class"),
        (r"aa7a0:.*adr\s+x2, 0x1449a8.*aa7a8:.*adr\s+x3, 0x145000", "Mac.getInstance"),
        (r"ab7d0:.*adr\s+x2, 0x1449ec.*ab7d8:.*adr\s+x3, 0x145030", "Mac.init"),
        (r"abdec:.*adr\s+x2, 0x145048.*abdf4:.*adr\s+x3, 0x145050", "Mac.update"),
        (r"acc1c:.*adr\s+x2, 0x144a18.*acc24:.*adr\s+x3, 0x144954", "Mac.doFinal"),
        (r"ca964:.*bl\s+0xa9d44", "getInstance call"),
        (r"ca9ac:.*ldur\s+x8, \[x29, #-0x28\].*ca9bc:.*ldr\s+x2, \[x8\].*ca9c0:.*bl\s+0xab130", "init receives Mac object without null conversion"),
        (r"cab8c:.*ldur\s+x8, \[x29, #-0x28\].*caba0:.*bl\s+0xab870", "update call"),
        (r"caa40:.*ldp\s+x3, x8, \[x29, #-0x30\].*caa50:.*bl\s+0xac1d8", "doFinal call"),
        (r"caa84:.*ldur\s+x8, \[x29, #-0x30\].*caa98:.*bl\s+0x94bc0", "byte-array copy"),
        (r"ca9e4:.*ldur\s+x8, \[x29, #-0x28\].*caa18:.*ldr\s+x8, \[x8, #0xb8\].*caa28:.*blr\s+x8", "Mac DeleteLocalRef"),
        (r"caac0:.*ldur\s+x8, \[x29, #-0x30\].*cabd4:.*ldr\s+x8, \[x24\].*cabe0:.*ldr\s+x8, \[x8, #0xb8\].*cabe4:.*blr\s+x8", "doFinal byte-array DeleteLocalRef"),
        (r"caa9c:.*ldr\s+w8, \[x23\].*caaac:.*cmp\s+w8, #0x0.*caab4:.*cset\s+w8, eq", "copy status becomes producer result"),
    ]
    for pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text("""# ARM64 Java Mac HmacSHA256 producer

## Call-level flow

```text
mac = Mac.getInstance("HmacSHA256")
if helper failed: return false

mac.init(key)        // key may be null; no native null-to-failure conversion
if helper failed: DeleteLocalRef(mac); return false

mac.update(data)
if helper failed: DeleteLocalRef(mac); return false

result = mac.doFinal()
if helper failed: DeleteLocalRef(mac); return false

copy result byte[] to native storage through 0x94bc0
success = copy-helper status == 0
DeleteLocalRef(result) when non-null
DeleteLocalRef(mac) when non-null
return success
```

The producer uses JNI helper status as the failure signal. Java null objects are
not silently rewritten into another key or an empty digest. A null Mac receiver,
null Key, or null doFinal result reaches the next JNI/helper operation, whose
status/pending exception controls failure.

## Helpers

| Address | Role |
|---|---|
| `0xa9d44` | `Mac.getInstance(String)` |
| `0xab130` | `Mac.init(Key)` |
| `0xab870` | `Mac.update(byte[])` |
| `0xac1d8` | `Mac.doFinal()` |
| `0x94bc0` | Java byte[] length/allocation/region copy to native storage |
| `0xca648` | orchestration, status propagation and local-ref cleanup |
""")
    print("JAVA_MAC_PRODUCER_STATIC_OK")


if __name__ == "__main__":
    main()
