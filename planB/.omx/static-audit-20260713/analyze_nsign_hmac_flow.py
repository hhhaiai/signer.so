#!/usr/bin/env python3
"""Prove the bounded Java-HMAC input path into the arm64 native correction flow.

This script parses existing javap/objdump text only. It never loads or executes
libsigner.so.
"""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
DISASM = ROOT / ".omx/libsigner-arm64-objdump.txt"
JAVA = Path(__file__).with_name("java-sign-flow.txt")
OUTPUT = Path(__file__).with_name("arm64-nsign-java-hmac-flow.md")


def body(text: str, start: int, end: int) -> str:
    selected = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and start <= int(match.group(1), 16) < end:
            selected.append(line)
    return "\n".join(selected)


def require(text: str, pattern: str, description: str) -> None:
    if re.search(pattern, text, re.MULTILINE) is None:
        raise AssertionError(f"missing {description}: {pattern}")


def main() -> None:
    disasm = DISASM.read_text(errors="replace")
    java = JAVA.read_text(errors="replace")
    stage2 = body(disasm, 0xCBBD4, 0xCBE94)
    integrity = body(disasm, 0xE6C0, 0xF1C8)
    byte_copy = body(disasm, 0x94BC0, 0x95020)

    checks = [
        (java, r"155: invokevirtual.*Object\.toString", "Map.toString serialization"),
        (java, r"161: invokevirtual.*String\.getBytes", "UTF-8 byte conversion"),
        (java, r"164: invokevirtual.*com/adjust/sdk/sig/c\.a:\(Landroid/content/Context;\[B\)\[B", "Java HMAC helper call"),
        (java, r"167: astore\s+5", "Java HMAC byte[] local"),
        (java, r"459: aload[ \t]+5[ \t]*\n\s*461: iload_1[ \t]*\n\s*462: invokevirtual.*NativeLibHelper\.a", "HMAC byte[] passed to nSign"),
        (stage2, r"cbbf4:.*str\s+x2, \[sp, #0x18\]", "stage-2 saves nSign byte[]"),
        (stage2, r"cbd40:.*ldr\s+x4, \[sp, #0x18\]", "stage-2 reloads nSign byte[]"),
        (stage2, r"cbd44:.*bl\s+0xe6c0", "stage-2 calls integrity helper"),
        (byte_copy, r"94c08:.*cmp\s+x2, #0x0", "null byte-array branch"),
        (byte_copy, r"94e50:.*bl\s+0x139e50", "native calloc"),
        (byte_copy, r"94ddc:.*ldr\s+x8, \[x8, #0x640\]", "JNI GetByteArrayRegion vtable slot"),
        (byte_copy, r"94de0:.*blr\s+x8", "GetByteArrayRegion call"),
        (byte_copy, r"94f04:.*bl\s+0x92ddc", "array-length helper"),
        (byte_copy, r"94eb0:.*str\s+x9, \[x8\]", "length output store"),
        (byte_copy, r"94eb8:.*str\s+x26, \[x8\]", "native byte-buffer output store"),
        (byte_copy, r"94fac:.*bl\s+0x139de0", "allocation-failure cleanup"),
        (integrity, r"e6e4:.*stp\s+x3, x4, \[sp, #0x18\]", "context and byte[] saved separately"),
        (integrity, r"edc4:.*ldr\s+x2, \[sp, #0x20\]", "original byte[] passed to copy helper"),
        (integrity, r"edcc:.*bl\s+0x94bc0", "byte[] copy helper call"),
        (integrity, r"eef8:.*ldur\s+x8, \[x29, #-0x78\]", "supplied-byte cursor loaded"),
        (integrity, r"ef00:.*ldrb\s+w8, \[x8\]", "supplied byte loaded"),
        (integrity, r"ef04:.*ldrb\s+w9, \[x9\]", "expected byte loaded"),
        (integrity, r"ef08:.*cmp\s+w8, w9", "byte comparison"),
        (integrity, r"f150:.*sub\s+x8, x8, #0x1", "remaining length decrement"),
        (integrity, r"f15c:.*add\s+x8, x8, #0x1", "supplied cursor increment"),
        (integrity, r"f168:.*add\s+x8, x8, #0x1", "expected cursor increment"),
        (integrity, r"ecc8:.*mov\s+w1, #0x7", "HMAC mismatch correction code 0x07"),
        (integrity, r"eccc:.*bl\s+0x13548c", "correction writer call"),
        (integrity, r"ed24:.*str\s+x9, \[sp, #0x28\]", "copied buffer saved for cleanup"),
        (integrity, r"efd8:.*ldr\s+x0, \[sp, #0x28\]", "copied buffer cleanup load"),
        (integrity, r"efdc:.*bl\s+0x139de0", "copied buffer freed before return"),
    ]
    for text, pattern, description in checks:
        require(text, pattern, description)

    OUTPUT.write_text(
        """# arm64 nSign Java-HMAC integrity path

本报告只解析已有 `javap` 与 `objdump` 文本，不加载或执行目标 SO。

## Proven Java source

```text
Map.toString()
-> UTF-8 bytes
-> com.adjust.sdk.sig.c.a(Context, byte[])  // HmacSHA256
-> byte[] local 5
-> NativeLibHelper.nSign(Context, Map, byte[], api)
```

JNI 第三个业务参数 `byte[]` 是 Java 侧对 `Map.toString()` 结果计算的 HMAC 完整性值，
而不是待签名 Map plaintext 本身。

## Proven native path

```text
0xcbbf4  save nSign byte[]
0xcbd40  reload as x4
0xcbd44  call 0xe6c0
0xedc4  reload byte[]
0xedcc  call 0x94bc0

0x94f04  obtain array length through helper 0x92ddc
0x94e50  calloc native storage
0x94ddc  JNIEnv vtable +0x640 = GetByteArrayRegion
0x94eb0  return copied length
0x94eb8  return copied buffer

0xef00/0xef04/0xef08  compare supplied and expected bytes
0xf150/0xf15c/0xf168  decrement remaining length and advance both cursors
0xecc8/0xeccc          emit correction 0x07 through 0x13548c
0xefd8/0xefdc          free the copied supplied-HMAC buffer
```

## Corrected descriptor conclusion

在严格的 `0xe6c0..0xf1c4` 范围内，复制出的 supplied-HMAC buffer 用于比较并在
返回前释放；没有找到把该 buffer 直接写入 native context `+0x118/+0x120` 的 store。
因此此前“final descriptor 8/9 就是 nSign supplied Java HMAC”的说法不能成立。
独立的完整 context producer 分析进一步证明这两个字段保持 `0/null`。

结合独立的 expected producer 报告，当前可安全固化的语义为：

```text
nSign byte[] = Java HMAC integrity input
expected     = Mac.HmacSHA256(Map.toString().getBytes(), API-selected Key)
mismatch     = correction code 0x07
slot 8/9     = reserved zero-length descriptor pair
```

API-selected Key 的 AndroidKeyStore/legacy resolver 异常状态仍需在 platform adapter
中逐项实现；但成功路径 expected HMAC 算法与输入已经闭合。
"""
    )
    print(f"NSIGN_JAVA_HMAC_STATIC_OK output={OUTPUT}")


if __name__ == "__main__":
    main()
