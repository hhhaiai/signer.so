#!/usr/bin/env python3
"""Recover the nine descriptors passed by the arm64 final consumer."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
DISASM = ROOT / ".omx/libsigner-arm64-objdump.txt"
OUTPUT = Path(__file__).with_name("arm64-final-nine-descriptors.md")


def function_body(text: str, start: int, end: int) -> str:
    selected = []
    for line in text.splitlines():
        match = re.match(r"\s*([0-9a-f]+):", line)
        if match and start <= int(match.group(1), 16) < end:
            selected.append(line)
    return "\n".join(selected)


def require(body: str, pattern: str, description: str) -> None:
    if re.search(pattern, body, re.MULTILINE) is None:
        raise AssertionError(f"missing {description}: {pattern}")


def main() -> None:
    body = function_body(DISASM.read_text(), 0x11DA64, 0x11EA78)

    checks = [
        (r"11dab0:.*add\s+x8, x19, #0x20", "context +0x20"),
        (r"11dab4:.*add\s+x2, x19, #0x50", "context +0x50"),
        (r"11dac0:.*str\s+x8, \[sp, #0x40\]", "saved +0x20 pointer"),
        (r"11dac4:.*bl\s+0x13917c", "128-byte descriptor allocation"),
        (r"11dac8:.*add\s+x10, x19, #0x30", "context +0x30"),
        (r"11dacc:.*add\s+x9, x19, #0xe0", "context +0xe0"),
        (r"11dae0:.*stp\s+x9, x10, \[sp, #0x30\]", "saved +0xe0/+0x30 pointers"),
        (r"11dae4:.*add\s+x9, x19, #0xf0", "context +0xf0"),
        (r"11e0d4:.*ldur\s+x2, \[x29, #-0x20\]", "selected Map bytes pointer"),
        (r"11e0dc:.*ldr\s+w1, \[sp, #0x5c\]", "selected Map length"),
        (r"11e0f0:.*stur\s+x0, \[x29, #-0xd8\]", "selected Map descriptor local"),
        (r"11e2b8:.*mov\s+w1, #0x4", "context +0x20 descriptor length"),
        (r"11e2bc:.*ldr\s+x2, \[sp, #0x40\]", "context +0x20 descriptor source"),
        (r"11e2d0:.*stur\s+x0, \[x29, #-0xc8\]", "context +0x20 descriptor local"),
        (r"11e410:.*rev\s+w8, w8", "selected Map length reversal"),
        (r"11e418:.*bl\s+0x13917c", "selected Map length descriptor"),
        (r"11e428:.*stur\s+x0, \[x29, #-0xd0\]", "selected Map length descriptor local"),
        (r"11e5f4:.*mov\s+w1, #0x20", "context +0x30 descriptor length"),
        (r"11e5f8:.*ldr\s+x2, \[sp, #0x38\]", "context +0x30 descriptor source"),
        (r"11e60c:.*stur\s+x0, \[x29, #-0xc0\]", "context +0x30 descriptor local"),
        (r"11e658:.*ldr\s+w8, \[x8, #0x118\]", "dynamic context length"),
        (r"11e65c:.*rev\s+w8, w8", "dynamic context length reversal"),
        (r"11e674:.*str\s+x0, \[sp, #0xe8\]", "dynamic length descriptor local"),
        (r"11e6b4:.*mov\s+w1, #0x14", "context +0xf0 descriptor length"),
        (r"11e6b8:.*ldr\s+x2, \[sp, #0x28\]", "context +0xf0 descriptor source"),
        (r"11e700:.*stur\s+x0, \[x29, #-0xb0\]", "context +0xf0 descriptor local"),
        (r"11e75c:.*sub\s+x0, x29, #0x18", "dynamic bytes allocation status"),
        (r"11e760:.*ldr\s+w1, \[x8, #0x118\]", "dynamic bytes length"),
        (r"11e764:.*ldr\s+x2, \[x8, #0x120\]", "dynamic bytes pointer"),
        (r"11e778:.*str\s+x0, \[sp, #0xe0\]", "dynamic bytes descriptor local"),
        (r"11e840:.*mov\s+w1, #0x10", "context +0xe0 descriptor length"),
        (r"11e844:.*ldr\s+x2, \[sp, #0x30\]", "context +0xe0 descriptor source"),
        (r"11e858:.*stur\s+x0, \[x29, #-0xb8\]", "context +0xe0 descriptor local"),
        (r"11e7c4:.*mov\s+w2, #0x9", "fixed descriptor count"),
        (r"11e7c0:.*ldp\s+x5, x4, \[x29, #-0xb8\]", "register descriptors x4/x5"),
        (r"11e7d0:.*ldp\s+x7, x6, \[x29, #-0xc8\]", "register descriptors x6/x7"),
        (r"11e7e0:.*ldr\s+x3, \[sp, #0x48\]", "register descriptor x3"),
        (r"11e7ec:.*str\s+x8, \[sp\]", "stack descriptor 6"),
        (r"11e7e4:.*str\s+x8, \[sp, #0x8\]", "stack descriptor 7"),
        (r"11e7d4:.*str\s+x8, \[sp, #0x10\]", "stack descriptor 8"),
        (r"11e7c8:.*str\s+x8, \[sp, #0x18\]", "stack descriptor 9"),
        (r"11e7f0:.*bl\s+0xf1ec8", "protected engine call"),
    ]
    for pattern, description in checks:
        require(body, pattern, description)

    OUTPUT.write_text(
        """# arm64 final consumer: fixed nine-descriptor input order

本报告只解析现有 objdump 文本，不加载或执行目标 SO。

## Call boundary

`0x11e7f0` 调用 `0xf1ec8` 时 `w2=9`。AArch64 ABI 下，descriptor 1..5 位于
`x3..x7`，descriptor 6..9 位于调用者栈 `sp+0x00..0x18`。

## Statically recovered order

| slot | call location | source | descriptor length |
|---:|---|---|---:|
| 1 | `x3` | `context + 0x50` | 128 |
| 2 | `x4` | `context + 0xf0` | 20 |
| 3 | `x5` | `context + 0xe0` | 16 |
| 4 | `x6` | `context + 0x30` | 32 |
| 5 | `x7` | `context + 0x20` | 4 |
| 6 | `[sp+0x00]` | 4-byte reversed selected-Map plaintext length | 4 |
| 7 | `[sp+0x08]` | `0x11d798` selected-Map plaintext bytes | dynamic |
| 8 | `[sp+0x10]` | 4-byte reversed `context + 0x118` length | 4 |
| 9 | `[sp+0x18]` | bytes at `context + 0x120` | `context + 0x118` |

每个对象均由 `0x13917c` 包装成 `{length,data}` descriptor。slot 6/7 是
`0x11d798` 的确定输出。独立的完整 context producer 分析证明 `+0x118/+0x120`
保持初始化后的 `0/null`，因此 slot 8 是四字节零，slot 9 为空。

## Compatibility consequence

这把后续静态追踪范围进一步缩小：`adj_signing_id` 的 engine-level 来源若不在
100-key selected-Map bytes 内，只可能来自其余固定 context 区域或更早的 protected
transformation，不可能来自保留的 slot 8/9。当前证据尚未给其他 context offsets 完成
语义命名，因此不能把
`adj_signing_id` 的 exact logical placement 错标为 `0x11d798` walker 行为。

同样，固定 `count=9` 是 descriptor 数量，不是算法编号或九套密码选择器。
"""
    )
    print(f"FINAL_NINE_DESCRIPTORS_STATIC_OK output={OUTPUT}")


if __name__ == "__main__":
    main()
