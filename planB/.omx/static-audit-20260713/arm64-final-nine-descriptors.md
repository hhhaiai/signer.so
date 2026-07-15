# arm64 final consumer: fixed nine-descriptor input order

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
