# Protected-engine correction `0x3e`：已闭环的跨 ABI 与真机差分证据

## 结论

`0xf4840..0xf4894` 的 `0x3e` 分支、`0x101b90` 的 explicit zero 和
`0x301 -> 0x106d00` schedule 均是原 SO 的真实行为。旧静态 VM 的错误不在分支、
helper、NZCV 或 register residual，而在 Pixel 向量把第三个 16-byte context-flags
descriptor 错写成了 Boolean `1`。

真实 Pixel context flags：

```text
low uint64: 0x1FFDFFFFFFFFFFBF
16 bytes:   bf ff ff ff ff ff fd 1f 00 00 00 00 00 00 00 00
```

ARM64 `0xf1fb0 ldr` + `0xf1fb4 rev` 导入后：

```text
lane2 = [0xbfffffff, 0xfffffd1f, 0, 0]
```

用该 descriptor 运行完整 42,732-instruction 文本解释器，无任何 skip/patch：

```text
arm64 protected engine 0xf1ec8 full static VM Pixel vector: PASS
executed_instructions=8009752
direct_calls=1316791
output_bytes=176
```

## ARM64 `0x3e` decision

```asm
f4848  bl   0x138b74       ; pop source
f4854  cmp  w0, #0
f485c  cset w2, eq
f4864  bl   0x138a70       ; push source == 0
f4878  bl   0x138b74       ; pop Boolean
f4884  cbz  w0, 0xf9e38    ; false skips correction
f4890  mov  w2, #0x3e
f4894  bl   0x138a70
```

```cpp
const uint32_t source = evaluation.pop(status);
evaluation.push(status, source == 0 ? 1u : 0u);
if (evaluation.pop(status) != 0) evaluation.push(status, 0x3e);
```

分支方向没有修改。正确 descriptor 使前序固定比较相等，测试 source 为 `1`，因此
`source == 0` 为 false，原始代码自然跳过 `0x3e`。

## schedule 与对齐状态

```text
0x11a110  materialize token 0x301
0x119e84  auxiliary push
0xf23a4   auxiliary pop
0xf3b4c   compare 0x301
0xf560c   0x301 handler
0x101c18 push wordCount 0x20
0x101c68 push sourceOffset 0x18
0x101c80 push lane 2
0x101d14..0x101d4c copy 32 words
0x101d1c -> 0x106d00
```

纠正输入后，静态 VM 在第一次 `0x106d00` 的状态：

```text
shared[0x40..0x43] = 1ffdffff ffffffbf 00000000 00000000
lane0[0..3]        = 1ffdffff ffffffbf 00000000 00000000
evaluation         = empty
auxiliary          = empty
counters           = empty
status             = 0
```

## x86_64 交叉确认

x86_64 独立包含：

```text
0x112098  token 0x301
0xe5fa0   dispatcher compare
0xfc546   fixed-frame builder
0xf67eb   explicit zero
0xe6e7c   sete source==0
0xe6eaa   false skips correction
0xe6eba   push 0x3e
```

因此 ARM64 的 `cset eq`、`cbz`、常量 `0x3e` 和 schedule 方向都不是误反编译。

## 真机证据

项目专用 Pixel 8 / package `local.qbdi.adjustreference` 的 helper-entry trace 分组结果：

```text
descriptor 0: 32 words
descriptor 1:  5 words
descriptor 2:  4 words = bfffffff fffffd1f 00000000 00000000
descriptor 3:  8 words
descriptor 4:  1 word
```

对应证据：

```text
.omx/static-audit-20260713/device-protected-descriptor-import.json
.omx/static-audit-20260713/device-lane2-init-frida.log
.omx/static-audit-20260713/device-lane2-init-reference-result.json
```

reference JSON SHA-256：

```text
b163eb800b2a425158f6b825e8e9439b4b9bd1bca8b0ed0be2a155f2ef9ceca0
```

插桩运行在结果写出后发生 Frida/JIT thread `SIGSEGV`；descriptor 值与结果文件可用于
前置数据流取证，但不得据此声称 instrumented process 稳定。后续避免扩大 inline hook。

## 禁止的实现方式

- `if (pc == 0xf4884) ...`
- skip `0x3e`
- patch lane0/shared words
- patch final codeword
- hardcode frozen signature

正式修复是保留完整 16-byte context flags 输入，并执行原始 schedule。

完整说明：

```text
native-reimplementation/PROTECTED_ENGINE_STATIC_RECOVERY.md
```
