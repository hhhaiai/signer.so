# Protected engine `0xf1ec8..0x11ba78`：完整静态解释与真机差分闭环

## 1. 结论

ARM64 `libsigner.so` 的 protected engine 是一个 `.eh_frame` 覆盖的单一函数：

```text
range:                 0xf1ec8..0x11ba78
size:                  0x29bb0
ARM64 instructions:    42,732
direct call sites:     7,223
unique direct targets: 17
indirect blr calls:     0
```

当前文本解释器已经表示全部 42,732 条指令和全部 17 个直接 helper 目标。修正第三个
输入 descriptor 的真实 16-byte context flags 后，无 PC 特判、无跳过 `0x3e`、无 lane
补丁、无输出硬编码，即可自然得到冻结 Pixel 8 的完整 176-byte 输出：

```text
arm64 protected engine 0xf1ec8 full static VM Pixel vector: PASS
executed_instructions=8009752
direct_calls=1316791
output_bytes=176
```

证据：

```text
.omx/static-audit-20260713/analyze_protected_engine_full.py
.omx/static-audit-20260713/arm64-protected-engine-full-vm.log
.omx/static-audit-20260713/arm64-schedule-to-106d00.md
```

这关闭了该 FDE 原先唯一的 `partial` 状态；但整个 SO 仍有 JNI 可达 unknown 函数，
因此不能把“protected engine 已闭环”扩大成“整个 SO 已完整替代”。

## 2. 九个输入 descriptor

final consumer `0x11da64..0x11ea78` 在 `0x11e7f0` 以固定 count `9` 调用 engine。
输入顺序为：

| index | source | length |
|---:|---|---:|
| 0 | context `+0x50` correction/codeword table | 128 |
| 1 | context `+0xf0` certificate SHA-1 | 20 |
| 2 | context `+0xe0` flags | 16 |
| 3 | context `+0x30` correction basis | 32 |
| 4 | context `+0x20` field2 | 4 |
| 5 | selected Map plaintext length, big-endian | 4 |
| 6 | selected Map plaintext | dynamic |
| 7 | context `+0x118` dynamic length, big-endian | 4 |
| 8 | context `+0x120` dynamic bytes | dynamic |

入口 `0xf1f48..0xf2058` 逐 descriptor 初始化 `work+0x20+i*8` 的 lane。完整 4-byte
word 在 `0xf1fb0` 读取，`0xf1fb4 rev w3,w8` 转成 big-endian logical word，随后
`0xf1fb8 -> 0x138318` 写入对应 arena。

## 3. 根因：descriptor 2 不是 Boolean

旧静态 Pixel 向量错误地把 context flags 简化为：

```text
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

即 `uint64 flags = 1`。这不是 helper 语义错误，而是输入模型错误。

隔离真机 trace 在 `0xf1fb8 -> 0x138318` 记录到第三个 descriptor 的四个 REV32 后
logical words：

```text
[0xbfffffff, 0xfffffd1f, 0x00000000, 0x00000000]
```

反向恢复 descriptor bytes：

```text
bf ff ff ff ff ff fd 1f 00 00 00 00 00 00 00 00
```

因此低 64-bit context flags 为：

```text
0x1FFDFFFFFFFFFFBF
```

真机分组证据：

```text
.omx/static-audit-20260713/device-protected-descriptor-import.json
.omx/static-audit-20260713/device-lane2-init-frida.log
.omx/static-audit-20260713/device-lane2-init-reference-result.json
```

该次 instrumented run 已先写出与冻结 reference 完全相等的结果 JSON：

```text
reference JSON SHA-256:
b163eb800b2a425158f6b825e8e9439b4b9bd1bca8b0ed0be2a155f2ef9ceca0

raw signature length: 176
raw signature SHA-256:
f2c90ec1284661b35b8d21579a1e8907a9aa38c1db0a74d4ad84d1f555bd46d9
```

注意：结果文件写出后，Frida inline instrumentation 使测试进程的 JIT thread 出现
`SIGSEGV`。因此该运行只用于 descriptor 入参取证，不能作为“插桩稳定性”证据；未插桩
冻结基线和先前安全 trace 的签名结果均一致。后续不应继续扩大 inline hook 面。

## 4. `0x301 -> 0x106d00` 调度

文本解释器在第一次到达 `0x106d00` 前执行 12,483 条指令：

```text
0x11a110  materialize auxiliary token 0x301
0x119e84  push token
0xf23a4   pop token
0xf3b4c   compare token with 0x301
0xf560c   enter exact 0x301 handler
0x101c18 push wordCount 0x20
0x101c68 push sourceOffset 0x18
0x101c80 push lane 2
0x101d14..0x101d4c copy 32 words
0x101d1c  reach 0x106d00
```

纠正 descriptor 后，`0x106d00` stop state 为：

```text
status:                    0
evaluation stack:          empty
auxiliary stack:           empty
counter chain:             empty
shared[0x40..0x43]:        1ffdffff ffffffbf 00000000 00000000
lane0[0..3]:               1ffdffff ffffffbf 00000000 00000000
```

真机 helper trace 的同一数据为：

```text
f5d1c source lane:
bfffffff fffffd1f 00000000 00000000

f5114 final shared words:
1ffdffff ffffffbf 00000000 00000000

f58b0 lane-copy reads:
1ffdffff ffffffbf 00000000 00000000
```

静态和真机由此在首次 `0x106d00` 前完全对齐。

## 5. `0x3e` 分支为何自然消失

`0xf4840..0xf4894` 的真实语义没有错误：

```cpp
const uint32_t source = evaluation.pop(status);
evaluation.push(status, source == 0 ? 1u : 0u);
if (evaluation.pop(status) != 0) {
    evaluation.push(status, 0x3e);
}
```

旧 descriptor `{1,0,...}` 使早期 lane/shared 数据错误，后续比较产生 zero source，因而
错误走入 `0x3e`。使用真实 context flags 后，固定比较的两侧相等，测试 source 为 `1`，
`source == 0` 为 false，原始分支自然跳过 correction `0x3e`。

这不是“删除 correction 0x3e”。当其他合法输入确实使 source 为 zero 时，解释器仍会
执行原始 `0x3e` 行为。

## 6. C++ 同步

`recovered_primitives.cpp` 已增加回归：

1. 用 `storeRecoveredContextFlags()` 把 `0x1FFDFFFFFFFFFFBF` 写入
   `RecoveredArm64NativeContext::descriptor3Bytes`；
2. 通过正式 `runRecoveredProtectedEngineInputInitializationF1ec8()` 导入第三个
   descriptor；
3. 验证 lane2 为：

```text
bfffffff fffffd1f 00000000 00000000
```

该回归防止以后再次把 16-byte flags descriptor 简化成 Boolean。

## 7. 禁止的伪修复

以下方法只能证明差异边界，不能进入正式实现：

- 在 `0xf4884` 强制 `w0=0`；
- 按 PC 跳过 `0x3e`；
- 把 lane0/shared word 改成预期值；
- 把最终 codeword 强制改成 `0xa19a`；
- 直接返回冻结 176-byte signature；
- 永久把 correction `0x3e` 从 C++ 规则中删除。

## 8. 当前整体边界

protected engine FDE 已从 `partial` 更新为 `recovered`。当前仓库的全量矩阵为：

```text
all FDEs:          347 recovered / 0 partial / 41 unknown
JNI-reachable:     298 recovered / 0 partial / 23 unknown
```

因此当前可以确认：

- Pixel 成功路径 protected engine 的输入、调度、branch、crypto 和输出已静态闭环；
- `0x3e` 根差异已由真实 descriptor 输入解释并消除；
- 正式证明不依赖执行补丁。

当前仍不能确认：

- 24 个 JNI 可达 unknown FDE 的全部行为；
- 所有 JNI exception、allocation failure、KeyStore/RSA failure、lockdown 和 cleanup；
- 所有设备/API/ROM/context flags 组合下的差分；
- 整个 `libsigner.so` 已达到可无条件替换状态。
