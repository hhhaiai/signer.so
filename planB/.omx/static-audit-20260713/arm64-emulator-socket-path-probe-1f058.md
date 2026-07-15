# ARM64 QEMU/Genymotion socket-path probe `0x1f058..0x1f95c`

## 1. 文件概况与范围

```text
ARM64:        0x1f058..0x1f95c
x86_64:       0x23d51..0x2422e
caller ARM64: 0xfaa8 in environment stage 0xf328
caller x86:   0x1370f in environment stage peer
callee:       path-existence array counter 0x1f95c / 0x2422e
```

当前 C++：

```text
native-reimplementation/recovered_primitives.cpp
SHA-256 7a5e394cb21dae986b7c2157973f0a663f6f28f794945a9e5a8fa55a27a88bac
```

## 2. 程序模块和执行流程

四个一次性 XOR 字符串在 ARM64/x86_64 中独立解码为：

```text
/dev/socket/qemud
/dev/qemu_pipe
/dev/socket/genyd
/dev/socket/baseband_genyd
```

函数构造四指针表，并保持固定顺序执行：

```text
pathCounter(paths[0..1], count=2, callerUint16)
pathCounter(paths[2..3], count=2, callerUint16)
```

已恢复的 `0x1f95c` 对每个路径调用 `access(path,F_OK)` 语义 helper `0xd7890`，路径存在
时才把 caller 的 16-bit 计数加一。`0x1f058` 不清零 incoming count；第二组继续累加第一
组结果，native `ldrh/add/strh` 保留 modulo-2^16 wrap。

上层 environment dispatcher 在调用前提供栈上的 `uint16_t`，返回后执行：

```text
count != 0 -> correction 0x01 + context flag bit 0
```

## 3. 关键函数及证据位置

```text
native-reimplementation/recovered_primitives.cpp:16127
  runRecoveredEmulatorSocketPathProbe1f058
native-reimplementation/recovered_primitives.cpp:16164
  recoveredEmulatorSocketPathProbe1f058Regression
native-reimplementation/recovered_primitives.cpp:29556
  executable regression guard
```

专用 verifier：

```text
.omx/static-audit-20260713/analyze_emulator_socket_path_probe_1f058.py
```

该 verifier 检查：

- ARM64/x86_64 FDE；
- 两个 ABI 的四条解码路径；
- 四指针表顺序；
- 两次、每次 count=2 的 `0x1f95c/0x2422e` 调用；
- shared caller `uint16_t`；
- `0xf328` caller 的 count!=0 / correction `0x01` gate；
- C++ regression guard、动态日志和 recovered coverage。

## 4. 输入、输出和数据结构

输入/输出是同一个 caller-owned：

```c
uint16_t* existingCount;
```

函数没有 JNI object、heap allocation、返回对象或 local-reference ownership。四个路径本身是
SO 内部一次性解码的全局字符串；C++ 以等价 immutable plaintext constants 表示。调用方
必须提供有效的 `uint16_t*`；原 SO 不对该指针做 null gate。

## 5. 原 SO observation-only 动态证据

专用测试：

```text
unidbg-adjust-runner/src/test/java/local/EmulatorSocketPathProbeNativeIntegrationTest.java
```

日志：

```text
.omx/static-audit-20260713/current-344-44-1f058-original-dynamic.log
```

关键输出：

```text
1f058 entries=1 count=0->0->0 groups=[2,2]
paths=[/dev/socket/qemud, /dev/qemu_pipe,
       /dev/socket/genyd, /dev/socket/baseband_genyd]
```

本地 Unidbg rootfs 中四条路径均未命中，所以第一组和第二组之后 count 都为 0。测试只读取
入口参数、指针表、两组 count 和 caller 返回值；没有修改寄存器、分支、路径判断结果、
文件系统、correction 或 target bytes。

## 6. 安全发现及严重程度

- **低/兼容性风险：** 只要任一固定路径存在就触发 correction `0x01`。某些兼容层、测试
  容器或厂商环境可能合法暴露同名 socket/pipe，从而产生 emulator false positive。
- **低/健壮性风险：** 原函数假定 output `uint16_t*` 有效；错误的内部调用会在路径命中时
  解引用无效指针。当前唯一已证明 caller 使用有效栈地址，因此不是已证实的外部输入漏洞。

## 7. 修复建议

1. 产品逻辑不应仅凭单一路径直接作高影响决定；应与 Build、property、sensor 等独立信号
   组合，并允许遥测确认 false-positive rate。
2. 若重构为公开接口，增加 non-null output contract 或改为直接返回 count；兼容实现保持
   原 SO 的 pointer contract。
3. 回归至少覆盖 0/1/2/4 个路径命中、两组顺序、incoming 非零、`0xfffe + 4 -> 2`
   wrap，以及 correction `0x01` gate。

## 8. 验证结果

```text
cross-ABI path constants: PASS
cross-ABI two-group orchestration: PASS
cross-ABI environment correction-0x01 gate: PASS
original-SO observation-only test: 1/1 PASS
clang++ syntax -Wall -Wextra -Werror: PASS
O2 executable regression: PASS
build-and-test / 15 oracle vectors: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen recovered backend exact match: PASS
all static analyzers: 153/153 PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
```

正式覆盖：

```text
all FDEs:      346 recovered / 0 partial / 42 unknown
JNI reachable: 297 recovered / 0 partial / 24 unknown
```

## 9. 尚不能确认的事项

- 当前动态 profile 只观察到四条路径全部不存在；1–4 个真实命中组合由已恢复 counter 和 C++
  故障注入回归覆盖，尚未通过修改 rootfs 动态构造，因为本轮坚持 observation-only。
- correction `0x01` 对最终服务端判定的独立权重仍属于更高层 protocol 行为，不由本 FDE
  单独决定。
- 剩余 42 个全文件 unknown、其中 24 个 JNI-reachable unknown 仍需逐项恢复。
