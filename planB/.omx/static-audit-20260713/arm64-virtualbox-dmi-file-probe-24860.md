# ARM64 VirtualBox DMI file-content probe `0x24860..0x25068`

## 1. 文件概况

授权审计目标和跨 ABI 对照：

```text
ARM64 SO:
  adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so
  SHA-256 8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371
  FDE 0x24860..0x25068

x86_64 SO:
  adjust-android-signature-3.67.0/jni/x86_64/libsigner.so
  SHA-256 a61a8c33b806f333d3c84d8392819a5508d5cf2fdcfb3c7e0e5a39bde1d771d2
  FDE 0x27397..0x278f6

ARM64 direct caller block:
  0xfbd4 in flattened environment FDE 0xf328..0xfce0

x86_64 direct caller block:
  0x1384b in flattened environment peer 0x130fb..0x13920

callee:
  ARM64  0x23274 readable-file descriptor batch
  x86_64 0x26286 peer
```

当前 C++ 恢复源码：

```text
native-reimplementation/recovered_primitives.cpp
SHA-256 7a5e394cb21dae986b7c2157973f0a663f6f28f794945a9e5a8fa55a27a88bac
```

该函数已从 inventory 的 `unknown` 更新为 `recovered`。当前正式矩阵为：

```text
all FDEs:      346 recovered / 0 partial / 42 unknown
JNI reachable: 297 recovered / 0 partial / 24 unknown
```

这里的 `JNI reachable=yes` 来自粗粒度 direct-call/tail-call 图；它不等同于
`0xf328` sole-entry flattened-state 证明中的自然可达性，具体边界见第 2 节。

## 2. 程序模块和执行流程

两个 ABI 独立解码出四个相同常量：

| 角色 | ARM64 VMA / 文件偏移 / XOR key | x86_64 VMA / 文件偏移 / XOR key | 解码结果 |
|---|---|---|---|
| record 0 path | `0x143440 / 0x13b440 / 0x6b` | `0x13be10 / 0x133e10 / 0x42` | `/sys/devices/virtual/dmi/id/product_name` |
| record 0 marker | `0x143470 / 0x13b470 / 0xba` | `0x13be40 / 0x133e40 / 0x72` | `VirtualBox` |
| record 1 path | `0x143480 / 0x13b480 / 0xdf` | `0x13be50 / 0x133e50 / 0xeb` | `/sys/devices/virtual/dmi/id/sys_vendor` |
| record 1 marker | `0x1434a8 / 0x13b4a8 / 0x40` | `0x13be78 / 0x133e78 / 0x88` | `innotek` |

解码后构造两个连续的 0x100-byte readable-file descriptor records：

```text
record[0]:
  path              = /sys/devices/virtual/dmi/id/product_name
  descriptors[0]    = VirtualBox
  descriptorKinds[0]= 3
  descriptorCount   = 1

record[1]:
  path              = /sys/devices/virtual/dmi/id/sys_vendor
  descriptors[0]    = innotek
  descriptorKinds[0]= 3
  descriptorCount   = 1
```

`kind=3` 已由恢复的 `0x23730` dispatcher 锁定为 ASCII
case-insensitive substring。函数随后执行：

```text
readableFileDescriptorBatch(records, recordCount=2, callerUint16)
```

`0x23274` 对每个可读文件取得内容，按 descriptor 顺序匹配；每个 record 首次命中后
把同一个 caller-owned `uint16_t` 加一并短路该 record。当前函数不会清零 incoming
count，因此保留 native modulo-`2^16` 累加。

### Flattened caller 的自然可达边界

原 SO 指令中确实存在：

```text
ARM64:
  0xfbcc  output = sp + 0x34
  0xfbd0  *output = 0
  0xfbd4  bl 0x24860
  0xfbd8  ldrh count
  0xfbe8  cmp count, 0

x86_64:
  0x13840 *output = 0
  0x13846 output = rsp + 0x36
  0x1384b call 0x27397
  0x13850 cmpw *output, 0
```

但是 `0xf328` 的 sole-entry opaque-state 常量传播只留下七个自然 probe：
`0x1f058`、`0x1fae4`、`0x25068`、`0x26de0`、`0x2c618`、
`0x2cc9c`、`0x21c34`，然后进入 `0xfce0`。现有证明没有把
`0xfbd4 -> 0x24860` block 纳入自然 signer chain。因此：

- 该 FDE 的函数语义和 direct call edge 已恢复；
- inventory 的粗粒度 JNI reachability 仍为 `yes`；
- 不能声称默认 signer 成功路径自然执行了这个 VirtualBox probe；
- 本轮动态验证使用隔离直接调用，只证明函数自身的 caller-visible 行为。

## 3. 关键函数及证据位置

恢复实现：

```text
native-reimplementation/recovered_primitives.cpp:3706
  runRecoveredVirtualBoxDmiFileProbe24860

native-reimplementation/recovered_primitives.cpp:3734
  RecoveredVirtualBoxDmiFileProbeRegressionState24860

native-reimplementation/recovered_primitives.cpp:3779
  recoveredVirtualBoxDmiFileProbe24860Regression

native-reimplementation/recovered_primitives.cpp:29581
  executable regression guard
```

ARM64 record publication 的关键指令：

```text
0x24fd8  stack record base
0x24fe8  record 0 path/marker decoded storage
0x24ff0  record 1 path/marker decoded storage
0x24ff4  descriptor kind = 3
0x24ff8  record count = 2
0x25000  record 0 path + descriptor[0]
0x25010  record 0 kind[0]
0x25014  record 0 descriptorCount
0x25018  record 1 path + descriptor[0]
0x2501c  record 1 kind[0]
0x25020  record 1 descriptorCount
0x25024  bl 0x23274
```

专用静态 verifier：

```text
.omx/static-audit-20260713/analyze_virtualbox_dmi_file_probe_24860.py
```

该 verifier 固定检查：

- ARM64/x86_64 FDE 边界；
- 两个 ABI 的四个常量和独立 XOR key；
- 两个连续 0x100-byte record 的 path/marker/kind/count 布局；
- `recordCount=2` 与 `0x23274/0x26286` 调用；
- flattened caller 的 zeroed `uint16_t` 转发和返回后读取；
- 原 SO observation-only 动态 token；
- C++ 符号、main guard 和 inventory recovered/JNI-reachable 状态。

全量静态门禁：

```text
ANALYZER_SUMMARY total=152 pass=152 fail=0
```

## 4. 输入、输出和数据结构

恢复函数的 caller-visible input/output：

```c
uint16_t* matchCount;
```

函数没有 JNI object 输入、Java local reference、返回对象或独立 heap ownership。两个
record 在调用期间位于原生栈上；四个解码字符串由 SO 内部 once-initialized storage
持有。C++ 以 immutable plaintext constants 表达同一协议数据。

0x100-byte record 当前使用的字段：

```text
+0x00  uint64 path pointer
+0x08  uint64 descriptors[0] pointer
+0xa8  uint32 descriptorKinds[0] = 3
+0xf8  uint64 descriptorCount = 1
size   0x100
```

其余 descriptor/kind slots 保持零。两个 records 按 record 0、record 1 顺序传入。

C++ regression 已覆盖：

```text
两个匹配:
  incoming 0xfffe + 2 -> 0x0000

两个不匹配:
  incoming 7 -> 7

固定:
  path order
  marker order
  kind [3,3]
  descriptorCount [1,1]
  recordCount 2
```

## 5. 安全发现及严重程度

1. **低/潜在兼容性风险：固定 DMI substring 可能误报。**
   如果某个兼容层、测试镜像或厂商系统的 DMI 文件合法包含 `VirtualBox` 或
   `innotek`，case-insensitive substring 会计为命中。当前 sole-entry 证明没有显示默认
   signer 路径自然进入该 block，所以这是潜在/替代入口风险，不是已证明的默认路径误报。

2. **低/内部健壮性风险：caller pointer 无 null gate。**
   原函数假定 `matchCount` 指向有效的 2-byte storage；真实文件命中时 callee 会读改写。
   当前唯一指令级 caller block 提供有效栈地址，未证明外部输入可直接控制该指针。

3. **低/检测信号质量风险：单一厂商字符串缺少强身份保证。**
   DMI 内容属于可变化的本地环境元数据；即使 block 可达，也只适合作为弱信号，不能单独
   作为高影响安全决策。

未发现该 FDE 自身进行越界 copy、外部网络访问、权限修改或凭据处理的证据。

## 6. 修复建议

1. 产品逻辑不要仅凭单个 DMI path/marker 作拒绝服务或强认证结论；应组合多个独立信号，
   并通过遥测验证 false-positive rate。
2. 产品级重写可把内部 pointer contract 改为显式返回 `uint16_t` 或增加 non-null
   precondition；兼容性恢复层应继续保持原 SO 的 incoming-count 和 wrap 语义。
3. 对读取内容设置明确最大长度、NUL termination 和 I/O failure 分类；继续复用当前已恢复
   `0x23274` 的 first-match-per-record 规则。
4. 回归至少覆盖大小写混合 substring、marker 缺失、文件不可读、incoming 非零、
   `0xfffe + 2 -> 0`、record 顺序，以及 `0xf328` sole-entry reachability 不漂移。

## 7. 尚不能确认的事项

- 原 SO 动态测试使用 `Module.emulateFunction()` 直接调用 `0x24860`；没有通过修改
  opaque state、寄存器、分支、返回值、文件内容或 rootfs 强制自然路径进入该 block。
- 本地 rootfs 两个 DMI 文件均未产生 marker match，因此真实 match 的动态计数增长由
  `0x23274/0x23730` 静态恢复和 C++ 回归证明，尚无 observation-only 原 SO 命中样本。
- 尚未证明除 `0xf328` flattened block 外存在其他运行时入口。
- 剩余 42 个全文件 unknown、其中 24 个 JNI-reachable unknown 仍需逐 FDE 恢复。

本轮已执行验证：

```text
dedicated cross-ABI analyzer: PASS
original-SO direct observation-only integration test: 1/1 PASS
  entries=1
  count=0->0
  paths=[product_name, sys_vendor]
  markers=[VirtualBox, innotek]
  kinds=[3,3]
  descriptorCounts=[1,1]

clang++ -std=c++17 -Wall -Wextra -Werror -fsyntax-only: PASS
O2 executable regression, 125 main guards: PASS
unique bool *Regression definitions: 130
build-and-test / 15 original-SO oracle vectors: PASS
ASan+UBSan: PASS
  LeakSanitizer disabled because macOS does not support it
frozen Pixel recovered backend exact match: PASS
all static analyzers: 153/153 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
RecoveredNativeBackendIntegrationTest:
  first run: fork JVM exit 134, tests run 0
  hs_err: SIGBUS in libunicorn_java.dylib tb_alloc_aarch64+0xd4
  isolated retry: 21/21 PASS
```

动态测试和日志：

```text
unidbg-adjust-runner/src/test/java/local/VirtualBoxDmiFileProbeNativeIntegrationTest.java
.omx/static-audit-20260713/current-345-43-24860-original-dynamic.log
.omx/static-audit-20260713/current-345-43-24860-maven-recovered.log
.omx/static-audit-20260713/current-345-43-24860-maven-recovered-retry.log
.omx/crash-diagnostics/hs_err_pid59754.log
```
