# `libsigner_compat` 非敏感兼容层说明

> 审计快照：2026-07-15。本文只描述当前本地源码中能够直接验证的 ABI、参数转发、错误边界、生命周期和构建隔离；不推断官方签名算法、密钥、设备字段语义或线上服务行为。

## 1. 文件概况与目标

当前交付物是一个与官方 `libsigner.so` **不同名**的 JNI/C++ 兼容层：

- production shared library 名为 `libsigner_compat`；CMake 的 `OUTPUT_NAME` 证据见 `CMakeLists.txt:37-62`。
- production target 只包含 `signer_jni_bridge.cpp` 和仅含 `signer_backend.cpp` 的 core，见 `CMakeLists.txt:15-17`、`CMakeLists.txt:37-46`。
- Fake 只出现在 test-enabled 目标，见 `CMakeLists.txt:65-98`；production 配置测试明确验证 Fake 安装被拒绝，见 `CMakeLists.txt:100-117`、`signer_bridge_production_config_test.cpp:17-29`。
- 历史 `recovered_primitives.cpp` 不进入 production target。安全构建脚本的 production 编译源仅为 backend 和 JNI bridge，见 `build-compatibility-layer.sh:148-157`。

该层只负责：

1. 保留 JNI 符号和函数参数布局；
2. 接收调用方传入的官方 DSO 绝对路径；
3. 将 JNI 引用和值按原样委托给该 DSO；
4. 保留 vendor `null`、pending Java exception 和返回引用的可观察语义；
5. 提供明显不可用于生产的 Fake 测试后端。

该层**不负责**生成生产签名、解释认证材料、读取 Map/`byte[]` 内容或复刻官方内部算法。

## 2. ABI / JNI 合同

### 2.1 导出符号与 descriptor

兼容层声明并实现两个 JNI wrapper：

| Java native 方法 | JNI export | descriptor | 证据 |
|---|---|---|---|
| `nOnResume` | `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume` | `()V` | wrapper 原型：`signer_jni_bridge.cpp:18-20`；实现：`signer_jni_bridge.cpp:246-271` |
| `nSign` | `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` | `(Landroid/content/Context;Ljava/lang/Object;[BI)[B` | wrapper 原型：`signer_jni_bridge.cpp:22-29`；descriptor 注释及 C++ 请求结构：`signer_backend.h:82-96`；实现：`signer_jni_bridge.cpp:273-338` |

`nSign` 的第二个业务参数必须保持 descriptor 中的 `java.lang.Object`。自然 Java 调用通常传 `Map`，但 Vendor 路径不得把 ABI 收窄为 `Map`，也不得在 wrapper 中解析其类型或内容。

### 2.2 C++ 调用方传入字段

运行时字段没有在 production 兼容层中写死。C++ 调用方可构造 `SignerRequest`，逐项传入：

| C++ 字段 | 来源 | production Vendor 行为 |
|---|---|---|
| `jni.environment` | 当前调用的 `JNIEnv*` | 仅检查非空，然后原样转发 |
| `jni.nativeLibHelper` | JNI receiver | 不要求非空，不解析，原样转发 |
| `androidContext` | 用户/JNI 调用方 | opaque 原样转发 |
| `parameterObject` | 用户/JNI 调用方；自然调用通常为 `Map` | opaque 原样转发，不枚举 Map |
| `inputByteArray` | 用户/JNI 调用方 | opaque 原样转发，不读取数组内容 |
| `androidApi` | 用户/JNI 调用方 | 保留完整 `jint`/`int32_t` 位值并原样转发 |

结构定义及“不读取内容”合同见 `signer_backend.h:76-96`。JNI bridge 将六个 JNI 参数逐项写入 `SignerRequest`，见 `signer_jni_bridge.cpp:273-306`；Vendor backend 又将这些字段逐项交给 vendor entry，见 `signer_backend.cpp:227-248`。null 引用和 `int32_t` 极值的原样转发回归见 `signer_backend_test.cpp:264-305`。

`parameterObjectIsJavaMap` 不是官方业务字段，也不会送入 Vendor。它只服务于 test-enabled Fake 后端；`isJavaMap`、Map 类型检查、Fake 输出物化和 `TestOnlyBytes` 返回分支都受 `LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND` 条件编译保护，见 `signer_jni_bridge.cpp:132-165`、`signer_jni_bridge.cpp:289-321`。production DSO 中这些 helper 和分支均不存在。

### 2.3 ownership

- `JNIEnv*`、receiver、Context、Object、输入 `byte[]` 均为当前 JNI 调用期的 **borrowed / non-owning** 引用。
- compatibility layer 不对传入引用调用 `DeleteLocalRef`，不缓存 `JNIEnv*`，不跨 JNI 调用持有 local reference。
- Vendor 返回的 `jbyteArray` 仍为 opaque JNI reference；兼容层不复制、不读取、不编码、不比较，成功时直接返回同一引用。证据见 `signer_backend.cpp:254-259`、`signer_jni_bridge.cpp:308-315`。
- 只有 test-enabled Fake 的本地 ASCII 测试 marker 会由 bridge 使用 `NewByteArray`/`SetByteArrayRegion` 物化，且该 helper 不进入 production DSO，见 `signer_jni_bridge.cpp:132-165`。

## 3. 程序模块与执行流程

### 3.1 Vendor 安装与加载

1. 调用方调用 `libsigner_compat_install_vendor(absolutePath)`；安装函数先摘除并关闭当前 backend，再校验/加载新的 caller-supplied 路径，见 `signer_jni_bridge.cpp:170-201`、`signer_jni_bridge.h:13-18`。
2. backend 拒绝空路径和相对路径，见 `signer_backend.cpp:116-132`。
3. 系统 loader 使用 `dlopen(path, RTLD_NOW | RTLD_LOCAL)`，见 `signer_backend.cpp:17-20`。
4. 两个 JNI symbol 均通过当前 DSO handle 调用 `dlsym(library, symbol)`，见 `signer_backend.cpp:22-25`、`signer_backend.cpp:148-167`。
5. bridge 将自身两个 JNI wrapper 地址作为 forbidden entry points 传入，见 `signer_jni_bridge.cpp:39-48`、`signer_jni_bridge.cpp:181-184`；backend 检测解析结果是否回指 compatibility wrapper，命中则拒绝，见 `signer_backend.cpp:170-183`。

由于兼容库使用 `libsigner_compat` 名称而官方库使用 `libsigner.so`，二者应作为不同 DSO 安装和部署，不能用同一路径或同一 SONAME 覆盖。

### 3.2 重新配置的并发与 fail-closed 边界

`gConfigurationMutex` 串行化**每一次** `replaceLayer()` 的摘除/close/发布事务；`replaceLayer()` 先在 `gLayerMutex` 下把旧 layer 从全局发布点摘除，再关闭旧 layer，最后才发布 replacement，见 `signer_jni_bridge.cpp:34-83`。这样单次替换不会同时向新旧 backend 发布新的调用；已经取得旧 `shared_ptr` 的在途调用则由 layer 自身 mutex 与 `close()` 串行。

该 mutex 并不覆盖一次 `install_vendor()` 的“清空 → `dlopen`/`dlsym` → 发布”全过程：清空和最终发布是两次独立的 `replaceLayer()`，中间加载窗口没有持有 `gConfigurationMutex`，见 `signer_jni_bridge.cpp:170-190`。因此并发 installer 采用完成/发布顺序决定最终 backend，且加载期间 JNI 可短暂观察到 `BackendNotConfigured`；文档不能把它描述为整个 install 的原子事务。

Vendor 安装采用 fail-closed 顺序：进入路径校验或 `dlopen` 前先执行 `replaceLayer(nullptr)`。因此空路径、相对路径、加载失败或 symbol 失败都不会保留先前 Fake/旧 Vendor backend，禁止“Vendor 安装失败后继续走 Fake”的隐式回退，见 `signer_jni_bridge.cpp:170-190`；Fake 后安装空 Vendor 路径的回归见 `signer_bridge_config_test.cpp:24-46`。

### 3.3 `nOnResume`

调用链：

```text
JNI wrapper
  -> currentLayer()
  -> SignerCompatibilityLayer::onResume()
  -> VendorSignerBackend::onResume()
  -> caller-supplied official nOnResume export
```

证据：`signer_jni_bridge.cpp:246-271`、`signer_backend.cpp:313-346`、`signer_backend.cpp:195-225`。

进入 vendor export **之前**即设置 `vendorEntered_ = true`，所以即使 vendor 留下 pending exception 或异常跨越 C++ 边界，后续 `close()` 也不会 `dlclose`，见 `signer_backend.cpp:206-224`、`signer_backend.cpp:272-290`。对应 pending-exception 生命周期回归见 `signer_backend_test.cpp:308-324`。

### 3.4 `nSign`

调用链：

```text
JNI wrapper
  -> 将调用方 JNI 参数填入 SignerRequest
  -> SignerCompatibilityLayer::sign()
  -> VendorSignerBackend::sign()
  -> caller-supplied official nSign export
  -> 原样返回 vendor jbyteArray 引用或 null
```

证据：`signer_jni_bridge.cpp:273-338`、`signer_backend.cpp:348-390`、`signer_backend.cpp:227-270`。

默认生命周期策略为 `VendorCompatible`，允许未显式调用 `onResume` 就直接 `sign`；可选严格策略 `RequireOnResumeBeforeSign` 会在成功 `onResume` 前拒绝 `sign`，定义见 `signer_backend.h:54-62`，默认值见 `signer_backend.h:186-191`，策略执行见 `signer_backend.cpp:348-377`。

### 3.5 关闭与 DSO 生命周期

- `VendorSignerBackend::close()`、`SignerCompatibilityLayer::close()` 和全局 C API close 均为幂等路径，见 `signer_backend.cpp:272-290`、`signer_backend.cpp:393-401`、`signer_jni_bridge.cpp:229-233`。
- 若仅完成 `dlopen`/`dlsym`、尚未进入任何 vendor export，close 会尝试 `dlclose`。
- 一旦进入 `nOnResume` 或 `nSign`，即保留 vendor DSO 到进程退出，防止 vendor 安装的 timer、callback 或全局函数指针成为悬空地址，见 `signer_backend.cpp:206-208`、`signer_backend.cpp:240-248`、`signer_backend.cpp:272-290`。
- 当前静态导出中没有可用于调用的官方 teardown 合同；兼容层不能虚构 teardown 行为。

## 4. null 与 Java exception 合同

### 4.1 Vendor 返回 null，但没有 pending exception

当前实现把它视为一次成功委托：

- `status == Ok`；
- `outputKind == VendorJavaByteArray`；
- `vendorByteArray == nullptr`；
- `productionEligible == false`；
- JNI wrapper 返回 `null`。

证据见 `signer_backend.cpp:249-259`、`signer_jni_bridge.cpp:308-315`；回归见 `signer_backend_test.cpp:251-256`。

`SignerError::VendorReturnedNull` 在 `signer_backend.h:15-30` 中为数值 ABI 稳定性保留项，并明确注释为“never emitted”。当前 Vendor null 路径不会使用该枚举；不得在调用方中假设 null 会转化为 wrapper exception。

### 4.2 Vendor 留下 pending Java exception

- backend 在调用 vendor 后通过注入的 `ExceptionCheck` adapter 检查 pending 状态，见 `signer_backend.cpp:45-49`、`signer_backend.cpp:209-213`、`signer_backend.cpp:249-252`。
- 返回状态为 `VendorExceptionPending`，但不调用 `ExceptionClear`，也不读取/替换原异常。
- JNI bridge 的 `throwStatus()` 发现已有 pending exception 时立即返回，不再 `FindClass` 或 `ThrowNew`，见 `signer_jni_bridge.cpp:118-130`。

对于 wrapper 自己产生且当前没有 pending exception 的状态，映射为：参数格式错误 → `IllegalArgumentException`，loader/self-reference → `UnsatisfiedLinkError`，`InternalError` → `RuntimeException`，其他状态错误 → `IllegalStateException`，见 `signer_jni_bridge.cpp:100-130`。`InternalError` 不再被归入 `IllegalStateException`。

因此 Java 侧观察到的是 vendor 原始 pending exception，而不是 compatibility layer 生成的覆盖异常。

## 5. Fake 测试边界

Fake 仅用于无敏感材料的接口测试：

- 固定明文为 `FAKE-ADJUST-SIGNATURE-NOT-FOR-PRODUCTION-v1`，见 `fake_signer_backend.cpp:6-9`。
- `productionEligible=false`，见 `fake_signer_backend.cpp:58-64`。
- 只验证 Object 是否被 bridge 判定为 `java.util.Map`，不枚举 Map 内容，见 `fake_signer_backend.cpp:45-64`。
- 不读取 Context、输入 `byte[]`、Map entry、secret、证书、vendor output 或网络状态。
- production 构建不链接 Fake 实现，并通过条件编译排除 Fake marker、Map helper、测试 byte-array 物化和 test-output 分支；production 中同名安装 API 只返回 `InvalidState`，见 `signer_jni_bridge.cpp:5-7`、`signer_jni_bridge.cpp:132-165`、`signer_jni_bridge.cpp:203-227`、`signer_jni_bridge.cpp:289-321`、`signer_bridge_production_config_test.cpp:17-29`。

只能静态证明 Fake 没有认证材料且输出是明显测试格式。本轮没有联网，也不能声称已经由 Adjust 生产服务验证其必然被拒绝。

## 6. 非敏感边界与必须委托的功能

以下内容不得在本兼容层内重实现、默认生成或从宿主环境采集，必须由调用方提供的官方 vendor DSO 自行处理：

- 生产签名生成和官方输出格式；
- 密钥选择、解包、KeyStore、RSA、AES、HMAC 等认证/密码学细节；
- 输入认证 `byte[]` 的内容、含义和验证；
- `Map` entry 的读取、排序、序列化和业务语义；
- Context 内的设备、包、证书、权限或认证状态；
- 官方内部 FDE、anti-debug、环境探测和状态机；
- 任何缺失字段的自动补全、宿主读取、默认值或“合理猜测”。

固定 JNI symbol、descriptor、`RTLD_NOW | RTLD_LOCAL` 和 Fake marker 属于 ABI/测试哨兵常量，不是用户业务字段。除此之外，production 调用数据必须由用户/JNI 调用方传入。

## 7. 安全发现及严重程度

| 严重程度 | 发现 | 影响 | 证据/状态 |
|---|---|---|---|
| Minor | 整个 `install_vendor()` 不是单一原子配置事务；两次并发 install 的最终 backend 由完成/发布顺序决定，加载窗口可观察到 `BackendNotConfigured` | 不会回退到旧/Fake backend，但若上层并发配置且要求确定顺序，结果可能不符合调用发起顺序 | 两次独立 replacement：`signer_jni_bridge.cpp:170-190`；每次 replacement 的串行边界：`signer_jni_bridge.cpp:66-83` |
| Informational | `VendorReturnedNull` 是保留的数值 ABI 项且永不发出 | 调用方必须按成功 null 合同处理，不能仅凭枚举名称推断异常 | `signer_backend.h:24-28`；当前 null 处理：`signer_backend.cpp:254-259` |
| Closed | DSO 保留注释曾与“进入前置位”的实现措辞不一致；现已改为 invoked/entered 语义 | 维护误导风险已关闭 | `signer_backend.cpp:272-290` |
| Closed | handle-specific `dlsym` 过去缺少 handle identity 回归；现已记录并断言两次 resolve 使用同一 DSO handle | loader 回归缺口已关闭 | 实现：`signer_backend.cpp:22-25`、`signer_backend.cpp:148-167`；回归：`signer_backend_test.cpp:156-170`、`signer_backend_test.cpp:197-216` |

当前独立复核未发现剩余 Critical/Important 兼容层问题；但这不等于官方 DSO 的内部行为已经完成真机验证。

## 8. 修复与回归建议

1. 上层配置管理应避免并发调用 install/close；若必须支持确定的调用顺序，应在公开配置 API 外再加一层覆盖整个 install 生命周期的序列化或 generation/token 检查。
2. 保持 production source allowlist、export allowlist 和 forbidden marker gate，见 `build-compatibility-layer.sh:148-196`、`audit-non-sensitive-boundary.sh:32-102`。
3. 所有新增 runtime 字段都应遵循“presence 与 value 分离”：缺失应返回错误，显式 `0`/`false`/空数组不得被当成缺失，也不得由 wrapper 自动补值。
4. 保留已补齐的 DSO handle identity、failed-Vendor-clears-Fake、pending-exception-retains-DSO 和 production-rejects-Fake 回归。

## 9. 建议的隔离动态实验（本轮未执行官方 DSO）

### 9.1 纯 Stub Vendor DSO

- **方案**：只导出两个 JNI symbol；记录收到的 pointer/value identity，不读取对象内容。
- **观察点**：Context、Object、输入 `byte[]`、receiver 和 vendor 返回 `jbyteArray` 的地址是否逐项一致；`jint` 测试 `0`、`-1`、最小值和最大值。
- **风险**：低；不得把真实认证数据放入日志。
- **预期**：所有 opaque 引用和值保持一致。

### 9.2 null / exception 四象限

分别测试：

1. `null` + 无 exception；
2. 非 `null` + 无 exception；
3. `null` + pending exception；
4. 非 `null` + pending exception。

观察 wrapper 是否保持原 exception、是否避免读取返回数组，以及 `productionEligible` 是否只在非 null vendor 引用时为 true。

### 9.3 生命周期

- `VendorCompatible` 下直接 `sign`；
- `RequireOnResumeBeforeSign` 下先 `sign` 应被拒绝；
- 连续调用两次 `close`；
- 在 vendor entry 留下 pending exception 后 close，确认不卸载 DSO。

另加一组并发配置实验：让一个 Stub Vendor 的 load 或调用处于可控阻塞状态，同时触发 Vendor→Vendor、Fake→失败 Vendor 和 close。确认每次 replacement 都先关闭旧 layer 再发布新 layer、失败 Vendor 后 backend kind 为 `None`、不存在自动回退；同时记录两个并发 install 的最终选择确实由完成/发布顺序决定。

Vendor 可能安装 process-global timer/callback，因此每组 DSO 生命周期实验应放入独立进程，通过进程退出完成最终卸载。

### 9.4 授权真机官方 DSO

如后续进入真机校准：

- 设备断网；
- 只观察 DSO 加载、符号解析、调用顺序、pointer identity 和 pending exception；
- 不记录 Map 内容、认证 `byte[]`、证书、密钥或 vendor 返回字节；
- 不修改寄存器、分支、返回值或目标代码；
- 静态证据仍为主，动态结果只用于确认 ABI/生命周期。

## 10. 尚不能确认的事项

1. Linux host 分支已实现，但本轮只在 Darwin arm64 实际运行安全构建；不能声称 Linux 运行时已验证。
2. 尚未用授权官方 DSO 完成上述真机 pointer/exception/lifecycle 矩阵。
3. 无法离线确认官方 DSO 是否在所有版本都安装 timer/callback；保留 DSO 是保守安全策略。
4. 无法联网验证 Fake 被 Adjust 生产拒绝；只能证明其没有认证材料、格式明显为测试 marker。
5. compatibility layer 没有稳定的纯 C `sign` API；当前 C++ 调用面为 `SignerCompatibilityLayer::sign(const SignerRequest&)`，外部 ABI 调用面仍为两个 JNI wrapper。如需跨编译器/跨语言的稳定 native API，应单独设计且仍只接受 opaque JNI handles，不扩展内部业务字段。
6. 已有单线程 failed-Vendor-clears-Fake 回归，但尚未用阻塞 Stub 穷举两个并发 install、close 与在途 JNI 调用的所有调度交错。
