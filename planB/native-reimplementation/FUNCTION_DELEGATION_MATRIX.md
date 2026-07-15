# `libsigner_compat` 函数委托矩阵

> 结论先行：production compatibility layer 只做 ABI、loader、状态和错误边界管理。所有生产认证与签名语义必须委托给调用方指定的官方 vendor DSO；所有运行时引用和值均由用户/JNI 调用方提供，不由 C++ wrapper 写死、采集或臆造。

## 1. 调用面矩阵

| Surface / descriptor | 本地 compatibility layer 动作 | Vendor 动作 | 输入/输出 ownership | null / exception | Production eligibility | 证据 |
|---|---|---|---|---|---|---|
| `libsigner_compat_install_vendor(path)` | 先摘除/关闭当前 layer，再校验 path、加载 Vendor，最后发布新 layer；失败后保持 `None`，不保留 Fake/旧 Vendor | 无；仅装载官方 DSO | `path` 在构造时复制到 `std::string` | 空/相对路径返回 `InvalidArgument`；open/resolve 失败返回对应状态；全部 fail-closed | 仅安装成功不产生签名 | `signer_jni_bridge.cpp:170-201`；`signer_backend.cpp:116-187`；回归 `signer_bridge_config_test.cpp:24-46` |
| `replaceLayer(replacement)` | 串行化单次“摘除旧 layer → close → 发布 replacement”事务 | 无 | 用 `shared_ptr` 保证在途调用对象存活；layer mutex 与 close 串行 | close 失败时不发布 replacement | N/A | `signer_jni_bridge.cpp:34-83` |
| 并发 install | 两次 install 各自包含两个独立 `replaceLayer()`；load 窗口不持有配置锁，最终 backend 由完成/发布顺序决定 | 各自执行 DSO load | 无业务字段共享 | load 窗口 JNI 可看到 `BackendNotConfigured`；不会回退旧/Fake | 最终成功发布的 Vendor 才有资格产生输出 | `signer_jni_bridge.cpp:66-83`、`signer_jni_bridge.cpp:170-190` |
| Vendor loader | `dlopen(path, RTLD_NOW | RTLD_LOCAL)`；在返回 handle 上解析两个 JNI symbol；拒绝自引用 | 提供两个 JNI exports | DSO handle 由 backend 管理；进入 vendor 后保留至进程退出 | symbol 缺失时在尚未进入 vendor 的前提下关闭 DSO | N/A | `signer_backend.cpp:17-25`、`signer_backend.cpp:140-187` |
| `nOnResume` / `()V` | 获取 layer；构造只含 `JNIEnv*`、receiver 和 exception adapter 的上下文；委托 | 接收原始 `JNIEnv*` 和 receiver；执行官方生命周期逻辑 | JNI 引用 borrowed/non-owning | pending exception 返回 `VendorExceptionPending`，不 clear/覆盖 | 不直接产生输出 | `signer_jni_bridge.cpp:18-20`、`signer_jni_bridge.cpp:246-271`、`signer_backend.cpp:195-225` |
| `nSign` / `(Landroid/content/Context;Ljava/lang/Object;[BI)[B` | 将 JNI 参数逐项写入 `SignerRequest`；production Vendor 路径不做 Map 检查；委托并原样返回 vendor reference | 接收 Context/Object/`byte[]`/API，解释所有官方语义并产生官方结果 | 输入 refs borrowed；vendor output opaque JNI ref | null/no exception 是成功 null；pending exception 不被覆盖 | 只有非 null vendor ref 时兼容层标记 true；服务端仍是最终判断者 | `signer_backend.h:82-107`；`signer_jni_bridge.cpp:273-338`；`signer_backend.cpp:227-270` |
| `JNIEnv*` | 只检查非空，并供 `ExceptionCheck` 使用 | 作为 JNI 调用上下文 | borrowed；不缓存 | null 返回 `InvalidArgument` | N/A | `signer_backend.cpp:200-204`、`signer_backend.cpp:235-239`、`signer_backend.cpp:303-310` |
| NativeLibHelper receiver | Vendor 路径不验证、不解析，原样转发 | 决定其 null/对象语义 | borrowed | 可为 null；compatibility layer 不发明错误 | 由 vendor 结果决定 | `signer_backend.cpp:206-208`、`signer_backend.cpp:242-248`；回归 `signer_backend_test.cpp:271-300` |
| Android Context | 不调用任何 Context 方法 | 若官方实现需要，由 vendor 自行访问 | borrowed opaque handle | 可为 null并原样转发 | 由 vendor 结果决定 | `signer_backend.h:89-96`、`signer_backend.cpp:242-248` |
| descriptor 中的 `Object` | production Vendor 路径不检查类型、不枚举内容 | 自行决定是否按 Map 或其他对象处理 | borrowed opaque handle | 可为 null并原样转发 | 由 vendor 结果决定 | `signer_backend.h:82-96`、`signer_jni_bridge.cpp:291-306` |
| `Map` 类型 | 仅 test-enabled Fake 路径执行 `IsInstanceOf(java/util/Map)`；helper 和调用点均条件编译 | Vendor 路径完全不依赖本地判定 | 临时 `jclass` 由 bridge 删除；Map 本身 borrowed | Fake 中非 Map 返回 `InvalidParameterFormat` | Fake 始终 false | `signer_jni_bridge.cpp:132-165`、`signer_jni_bridge.cpp:289-298`、`fake_signer_backend.cpp:45-64` |
| Map 内容/参数语义 | **不读取、不排序、不序列化、不补字段** | 全部由官方 vendor 处理 | 无本地所有权 | compatibility layer 不产生内容级错误 | 仅 vendor 输出可能进入 production path | `signer_backend.h:82-88` |
| 输入 `byte[]` | 不调用数组读取 API，原样转发引用 | 解释认证数据的内容、长度和格式 | borrowed opaque handle | 可为 null并原样转发 | 由 vendor 结果决定 | `signer_backend.cpp:242-248`；回归 `signer_backend_test.cpp:279-301` |
| Android API `jint` | `static_cast<int32_t>` 后按位值转发 | 自行解释版本语义 | 值类型 | `0`、负数、极值均不被 wrapper 改写 | 由 vendor 结果决定 | `signer_jni_bridge.cpp:300-306`；回归 `signer_backend_test.cpp:285-301` |
| Vendor 返回 `jbyteArray` | 不读取、不复制、不编码；直接返回同一 ref | 产生并拥有 JNI 返回语义 | opaque JNI ref；按 JNI 返回合同交给 JVM/调用方 | pending exception 优先；无 exception 的 null 保持 null | `output != nullptr` 时 true | `signer_backend.cpp:249-259`、`signer_jni_bridge.cpp:308-315` |
| `throwStatus` | 仅在没有 pending Java exception 时映射 wrapper 状态并 `ThrowNew`；`InternalError` 映射 `RuntimeException` | 无 | 临时异常 class local ref 由 bridge 删除 | 已有 exception 时立即返回，不覆盖 vendor exception | N/A | `signer_jni_bridge.cpp:100-130` |
| 默认生命周期 | `VendorCompatible`：可直接 sign | vendor 自行完成内部初始化 | layer/backend 使用互斥锁保护状态 | 成功 sign 后 layer 进入 Resumed | 由 vendor 输出决定 | `signer_backend.h:54-62`、`signer_backend.cpp:348-377` |
| 严格生命周期 | `RequireOnResumeBeforeSign`：成功 resume 前拒绝 sign | 无额外行为 | policy 为 layer 成员 | 返回 `InvalidState` | N/A | `signer_backend.cpp:361-367`；Fake 回归 `signer_backend_test.cpp:45-60` |
| `close()` | 幂等；尚未进入 vendor 时可 `dlclose`；进入后丢弃本地 handle 但保留 loader 引用至进程退出 | 没有已确认 teardown export | layer/backend 自身状态归 Closed | 重复 close 成功 | N/A | `signer_backend.cpp:272-290`、`signer_backend.cpp:393-401`、`signer_jni_bridge.cpp:229-233` |
| Fake backend | 仅检查基本调用状态和 Map 类型；返回固定测试 marker；全部仅进入 test-enabled binary | 无 Vendor 调用 | 本地 `std::vector<uint8_t>`，由 test bridge 物化 Java array | 错误映射为 wrapper 状态 | 永远 false | `fake_signer_backend.cpp:6-9`、`fake_signer_backend.cpp:31-70`、`signer_jni_bridge.cpp:132-165` |
| production Fake installer | 保留稳定 C symbol，但编译为拒绝 stub；Fake helper/marker/Map/test-output 分支均不进入 production DSO | 无 | 无 backend 被安装 | 返回 `InvalidState` | false/N/A | `signer_jni_bridge.cpp:203-227`、`signer_jni_bridge.cpp:289-321`、`signer_bridge_production_config_test.cpp:17-29` |
| `recovered_primitives.cpp` | production 中不编译、不链接、不执行；只允许静态审计/`-fsyntax-only` | 不适用 | audit-only 文件 | 默认旧执行脚本拒绝 | production-ineligible | `build-compatibility-layer.sh:148-157`、`audit-non-sensitive-boundary.sh:100-103`、`build-and-test.sh:6-18` |
| 官方内部 FDE / anti-debug / environment probes | 不重实现、不调用 recovered fallback、不采集宿主字段 | 必须由官方 vendor 自行执行 | compatibility layer 无所有权 | vendor exception/null 原样保留 | 只可能通过 vendor 结果进入生产 | production target 清单：`CMakeLists.txt:15-63` |

## 2. C++ 字段来源合同

### 2.1 必须由调用方提供

`SignerRequest` 的以下字段全部由用户/JNI 调用方传入：

```text
JNIEnv*
NativeLibHelper receiver
Android Context
descriptor 中的 Object
输入 byte[]
Android API jint
```

定义见 `signer_backend.h:76-96`，bridge 赋值见 `signer_jni_bridge.cpp:300-306`。compatibility layer 不为 null 字段创建替代对象，也不为 API 值设置“合理默认值”。

`JniExceptionOperations` 是异常观察基础设施，不是业务字段。标准 JNI wrapper 会自动提供基于 `ExceptionCheck` 的 callback，见 `signer_jni_bridge.cpp:85-98`；直接使用 C++ layer/backend 且要求保持 pending-exception 合同的调用方，必须提供等价的 `exceptionPending` callback，定义见 `signer_backend.h:70-80`、消费逻辑见 `signer_backend.cpp:45-49`。

### 2.2 允许固定的常量

只有下列非业务值可以固定：

- 两个 JNI export 名：ABI 必须一致，见 `signer_backend.cpp:12-15`；
- Java descriptor：ABI 必须一致，见 `signer_backend.h:82-83`；
- `RTLD_NOW | RTLD_LOCAL`：loader 策略，见 `signer_backend.cpp:17-20`；
- Fake marker：专用于测试并明显 production-ineligible，见 `fake_signer_backend.cpp:6-9`。

这些值不是设备、用户、认证或请求字段。

### 2.3 禁止由 compatibility layer 生成的字段

不得生成或猜测：

- 时间、随机数、设备标识、包名、证书、SDK 信息；
- Map key/value 或序列化顺序；
- 认证 HMAC、密钥、摘要、IV、nonce；
- 官方 correction/status/environment 语义；
- 缺失 Context/Object/`byte[]` 的替代值。

如果 vendor 需要这些信息，应通过既有 Context/Object/`byte[]`/API 调用合同获得，而不是把其内部格式扩展到 compatibility layer。

## 3. 错误优先级

1. Vendor 安装先清空旧 backend；路径/loader/配置错误在进入新 vendor 前返回，失败后 backend 保持 `None`，不回退旧 Vendor 或 Fake；
2. vendor 调用后若存在 pending Java exception，保留该 exception，并返回 `VendorExceptionPending` 内部状态；
3. vendor 无 exception 且返回 null，则返回成功 null，不生成 `VendorReturnedNull` 异常；
4. vendor 非 null 且无 exception，原样返回引用；
5. Fake 输出只在 `LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND` 构建中走 `TestOnlyBytes && !productionEligible` 分支；production DSO 不编译该分支；
6. wrapper 自己产生的 `InternalError` 映射为 `java/lang/RuntimeException`；已有 vendor pending exception 优先且不被覆盖。

证据见 `signer_jni_bridge.cpp:100-130`、`signer_jni_bridge.cpp:170-190`、`signer_backend.cpp:227-270`、`signer_jni_bridge.cpp:308-325`。

## 4. 回归门禁

- 普通 backend/bridge/production-config tests 构建与执行：`build-compatibility-layer.sh:122-162`。
- ASan+UBSan 三个测试构建与执行：`build-compatibility-layer.sh:164-193`。
- production 仅编译 backend + bridge：`build-compatibility-layer.sh:148-157`。
- 七个 export 的严格 allowlist：`audit-non-sensitive-boundary.sh:32-61`。
- Fake/recovered/`java/util/Map`/sensitive symbol 与 marker 禁止清单：`audit-non-sensitive-boundary.sh:63-98`。
- recovered 文件只允许 `-fsyntax-only`：`audit-non-sensitive-boundary.sh:100-103`。
- 历史 oracle 脚本默认拒绝：`build-and-test.sh:6-13`。

## 5. 回归状态与仍需补的测试

handle-specific `dlsym` 已由 stub 记录和断言两次 resolve 都收到 `mockOpen()` 返回的同一 DSO handle，见 `signer_backend_test.cpp:156-170`、`signer_backend_test.cpp:197-216`。Fake 后失败 Vendor 安装会清空 backend 的 fail-closed 行为也已有回归，见 `signer_bridge_config_test.cpp:24-46`。

仍建议补充阻塞 Stub 多线程回归，覆盖两个并发 install、close 与在途 JNI 调用的调度交错；当前实现保证每次 `replaceLayer()` 事务串行，但整个 install 的两次 replacement 之间存在未持锁的 DSO load 窗口，见 `signer_jni_bridge.cpp:66-83`、`signer_jni_bridge.cpp:170-190`。
