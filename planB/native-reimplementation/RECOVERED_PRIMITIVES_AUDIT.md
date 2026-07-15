# `recovered_primitives.cpp` 安全审计

## 1. 文件概况

| 属性 | 当前值 |
|---|---|
| 文件 | `native-reimplementation/recovered_primitives.cpp` |
| 行数 | 31,213 |
| SHA-256 | `abafec344a954689d9ec30953fa6d24c8ddc5c21480d92720371b976e4f336fa` |
| Severity | **Critical** |
| Classification | **audit-only / production-ineligible** |
| 默认允许行为 | 静态阅读、hash、line count、`-fsyntax-only` |
| 默认禁止行为 | 链接、生成 executable、运行、作为 production fallback、打包进 DSO/APK |

上述 hash/行数对应 2026-07-15 本地快照。后续任何修改都必须重新计算指纹并重新核对本文行号。

## 2. Critical 判定

该文件不是普通的“函数桩”或仅含接口的兼容代码。静态证据表明它同时包含：

1. 固定认证/密码学 material；
2. AES、SHA、HMAC 等完整实现；
3. production-format payload 组合；
4. 将 IV、密文和认证 tag 组合成结果的 `sign()`；
5. 带有 `main()` 的可执行入口；
6. 完整 ciphertext/tag/signature 历史向量；
7. 可接受用户参数并打印 `SIGNATURE_HEX` 的 CLI。

因此，即使部分恢复逻辑的正确性、版本适配或完整性仍未确认，它仍具备构造生产格式认证材料的能力，不能进入“非敏感 production 兼容层”。

## 3. 敏感与 production-format 能力证据

> 本文故意不复制固定 key 字节、完整 ciphertext、tag 或 signature，只记录其存在位置。

| 能力 | 静态证据 | 风险说明 |
|---|---|---|
| 固定 AES/HMAC/custom SHA state material | `recovered_primitives.cpp:13845-13863` | 将历史保护材料固化在源码中，扩大泄露和误用面 |
| AES-256 block/CBC/PKCS#7 | `recovered_primitives.cpp:14307-14342` | 可直接完成 payload 加密 |
| SHA-256/HMAC-SHA256 | `recovered_primitives.cpp:14439-14524` | 可直接完成摘要与认证 tag |
| 字段 material 构造 | `recovered_primitives.cpp:26307-26324` | 将证书、环境、随机字段、状态和明文组合进派生值 |
| production-format payload | `recovered_primitives.cpp:26325-26349` | 明确形成有字段编号和固定布局的 payload |
| 完整 `sign()` 结果组合 | `recovered_primitives.cpp:26352-26364` | 组合 IV、CBC ciphertext 和 HMAC tag |
| 可执行入口 | `recovered_primitives.cpp:30170-30176` | 文件可被直接编译为命令行程序 |
| ciphertext/tag/signature vectors | `recovered_primitives.cpp:30901-30942` | 具备完整结果比对能力；本文不复制其字节 |
| production-format 结果说明 | `recovered_primitives.cpp:30979-30987` | 程序自身打印结果布局和历史 PASS 信息 |
| CLI 参数解析 | `recovered_primitives.cpp:31009-31155` | 可接受时间、证书、明文/参数、随机输入、状态、correction/HMAC 等字段 |
| 严格字段 presence 检查 | `recovered_primitives.cpp:31172-31201` | custom 模式会拒绝缺失字段，不再自动继承 fixture 值 |
| `SIGNATURE_HEX` 输出 | `recovered_primitives.cpp:31203-31210` | custom 请求可进入结果生成与输出路径 |

## 4. “字段由用户传入”现状

### 4.1 已做到的部分

历史文件中的 `NativeInputs` 明确列出时间、correction、随机字段、证书摘要、native plaintext 和状态，见 `recovered_primitives.cpp:18621-18628`。presence 与实际 value 被单独记录，目的就是区分“缺失”和显式 `0`/`false`/空值，见 `recovered_primitives.cpp:18630-18642`。

custom CLI 路径会：

- 从用户参数填充字段，见 `recovered_primitives.cpp:31009-31155`；
- 对未提供字段建立 missing list；
- 明确输出“does not synthesize omitted fields”并拒绝继续，见 `recovered_primitives.cpp:31172-31201`。

0x1709c 的模型也没有直接读取分析主机的 `/proc`。除已静态证明的原始路径常量外，文件字节、I/O 结果、分配和内存写入都由调用方提供的 operations callback 决定，见 `recovered_primitives.cpp:17424-17468`。这使测试可以传入观测值而不从宿主“无中生有”。

### 4.2 仍不能转为 production 的原因

“允许用户传入字段”不等于“文件已经非敏感”：

- `--use-regression-fixture` 仍会选择历史 fixture，见 `recovered_primitives.cpp:30988-30999`；
- 固定认证/密码学 material 仍在源码中，见 `recovered_primitives.cpp:13845-13863`；
- 完整签名组合仍可被调用，见 `recovered_primitives.cpp:26352-26364`；
- `main()` 在处理 CLI 前会运行大量历史回归，见入口 `recovered_primitives.cpp:30170-30176` 以及后续回归链；
- 完整历史结果向量和 `SIGNATURE_HEX` 输出仍存在，见 `recovered_primitives.cpp:30901-30942`、`recovered_primitives.cpp:31203-31210`。

因此当前正确策略不是继续把更多字段暴露到该文件的 production API，而是：

1. 将该文件保留为 audit-only 历史证据；
2. production 兼容层只接受 JNI ABI 的 caller-supplied opaque handles/value；
3. 所有生产签名语义委托给调用方提供的官方 DSO。

对应的非敏感 C++ 请求/输出合同见 `signer_backend.h:82-107`，bridge 逐项接收 caller-supplied 字段见 `signer_jni_bridge.cpp:300-306`，Vendor 原样转发见 `signer_backend.cpp:242-248`。

## 5. CLI 暴露面

`main()` 位于 `recovered_primitives.cpp:30170`。CLI 前缀集中在 `recovered_primitives.cpp:31009-31019`，参数解析延伸至 `recovered_primitives.cpp:31155`，最终 custom 请求在 `recovered_primitives.cpp:31207-31210` 打印十六进制结果。

审计结论：

- presence 检查解决了“遗漏字段时静默使用 fixture/default”的准确性问题；
- 但 CLI 本身仍是敏感能力入口；
- 不应在默认构建、CI、安装包、开发工具或 production 调试镜像中生成该 executable；
- 不应把 `--use-regression-fixture` 作为兼容层 fallback。

## 6. 与 production target 的隔离

当前门禁如下：

1. CMake production core 只含 `signer_backend.cpp`，shared library 只追加 `signer_jni_bridge.cpp`，见 `CMakeLists.txt:15-17`、`CMakeLists.txt:37-46`。
2. 安全 shell 构建的 production DSO 只编译上述两个文件，见 `build-compatibility-layer.sh:148-157`。
3. Fake 只进入 test-enabled binaries：普通目标见 `build-compatibility-layer.sh:122-138`，sanitizer 目标见 `build-compatibility-layer.sh:164-180`；production DSO 无 Fake source，见 `build-compatibility-layer.sh:148-157`。此外 Fake Map helper、测试 byte-array materialization 和 test-output 分支受编译宏保护，见 `signer_jni_bridge.cpp:132-165`、`signer_jni_bridge.cpp:289-321`。
4. production export 严格限定为两个 JNI wrapper 和五个配置 C API，见 `audit-non-sensitive-boundary.sh:32-61`。
5. production DSO 禁止 Fake/recovered symbols、`java/util/Map` Fake helper痕迹和敏感 marker，见 `audit-non-sensitive-boundary.sh:63-98`。
6. 对历史文件的安全审计编译只有 `-fsyntax-only`，无 `-o`、无链接、无运行，见 `audit-non-sensitive-boundary.sh:100-103`。
7. 历史 `build-and-test.sh` 默认立即拒绝；只有显式 legacy audit 环境变量才会到达旧主体，见 `build-and-test.sh:6-18`。
8. Vendor 安装在校验/加载新路径前先清空旧 backend；任何失败均保持 `BackendKind::None`，不会自动回退到 Fake 或 recovered，见 `signer_jni_bridge.cpp:170-190`、`signer_bridge_config_test.cpp:24-46`。

## 7. 允许与禁止操作

### 7.1 默认允许

- 文本静态阅读；
- 计算 SHA-256 和行数；
- 生成只含文件位置、不复制敏感字节的审计报告；
- `c++ -std=c++17 -Wall -Wextra -Werror -fsyntax-only recovered_primitives.cpp`；
- 检查 production target source list、exports、symbols 和 strings；
- 对非敏感 compatibility layer、Fake 或纯 stub Vendor DSO 运行单元测试和 sanitizer。

### 7.2 默认禁止

- 把 `recovered_primitives.cpp` 编译/链接成 executable 或 library；
- 执行现有历史 recovered binary；
- 将其链接进 `libsigner_compat`、APK、AAR、测试设备镜像或 CI 发布物；
- 以其作为 Vendor 加载失败、null、exception 或签名失败时的 fallback；
- 导出固定 key/material、完整向量或生产格式生成 API；
- 使用该文件生成、验证或提交真实生产请求；
- 把动态真机观察结果写回为硬编码设备字段或默认值。

## 8. 风险矩阵

| 风险 | 严重程度 | 触发条件 | 影响 | 当前控制 |
|---|---|---|---|---|
| 历史固定 material 泄露/误用 | Critical | 源码、二进制或日志被分发 | 认证边界失效、兼容层被误认为独立 signer | production source/strings gate |
| 生成 production-format 输出 | Critical | 链接或执行历史文件 | 产生不应由非敏感层具备的能力 | 默认构建拒绝；compile-only |
| 自动 fallback 到 recovered | Critical | Vendor 失败时调用历史算法 | 隐式绕过官方安全/版本边界 | 架构上禁止；Vendor 安装 fail-closed，失败后为 `None` |
| fixture/default 被误当真实设备数据 | High | 使用 regression fixture 或环境默认值 | 结果不准确、测试污染、错误安全结论 | custom presence 检查；文件整体 audit-only |
| 敏感 CLI 被纳入工具链 | High | CI/开发脚本继续编译旧入口 | 能力扩散、误执行 | `build-and-test.sh:6-13` 默认拒绝 |
| 历史 build 目录残留 executable 被误运行 | High | 人工直接执行旧产物 | 绕过新构建门禁 | 文档/流程禁止；建议独立归档或加文件系统访问控制 |
| 真机调试日志泄露输入/输出 | High | 记录 Map、认证数组、证书、返回字节 | 敏感数据落盘 | 只允许 pointer/order/exception 观察 |
| 静态行号/指纹漂移 | Medium | 文件继续修改但报告未更新 | 审计证据失真 | 每次修改重新 hash、wc、`nl -ba` |

## 9. 修复与回归门禁建议

1. **保持架构隔离**：不把历史 `NativeInputs` 或 `sign()` 暴露为 production header/API。
2. **CI 使用安全入口**：只执行 `build-compatibility-layer.sh`；禁止默认执行 legacy 脚本。
3. **artifact allowlist**：发布目录只允许 `libsigner_compat.{so,dylib}` 及必要符号文件，不允许任何 `recovered-primitives*` executable。
4. **source allowlist**：production link command 必须只有 backend + bridge；任何 Fake/recovered source 出现即失败。
5. **export/strings 双门禁**：继续执行 `audit-non-sensitive-boundary.sh:32-102`，并保留负向 gate 测试。
6. **presence/value 分离**：未来任何非敏感输入结构都必须显式记录字段是否由调用方提供；不使用 `0`、空字符串或 false 作为“未提供”的隐式标记。
7. **不记录敏感数据**：错误消息只描述状态，不拼接 Map 内容、输入数组、证书、密钥或 vendor 返回字节。
8. **历史产物治理**：在保留取证证据的前提下，将旧 executable 移入明确的隔离归档目录或设置不可执行权限；该动作属于后续运维决策，本轮未删除历史产物。

## 10. 建议的隔离动态实验（不执行 recovered signer）

### 10.1 Compatibility stub 验证

用纯 Stub Vendor DSO 验证：

- `dlopen`/handle-specific `dlsym`；
- Context/Object/`byte[]`/API 的 pointer/value identity；
- vendor return reference identity；
- null/pending exception 四象限；
- vendor entry 后 DSO 保留。

Stub 不读取对象内容，不生成认证数据。

### 10.2 真机 observation-only 校准

如需使用已授权真机和官方 DSO：

- 设备与宿主网络关闭；
- 独立测试进程；
- hook 只观察调用地址、顺序、pointer identity 和 `ExceptionCheck`；
- 不修改寄存器、返回值、JNI 对象、分支或目标字节；
- 不 dump Map、输入 `byte[]`、证书、secret 或返回结果；
- 测试结束以进程退出完成 DSO 生命周期收尾。

动态结果只用于确认 ABI 与生命周期，不用于把观察到的设备值固化为 C++ 默认值。

### 10.3 风险与预期观察点

| 实验 | 主要风险 | 预期观察 |
|---|---|---|
| Stub pointer identity | 日志误记真实数据 | 所有 caller-supplied handle/value 原样到达 vendor |
| null/exception 矩阵 | 原异常被测试框架覆盖 | pending exception 保留；null/no exception 保持成功 null |
| 生命周期 | 提前卸载含 callback 的 DSO | vendor entry 后 `close` 不调用 `dlclose` |
| 真机官方 DSO | 采集或落盘敏感信息 | 只得到 ABI/order/exception 元数据，不得到业务内容 |

## 11. 尚不能确认的事项

1. 未执行历史 `recovered_primitives.cpp` 或其现有 executable，因此不对当前文件的完整运行正确性作新声明。
2. 未执行官方生产 signer 的在线请求，无法验证任何输出是否被 Adjust 服务接受或拒绝。
3. 无法联网验证 Fake 被 Adjust 生产拒绝；只能静态证明 Fake 不含认证材料且输出具有明显测试格式。
4. 历史 recovered 文件是否覆盖官方全部版本、ABI 和状态机仍不能确认；该不确定性不会降低其 Critical 分级。
5. 当前工作区仍保留历史 recovered executables；新门禁不会自动删除或阻止人工直接执行这些旧产物。
6. Linux host 的安全构建分支尚未在 Linux 真机运行验证；本轮验证平台为 Darwin arm64。
