# libsigner 非敏感兼容层执行计划

## 目标

在 `native-reimplementation/` 中交付一个 C++17 非敏感接口兼容层：精确保留 JNI/ABI、参数引用、错误边界和生命周期；所有生产签名逻辑仅由调用方提供的官方 `libsigner.so` 完成；测试 Fake 明确不可用于生产；历史 `recovered_primitives.cpp` 仅审计、不可进入默认构建或执行路径。

## 不可突破的边界

- 不恢复、复刻、组合或新增任何能够生成 Adjust 生产有效签名的算法。
- 不提取、读取、缓存或记录密钥、设备秘密、证书材料、认证 byte[] 内容、Map 内容、认证状态或官方返回字节。
- Vendor 失败时不得自动回退到 Fake 或 recovered C++。
- Vendor 参数和返回 JNI 引用保持 opaque、borrowed、原样转发。
- Fake 只链接测试目标；生产兼容库必须拒绝安装 Fake。
- 兼容库命名为 `libsigner_compat`，不得与官方 `libsigner.so` 同名。
- 不联网，不访问外部主机；不对 Adjust 生产服务做拒绝验证。
- 不执行历史 recovered signer；最多对 `recovered_primitives.cpp` 做 compile-only 静态审计。

## 成功标准

1. 精确导出两个 JNI 符号，并保留 descriptor `()V` 与 `(Landroid/content/Context;Ljava/lang/Object;[BI)[B`。
2. `VendorSignerBackend` 使用调用方提供的绝对路径、`RTLD_NOW | RTLD_LOCAL`、handle-specific `dlsym`，并防止解析回 wrapper 自身。
3. Context/Object/byte[]/API、vendor null 结果和 pending exception 均按合同原样保留。
4. 生命周期支持 vendor-compatible 直接 sign 与可选严格 `onResume -> sign`；close 幂等；vendor 已进入回调路径后不 `dlclose`。
5. Fake 固定输出明确的 test-only 明文，`productionEligible=false`，且不进入 production shared library。
6. 默认安全构建不编译、不链接、不执行 `recovered_primitives.cpp`；旧执行脚本默认拒绝。
7. 普通构建、CMake、单元测试、ASan/UBSan、导出审计和敏感字符串 gate 全部通过。
8. 文档覆盖函数委托矩阵、输入输出/ownership/error/lifecycle 合同、历史 recovered 风险与尚不能确认事项。

## 阶段

### 阶段 1：核对当前实现与建立最新基线 — `complete`

- 读取现有 backend、JNI bridge、tests、CMake 和旧构建入口。
- 运行当前测试与 compile-only 检查，记录所有真实失败。
- 独立复审 ABI、异常、null、生命周期、loader 和线程安全边界。

当前结果：普通基线、回归红绿、CMake 3/3 和独立 re-review 已完成；最终复审为 0 Critical / 0 Important / 0 Minor。

### 阶段 2：补齐安全构建与隔离门禁 — `complete`

- 新增 `native-reimplementation/build-compatibility-layer.sh`。
- 新增 `native-reimplementation/audit-non-sensitive-boundary.sh`。
- 将 `native-reimplementation/build-and-test.sh` 改为默认拒绝旧 recovered 执行，只有显式历史审计变量才允许进入旧脚本主体。
- 确保 production target 不链接 Fake/recovered，并检查导出与敏感字符串。

### 阶段 3：补齐合同与审计文档 — `complete`

- 新增 `NON_SENSITIVE_COMPATIBILITY.md`。
- 新增 `FUNCTION_DELEGATION_MATRIX.md`。
- 新增 `RECOVERED_PRIMITIVES_AUDIT.md`。
- 文档只记录可验证合同，不虚构运行时字段或官方内部行为。

### 阶段 4：全量本地验证与修复循环 — `complete`

- 编译 `-Wall -Wextra -Werror`。
- 运行 backend 与 bridge 测试。
- 运行 ASan + UBSan 测试。
- 运行 CMake configure/build/ctest。
- 重新构建 production shared library并执行 `nm`/`strings` gate。
- 对 `recovered_primitives.cpp` 只执行 `-fsyntax-only`。

### 阶段 5：仓库级残留路径审计与最终报告 — `complete`

- 检查根目录 `test-recovered-backend.sh` 与 Java `RecoveredNativeBackend` 路径。
- 在不扩大当前实现范围的前提下，明确已隔离项与仍存在的 repository-level gap。
- 按用户要求输出：文件概况、模块/流程、关键函数证据、数据结构、安全发现、修复建议、尚不能确认事项。

## 错误记录

| 时间 | 命令/阶段 | 错误 | 处理 |
|---|---|---|---|
| 2026-07-15 | `git status --short` | 当前目录不是 Git 仓库 | 不使用 commit/branch 工作流；以文件哈希、清单和验证日志作为证据 |
| 2026-07-15 | ASan+UBSan 首轮 | Apple ASan 报告 `detect_leaks is not supported on this platform` 并在测试前中止 | 改用 `detect_leaks=0` 重跑 ASan/UBSan；LeakSanitizer 作为未覆盖项单列 |
| 2026-07-15 | legacy 默认拒绝的 command-substitution 包装复测 | 外层包装曾异常报告空输出/exit 0，与脚本不符 | 改用 `/usr/bin/env ... /bin/bash -x` 直接执行；确认 gate 在任何编译前输出拒绝并 exit 1，历史 executable 未执行 |
| 2026-07-15 | 文档敏感模式扫描 | `rg` 将以 `--java-hmac...` 开头的 pattern 误识别为命令选项 | 使用 `rg -n -- "pattern" ...` 重新执行，扫描无命中 |

## 决策记录

- 用户当前明确要求已经构成批准的架构设计，不再等待额外设计确认。
- 停止先前的 388-FDE/生产签名恢复目标。
- 旧 `recovered_primitives.cpp` 不删除历史内容，但必须默认不可构建/不可执行，并被标注为 Critical audit-only artifact。
- 本轮允许执行兼容层自身、纯 stub/Fake 单元测试和 sanitizer；不执行官方生产签名路径或历史 recovered signer。
