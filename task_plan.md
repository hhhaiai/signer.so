# libsigner.so 逆向分析计划

## 目标

在不修改原始样本的前提下，完整映射 `libsigner.so` 的运行逻辑，重点恢复 JNI 入口、签名算法、状态初始化、反分析/LLVM 混淆结构，并交付可复核的伪代码、调用图、关键常量、复现脚本，以及可在 PC 上直接加载并调用该 Android `.so` 的执行环境。

核心运行验收以 **纯 PC、本地离线、自包含 fixture** 为准：不得要求安卓真机、ADB、真机 AndroidKeyStore 或设备在线配合。包名、证书、SDK、`key2`/HMAC、传感器和系统边界均由本地配置或严格 emulator bridge 提供；真实设备材料只作为可选的 byte-for-byte oracle 输入，不是运行前置条件。

## 工作约束

- 原始文件只读；所有解包、修补、导出物放入独立目录。
- 以实际 ELF/运行时证据优先，现有 `.txt` 仅作为线索。
- 每个结论记录文件偏移、虚拟地址、符号/交叉引用或动态证据。
- 不将“反编译器输出”直接等同于原始逻辑；需要通过交叉引用、数据流和可执行验证收敛。

## 阶段

| 阶段 | 状态 | 交付物 |
|---|---|---|
| 1. 样本保全与资产盘点 | complete | 哈希、架构、压缩包清单、工具链清单 |
| 2. ELF/JNI/加固结构映射 | complete | sections、imports/exports、JNI 注册、混淆与反分析特征 |
| 3. 关键入口并行深挖 | complete | `nSign`、`nOnResume`、初始化/辅助函数调用链 |
| 4. 算法与数据结构恢复 | complete | 参数语义、关键常量、32 位栈式 VM、显式/隐式状态边界、证据分级恢复代码 |
| 5. PC 调用环境设计与测试向量 | complete | unidbg 主路径、QBDI 兼容边界、真实与固定 VM 向量 |
| 6. PC harness 实现与动态验证 | complete | unidbg SDK 23/30 均出 304 字节；trace、VM 向量与 strict bridge 已复验 |
| 7. 可复用 Skill 创建与双端安装 | complete | Codex + Claude Code 已安装并做脚本验证；Claude CLI 模型级测试受登录状态限制 |
| 8. 清理与最终报告 | complete | 根/运行 README、验证记录、规划文件回填、全量验证、明确剩余未知 |
| 9. 独立工程运行手册 | complete | 面向使用者的首次部署、调用、集成、输出解释和故障排查文档 |
| 10. Word 操作文档 | complete | 正式 DOCX 操作手册、OOXML/结构审计与 QuickLook 首屏检查；本机缺少 LibreOffice，未完成标准全页渲染 |

## 验收标准

- 能说明库如何装载、JNI 方法如何绑定、每个公开入口的输入输出和副作用。
- 能从入口追到签名结果生成点，列出参与计算的数据、顺序、常量和外部依赖。
- 对主要 LLVM 混淆手段给出具体证据和去混淆策略，而非只做工具指纹判断。
- 关键伪代码至少由两类证据交叉验证：反汇编/数据流、已有运行记录、动态 hook、或独立重实现输出。
- unidbg harness 可从命令行装载样本并调用目标 JNI 方法；所需 Java/Android stub 有明确实现和错误诊断。
- QBDI 或经证据选择的等价 PC 方案能捕获关键基本块/调用/内存访问，并能用同一测试向量对照移动端或 unidbg 结果。
- 至少提供一个一键运行入口，输入参数可配置，输出包含原始返回值及必要的 trace/debug 信息。
- 创建并验证可复用的 Android SO 深度逆向 Skill，直接安装到 Codex 与 Claude Code 的个人 Skill 目录。
- 所有生成物与原始样本隔离，步骤可从干净基线重放。

## 风险与未知

- 当前尚未确认压缩包内 ABI、是否有壳/自解密代码、是否依赖 Android Java/系统环境。
- 若缺少匹配 APK/Java 调用方或运行设备，动态验证可能只能做到局部 emulation/replay。
- OLLVM 控制流平坦化可能使通用反编译器产生严重伪代码失真，需要脚本化 CFG/数据流恢复。
- “ubqi”暂按 QBDI 理解；若资产或工具链表明是另一框架，将在不改变“PC 直接调用 + 指令级观测”目标的前提下调整实现。
- 受保护签名主体已证实是 32 位栈式 VM program/orchestrator；当前恢复到 VM 结构、handler 语义、9 个输入 blob 和固定 304 字节输出边界，尚不能诚实宣称已把全部虚拟化程序重写为脱离原 `.so` 的原始算法源码。
- 当前无真实设备 `key2`、目标 APK 证书、移动端同状态 oracle；因此本地结果已证明流程可执行，但不能宣称与某一真实设备逐字节相同。
- macOS 宿主不能直接装载 Android ELF；QBDI 真实分支需要兼容 Android/Linux loader 或进程，当前只验证 schema/stub/environment checker。
- SDK 18-22 的官方 legacy 分支在 runtime 探测中首先要求 `SharedPreferences("adjust_keys")`，随后还需 RSA AndroidKeyStore 包装/解包；当前 PC harness 为保持 strict 语义明确支持 SDK >=23，不用空 `getString`/假 RSA 伪造 legacy 成功。

## 收尾结果

1. `recovered/vm-zero-vector.json` 已包含 fresh-emulator 首次 VM 调用的完整 304 字节输出。
2. `recovered/vm-live-inputs.md` 已记录两次 live 9-Blob 差分，并通过 clean-context replay 证明还存在隐式 mutable state。
3. SDK 23/30 已完整跑通；SDK 18-22 的 SharedPreferences/RSA legacy 边界已探明并被 strict 拒绝，未用假 stub 冒充支持。
4. `README.md`、`runtime/unidbg/README.md`、`analysis/verification.md` 已完成。
5. Maven 18 tests、Python 9 tests、QBDI CTest、Skill 双端、四 ABI 哈希、C/C++ smoke 和项目外一键运行均已重新验证。

## Planning Skill 状态索引

### Phase 1 — 样本保全与资产盘点
**Status:** complete

### Phase 2 — ELF/JNI/加固结构映射
**Status:** complete

### Phase 3 — 关键入口深挖
**Status:** complete

### Phase 4 — 算法与数据结构恢复
**Status:** complete

### Phase 5 — PC 运行环境与向量设计
**Status:** complete

### Phase 6 — unidbg/QBDI 实现与动态验证
**Status:** complete

### Phase 7 — Skill 双端安装
**Status:** complete

### Phase 8 — 文档与最终验证
**Status:** complete

### Phase 9 — 独立工程运行手册
**Status:** complete

### Phase 10 — Word 操作文档
**Status:** complete

## 错误记录

| 时间 | 错误 | 处理 |
|---|---|---|
| 2026-07-10 | 当前工作区不是 Git 仓库，无法按通用 Skill 流程提交设计文档 | 保留所有规划/证据文件；不为此分析任务擅自初始化 Git，最终明确记录未提交状态 |
| 2026-07-10 | `/opt/local/bin/python3 -m json.tool` 因异常 `argparse -> requests` 导入失败 | 改用已安装的 `jq`；详细记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | `grep.app` API 被 Vercel challenge 以 HTTP 429 拦截 | 停止重试，转用 Maven Central 官方 artifact；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 元数据中的 3.35.1 AAR 返回 404，首个 `set -e` 批处理提前退出 | 改为逐版本容错下载；3.62.0 已精确匹配，记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | Task 1 首次资源复制在 `runtime/unidbg` workdir 下误用根目录相对路径 | 改用 `../../jni/...` 并先验证路径；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | Maven 默认 compiler 3.1 使用已废弃 source/target 5，RED 测试未到目标失败点 | 固定 compiler plugin 3.11.0 + release 11；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | JNI 单测把 `VM` 接口直接传给要求 `BaseVM` 的分派方法 | 在直接分派测试中显式转换实际 VM；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 测试误把 `DvmClass.getName()` 预期为 slash 形式 | 修正为 unidbg 返回的 dotted Java name；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 首次真实 `nSign` 缺少 `PackageInfo.signatures`，且无日志 provider 导致 unidbg 交互 debugger 挂起 | 增加证书 JNI bridge 与 `slf4j-simple`，终止遗留 Surefire 进程；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 证书路径继续缺少 `MessageDigest.getInstance(String)` | 用 host JCA 桥接静态 digest factory；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 实际证书摘要使用 `MessageDigest.update([B)` + `digest()` | 增加增量摘要 JNI bridge；记录于 `.learnings/ERRORS.md` |
| 2026-07-10 | 系统 Python 3.9 不支持分析 helper 使用的 `int.bit_count()` | 根因是解释器版本差异；改用 `bin(value).count("1")` 做兼容的 bit 差分统计，不修改交付代码 |
| 2026-07-10 | `/usr/bin/python3` 运行 Skill `quick_validate.py` 缺少 PyYAML | 不安装新依赖；改用 Skill 自带 `python_runner.sh` 自动选择已有且依赖完整的解释器，两端验证均通过 |
| 2026-07-10 | 将最低 SDK 从 21 试探降到 18 后，真实路径依次要求 `Context.getSharedPreferences`、`SharedPreferences.getString`，证明 legacy 分支尚未完整桥接 | 回到最早不确定边界，删除部分 permissive bridge；将 harness 最低 SDK 收紧为已验证的 23，并增加拒绝 SDK 22 的回归测试 |
| 2026-07-10 | QBDI fresh build 发现 `trace_schema_test` 需要 `TraceEvent.module_size`，header/callback 尚未同步 | 用现有失败测试做 RED，补齐字段、范围校验、JSON 输出和 callback 赋值；重新 CMake/CTest 1/1 通过并经公共 validator 验证 |
| 2026-07-10 | Planning Skill 完成检查只识别 Phase heading + Status marker，旧计划使用表格导致报告 `0/0` | 保留可读表格，并追加 8 阶段机器可读状态索引 |
