# libsigner Reverse Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 恢复 Adjust Signature 3.62.0 的关键 native 逻辑，并交付可在 PC 上真实调用原始 Android `.so` 的 unidbg 工程、统一 trace 和双端安装 Skill。

**Architecture:** 以官方 AAR 和当前样本哈希锁定版本，以 ARM64 unidbg 作为主执行后端；用失败驱动的 JNI bridge 补齐 Android/Java 对象边界。静态恢复与动态 trace 使用同一地址表，QBDI 作为可选后端而不是错误地在 macOS 直接加载 Android ELF。

**Tech Stack:** Java 11, Maven, unidbg 0.9.8, JUnit 5, Python/shell analysis helpers, ELF/binutils/radare2, optional QBDI.

---

### Task 1: 建立样本身份与 HMAC 边界测试

**Status:** complete

**Files:**
- Create: `runtime/unidbg/pom.xml`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/SampleIdentityTest.java`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/HmacInputBuilderTest.java`
- Create: `runtime/unidbg/src/main/resources/arm64-v8a/libsigner.so`

- [x] 先写测试，断言 ARM64 SHA-256 为 `fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736`。
- [x] 先写固定 `LinkedHashMap`、固定 HMAC key 的 expected input string 和 HMAC-SHA256 HEX 测试。
- [x] 运行 `mvn test`，确认因 `HmacInputBuilder` 尚不存在而失败。
- [x] 实现最小 `HmacInputBuilder`，只支持有序 String Map 和 HMAC-SHA256。
- [x] 重跑测试至通过。

### Task 2: 实现可诊断的 JNI runtime

**Status:** complete

**Files:**
- Create: `runtime/unidbg/src/main/java/com/adjust/research/SignerConfig.java`
- Create: `runtime/unidbg/src/main/java/com/adjust/research/SignerRequest.java`
- Create: `runtime/unidbg/src/main/java/com/adjust/research/AndroidRuntimeJni.java`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/AndroidRuntimeJniTest.java`

- [x] 写测试覆盖 package name、Map entrySet/iterator/entry key/value、Object.toString 的宿主对象桥接。
- [x] 运行测试确认缺失实现失败。
- [x] 使用 `AbstractJni` + `ProxyDvmObject`/精确 override 实现 bridge；未知 signature 抛出诊断异常。
- [x] 重跑测试。

### Task 3: 加载真实 `.so` 并建立失败基线

**Status:** in_progress

**Files:**
- Create: `runtime/unidbg/src/main/java/com/adjust/research/LibSignerEmulator.java`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/LibSignerEmulatorTest.java`

- [x] 写测试要求定位 `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` 与 `..._nOnResume`。
- [x] 写 native smoke test，调用 descriptor `nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B` 并要求返回非空。
- [x] 首次运行记录第一个真实缺失 JNI/system/IO 调用，确认测试因该边界失败而非测试配置错误。
- [ ] 每次只补一个被证据触发的 bridge/IO 行为并重跑，直至得到真实非空返回。

### Task 4: 构建 CLI 与稳定测试向量

**Files:**
- Create: `runtime/unidbg/src/main/java/com/adjust/research/SignerCli.java`
- Create: `runtime/unidbg/src/test/resources/request-sandbox.json`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/SignerCliTest.java`
- Create: `runtime/unidbg/run.sh`

- [ ] 写 CLI 测试覆盖固定 key、自带 HMAC、HEX/Base64 输出和错误 key 参数。
- [ ] 实现 `--param key=value`、`--request-json`、`--hmac-key-hex`、`--hmac-hex`、`--sdk`、`--package`。
- [ ] `run.sh` 只调用 Maven/已打包 jar，不依赖当前工作目录中的隐式文件。
- [ ] 从干净目录执行一键命令并保存输出向量。

### Task 5: 指令 trace 与地址映射

**Files:**
- Create: `runtime/unidbg/src/main/java/com/adjust/research/TraceRecorder.java`
- Create: `runtime/unidbg/src/test/java/com/adjust/research/TraceRecorderTest.java`
- Create: `recovered/address-map.md`
- Create: `recovered/strings.json`

- [ ] 写 trace 测试，要求 JSONL 至少包含模块相对 PC `0x0a95ac`，且所有记录都在模块范围内。
- [ ] 实现地址范围、最大指令数和关键函数过滤。
- [ ] 把静态解密字符串的地址/key/guard 写入机器可读 JSON。
- [ ] 用一次真实签名 trace 更新地址表，不把日志噪声当业务调用。

### Task 6: 恢复源码级逻辑

**Files:**
- Create: `recovered/jni_contract.h`
- Create: `recovered/signer_pipeline.cpp`
- Create: `recovered/native-analysis.md`
- Create: `analysis/scripts/decode_xor_strings.py`
- Create: `analysis/scripts/extract_ghidra_function.py`
- Create: `analysis/tests/test_decode_xor_strings.py`

- [ ] 先写字符串解密脚本测试，使用已知 `environment`/`sandbox` 向量。
- [ ] 实现脚本并导出所有可证明的字符串。
- [ ] 恢复 `nOnResume`、`nSign`、`0x08b510`、`0x0a8dec` 及签名核心调用链。
- [ ] 对每个 helper 标明“已命名/仅地址化/待动态验证”，禁止补写无证据算法。
- [ ] 用跨 ABI 与动态 trace 验证关键分支。

### Task 7: QBDI/统一 trace 后端

**Files:**
- Create: `runtime/qbdi/CMakeLists.txt`
- Create: `runtime/qbdi/src/trace_schema.h`
- Create: `runtime/qbdi/src/android_attach_tracer.cpp`
- Create: `runtime/qbdi/check-environment.sh`

- [ ] 写 schema 单元测试/编译测试，确保与 unidbg JSONL 字段一致。
- [ ] 实现 Android/Linux 进程内 QBDI callback，按模块基址输出相对 PC。
- [ ] `check-environment.sh` 明确检测 QBDI、目标 Android loader/进程和 ABI；缺失时非零退出并给出精确缺项。
- [ ] 在当前主机至少验证环境检查和编译前置；若无 QBDI，保留 unidbg trace 为已验证主路径并记录未执行差距。

### Task 8: 创建并安装 Skill

**Files:**
- Create: `~/.codex/skills/android-so-reversing/SKILL.md`
- Create: `~/.codex/skills/android-so-reversing/agents/openai.yaml`
- Create: `~/.codex/skills/android-so-reversing/references/*.md`
- Create: `~/.codex/skills/android-so-reversing/scripts/*.py`
- Install: `~/.claude/skills/android-so-reversing`

- [ ] 记录无 Skill 基线代理的遗漏/提前停止行为。
- [ ] 使用官方 `init_skill.py` 初始化规范目录。
- [ ] 编写最小 Skill，针对基线缺口加入证据优先、跨 ABI、JNI 失败驱动、动态一致性和完成门槛。
- [ ] 运行 `quick_validate.py` 与脚本单测。
- [ ] 用隔离代理执行同一压力场景，验证安装后流程改善。
- [ ] 确认 Codex 和 Claude Code 两个路径均可发现且内容一致。

### Task 9: 最终验证

**Files:**
- Update: `task_plan.md`
- Update: `findings.md`
- Update: `progress.md`

- [ ] 运行 unidbg 全量测试、打包和一键 smoke command。
- [ ] 核对原始样本哈希未变化。
- [ ] 核对恢复代码、报告和 trace 的地址一致。
- [ ] 列出 QBDI/移动端密钥等真实未验证项，不以空输出或退出码 0 代替成功。
