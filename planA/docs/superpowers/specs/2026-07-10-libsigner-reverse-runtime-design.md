# libsigner 3.62.0 逆向与 PC Runtime 设计

## 目标

交付两个互相校验的结果：

1. 对 Adjust Signature 3.62.0 `libsigner.so` 的源码级逻辑恢复、地址映射和混淆分析；
2. 在普通 PC 上加载原始 Android `.so` 并调用 `nSign(Context,Object,byte[],int):byte[]` 的可运行工程，支持稳定输入、原始输出和指令级追踪。

## 已锁定的事实

- 工作区四 ABI 样本与 Maven Central `com.adjust.signature:adjust-android-signature:3.62.0` 逐字节一致。
- 静态 JNI 方法：
  - `nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B`
  - `nOnResume()V`
- `Object` 的真实运行类型是 `Map<String,String>`。
- `byte[]` 是 Java 层对 `map.toString().getBytes("UTF-8")` 计算的 HMAC-SHA256。
- `int` 是 Android API level。
- 设备 HMAC key 存在 AndroidKeyStore 别名 `key2`；没有同一 key 时不能声称与另一台手机逐字节一致。

## 架构

### 1. `runtime/unidbg`

主执行器，使用 ARM64 原始样本和 unidbg 0.9.8：

- `SignerConfig`：ABI、package name、SDK level、HMAC key/HMAC 值、trace 配置。
- `SignerRequest`：保持插入顺序的参数 Map、`activity_kind`、`client_sdk`。
- `HmacInputBuilder`：严格复现 Java `LinkedHashMap.toString()` 的 UTF-8 输入和 HMAC-SHA256。
- `AndroidRuntimeJni`：提供 Context/package、Map/Set/Iterator/Entry、必要 Android API 的 JNI bridge；未实现调用必须抛出带完整 signature 的错误，禁止静默返回假值。
- `LibSignerEmulator`：加载未经修改的 `.so`，按静态 JNI descriptor 调用 `nSign`/`nOnResume`。
- `TraceRecorder`：限定在 `libsigner.so` 模块范围内记录 PC、基本块、调用和选择性内存访问，输出 JSONL。
- `SignerCli`：从命令行/JSON 读取参数，输出原始 bytes、HEX、Base64、Map/HMAC 输入快照和 trace 路径。

### 2. `runtime/qbdi`

QBDI 路线不伪装成 macOS 可直接 `dlopen` Android ELF。设计为两个后端：

- 默认、完全本地可运行：复用 unidbg/Unicorn 的模块级 trace，输出统一 trace schema。
- 可选 QBDI：在 Linux/Android x86_64 或实际 Android 进程中加载同一 trace schema 的 QBDI callback；若本机没有 QBDI/Android loader，安装检查明确报告缺项，不影响 unidbg 主路径。

这样既满足 PC 直接调用，又不把“QBDI 能跨 ABI/跨 libc 直接装载 Android ELF”作为错误前提。

### 3. `recovered/`

- `jni_contract.h`：已恢复 JNI 原型和数据边界。
- `signer_pipeline.cpp`：去混淆后的高层伪代码/可编译参考实现；未知内部算法以地址化 helper 保持，不编造语义。
- `address-map.md`：AArch64 地址、跨 ABI 对应、调用者/被调用者和证据。
- `strings.json`：静态解密出的字符串、地址、XOR key、guard。

### 4. Skill

创建 `android-so-reversing` Skill，包含：

- 样本保全、版本溯源、跨 ABI 对照、JNI 契约恢复；
- OLLVM CFG/字符串去混淆；
- unidbg 缺失 JNI 的失败驱动补齐；
- QBDI/Unicorn 动态 trace 选择；
- 完成判定和证据模板。

规范源安装到 `~/.codex/skills/android-so-reversing`，Claude Code 端安装到 `~/.claude/skills/android-so-reversing`，并执行独立触发/流程测试。

## 数据流

1. CLI 读取有序参数。
2. 注入 `activity_kind`、`client_sdk`。
3. 按 Java `Map.toString()` 规则构造 HMAC 输入。
4. 使用固定测试 key、用户 key，或用户直接提供的移动端 HMAC。
5. 将 Context、Map、HMAC byte[]、SDK int 传入真实 native `nSign`。
6. 捕获返回 byte[]，生成 HEX/Base64；保留 native/Java 边界快照。
7. 若启用 trace，只记录目标模块并按地址表标注关键函数。

## 错误处理

- 样本哈希不匹配：立即停止并报告版本漂移。
- JNI signature 未覆盖：抛出完整 signature、当前 PC/LR 和对象类型；不使用空字符串/0 掩盖。
- 缺少移动端 key：允许执行确定性测试 profile，但输出明确标注“流程等价、非目标设备同 key”。
- timer/后台线程不受后端支持：保持 `nSign` 同步主路径，`nOnResume` 独立测试；仅在证据表明影响返回值时增加可逆 hook。
- trace 过大：按模块、地址区间和最大指令数裁剪。

## 测试策略

- 样本身份测试：四 ABI SHA-256 与 3.62.0 矩阵一致。
- Java 边界测试：固定有序 Map 的 `toString()` 与 HMAC 向量固定。
- JNI descriptor 测试：只允许已恢复的四参数签名。
- Loader 测试：ARM64 `.so` 成功加载并定位两个导出。
- Native smoke test：固定 profile 返回非空 byte[]，重复运行输出一致或明确识别动态字段。
- 差分测试：改变一个 Map 字段、HMAC、SDK level，证明输出/分支对应变化。
- Trace 测试：包含 `nSign` 入口 `0x0a95ac`，且不记录模块外噪声。
- Skill 测试：无 Skill 基线与安装后同一压力场景对比，验证不会把推测当事实、不会在第一个缺失 JNI 处停下。

## 非目标

- 不伪造目标设备 AndroidKeyStore 私钥/密钥。
- 不修改原始 `.so` 作为默认运行条件。
- 不把旧 `ad_unidbg` jar 的空输出当成功结果。
- 不承诺从优化/混淆二进制恢复原开发者变量名和注释；交付的是语义等价逻辑与证据映射。

