# libsigner.so 分析发现

> 本文件只记录经样本或运行证据支持的发现。推测会明确标注为“待验证”。

## 样本与资产

- `py/libsigner.so`：AArch64 Android ELF，SHA-256 `fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736`，Build ID `4bceadd7c29ee1578f31fc9c5f980f2218c4791e`。
- `jni/` 包含 `arm64-v8a`、`armeabi-v7a`、`x86`、`x86_64` 四个 ABI 的 `libsigner.so`，适合跨架构语义对照；详细哈希待补。
- `libsigner.zip` 只包含 `libsig.txt`，不是二进制样本包；ZIP SHA-256 `10dd0131b44e5b18dded676d55d77bc784c5745e8eeb6ad9deb1c07c6cb090fa`。
- 已有材料包括两个 JNI 入口文本、约 2.95 MB 的 `libsig.txt`、`parse.txt`、`py/` 试验代码，以及一个已有 unidbg Maven 项目 `files/`。
- `files/` 还包含 `libsecsdk.so` 与 `libspringIns.so`，两者均为 AArch64 stripped ELF；需确认是否为同一业务链的依赖或旧分析样本，不能先验混用。
- 当前可用关键工具：GNU `readelf`、GNU `objdump`、`rabin2`/`r2`、Java/Javac、Maven/Gradle、Clang、Python、Frida。当前 PATH 未发现 Ghidra、QEMU user 或 QBDI CLI。
- 对 Maven Central 所有可用版本做四 ABI 的 size/SHA-256/Build ID 矩阵后，确认工作区四个 `libsigner.so` 与官方 `com.adjust.signature:adjust-android-signature:3.62.0` **逐字节完全一致**。版本判定置信度为确定；矩阵保存于 `analysis/upstream/adjust-signature/version-matrix.tsv`。
- 官方 3.62.0 AAR 现在作为独立上游证据保存于 `analysis/upstream/adjust-signature/versions/adjust-android-signature-3.62.0.aar`，原工作区样本保持未修改。

## ELF / JNI

- AArch64 动态符号只有两个业务导出：`Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume`（VA `0x0a894c`，4 字节尾跳）与 `Java_com_adjust_sdk_sig_NativeLibHelper_nSign`（VA `0x0a95ac`，大小 3476）。没有 `JNI_OnLoad` 导出，因此属于静态 JNI 符号绑定；现有 harness 无条件调用 `JNI_OnLoad` 的假设需要修正。
- AArch64 依赖：`liblog.so`、`libm.so`、`libdl.so`、`libc.so`；导入包含 timer、文件/目录、property、socket、时间、mmap 等能力。
- ELF 为 stripped、BIND_NOW、GNU_RELRO、NX stack；`.text` 约 `0x108c3c` 字节，`.init_array` 有两个入口，存在 CPU feature 初始化逻辑。
- 四 ABI 是同一业务库的不同构建；`py/libsigner.so` 与 `jni/arm64-v8a/libsigner.so` 字节完全相同。
- AArch64 `nSign` 的反编译原型明确包含 `JNIEnv*`、`jclass/jobject` 后的 **4 个 Java 参数**（总计 6 个 native 参数）；已有 `py/AdjustSigner.java` 仅假设两个 Java 参数，当前调用签名不可信。

## 混淆与反分析

- `nSign`、`nOnResume` 等函数存在典型控制流平坦化：以 64 位随机状态常量驱动多层 dispatcher；这是具体 CFG 证据，不只是编译器指纹。
- 大量字符串/常量在首次使用时通过固定字节 XOR 原地解密，并以 `FUN_00212730(0,1,&guard)` 原子 guard 保证只解密一次；`FUN_00212730` 本质是 compare-and-swap/LDXR-STXR 风格的一次性初始化门闩。
- 明文字符串极少，当前直接可见业务线索主要为 `SHA-256`；说明字符串加密确实生效。
- `.comment` 指向 Android Clang 17.0.2 / LLD 17.0.2，但控制流形态明显不是普通优化单独造成。

## `nSign`

- AArch64 VA `0x0a95ac`，大小 3476；会调用共享初始化 `0x0b0a48`、核心参数处理 `0x08b510`、结果转换 `0x0a8dec`、两次 `clock_gettime`，并生成多个格式化时间字符串。
- 入口保存 Java 参数 3..6；说明目标 Java 声明含四个业务参数。具体类型仍需从 JNI vtable 调用和官方/调用方类定义恢复。
- `0x08b510` 接收 `JNIEnv*`、若干输入句柄、常量字符串和输出结构；`0x0a8dec` 将输出结构转换为最终 JNI 返回对象。把 `0x08b510` 直接称为“SHA-256 核心函数”没有证据，现有 `py/some.cpp`/`a.py` 属推测性草稿，不能作为恢复代码。
- 从相关本地 `ad_unidbg` jar 的已编译调用器恢复出精确 Java descriptor：`nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B`。这与当前样本反编译出的四个业务参数完全吻合：`Context`、`Object`、`byte[]`、`int`，返回 `byte[]`。
- 静态解密入口常量：`DAT_0021e730 ^ 0x16` 为 `"environment"`，`DAT_0021e740 ^ 0x75` 为 `"sandbox"`；`nSign` 会从参数处理结果取 `environment` 并与 `sandbox` 比较。
- 另外两段只解密一次的字符串分别为 `"Signing all the parameters begin"` 与 `"Signing all the parameters end  "`；时间日志格式恢复为 `%Y-%m-%dT%H:%M:%S`、`%z` 和 `%s: %s.%03dZ%s`。因此两次 `clock_gettime` 主要服务于 sandbox 环境的耗时日志，而不是直接证明时间戳参与签名。
- 官方 3.62.0 `classes.jar` 再次确认 native 声明为 private instance method：`byte[] nSign(Context,Object,byte[],int)`；Java wrapper `a(...)` 负责转发。`nOnResume()` 同样是 private native，并由 wrapper 调用。
- 第二个业务参数在真实 Java 调用链中是 `Map<String,String>`（native descriptor 为兼容性写成 `Object`），第三个参数是 `HmacSHA256(map.toString().getBytes("UTF-8"))`，第四个参数是 `Build.VERSION.SDK_INT`。
- Java 侧密钥别名固定为 `key2`：API >= 23 使用 AndroidKeyStore 直接生成 HMAC-SHA256 key；API 18..22 生成随机 16 字节 key，用 AndroidKeyStore RSA 包装后存入 SharedPreferences `adjust_keys/encrypted_key`。因此要与某台真实手机逐字节一致，必须复用同一设备的 `key2` 或直接提供该次 HMAC 字节；PC 自生成 key 只能保证流程等价，不能凭空复制另一设备的密钥态。
- Java wrapper 会临时把 `activity_kind` 与 `client_sdk` 放入参数 Map，调用 native，随后把返回 byte[] 转为大写十六进制写入 `signature` 字段；这定义了本地 CLI 的正确输入/输出语义。
- 3.62.0 的公共 SDKv5 路径还会读取 native 输出 Map 字段 `signature`、`adj_signing_id`、`headers_id`、`algorithm`、`native_version` 并拼接 `authorization`，说明 native/Java 组合同时支持旧 byte[] 签名与新多字段签名流程。

## `nOnResume`

- 导出 VA `0x0a894c` 是到共享实现的 4 字节尾跳；完整实现副本/共享函数位于 `0x0b0a48`。
- 首次调用会清零临时结构、同步执行一次回调 `0x0b0d08`，随后用 `timer_create(CLOCK_MONOTONIC=1, SIGEV_THREAD)` 注册同一回调，并设置 1 秒初始延迟、1 秒周期。
- 全局 guard `DAT_0021faa8` 使 timer 初始化幂等；timer 成功设置后 guard 置 1。现有“每次 nSign 都建立新 timer”的推断不准确。

## 动态验证

- unidbg ARM64 主路径已真实执行完整 JNI 边界：Context/package、证书 SHA1、sensors/display、stack trace、AndroidKeyStore `key2`、native HmacSHA256、`/proc/fd` 检测、97 项参数查询、9-Blob VM、`NewByteArray(304)` 和 Map metadata 写回。
- native 返回为真实非空 304 字节；运行时写入 `headers_id=8`、`adj_signing_id=1300000`、`native_version=3.62.0`、`algorithm=adj7`。这把此前“可能修改 Map”的静态推断提升为运行确认。
- ARM64 `0x8b510` 已在动态 JNI 轨迹中确认服务于 `Map.get("environment")`，不能再标为 hash/crypto core。
- 真正受保护的 9-Blob 签名程序入口为 ARM64 `0xb6c50`、x86_64 `0x9dcf0`；context allocator 为 ARM64 `0x111a18`、x86_64 `0x103bc0`。已验证 push/pop/dup/pick/roll、frame store/length/seek/push-frame；pop 空栈错误码 3，pick/roll 越界错误码 4。
- 固定形状 VM 输出长度为 304。零填充 9-Blob 的 fresh emulator 首次调用回归值为 SHA-256 `d43a36f81b41cebd016c03e7e7e075e4df5741f46efc33380eabc2182272f1e2`，前缀 `59f066a1020fd01a6df980ae48bdcca6`；它不是任意调用序列下的无状态向量。
- 两次相同 CLI 配置捕获到 blob 1、4、5 变化，blob 2、3、6、7、8、9 稳定，最终签名也变化。进一步把完全相同的 9 Blob 连续送入 fresh contexts，得到不同 304-byte hash，证明显式 Blobs 之外还存在 VM/context/global mutable state。完整 JNI 完成门因此是合法 304-byte/metadata/strict bridge，而不是固定字节。

## PC 直接调用环境

- 用户要求提供 unidbg 与“ubqi”类实现，使 PC 能直接调用 `.so` 并尽量获得与移动端一致的结果。
- 用户最终优先级明确为 **无需安卓真机配合的纯本地代码运行**。因此完成标准是：PC 上由 unidbg 执行原始 Android ELF/JNI，所有必要 Android 对象、证书、`key2`、SDK、文件和传感器边界均由本地 fixture/bridge 提供；不把 ADB、真机 KeyStore 或真实证书设为前置条件。
- 当前将“ubqi”作为 QBDI 的可能笔误处理，最终方案需由样本 ABI、依赖和现有工程资产验证。
- 工作区已有 `files/pom.xml`、`SimpleAnalyzer.java`、`SpringInsAnalyzer.java` 和已构建 jar，表明此前存在 unidbg 尝试；其是否能直接加载 `libsigner.so` 尚未验证。
- 现有 `files/` 工程面向无关的 `libspringIns.so`/`libsecsdk.so`，不是可直接交付的 `libsigner.so` harness。
- `py/AdjustSigner.java` 还存在三项已证实问题：假设存在 `JNI_OnLoad`、使用错误的两参数 `nSign` Java 签名、把 `module.findSymbolByName("timer_create")` 当成库内导出而非未定义导入；需要从测试先行重建，不能直接修补后宣称可用。
- 发现高度相关的本地 Maven 产物：`~/.m2/repository/com/adjust/sdk/sig/ad_unidbg/1.0-SNAPSHOT/ad_unidbg-1.0-SNAPSHOT.jar`（约 43 MB），Manifest 主类由 POM 指向 `com.adjust.sdk.sig.AdjustSigner`，且项目属性标记 unidbg `0.9.8`。这是活动分析链直接相关资产，下一步将反编译并实际运行验证，而不是重新猜测接口。
- Maven Central 未找到公开的 `com.adjust.sdk.sig` artifact，说明上述 jar 很可能是本机此前构建的本地工程，而非可依赖的上游发布物。
- 该 jar 内含四 ABI 的另一版 `libsigner.so`，哈希/Build ID 均与当前工作区样本不同，不能拿其输出替代当前样本；但 Java API descriptor 和 harness 结构可作为强线索。
- 已实际运行旧 jar 的 ARM64 路径：库能装载并进入 native `nSign`，但在 `android/content/Context->getPackageName()Ljava/lang/String;` 处因未实现 JNI stub 进入 debugger，最终返回空签名。进程虽退出码为 0，但功能未成功；这提供了新 harness 的第一个可复现失败基线。
- 旧 jar 的匿名 `AbstractJni` 只覆盖了错误层次/无关的 `NativeLibHelper->nSign` 与 `nOnResume` 回调，没有实现真实 native 代码请求的 Android API，因此不满足“本地完全可跑”。
- Maven Central 已确认官方 artifact 坐标为 `com.adjust.signature:adjust-android-signature`；搜索索引一度显示 3.47.0，但仓库元数据和逐版本下载证明当前最新为 3.67.0、目标样本为 3.62.0。后续以仓库元数据/哈希而非搜索索引摘要为准。
- 官方 artifact 的最新版本实际为 3.67.0；当前样本精确对应 3.62.0。3.62.0 AAR 的 Java 层与 native 输入链已恢复，可直接作为 PC harness 的接口规范。
- 本地可运行方案应支持两种 key 输入：`--hmac-hex/--hmac-base64`（直接复现一次移动端调用）以及 `--hmac-key-hex`（在 PC 上按 Java wrapper 规则计算）；默认测试 profile 使用固定 key 保证结果可重复。
- 新的 `runtime/unidbg` harness 已替代旧 jar 的 permissive stub：未知 JNI/IO 边界严格失败；`run.sh` 可从项目外目录构建并执行，支持请求 JSON/有序参数、HMAC key 或 override、证书、SDK、包名、输出编码和有上限 JSONL trace。
- SDK 30 现代证书分支已在纯 PC 环境动态跑通：fixture 暴露单签名 `PackageInfo.signingInfo`，`hasMultipleSigners()` 返回 false，`getSigningCertificateHistory()` 返回同一本地 certificate；不需要真实 `SigningInfo` 或安卓设备。
- 已保存两次完整 sandbox 运行与 32-event trace 于 `runtime/unidbg/vectors/`。trace 的相对 PC 从 `0xa95ac` 开始，经过 schema validator；CodeHook 只在 emulation 返回后关闭，避免 Unicorn/JVM 因 hook 内 `unhook()` 崩溃。

## Skill 交付

- 用户要求将完整流程沉淀为可复用 Skill，并直接安装到 Codex 与 Claude Code。
- 计划采用一个规范化源 Skill，并确保 `~/.codex/skills` 与 `~/.claude/skills` 均可发现；安装前需做无 Skill 基线评估，安装后用相同压力场景复测。

## 待解决问题

- 压缩包内哪一个文件是实际运行样本？
- 签名输入、Java 调用方与预期输出样例是否已包含在现有资产中？
- 样本是否执行动态 JNI 注册、运行时解密或自修改？
- 是否已有可作为基准的移动端输入/输出、Context/PackageManager/证书等 Java 环境数据？
