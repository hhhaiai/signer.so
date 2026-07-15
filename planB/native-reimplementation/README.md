# Native C++ reimplementation workbench

这里是从 ARM64 `libsigner.so` 恢复出的独立 C++17 signer 核心。编译和执行时不加载：

- Java / JNI；
- Unidbg / Unicorn；
- 原始 `libsigner.so`；
- Android Emulator、ADB、Frida 或真机。

只使用 macOS 已有的 Apple Clang/C++ 标准库，不自动安装系统插件。

## 当前静态恢复状态（2026-07-15）

ARM64 `.eh_frame` 共 **388** 个函数范围：**347 recovered / 0 partial /
41 unknown**。从两个 JNI export 静态可达 **321** 个范围，其中 **298 recovered /
0 partial / 23 unknown**。`0xf1ec8..0x11ba78` protected engine 已在纠正完整
16-byte context-flags descriptor 后，由 42,732-instruction 文本 VM 无补丁产出冻结
176-byte reference。

本目录已同步最新 SO 反编译结论：

- `AUTHORIZED_STATIC_AUDIT_REPORT.md`：按授权要求整理的七节审计报告；
- `PROTECTED_ENGINE_STATIC_RECOVERY.md`：context flags 根因、`0x301 -> 0x106d00 ->
  0x3e` 跨 ABI/真机证据和无补丁完整 VM 结果；
- `SO_FUNCTION_COVERAGE.md`：388 个 FDE 的权威逐项状态；
- `STATIC_ANALYSIS.md`：实现与静态证据边界。

protected engine 的旧 `0x3e` mismatch 已关闭，但 JNI 可达仍有 23 个 unknown。
本轮另行关闭了 20 个精确的 `context+0xe0` flag-mask leaf 和三个独立 RET-only
FDE：地址/掩码表、幂等回归和逐指令 verifier 位于
`.omx/static-audit-20260713/arm64-detector-context-flag-leaves.md`；这些范围不在当前
JNI 静态可达图内，因此只减少全文件 unknown，不改变 JNI-reachable 计数。
随后又闭合了 `0x8070..0x80c0` 的五个模块 finalize/no-op/callback/atexit
runtime FDE，以及 `0x139d04` CPU-feature constructor wrapper。其独立 callee
`0x1398cc` 现已按逐指令 HWCAP/HWCAP2 与 `ID_AA64*` 字段映射闭合；C++ 通过
`Provided` presence gate 要求调用方显式传入真实零值或非零值，并保留全部中间 global
publication 顺序，不读取或伪造宿主设备字段。
其后独立闭合了非 JNI-reachable 的 `0xb1e40..0xb21b4`：两个 ABI 均证明
XOR-once `java/lang/Exception`、`FindClass -> exception consume -> ThrowNew(message)`、
status `18` 与 non-null class local-ref cleanup；专用证据位于
`.omx/static-audit-20260713/arm64-jni-throw-exception-b1e40.md`。
非 JNI-reachable 的 `0xa0640..0xa1230` 与 `0x91428..0x917a8` 也已作为一个
AndroidKeyStore key-pair cluster 闭合：前者跨 ABI 固定解码
`generateKeyPair()Ljava/security/KeyPair;`，恢复 GetObjectClass/GetMethodID/
CallObjectMethod、三次 exception consume、status `3/18/28`、class local-ref cleanup
和 KeyPair reference transfer；后者恢复 XOR-once `AndroidKeyStore` byte lock、
`KeyStore.getInstance -> load(null) -> generateKeyPair` 顺序、逐 helper status
short-circuit、成功时双引用转交和失败时双 output 清零。运行时 JNIEnv、generator 和
output slots 均由调用方提供；专用证据位于
`.omx/static-audit-20260713/arm64-android-keystore-keypair-cluster-91428.md`。
相邻的非 JNI-reachable `0x93fd0..0x94bc0` 与 `0x917a8..0x91d2c` 随后恢复为
`BigInteger.toByteArray()` JNI helper 和 unsigned big-endian byte materializer：恢复
`toByteArray -> GetByteArrayElements`、零长度 status `28`、单字节零 sign-prefix 移除、
signed 32-bit length widening、`calloc(length,1)`、allocation status `2`、
`memcpy(elements+skip)`、release/delete 顺序和双 output failure clearing；专用证据位于
`.omx/static-audit-20260713/arm64-big-integer-unsigned-bytes-917a8.md`。
JNI-reachable `0x96ea8..0x975f0` 现已恢复为 `Cipher.init(int, Key)` helper：
ARM64/x86_64 均固定解码 `init` 与 `(ILjava/security/Key;)V`，执行
`GetObjectClass -> GetMethodID -> CallVoidMethod`、三次 exception consume、status
`3/18/41` 和 cipher-class local-ref cleanup。唯一 caller 固定传入 mode `2`
（`Cipher.DECRYPT_MODE`）；portable C++ 仍按 signed `jint` 接收调用方 mode，并原样转发
caller-supplied cipher/key。证据位于
`.omx/static-audit-20260713/arm64-jni-cipher-init-96ea8.md`。API 18 原 SO 的
observation-only hook 也已自然命中一次：entry/call mode 均为 `2`，cipher/key 原样转发，
`init(ILjava/security/Key;)V` 精确匹配，status `0 -> 0`、call exception `0`，并恰好清理
一次 cipher-class local ref。
当前最小的非 JNI-reachable unknown `0x9816c..0x9885c` 也已闭合为 object-class
assignability helper：caller 显式提供 object 和 class name，原生依次执行
`GetObjectClass -> FindClass -> IsAssignableFrom`、三次 exception consume、status
`3/18/28`、jboolean 归一化、object-class 后 target-class local-ref cleanup，并在 incoming
status 非零时清 output。证据位于
`.omx/static-audit-20260713/arm64-jni-class-assignable-9816c.md`。
JNI-reachable `0xb081c..0xb0f38` 现已恢复为通用 `update(byte[])` void-method
helper：ARM64/x86_64 均固定解码 `update` 与 `([B)V`，按
`GetObjectClass -> GetMethodID -> CallVoidMethod` 执行三阶段 exception consume，
使用 status `3/18/28`，成功时保留 incoming status，并在所有 class-acquired 路径清理
object-class local ref。caller 的 object 和 byte array 原样转发，无 returned-object
publication。原 SO observation-only hook 进一步证明单次自然调用的 incoming/caller
status 均为 0、method/signature 精确、object/byte-array 指针原样转发、call exception 为 0
且 class ref 恰好清理一次。专用证据位于
`.omx/static-audit-20260713/arm64-jni-byte-array-update-b081c.md`。
相邻 JNI-reachable `0xb0f38..0xb1e40` 现已恢复为双 overload
`MessageDigest.digest` helper：caller 的 optional byte array 为 null 时选择
`digest()()[B`，非 null 时选择 `digest([B)[B`。两个 ABI 共同锁定
`GetObjectClass -> GetMethodID -> CallObjectMethod`、三次 exception consume、status
`3/18/28`、object-class local-ref cleanup、returned digest byte-array transfer 和
incoming-status output clearing；byte-array overload 原样转发 caller input。原 SO API 18
自然日志动态确认 no-arg overload 的 method lookup 和 call return PC。专用证据位于
`.omx/static-audit-20260713/arm64-jni-message-digest-digest-b0f38.md`。
JNI-reachable `0xb9424..0xb9cc8` 现已恢复为
`PackageInfo.signingInfo` object-field reader：PackageInfo object、JNIEnv、status 和
output slot 均由调用方提供，C++ 不创建或替换 `SigningInfo`。两个 ABI 固定解码
`signingInfo` 与 `Landroid/content/pm/SigningInfo;`，依次执行
`GetObjectClass -> GetFieldID -> GetObjectField`、三次 exception consume、status
`3/18/28`、class local-ref cleanup 和 returned-reference transfer；incoming status
非零时仍执行 JNI，但在 cleanup 后清 output。专用证据位于
`.omx/static-audit-20260713/arm64-jni-signing-info-field-b9424.md`。
JNI-reachable `0x2c618..0x2cc9c` 也已恢复为 Raspberry manufacturer system-property
probe：两个 ABI 的 XOR-once 常量均解码为 `ro.product.manufacturer`、
`ro.product.vendor.manufacturer` 与 `raspberry`；两条 kind-3 record 通过 `0x24444`
统计匹配数并返回 `uint16 != 0`，上层 true 路径追加 correction `0x28`。隔离 Unidbg
分别证明 Google profile 返回 false，而混合大小写 Raspberry profile 返回 true 并恰好
一次进入 `0xf988` 的 correction `0x28` 调用。
紧邻的 JNI-reachable `0x2cc9c..0x2e1d4` 已恢复为五属性
minical/vcloud/Scorpio probe：两个 ABI 的八段 XOR-once 数据解码为 manufacturer、
vendor manufacturer、model、vendor model、display id 与三个 marker；五条 kind-3
record 固定 count 5 交给 `0x24444`，并返回清零 uint16 match count 是否非零。隔离
Unidbg 证明普通 Google profile 返回 false 且不提交 correction `0x2c`，混合大小写
`MiNiCaL` manufacturer 返回 true 并恰好提交一次 `0x2c`。专用证据位于
`.omx/static-audit-20260713/arm64-environment-probe-2cc9c.md`。
`0x8746c` producer 的全部直接 JNI/helper 依赖已经闭合：新增恢复
`0xb5828` `Context.getSystemService(SENSOR_SERVICE)`、`0xbb5a0`
`Resources.getSystem()`、`0xbea74/0xbf5fc` `Sensor.getName/getVendor()` 和
`0xc0180` `SensorManager.getSensorList(-1)`。当前又完成了非 property 的
`runRecoveredDetectorSensorDisplayPipeline8746c`：两个 ABI 均证明
`getSensorList(-1) -> size() -> signed jint index<size -> get(index) -> name/name UTF ->
vendor/vendor UTF -> 0x8f56c`，sensor terminal cleanup 后再执行
`Resources.getSystem -> DisplayMetrics -> widthPixels -> heightPixels`。隔离 Unidbg
两 sensor profile 观察到 count `0->1->2`、严格输入保序，并证明循环内不释放上一项：
仅最后一项 name/vendor UTF 与 Sensor/name/vendor local ref 被清理，随后才进入 display
stage。C++ 兼容模型保留该 ownership 缺口，并以 `int32_t` 表达 ARM64 `lt` 与 x86_64
`cmovl` 的 signed `jint` 条件；回归覆盖 size `0/-1/1/2`、九个 sensor 阶段失败、
appender `2/0x26` 和四个 display 阶段失败。独立 128-sensor observation 进一步确认
index `0..126` 发布 127 项，第 128 次 append 返回 `0x26`、count 保持 127、仅清最后
一项临时 JNI 资源并跳过整个 display stage。producer 内部十三个 property
materialization stage 也已闭合：跨 ABI 解码并映射 `ro.product.name/manufacturer/
brand/model/device`、`ro.build.display.id/fingerprint/type/user/host`、`ro.hardware`、
`ro.bootloader` 和 `ro.product.cpu.abilist` 到 scratch `+0x00..+0x68`；确认共用
`0x60` 栈缓冲、`malloc(length+1)`、延迟一阶段发布，以及十三处 allocation failure
均清当前字段并返回 `2`。C++ 只固定 property 标识符和字段 offset，值全部由调用方
`readProperty(name, output)` callback 提供，不内置或伪造设备值。新增的
`RecoveredDetectorInputProfile8746c` 进一步把十三个 property、display width/height 和
sensor name/vendor pair 统一暴露给 C++ 调用方；缺失 property 默认报错，只有调用方显式
选择 `UseEmptyString` 才使用空字符串，display 和 sensor list 也必须显式标记为已提供。
producer 本身现已迁移为 recovered：新增 verifier 解析 x86_64 的 231 个 flattened state
literal，并用 ARM64 交叉确认 service failure 固定为 `0x24`、width/height failure 固定为
`0x1d`，其余 helper status 原样发布；appender 非零后仍执行 index increment。新增原生
destructor-envelope 回归覆盖 13 个 property allocation failure、九类 sensor failure、
第二个 pair 的 `0x26`、四类 display failure 和成功路径，确认原 `0x8fb44` 清八个固定
字段与已发布 pair，同时保留 `+28/+40/+48/+58/+68`、count 和 display 字段。专用证据位于
`.omx/static-audit-20260713/analyze_detector_scratch_failure_publication_8746c.py`、
`.omx/static-audit-20260713/analyze_detector_sensor_display_pipeline_8746c.py` 和
`.omx/static-audit-20260713/arm64-detector-scratch-producer-8746c-progress.md`。
最新闭合了 `0xbce98..0xbd6a8` 的 JNI DisplayMetrics getter：跨 ABI 精确解码
`getDisplayMetrics()Landroid/util/DisplayMetrics;`，恢复 GetObjectClass/GetMethodID/
CallObjectMethod、三次 exception consume、status `3/18/28`、class local-ref cleanup、
returned local-ref transfer 和 incoming-status 清零规则。隔离 Unidbg 三次均从 Resources
返回 `android/util/DisplayMetrics`，随后同一对象由 `0xb21b4` 读取出 1440x3120。
此前闭合了 `0xa948c..0xa9d44` 的 JNI indexed object-method reader：跨 ABI 精确解码
`get(I)Ljava/lang/Object;`，恢复 `GetObjectClass/GetMethodID/CallObjectMethod`、三次
exception consume、class local-ref cleanup、返回 local-ref 转交、incoming-status 保留和
status `3/18/28`。隔离 Unidbg 原 SO 的 V4/V4-repeat/V5 观察到 index 0 返回
`android/hardware/Sensor`、status 0，并由 producer 形成单个
`LSM6DSO | STMicroelectronics` pair。此前闭合的相邻 `0xa8978..0xa948c` JNI
`size()I` reader 在同一 profile 返回 1；`0xb21b4..0xb2978` JNI int-field
reader 在 producer 的两个调用分别读取
`heightPixels` 和 `widthPixels`，精确恢复 `GetObjectClass/GetFieldID("I")/GetIntField`、
三次 exception consume、class local-ref cleanup 和 status `3/18/28`。隔离 Unidbg
profile 以 `1440x3120` 动态互证 `scratch+0x60=width`、`+0x64=height`。此前闭合了
`0x8f56c..0x8fb44` 的 detector scratch owned string-pair appender 和
`0x8fb44..0x90714` 的配对 content destructor：appender 最多发布 127 项并保留第 128 项
全空 sentinel，destructor 按固定字段顺序释放后扫描到该 sentinel。此前还闭合了
`0xd313c..0xd352c` 的 dot-separated metadata area-name resolver，以及
`0xd352c..0xd3d90` 的 `/dev/__properties__/property_info` mapped source creator。
结合 `0xd28d0` parser、`0xd22d4` content destructor、`0xd3d90` mapped owner
destructor 和 `0xd4220` metadata owner wrapper，system-property metadata 的 source
构造、tree 构造、查询、失败回滚和销毁主链已经连通。
所以当前仍不能宣称整个 SO 已完整替代。不得把调试用 `skip 0x3e`、PC 特判或最终
lane 硬改写入正式实现。

## 构建和确定性验证

```bash
cd /Users/sanbo/Desktop/api/qbdi
./native-reimplementation/build-and-test.sh
```

2026-07-15 在当前 `recovered_primitives.cpp` 上重新执行的联动结果：

- `build-and-test.sh` 完整通过，`main()` 的 125 个 regression guard 均由 executable
  入口覆盖；源码共有 130 个唯一 `*Regression` 定义；
- 15 组 176/192/208-byte 原 SO oracle 向量逐字节一致；
- 当前源码以 ASan+UBSan 重新编译并运行通过；macOS 不支持 LeakSanitizer，运行时明确使用
  `ASAN_OPTIONS=detect_leaks=0:halt_on_error=1`，不能把该结果扩展成 leak 检查通过；
- `test-recovered-backend.sh` 与冻结 Pixel JSON 完整结构相等，输出 176 bytes；
- Maven 离线模式下 `RecoveredNativeBackendIntegrationTest` 与
  `SignerNativeIntegrationTest` 分别通过；
- 隔离 Unidbg 直接加载本地 ARM64 `libsigner.so`，`nOnResume`、`nSign` 成功并返回
  176-byte `adj8` 结果；该 smoke 证明当前原 SO runner 可运行，不证明剩余 57 个 unknown
  已由 C++ 覆盖。

该命令会验证：

1. AES-256 key expansion、14 轮 block encryption；
2. AES-256-CBC + PKCS#7；
3. SHA-256、HMAC-SHA256；
4. Bionic `srandom/random` 兼容 PRNG 和 IV；
5. correction encoder 与按 8-halfword 分块的 field-0 扩容；
6. field 0 的 base codeword + ordered correction 覆盖规则；
7. field 4 的 custom-state SHA-256；
8. 从结构化输入构造动态 payload（已验证 113 / 129 / 145 bytes）；
9. 176-byte Pixel、192-byte 九 correction 与 208-byte 十七 correction 结果；
10. 冻结 Pixel、`timeSeconds+1`、trampoline=false、correction05=false、空
    `/proc/self/maps`、缺失 `/proc/self/maps`、修改 device name/native plaintext、
    缺失 Java 字段、APK/PackageManager 证书不一致并观察到 correction `0x2a`，以及
    `/proc/self/cmdline` mismatch `0x09`、cmdline 缺失/空 `0x34`，以及九 correction
    触发 16-halfword/192-byte 扩容，以及十七 correction 触发
    24-halfword/145-byte payload/208-byte result。此前动态阶段共有十五类完整向量
    与原 SO 逐字节一致；API23+ Java HMAC mismatch `0x07` 已有成对证据。API18-22
    legacy RSA 解包适配是之后加入的静态实现；本轮离线 `mvn -o -DskipTests compile`
    已通过，但尚未运行验证，不能计入
    已通过向量；其余已验证变体均先由
    原 SO 产生 oracle，再要求 C++ 逐字节完全一致。

## Detector 字段由 C++ 调用方显式传入

`RecoveredDetectorInputProfile8746c` 是调用方输入适配层，不包含 Pixel、bullhead、Google、
LGE 或其他设备画像默认值。固定在源码中的只有原 SO 协议要求查询的十三个 property
**名称**及其 scratch offset；property **值**、display 尺寸和 sensor 列表都来自调用方。

```cpp
using namespace recovered;

RecoveredDetectorInputProfile8746c profile;
setRecoveredDetectorInputProperty8746c(
        &profile, "ro.product.model", userModel);
// 其余十二个已恢复 property 也由调用方逐项设置。

profile.displayMetricsProvided = true;
profile.displayWidth = userWidth;
profile.displayHeight = userHeight;

profile.sensorListProvided = true;
profile.sensorNameVendorPairs.push_back({userSensorName, userSensorVendor});

RecoveredDetectorScratch868b4 scratch{};
const auto status = materializeRecoveredDetectorInputProfile8746c(
        &scratch, profile);
if (status == RecoveredDetectorInputProfileStatus8746c::Success) {
    // 调用已恢复的 detector consumer。
    destroyRecoveredDetectorInputProfileScratch8746c(&scratch);
}
```

约束是显式且可验证的：

- property 未提供时默认返回 `MissingProperty`，不会猜测设备值；
- 调用方确实需要“缺失即空串”时，必须显式设置
  `missingPropertyPolicy = UseEmptyString`；
- property value 最多 95 bytes，给原生 `0x60` buffer 保留结尾 NUL；
- display 即使要传 `0x0`，也必须设置 `displayMetricsProvided=true`；
- 空 sensor list 是合法输入，但必须设置 `sensorListProvided=true`；
- sensor pair 最多 127 项，保留第 128 项全空 sentinel；
- profile materializer 使用独立安全 cleanup 释放全部十三个 property 和所有 sensor pair；
  它与兼容性精确但只释放八个固定 property 的原 `0x8fb44` destructor 明确分开。

源码中仍存在 Pixel 等固定字节作为原 SO oracle/regression 测试向量；这些值只用于验证，
不会被 `RecoveredDetectorInputProfile8746c` 当作调用方未提供字段的运行时默认值。

## CPU feature 字段也由 C++ 调用方显式传入

`0x1398cc` 的 portable recovery 不执行宿主 `getauxval()` 或 `mrs`。调用方同时提供值和
presence flag；因此全零寄存器快照是合法输入，未设置 flag 才表示缺失：

```cpp
RecoveredCpuFeatureDecoderInput1398cc input;
input.publishedFeaturesProvided = true;
input.publishedFeatures = userPublishedFeatures;
input.taggedHwcapProvided = true;
input.taggedHwcap = userHwcap | (1ULL << 62U);
input.auxDescriptorProvided = true;
input.auxDescriptor = {24, userHwcap, userHwcap2};

// 仅当 HWCAP bit 11 非零时需要；值为 0 也必须显式设置 Provided=true。
input.idAa64Pfr1Provided = true;
input.idAa64Pfr1 = userIdAa64Pfr1;
input.idAa64Pfr0Provided = true;
input.idAa64Pfr0 = userIdAa64Pfr0;
input.idAa64Zfr0Provided = true;
input.idAa64Zfr0 = userIdAa64Zfr0;
input.idAa64Isar0Provided = true;
input.idAa64Isar0 = userIdAa64Isar0;
input.idAa64Isar1Provided = true;
input.idAa64Isar1 = userIdAa64Isar1;

const auto decoded = runRecoveredCpuFeatureDecoder1398cc(input);
```

若 bit 62 未设置，原函数不会读取 descriptor，恢复实现也不会要求它；若 HWCAP bit 11
未设置，则五个 `ID_AA64*` 字段不需要提供。PFR0 未声明 SVE 时，ZFR0 同样不需要提供。
固定的 `{24,...}` 首元素、bit 62 tag、HWCAP bit 11 分支和 feature bit masks 属于原 SO
算法常量，不是编造的设备数据。逐指令证据见
`.omx/static-audit-20260713/arm64-cpu-feature-decoder-1398cc.md`。

## 已恢复的完整动态结果路径

```text
timeSeconds
  -> Bionic random, pairwise XOR
  -> 16-byte IV

observed correction codes
  -> encodeCorrection
  -> environment halfwords 按 8 个一组扩容：8、16、24、32...

certificate SHA1 + environment halfwords + field2 + SHA256(empty)
+ state + native plaintext
  -> SHA-256 with recovered custom initial state
  -> 32-byte field 4

payload fields 0..6
  -> 113 bytes（8 halfwords）、129 bytes（16）或 145 bytes（24）
  -> AES-256-CBC + PKCS#7
  -> 128-byte、144-byte 或 160-byte ciphertext
  -> HMAC-SHA256(ciphertext)
  -> 32-byte tag

IV || ciphertext || tag
  -> 176-byte、192-byte 或 208-byte signature
```

### field 0

先生成：

```text
encode(0x40), encode(0x41), ... encode(0x47)
```

然后把环境检测产生的 correction codes 按发生顺序编码，并覆盖前 N 个槽位。初始为
8 个 halfword；当 correction 数量超过 8 时，原 SO 会扩为 16，base pattern 每 8 个重复。

```text
Pixel / trampoline=true  corrections = 2b,36,25,05
Pixel / trampoline=false corrections = 2b,36,05
Pixel / correction05=false corrections = 2b,36,25
Pixel / empty proc maps  corrections = 2b,37,36,25,05
Pixel / missing proc maps corrections = 2b,37,35,36,25,05
APK/package certificate mismatch = 2b,2a,36,25,05
nine-correction combined profile = 2b,09,37,2a,3c,35,36,25,05
```

前九类完整 176 bytes 和最后一类完整 192 bytes 均已与原 SO oracle 精确一致。maps
三种已观察状态中均有 `0x36`，所以它是 maps probe/scan 基线完成事件；`0x37` 对应
没有找到同时包含当前 package 和 `/base.apk` 的映射行，`0x29` 对应找到的首条 APK
路径与 `publicSourceDir` 不同，`0x35` 对应 maps 路径缺失/访问失败。单行精简 oracle 已证明
地址、权限、inode、空格及 Frida/Xposed 关键词不是该分支的决定因素。

### field 4

field 4 不是普通 `SHA256(material)`。SO 先加载固定 source words，再逐 word XOR
`0xcccccccc`，得到自定义 SHA-256 chaining state：

```text
cd46a0de d5c62fe0 02cb3985 fd4a15a3
07cad499 63840dbf 51698010 ca03ff52
```

随后对下列 material 使用标准 SHA-256 padding 和 compression：

```text
certificateSha1 (20)
+ 00 <halfword count> + environment halfwords
+ field2 in forward order 00 01 02 03 (4)
+ SHA256(empty) (32)
+ state byte (1)
+ native plaintext (Pixel: 154)
= Pixel 229 bytes；16-halfword profile 相应增加 16 bytes
```

Pixel 四个 block 的 chaining state 和最终
`fef6ae81ab7a34b0...2e105380` 均与原 SO 动态 trace 一致。

## 当前 CLI

构建后：

```bash
./native-reimplementation/build/recovered-primitives \
  --use-regression-fixture \
  --time-seconds=1760000001

./native-reimplementation/build/recovered-primitives \
  --use-regression-fixture \
  --signer-code-trampoline-detected=false
```

上面两条只用于重放冻结 oracle。`--use-regression-fixture` 是显式测试开关；不传该
开关时，CLI 进入严格用户输入模式，不会继承 Pixel/Google/宿主机样本。严格模式要求
调用方完整提供 `timeSeconds`、correction codes、field 2 的 urandom bytes、证书 SHA-1、
native plaintext（或至少一个结构化参数）和 `state`。例如：

```bash
./native-reimplementation/build/recovered-primitives \
  --time-seconds=0 \
  --correction-codes= \
  --urandom-hex=00000000 \
  --certificate-sha1=0000000000000000000000000000000000000000 \
  --native-plaintext-hex= \
  --state=false
```

该例同时证明合法的 `0`、`false`、空 correction 列表和空 plaintext 与“未提供”是两种
状态；少传任一必需字段会明确失败并列出缺失项，而不是从回归 fixture 补值。字段矩阵、
Java adapter 边界和验证记录位于
`.omx/static-audit-20260713/caller-supplied-runtime-inputs.md`。

可配置参数：

```text
--use-regression-fixture                         # 仅冻结 oracle/回归
--time-seconds=<uint32>
--signer-code-trampoline-detected=true|false     # 仅配合 regression fixture
--correction-codes=2b,36,25,05
--certificate-sha1=<40 hex chars>
--native-plaintext-hex=<even-length hex>
--param-hex=<key>=<UTF-8 value as even-length hex>  # repeatable
--urandom-hex=<at least 4 bytes of hex>
--state=true|false
--java-hmac-key-hex=<resolved key bytes>
--java-map-string-hex=<UTF-8 Map.toString() bytes>
--java-hmac-hex=<third nSign byte[]>
```

输出中的 `SIGNATURE_HEX=` 是独立 C++ 计算结果。

`--param-hex` 可重复传入，C++ 会按 SO 中恢复出的 100-key 固定表构造 engine-level
logical plaintext，并按 `0x8af4` 对 `secret_id/headers_id/native_version` 使用固定
`1400000/9/3.67.0`。重复 key 采用最后一次值，模拟 Map 覆盖；`--param-hex` 与直接的
`--native-plaintext-hex` 互斥，避免静默选择不同输入源。这里不再把该插入错误归因于
`0x11d798` Map walker；其最终 descriptor 拼接层仍在继续静态追踪。

三个 `--java-*` 参数必须同时提供。C++ 会用恢复出的 Java 参数完整性规则计算
`HMAC-SHA256(key, mapStringUtf8)`，比较 `nSign` 第三个 `byte[]`，并在 `0x2b`
之后自动插入或移除 correction `0x07`。这里接收的是已经从 AndroidKeyStore 取得、
或在 API 18-22 上经 RSA/PKCS#1 解包后的 key；平台 KeyStore/RSA 状态解析仍由上层
profile adapter 提供，最终 adj8 envelope 不依赖 Android/JNI。

源码现在还提供纯 C++ `EnvironmentObservations` 和 `deriveCorrectionCodes()`，按已恢复
顺序从 cmdline、maps、publicSourceDir、APK certificate、ART/linker、SDK property、
trampoline 与 timing 观察推导：

```text
2b, 07, 34-or-09, 37-or-29, 38, 2a, 2f, 3c, 35, 36, 25, 05
```

该层只做平台无关的数据解析与 correction 排序，不主动读取本机 `/proc`，因此不会把
macOS 工作站状态误当成 Android 状态。Android/JNI 文件与 KeyStore 观察仍应由独立
platform adapter 填入。

`--urandom-hex` 将输入的前 4 bytes 映射为 field 2；payload 中 field 2 仍按原逻辑
反序写入，field-4 hash material 中按正序写入。冻结 profile 使用
`0001020304050607`，因此得到 field 2 `00 01 02 03`。独立 CLI 的严格模式必须显式提供
该参数；嵌入式 C++ 调用则由调用方直接构造完整的 `NativeInputs.field2`。

## 新恢复的完整 Map plaintext materializer

arm64 `0x11d798` 已更正为 JNI Map plaintext 两遍生成器，而不是 final ciphertext
输出器。它先通过 `0x11d40c` counting sink 计算所有选中 Map value 的拼接长度，再
`calloc(length+1)`，随后通过 `0x11d528` bounded-copy sink 写入无分隔符 plaintext。

`0x11ba78` 会将 `0x145a30` 的 1363-byte 表 XOR `0x52`，得到 100 个有序 Map key。
旧 recovered backend 只列出 15 个冻结 profile 字段，会漏掉 revenue、event、partner、
payload 等请求字段。本轮已把完整 100-key 表加入 C++ `buildNativePlaintext()` 和 Java
recovered backend。`0x8af4` 的静态 ARM64 解释进一步证明三个 special emit：表内
`secret_id` 固定为 `1400000`，`headers_id` 固定为 `9`，`native_version` 固定为
`3.67.0`；caller 同名值被忽略。`adj_signing_id` 不在 100-key 表中，因此不由 plaintext
walker 读取；`adj_signing_id=1400000` 仍会由 `0xaf3c -> 0x9954c` 作为 native result
metadata 执行 `Map.put`，但这是不同的输出层。

完整 100-key 编号表由纯静态脚本生成：

```text
.omx/static-audit-20260713/decode_map_key_table.py
.omx/static-audit-20260713/arm64-map-key-table.txt
```

生成的 plaintext bytes 和 4-byte reversed length 是 `0xf1ec8` 固定九输入 work object
中的两个 descriptor；固定 `count=9` 不是 algorithm id。因此当前“多套密码”证据仍
指向 Java API 分流和同一 adj8 pipeline 内的 SHA/AES/HMAC 多层组合，而不是九套 final
envelope。地址、sink 布局、完整字段表和输入关系见：

```text
.omx/static-audit-20260713/arm64-output-materializer.md
.omx/static-audit-20260713/arm64-map-metadata-jni.md
.omx/static-audit-20260713/arm64-final-nine-descriptors.md
```

## JNI `byte[]` 返回对象已闭合

final consumer 的返回对象不是由 `0xcc47c` 生成。ARM64 静态链路为：

```text
0xa334: context+0x18 = null；Map.remove 四个 native metadata
0xaf3c:
  0x9548c -> NewByteArray(nativeLength) -> context+0x18
  0x95680 -> SetByteArrayRegion(result, 0, nativeLength, nativeBytes)
0xcbe98: return context+0x18
```

`0x9aa5c` 已恢复为 `Map.remove(Object)` helper，四个 key 是 `headers_id`、
`native_version`、`adj_signing_id`、`algorithm`。`NewByteArray` pending exception
或 null result 都写 native status `31` 并清空 result；已有非零 status 会保留原值但
同样清空新建 result。`SetByteArrayRegion` 对 null array 写 `3`，pending exception
写 `32`，但 copy exception 不会清空已经创建的 reference；此时 pending Java exception
阻止正常返回。最终 `0x11da64` 仅在 status 为零时返回 true，JNI 层返回
`context+0x18` 中的 Java `byte[]`。C++ 已增加
`RecoveredNativeResultState` 与 `modelRecoveredNativeResultMaterialization()`，静态证据：

```text
.omx/static-audit-20260713/analyze_jni_result_materialization.py
.omx/static-audit-20260713/arm64-jni-result-materialization.md
```

`0xaf3c` 的完整 result/metadata transaction 也已闭合。flattened call-site 地址不能
直接排序；恢复出的成功执行顺序是：

```text
NewByteArray -> SetByteArrayRegion
-> Map.put(headers_id, 9)           @ 0xc544
-> Map.put(adj_signing_id, 1400000) @ 0xc7f4
-> Map.put(native_version, 3.67.0)  @ 0xbffc
-> Map.put(algorithm, adj8)         @ 0xc6a4
```

创建、copy 或任一次 put 后只要 status 非零，就进入公共 state
`0x43c03deaa70c8d82`，在 `0xc250` 调 `0xa334`：清空 result 并删除全部四个
metadata。rollback remove 的失败可覆盖原错误码。只有最后一次 put 后 status 仍为零，
才选择 `0x4c81a55be310eef5` 并在 `0xcdb8` 返回。C++ 对应
`modelRecoveredNativeResultBuilder()`；静态证据：

```text
.omx/static-audit-20260713/analyze_native_result_builder_transaction.py
.omx/static-audit-20260713/arm64-native-result-builder-transaction.md
```

## Native signing-context orchestrator 已闭合

`0xcbe98` 的 post-dereference 输入门槛、时钟失败、阶段顺序和 owned cleanup 已恢复。
外层 descriptor 的四个 pointer slot 会先被无条件解引用；加载后的值必须满足：

```text
androidApi >= 1
JNIEnv / Context / Map / supplied Java-HMAC 均非空
```

`0xcc47c` 是独立的 `CLOCK_REALTIME` 毫秒采样器。成功返回
`seconds*1000 + nanoseconds/1e6`；失败在 status 非空时写 `14` 并返回 `0.0`，没有
`gettimeofday` fallback。ARM64 与 x86_64 同构。有效 orchestrator 顺序为：

```text
clock -> context init -> certificate stage (failure status reset)
-> 0xcba90 -> 0xcbbd4 -> 0x143e8 -> 0xd6888 -> 0xf224
-> 0x11da64 final consumer
-> free +0x108, free +0x110, free +0x120
-> return context+0x18
```

final consumer 的 boolean 只选择 flattened cleanup 入口，true/false 最终都进入相同
ownership cleanup。C++ 已增加 `recoveredSigningContextClockMilliseconds()`、
`modelRecoveredSigningContextOrchestrator()` 和
`runRecoveredNativeSigningContextOrchestrator()`。证据：

```text
.omx/static-audit-20260713/analyze_native_signing_context_orchestrator.py
.omx/static-audit-20260713/arm64-native-signing-context-orchestrator.md
```

## `Map.remove` cleanup/status 已闭合

`0x9aa5c` 的失败状态与引用处理已由 ARM64/x86_64 交叉恢复：

```text
env/map/key null                         -> status 3
GetObjectClass exception/null            -> status 18
GetMethodID exception/null               -> status 18
NewStringUTF exception/null              -> status 34
CallObjectMethod(Map.remove) exception   -> status 28
success                                  -> 保留调用前 status
```

class local ref 和创建成功的 key `jstring` 会清理；`Map.remove` 返回对象保存在
ARM64 `x19`，但没有传给 `DeleteLocalRef`。相反，创建过 key string 的路径会把 flattened
初始 state anchor（ARM64 `x23`，x86_64 `%r13`）传给一次 vtable `+0xb8`
`DeleteLocalRef`。平台无关 C++ 只通过 `opaqueAnchorDeleteAttempted` 记录此行为，不直接
构造无效 JNI reference。`0xa334` 现也已闭合：先清空 `context+0x18`，再无条件删除
`headers_id/adj_signing_id/native_version/algorithm`，调用之间不检查 status；后续失败会
覆盖旧 status，后续成功则保留旧失败。C++ 对应：

```text
RecoveredMapRemoveState
modelRecoveredMapRemove()
modelRecoveredMetadataCleanup()
```

静态证据：

```text
.omx/static-audit-20260713/analyze_map_remove_cleanup.py
.omx/static-audit-20260713/arm64-map-remove-cleanup.md
```

进一步的 Java+arm64 静态数据流已确认：`nSign` 的 `byte[]` 是
`HmacSHA256(UTF8(Map.toString()))` 的 Java 完整性值。native `0x94bc0` 将其复制，
`0xe6c0..0xf1c8` 已直接以 C++ 实现：按原顺序执行 API-specific key resolver、
`Map.toString()`、`String.getBytes()`、Java Mac producer、supplied `byte[]` native copy 和
逐字节比较；不匹配时写 correction `0x07`，并按原 ownership 顺序释放两个 native
buffer 与三个 JNI local reference。实现还保留三次 `15000ms` timing probe，以及基础设施
失败返回 false、由 caller 标记后继续签名的 fail-open 行为。

`0xf328..0xfce0` 也不再通过单一 opaque callback：C++ 直接维护 `0x878` 字节 scratch，
依次执行 7 个可达 environment probe，按原阈值追加 corrections
`01/02/03/08/28/2c/1f`，再调用 `0xfce0` final stage。成功时才执行 `0x12a30`；所有出口
都执行 `0x13000` fallback-mask 和 scratch destructor。各 probe body 仍以原地址命名的
callback 隔离，等待逐个闭合，不把 callee 的未知语义伪装成已恢复。

其 final callee `0xfce0..0x12a30` 已恢复 24 个 one-time initializer 的完整明文结果：
24 个 emulator/automation tool marker 与 23 个 build/product marker 已作为 immutable C++
arrays 落地；静态+本地 trace 还固定了 `0x7ba5c -> 0x7bbb0(24) -> 0x868b4(24)` 和
`status==0` 返回主干。`0x7ba5c` fanout wrapper、`0x7bbb0` 八固定字段 matcher 与
`0x868b4` 动态槽 matcher 已直接实现；共享的 `0x127a78` substring helper、`0x40c70`
generic detector、`0x44c38` predicate wrapper 和 `0x42eb0` paired-descriptor wrapper
也已闭合。该 FDE 暂不提升为 recovered，因为 fanout 内其余 detector body 仍需逐个实现。
其 positive-score 路径使用的 `0x1354bc` correction-array writer 已独立闭合：按顺序
写入 uint16 code，null/count 为 no-op，flag bit 0 由 caller 负责。
因此不能再把该 supplied byte array 直接命名为 final slot 8/9。进一步对完整 ARM64
context-bearing 调用链做保守 may-alias 分析后，`0xcc3e8..0xcc3f4` 的
`memset(context+0x08, 0, 0x120)` 已证明覆盖 `+0x118/+0x120`，所有可达固定 offset
写入均不触及这两个字段。因此 slot 8 固定为四字节零长度，slot 9 为空；它们是保留输入，
不是另一份 HMAC 或 `adj_signing_id`。证据报告位于：

```text
.omx/static-audit-20260713/arm64-nsign-java-hmac-flow.md
.omx/static-audit-20260713/analyze_context_dynamic_pair.py
.omx/static-audit-20260713/arm64-context-dynamic-pair.md
```

expected Java-HMAC 的 native producer 也已静态闭合：`0x9b684` 调用
`Map/Object.toString()`，`0x9c030` 调用无参数 `String.getBytes()`，`0xc8ec0` 按 API
选择 key 路径，`0xca648` 依次执行 `Mac.getInstance("HmacSHA256")`、`init`、`update`、
`doFinal`，最后由 `0x94bc0` 复制 expected byte array。API >=23 使用
`AndroidKeyStore/key2`，API 18..22 使用 `adjust_keys/encrypted_key` legacy unwrap，API <18
返回不支持状态。API 18..22 的 success path 已进一步闭合为
`getSharedPreferences -> getString -> Base64.decode -> AndroidKeyStore key2 ->
RSA/ECB/PKCS1Padding private-key decrypt -> SecretKeySpec(raw,"AES")`。C++ 已加入精确 API
route 枚举，并实现两次尝试、仅 `InvalidKeyException/UnrecoverableKeyException` 重试、
reset、连续失败 lockdown、unsupported lockdown、null native result 和临时字段清理的
platform-neutral 可观察状态机。真正的 Android KeyStore/JNI 调用和异常到状态的映射仍
属于待完成 platform adapter。证据：

```text
.omx/static-audit-20260713/analyze_expected_java_hmac.py
.omx/static-audit-20260713/arm64-expected-java-hmac.md
.omx/static-audit-20260713/analyze_legacy_key_resolver.py
.omx/static-audit-20260713/arm64-legacy-key-resolver.md
.omx/static-audit-20260713/analyze_java_retry_lockdown.py
.omx/static-audit-20260713/java-retry-lockdown.md
.omx/static-audit-20260713/analyze_api23_keystore_resolver.py
.omx/static-audit-20260713/arm64-api23-keystore-resolver.md
```

API >=23 的 `0xc9250` 也已闭合到 call-level failure/null/ownership：它执行
`KeyStore.getInstance("AndroidKeyStore") -> load(null) -> getKey("key2",null)`；任一 JNI
helper 失败时返回 false，但 `getKey` 调用成功且返回 Java null 时 resolver 仍返回 true 并
把 null 交给后续 `Mac.init`。临时 KeyStore local ref 在创建成功后的所有退出路径由
`DeleteLocalRef` 清理，Key ref 转交调用者。C++ `modelRecoveredApi23KeyResolver()` 保留了
`call failed`、`null key`、`non-null key` 三种状态，不能把 null 偷换成 resolver failure。

后续 `0xca648` 的 Java Mac producer 也已闭合到 helper/status/ownership：
`Mac.getInstance -> init(Key) -> update(byte[]) -> doFinal -> 0x94bc0 byte[] native copy`。
它同样不把 null Key 或 null result 改写为备用 key/空 digest，而是让下一 JNI/helper 的
status 或 pending exception 决定失败；Mac 和 doFinal byte[] local refs 在已创建时清理。
C++ `modelRecoveredJavaMacProducer()` 表达阶段状态和两类 local-ref ownership。证据：

```text
.omx/static-audit-20260713/analyze_java_mac_producer.py
.omx/static-audit-20260713/arm64-java-mac-producer.md
```

继续向上追踪后发现，expected Java-HMAC 基础设施失败不是 `nSign null` 的直接条件，而是
native integrity stage 的 **fail-open**：`0xe6c0` 只有完整 match/mismatch 才把 stage result
置 true；mismatch 追加 `0x07`。KeyStore/Mac/JNI byte-array copy 等失败保持 false 且不追加
`0x07`。`0xcbbd4` 的 false 分支调用 `0xf1fc`、清零局部 status 后，仍继续两段
`context+0x108/+0x110` owned-pointer 构造；它不是提前 return。`0xcbe98` 在 `0xcc254`
调用该 void stage 后立即继续 environment dispatcher 和 `0x11da64` final consumer。因此 faithful C++ 必须把
结果分为 `SkippedFailOpen / Match / MismatchCorrection07`，而不是把 skip 当作 native null。
对应实现和证据：

```text
C++ classifyRecoveredJavaHmacIntegrity()
C++ applyRecoveredJavaHmacIntegrityOutcome()
.omx/static-audit-20260713/analyze_hmac_fail_open.py
.omx/static-audit-20260713/arm64-hmac-fail-open.md
```

`buildNativePlaintext()` 的 composition 已按 `0x8af4` 修正：在 100-key 顺序的
`secret_id` 位置固定写 `1400000`，在 `headers_id/native_version` 位置固定写
`9/3.67.0`；调用者对这三个 key 的缺失或伪造都不会改变 signed material。表外
`adj_signing_id` 不参与这个 walker。此前“在 activity_kind 前额外插入固定
adj_signing_id”的兼容假设已移除，冻结 exact vector 保持逐字节一致。

## 尚未完成的边界

C++ 算法路径已经能直接产生完整结果，不再使用固定 113-byte payload 或固定最终
176 bytes。原 SO oracle 已证明 field 0 按 8 halfwords 分块扩容，并闭合
8→16→24；源码按同一规则支持后续 32 等容量。仍不能把整个项目宣称为
“任意 Android 环境的完整 SO replacement”：

本轮已经从 protected engine 中恢复并实现十个高频容器 helper，而不是只给它们命名：

```text
0x138318  framed word write，128-word realloc，失败 status 2
0x138560  push frame base，失败 status 2
0x138660  pop frame/rollback length，空 frame status 7
0x138728  current frame length
0x138744  frame-relative read，超 capacity 返回 0
0x138a70  linked word-stack push，失败 status 2
0x138b74  linked word-stack pop，空栈 status 3
0x138c8c  duplicate indexed stack word，越界 status 4
0x138e58  duplicate-top wrapper，固定 index 0，空栈 status 4
0x138e60  swap top with indexed item，越界 status 4
```

对应 C++ 保留了 arm64 对象 offset、严格 `count > index` 条件、128-word 增长粒度，
以及 `realloc` 失败时直接覆盖旧指针的原生非原子语义。这一批容器恢复当时把逐函数
当时的历史覆盖数字不再作为当前状态；权威最新总数是
347 recovered / 0 partial / 41 unknown，这仍不代表整个 SO 已完成。相邻恢复还包括
counter-chain、big-endian export wrapper、arena/stack 构造析构、五个 tail alias，以及
compiler-emitted acquire byte CAS 与 Exynos 9810 LSE blacklist。

最新 JNI helper `0xba914..0xbb5a0` 已按 ARM64/x86_64 共同证据闭合为
`PackageManager.getPackageInfo(String,int)` reader：父流程分别转发 legacy `0x40` 和
API 28+ `0x08000000` flags；C++ 保留 status `3/18/35`、三次 exception consume、
PackageManager class local-ref cleanup、返回 PackageInfo transfer 和 incoming-status output
clearing。父函数 `0x1dde0..0x1e578` 也已独立恢复：使用 signed Android API level，
API `<28` 走 `getPackageInfo(...,0x40)` 和 `PackageInfo.signatures` 并发布
`hasMultipleSigners=false`；API `>=28` 走 `0x08000000`、`PackageInfo.signingInfo`、
`hasMultipleSigners()`，再选择 APK contents signers 或 signing-certificate history。
返回的整个 `Signature[]` 转交 caller，父级 local-ref 按 SigningInfo、PackageInfo、
PackageManager、packageName 顺序清理。数组元素 `GetObjectArrayElement(Signature[],0)`
位于下一 FDE `0x1e578..0x1f058`，不属于 `0x1dde0`。

`0x1e578` 的直接 helper `0xc2248..0xc2b78` 已进一步闭合为
`Signature.toByteArray()[B` reader。ARM64/x86_64 证明它与独立 FDE `0x93fd0`
共享相同 observable JNI contract：status `3/18/28`、三次 exception consume、
object-class local-ref cleanup、返回 byte-array transfer 和 incoming-status output clear；
原 SO API 18 自然日志确认 `GetObjectArrayElement(Signature[],0)` 后紧接该调用。
其调用链中的 `0xb0f38..0xb1e40` 也已闭合为 `MessageDigest.digest` 双 overload
helper。`0xaf438..0xb081c` 现也已恢复为
`MessageDigest.getInstance(String)`：固定 class/method/signature、status `3/18/27/28`、
四次 exception consume、class 后 algorithm String cleanup、返回 MessageDigest transfer，
并由原 SO observation-only 测试确认父级传入 `SHA1`。

父函数 `0x1e578..0x1f058` 已完成恢复：从 `Signature[]` 取 index 0，执行
`Signature.toByteArray -> MessageDigest.getInstance("SHA1") -> update -> digest()`，再经
`GetArrayLength/GetByteArrayElements` 要求精确 20 bytes。数组元素失败写 status `28`，
长度不是 20 写 status `20`；成功按原 SO 的 16+4 字节布局发布。释放/清理顺序为
`ReleaseByteArrayElements -> MessageDigest -> certificate byte[] -> digest byte[] -> Signature[]`，
原 SO 未显式删除单个 Signature element，恢复实现保持该行为。失败不会主动覆盖 caller
的 20-byte output。专用跨 ABI analyzer、O2/ASan+UBSan 回归和原 SO observation-only
ownership 测试均已通过。

环境阶段的首个 probe `0x1f058..0x1f95c` 也已从 unknown 闭合为
QEMU/Genymotion socket-path probe。ARM64/x86_64 各自解码出
`/dev/socket/qemud`、`/dev/qemu_pipe`、`/dev/socket/genyd` 和
`/dev/socket/baseband_genyd`，按前两条/后两条分两次调用已恢复的 `0x1f95c`
path-existence counter，共享 caller 的 `uint16_t` 累加值且不主动清零。environment
dispatcher 对最终计数执行 `!=0` gate 并提交 correction `0x01`。原 SO 离线
observation-only 测试确认两组 count 均为 2、路径顺序一致，本地 rootfs 结果为
`0->0->0`；专用跨 ABI analyzer、O2、ASan+UBSan 和全量回归均通过。

`0x24860..0x25068` 也已闭合为 VirtualBox DMI file-content probe：两个 ABI
分别构造 `/sys/devices/virtual/dmi/id/product_name` + `VirtualBox` 与
`/sys/devices/virtual/dmi/id/sys_vendor` + `innotek` 两个精确的 0x100-byte
record；marker kind 均为 3（ASCII case-insensitive substring），descriptor count 均为 1，
随后以 record count 2 调用已恢复的 `0x23274` readable-file batch，并共享 caller-owned
`uint16_t` 累加值。原 SO observation-only 隔离调用确认 path/marker/kind/count 与
caller pointer 转发；本地两个文件均未命中，count 为 `0->0`。需要保留的边界是：
`0xf328` 内确有 `0xfbd4 -> 0x24860` 的 flattened call block，但现有 sole-entry
状态证明没有把该 block 纳入自然 signer 链，因此该动态证据只证明函数自身，不声称默认
签名成功路径自然执行它。

最新最小 JNI unknown `0xb2978..0xb3230` 已闭合为 caller-selected String-field
reader。ARM64/x86_64 均固定执行
`GetObjectClass -> GetFieldID(fieldName,"Ljava/lang/String;") -> GetObjectField`，
每阶段消费 exception；null object/name 写 status 3，class/field acquisition failure 写
18，object-field exception 或 null result 写 28。class local-ref 在所有已取得 class 的路径
清理，成功 String ref 转交 caller；incoming status 不阻止 JNI，但最终非零 status 清输出。
唯一 caller `0x179f8` 传入 once-decoded `publicSourceDir`。原 SO 自然路径
observation-only 测试确认 `ApplicationInfo.publicSourceDir`、固定 String signature、
三次 exception 为 0、单次 class cleanup，并把同一 String handle 转给 UTF helper。

`0x1709c..0x179f8` 已进一步闭合为 `/proc/self/cmdline` owned-string producer。
固定项只有原 SO 的 OS 路径、`R_OK`、`AT_FDCWD`、`O_RDONLY` 和 4095-byte read
capacity；cmdline bytes、access/open/read/close 结果、allocator 及内存写/复制操作都经
`RecoveredProcSelfCmdlineOperations1709c::context` 由 C++ caller/profile 注入，不读取
macOS 宿主 `/proc`，也不合成进程名。双 ABI 均在 read 后无条件 close，access/empty
read 写 status 8，open low-32-bit `-1` 写 12，allocation failure 清 output 并写 2；
成功保留 incoming status，terminator-before-copy，完整复制后才发布 owned pointer。
原 SO 只判断 `readResult == 0`：负 read 会按 uint64 wrapping 进入 allocation/copy，
其中 `-1` 可形成 `malloc(0)` 后 `allocation[-1]` 与巨量复制，已列为 High 内存安全发现。
恢复回归通过 memory-effect callbacks 证明该兼容边界而不在宿主测试进程执行 UB。

最新关闭的 JNI 可达叶函数簇还包括：`0x34820` 的 packed low-24 transition
predicate、`0x34954` 的普通 record key 交叉计数器、调用前者的 `0x34bf4`
packed-transition 交叉计数器，以及 `0xd1a38` 的 `{offset,length}` slice 到 owned
NUL string materializer。其后 `0xd1bf4` 已恢复为 UINT32 索引/string-offset-table
owned clone，`0xd2018` 则闭合两阶段 materialization 与 first-then-second rollback。
`0xd28d0` 随后按 0x1c-byte descriptor 的 source-relative offset 构造 0x30-byte
metadata tree：`+0x18` 数组递归调用自身，`+0x28` 数组只调用 `0xd2018`；两次
`calloc(uint32_count,0x30)` 都立即发布 pointer，count 仅在元素成功后递增，任一失败
统一调用 `0xd22d4` 回滚。
`0xd313c` 按点分段下降 metadata tree：中间段在 `+0x18` 数组以
`strncmp(segmentLength)` 首匹配，最终段在 `+0x28` 数组以 `strcmp` 精确匹配并返回
leaf second string。`0xd352c` 解码固定 property-info 路径，执行
access/openat/fstat/size gate/mmap 并复制映射前 24 字节；原生没有在解引用前检查
`mmap` 是否返回 `MAP_FAILED`，恢复实现和审计文档已明确保留该失败边界。
`0x124c90` 已恢复为 public-source parser-owner 构造器：先用 `R_OK` 检查路径，
以跨 ABI 一致的一次性解码模式 `rb` 打开文件，再 `calloc(1,0x48)` 并按
`+0x18/+0x28/+0x38` 初始化三个 owner；access/fopen 失败写 status 2，allocation
失败写 status 1，且原生 allocation-failure 路径不会关闭已经打开的流。
`0x125074` 则恢复为配对的复合 parser-owner 析构器：可选 `FILE*` 先 `fclose` 并清零，
再按 `+0x18/+0x28/+0x38` 顺序析构三个 embedded owner，最后释放外层 owner。
相邻 `0x125210` 解码并匹配 ZIP EOCD signature `50 4b 05 06`；`0x125770`
从 EOF `-22` 开始反向扫描到 `-65556`，完整耗尽返回 `-65557`。
`0x1259b8` 已继续闭合 APK Signing Block locator：从 EOCD `+12` 读取 Central
Directory offset，绝对定位后校验 `50 4b 01 02`，再以 `-20` 定位并校验
`APK Sig Block 42`；随后 `-24` 记录 footer offset/uint64 size，以原生模 64 位
`8-size` 相对 seek 定位 block header，并要求 header/footer size 相等。checked I/O
失败沿用 status 2，三类语义 mismatch 分别写 status 3/5/6；成功时 stream 留在第一项
ID-value entry，owner `+0x08/+0x10` 已细化为 footer offset/size。
下游 `0x127194` 也已恢复为 Signing Block entry dispatcher：循环 raw fread
`uint64 size + uint32 ID`，将 v2 `0x7109871a`、v3 `0xf05368c0`、v3.1
`0x1b93ad61` 分别路由到 owner `+0x18/+0x28/+0x38`。已确认 recognized entry
使用 `low32(size)-4`，unknown entry 使用 checked ftell、模 64 位
`footerOffset+blockSize` 门控和 full64 `size-4` raw fseek；raw read 零返回不写错误，
raw fseek 失败写 status 7。
`0x13dc8/0x14078` 两个 record stage 也已闭合：共同调用 `0x34f9c` 过滤，
分别用 `0x34bf4/0x34954` 计数并提交 correction `0x04/0x0a`；allocation failure
提交 `0x32`，最后写入各自 context mask 并释放临时数组。
无内部 callee 的 `0x87158` 也已恢复：读取 scratch display width `+0x60` 和 height
`+0x64`，以正向或反向匹配八个固定 resolution pair，首个命中返回 true。
前三个 record helper 均以 `uint16_t` 计数语义和 x86_64 对应函数交叉确认；
`0xd1a38` 还证明 `length=UINT32_MAX` 时原生请求 `0x100000000` bytes，allocation
failure 时 cursor 已前移、output 清零并写 status 2。静态证据脚本位于：

```text
.omx/static-audit-20260713/analyze_packed_transition_34820.py
.omx/static-audit-20260713/analyze_record_cross_match_34954.py
.omx/static-audit-20260713/analyze_packed_transition_counter_34bf4.py
.omx/static-audit-20260713/analyze_slice_string_materializer_d1a38.py
.omx/static-audit-20260713/analyze_indexed_string_materializer_d1bf4.py
.omx/static-audit-20260713/analyze_owned_string_pair_d2018.py
.omx/static-audit-20260713/analyze_recursive_metadata_destructor_d22d4.py
.omx/static-audit-20260713/analyze_recursive_metadata_parser_d28d0.py
.omx/static-audit-20260713/analyze_metadata_area_resolver_d313c.py
.omx/static-audit-20260713/analyze_property_info_source_d352c.py
.omx/static-audit-20260713/analyze_parser_owner_constructor_124c90.py
.omx/static-audit-20260713/analyze_parser_owner_destructor_125074.py
.omx/static-audit-20260713/analyze_zip_eocd_cluster_125210_125770.py
.omx/static-audit-20260713/analyze_apk_signing_block_locator_1259b8.py
.omx/static-audit-20260713/analyze_apk_signing_block_entries_127194.py
.omx/static-audit-20260713/analyze_detector_record_stages_13dc8_14078.py
.omx/static-audit-20260713/analyze_unordered_fixed_pair_matcher_87158.py
.omx/static-audit-20260713/analyze_detector_scratch_appender_8f56c.py
.omx/static-audit-20260713/analyze_detector_scratch_destructor_8fb44.py
.omx/static-audit-20260713/analyze_detector_scratch_property_pipeline_8746c.py
.omx/static-audit-20260713/arm64-detector-scratch-property-pipeline-8746c.md
.omx/static-audit-20260713/unidbg-detector-scratch-unique-properties-raw.log
.omx/static-audit-20260713/analyze_jni_int_field_reader_b21b4.py
.omx/static-audit-20260713/analyze_jni_size_method_reader_a8978.py
.omx/static-audit-20260713/analyze_jni_indexed_object_method_reader_a948c.py
.omx/static-audit-20260713/arm64-jni-indexed-object-method-reader-a948c.md
.omx/static-audit-20260713/unidbg-detector-scratch-a948c-raw.log
.omx/static-audit-20260713/analyze_jni_display_metrics_getter_bce98.py
.omx/static-audit-20260713/arm64-jni-display-metrics-getter-bce98.md
.omx/static-audit-20260713/unidbg-detector-scratch-bce98-raw.log
.omx/static-audit-20260713/analyze_detector_jni_object_pipeline.py
.omx/static-audit-20260713/arm64-detector-jni-object-pipeline.md
.omx/static-audit-20260713/analyze_jni_system_service_getter_b5828.py
.omx/static-audit-20260713/arm64-jni-system-service-getter-b5828.md
.omx/static-audit-20260713/unidbg-detector-scratch-system-service-raw.log
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
.omx/static-audit-20260713/unidbg-detector-scratch-trace-20260715.md
```

继续恢复的 `0x1392c4/0x1393cc` 已证明 protected work object 是 `0xa0` bytes，
包含两个 stack、一个 shared arena、一个 counter chain 和 **16 个** arena lanes；此前
“九 slot”描述实际指 final consumer 的九个 input descriptors，现已更正。构造器对
17 个 arena 都传入 `0x100` 请求容量，并在任何 child allocation 失败后调用完整析构器。

`0x12e95c/0x12eb48/0x13716c` 也已提升为 C++：前者是 unsigned 96-bit comparator，
第二个是 final-boundary predicate，后者扫描 32-byte boundary records，普通项匹配
`current <= query < next` 半开区间，最终返回调用方传入的 cookie 或 null。该 helper
属于 range/table predicate，不是多套加密算法 selector。

相邻 `0x136a00` 现已完整恢复为 string-array builder：它先按每项
`strlen(item)+1` 计算容量，再在**每一项之后（包括最后一项）**复制 delimiter。调用方
将 `0x1460c8` 一次性解码成单空格，所以 `{"a","b"}` 的结果是 `"a b "`，而不是
`"a b"`；`count=0` 返回一个成功分配的空字符串。等价实现是
`joinStringArrayWithTrailingDelimiter`。加上本轮 KeyStore 三个 JNI helper 与 API23 resolver
以及 Java Mac 四个 JNI helper、byte-array copy helper 后，覆盖矩阵曾继续推进；当前
权威数字统一以本文件顶部和 `SO_FUNCTION_COVERAGE.md` 为准。

继续向上已将 `0x135640 -> 0x12c12c -> 0x13716c` 串联：静态 marker 跨 ABI 解码为
`android`；`0x12c12c` 进行 ASCII case-insensitive marker 匹配并通过三次
base-10 `strtol` 写出 `uint32_t[3]`，随后两组 32-byte range 表被检查，最终组合条件是
`first == null && second != null`。其中 `0x12c12c` 的 scanner 现已通过 x86_64
持久 stack slots 与 ARM64 opaque states 交叉闭合：它先返回首次 ASCII
case-insensitive marker 匹配的末尾，再对每段执行“跳过连续 `.`、扫描到下一个
`.`/NUL、按阶段原地截断并立即 `strtol`”。转换失败不会寻找下一组 triplet，已经发生
的 NUL 写入与 output 写入会保留。对应完整入口是 `parseProtectedAndroidTriplet`；
`0x12c12c` 已提升为 recovered。`0x135640` 也已闭合：它无条件扫描并 malloc-copy
source，在 copy 成功后独立调用 trailing-space join，再对 writable copy 调 parser；source
分配失败写 status `2`，parser 失败写 status `5`，成功不改 status，最后依次释放 source
copy 和 joined result。对应完整入口是 `protectedAndroidMarkerRangeGate`。

其中转换原语现已进一步写入 C++：marker 比较只把 ASCII `A..Z` 折叠为小写；parser
仅在第一次 `strtol` 前清零一次 `errno`，三次转换都先截取 `long` 的低 32 位写入输出，
再按 `end != start && errno != ERANGE` 判断。第三次转换成功块不检查 `*end == '\0'`，
所以不能用严格 semver parser 替代。对应函数是 `foldProtectedAsciiMarkerByte`、
`protectedAsciiMarkerBytesEqual` 和 `parseProtectedDecimalComponent`。

注意，相邻静态区还存在独立解码的 `ActivityPackageSender`，但它不是本 pipeline 传给
`0x12c12c` 的 marker；交叉 ABI 写引用已排除该旧命名。

1. 已观察到的 correction code 可以传入，trampoline 检测已映射；其他 Android/native
   probe 到 correction code 的全部分支仍需逐个映射；
   当前已进一步证明 `0x05` 来自 `0xd184` 的 `gettimeofday/clock_gettime` 时序检查，
   该检查写入 native context byte `+0x8`，`0xf224` 再据此产生 correction；`0x2b`
   来自初始化 wrapper；dispatcher `0x14d9c` 调用 `0xd78b8` 读取 `/proc/self/maps`。
   该 FDE 已由完整 ARM64 解释器闭合为区分大小写的 `frida-agent` substring scanner：
   `access(path,R_OK=4)` 或 `fopen(path,"r")` 失败写 status `8`，dispatcher 将该 status
   映射为 correction `0x35`；命中 marker 返回 true 并映射为 `0x22`。它不是
   package/base.apk scanner。package/base.apk 映射存在性与 mapped path/publicSourceDir
   差异来自独立的 `0x18540` list producer / `0xd474` consumer 链，分别产生
   `0x37`/`0x29`；并已证明 `/proc/self/cmdline` 缺失/空产生
   `0x34`，非空进程名与 runtime packageName 不一致产生 `0x09`，`0x38` 是
   publicSourceDir 不可访问；`0x3c` 是 `ro.build.version.sdk` 按 native `atoi` 解析后的
   值与传入 native 的 `androidApi` 不一致。当前 Unidbg resolver 在属性未配置时回退
   为 `23`，这解释了稀疏 profile 中 API 23 无 `0x3c`、API 24+ 有 `0x3c` 的旧现象。
   `0x2f` 也已闭合：`0xf18f4` 依次 `stat()`
   `/system/lib64/libart.so` 与 `/system/lib64/ld-android.so`，两者都不存在时
   `0x14f40` wrapper 才追加该 correction；任一存在即不追加。Java recovered backend
   已按该 OR-existence 规则自动推导，C++ 回归也加入了完整 176-byte 原 SO oracle。
   `0x07` 也已通过成对 oracle 闭合：`nSign` 第三个 `byte[]` 参数若不等于
   `HMAC-SHA256(signingKey, params.toString().getBytes(UTF-8))` 就追加 `0x07`；正确
   HMAC 只移除该 correction。该 Java HMAC 不进入最终 adj8 payload/ciphertext，但会
   参与完整性 correction。API 23+ recovered backend 直接使用配置的 HMAC key；
   API 18-22 在 profile 提供配对 PKCS#8/X.509 RSA key 和 `encrypted_key` 时，最新
   Java 适配会按原 Java 路径解包 secret 再自动推导 `0x07`；该新增适配当前已通过
   离线 compiler check，但尚未运行验证，不能与已验证 API23+ 路径等同。
   关闭 `0x05` 的原 SO
   payload 仍为 field 6=`01`，所以该 timing flag 与 payload state 不是同一字段；
   `0x2a` 已证明是 `baseApk` 实际 signer certificate 与 PackageManager 模拟证书不一致，
   Java recovered backend 已自动解析 v1/v2/v3/v3.1 APK signer 并产生该 correction；
2. Java `RecoveredNativeBackend` 已按恢复顺序直接拼接参数，并用原 SO oracle 验证完整
   Pixel、缺失字段、maps 分支、timing correction 和 APK 证书匹配分支；尚未观察到的
   新 SDK 字段仍需按新 oracle 扩展；
3. Java 默认 backend 为 `unidbg` 以保持兼容，但 JSON 可配置
   `runtime.backend=recovered`，该路径已通过冻结 Pixel 完整严格比对。

因此当前准确表述是：**动态算法核心已有此前十五类 176/192/208-byte oracle 证据；
本轮新增环境 correction 与 urandom/field-2 的 C++ adapter，修正 final-consumer 边界，
并把隐藏算法剩余面收敛到 `0xf1ec8..0x11ba74` protected engine。该 engine 的 arena 和
linked-stack 基础词汇已经源级恢复；剩余工作包括把 7,223-call schedule 和 645 个 branch
predicate 提升为完整高层数据流、legacy RSA 适配验证、失败/重试/lockdown 语义及 JNI/platform adapter，
而不能只写成“尚未命名的 correction”。其中 retry/lockdown 的 Java 可观察控制流已迁入
C++，剩余的是 Android KeyStore/JNI exception/null/local-ref 与并发适配。**

`nSign` 外层继续新增两个完整静态恢复单元：`0xd4908` 每次先同步调用
`0xd4e0c`，再以进程全局 byte 做一次性门控，安装
`CLOCK_MONOTONIC + SIGEV_THREAD` 的 1 秒周期 timer；create/arm 失败均静默返回且不置
installed。`0xaebf8` 则是 Map 字符串 owned-copy helper：nSign 用它读取一次性解码的
`environment` key，随后与解码出的 `sandbox` 做逐字节比较；helper 自身在 `Map.get` 后取得 modified UTF-8，
分配 `length+1`、逐字节复制并补 NUL，随后 ReleaseStringUTFChars/DeleteLocalRef；非法
Map/key 为 status 2，malloc 失败为 status 3。对应 C++ 为
`model/runRecoveredPeriodicTimerInstall` 与 `model/runRecoveredMapStringCopy`，静态回归
不会创建真实 OS timer。

JNI `nOnResume` 导出 `0xcba8c..0xcba90` 只有一条无条件 tail branch 到上述
`0xd4908`，没有独立参数变换或返回处理；C++ 入口
`runRecoveredNOnResumeExport` 因而直接转交 `runRecoveredPeriodicTimerInstall`。
环境 dispatcher 后的四个固定 wrapper `0x14e10/0x14e44/0x14e78/0x14eac`
也已直接恢复：依次写 correction `0x35/0x36/0x3a/0x3a`，随后统一设置
`context+0xe0` flag bit 0。
紧邻的 `0x14ee0..0x14ef8` 是单一 flag 叶函数，执行
`context+0xe0 |= 0x0460603c00000000`，也已直接实现。
dispatcher 入口前的 `0x14338/0x14350/0x14368` 三个固定 flag 叶函数及
`0x14380/0x143b4` 两个相同 correction `0x32` wrapper 也已闭合。
`0x13dc4..0x13dc8` 仅 tail branch 到 `0x14380`，由独立 C++ alias 入口表示。
另闭合了四个小型 JNI 可达叶函数：`0xd7890` 的 `access(path,F_OK)` 布尔 helper、
`0x122fdc/0x124a18` 两个空链表 `{head=0,tailSlot=&head}` 初始化器，以及
`0x130128` 的独立 no-op return。

`0xcc604 nSign` 已通过完整 ARM64 解释器和 callback-driven C++ 闭合：五个 JNI 值分别
进入 16-byte wrapper，0x30-byte descriptor 的 `+0/+8/+10/+18/+20` 依次为 env 值以及
Context/Map/HMAC/API wrapper 指针。timer 后复制 `Map["environment"]`；只有复制成功、
结果非 null 且严格等于小写 `sandbox` 时 environment auxiliary flag 才为零。第一次
`cc47c` 失败只跳过 begin log，不会被带入签名后的判断；签名后 status 被清零，第二次
`cc47c` 独立决定 end log。两次失败均不清空 `cbe98` 保存的 `jbyteArray`。对应执行入口为
`runRecoveredNsignOrchestratorCC604`，完整解释器证据为
`analyze_nsign_jni_orchestrator_full.py`。与原生一致，Map helper 产生的 environment owned
string 在该导出内没有 free，属于每次成功复制都会发生的泄漏边界。

timer callback `0xd4e0c` 现已跨 ARM64/x86_64 闭合：它一次性解码
`/proc/%d/status` 与 `TracerPid:`，使用 getpid、access、openat、最多 0x800-byte read 和
close，ASCII case-insensitive 查找 marker，再按 native atoi 的空白/符号/十进制规则解析。
非零 TracerPid 将进程全局 verdict 永久置 1。`0xd6888` 消费该 verdict：命中时追加
correction `0x26` 并置 context flag bit 0；无论命中与否都置 bit 38。对应实现为
`model/runRecoveredTracerPidPeriodicCallback` 与 `applyRecoveredTracerPidPostStage`。
这条链是周期反调试探针，不是密码算法动态选择器。

`0x12ec1c` timing-log front end 也已跨 ABI 闭合。它接收 epoch milliseconds，按
`trunc(ms/1000)` 生成 `time_t`、按 `trunc(fmod(ms,1000))` 生成 signed millisecond，
使用 `localtime` 与 `%Y-%m-%dT%H:%M:%S`/`%z`，最终构造
`%s: %s.%03dZ%s` 并交给 `0x12fa24`。nSign 两个 label 精确为
`Signing all the parameters begin` 和带两个尾随空格的
`Signing all the parameters end  `。这里故意是 local time 后拼字面 `Z` 和 numeric zone，
兼容实现不能擅自正规化成 UTC。C++ 入口为 `model/runRecoveredTimestampLog`；下游
Android log routing 仍作为独立恢复单元。
