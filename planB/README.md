# adjust signature 3.67.0 self-contained Java signer

本工程不在运行时加载 `adjust-android-signature-3.67.0/classes.jar`。AAR 中的 Java 逻辑已经在源码中重新实现，只有原生 `libsigner.so` 由 Unidbg 执行。

`SO_REVERSE_STATUS.md` 记录 native 已验证行为、已定位地址和剩余环境 probe 映射边界。
`native-reimplementation/` 已能在不加载原 SO 的情况下，从结构化 native 输入独立生成
完整 signature；冻结 Pixel 路径为 176 bytes，已验证的九 correction 路径为 192 bytes。
Java signer 现支持两种 desktop backend：默认
`unidbg` 继续执行原 SO；`recovered` 调用项目内独立 C++17 核心，不加载原 SO。

目录职责、`device-reference` 的调用边界、生成物分类和维护/回归路径见
[`PROJECT_MAP.md`](PROJECT_MAP.md)。

对外保持以下 API：

```java
com.adjust.sdk.sig.Signer.getVersion()
com.adjust.sdk.sig.Signer.onResume()
com.adjust.sdk.sig.Signer.sign(Context, Map<String, String>, String, String)
com.adjust.sdk.sig.Signer.sign(Context, Map<String, String>, Map<String, String>, Map<String, String>)
```

内部调用链：

```text
Signer Java 参数逻辑
  -> AndroidKeyStore / HmacSHA256
  -> NativeLibHelper.nOnResume() / nSign(...)
  -> runtime.backend=unidbg
       -> AdjustSignatureRunner -> Unidbg 0.9.9 -> arm64-v8a/libsigner.so
     runtime.backend=recovered
       -> RecoveredNativeBackend -> source-built recovered-primitives
```

`SignerEngine` 的顺序固定为：构造时调用一次 `Signer.onResume()`，成功后才允许调用 `sign(...)`。不会出现跳过 `onResume` 直接签名的路径。

## 不加载原 SO 的 C++17 算法核心

```bash
cd /Users/sanbo/Desktop/api/qbdi
./native-reimplementation/build-and-test.sh
```

这条路径完全在电脑运行，不需要 Java/JNI、Unidbg、原 `libsigner.so`、Android
Emulator、ADB、Frida 或真机，也不自动安装系统插件。当前已独立实现：

```text
Device/native inputs
  -> Bionic-random IV
  -> correction-code field 0
  -> custom-state SHA-256 field 4
  -> dynamic payload（已验证 113 / 129 bytes）
  -> AES-256-CBC + PKCS#7
  -> HMAC-SHA256(ciphertext)
  -> dynamic signature（已验证 176 / 192 bytes）
```

可直接修改已恢复输入：

```bash
./native-reimplementation/build/recovered-primitives \
  --time-seconds=1760000001

./native-reimplementation/build/recovered-primitives \
  --signer-code-trampoline-detected=false

./native-reimplementation/build/recovered-primitives \
  --correction-codes=2b,36,25,05 \
  --certificate-sha1=164a86faf30e412b59223a36ccbe0f6e46e40958 \
  --native-plaintext-hex=<hex> \
  --state=true
```

完整 CLI、field 0/field 4 公式和未完成边界见
[`native-reimplementation/README.md`](native-reimplementation/README.md)。当前准确状态是：

- 完整算法核心和十三类原 SO oracle 已闭合，包括 field 0 按 8 个 halfwords 分块扩容的
  192-byte（16 halfwords）与 208-byte（24 halfwords）完整结果；
- Java/Unidbg normal path、原 API descriptor、`onResume -> sign` 和冻结真机 strict test
  已闭合；
- Java 已能可选切换到独立源码 backend，冻结 Pixel job 在该路径上也完整严格一致；
- 剩余工作是把其他 Android/native probe 全部映射成 correction event，从而减少非 Pixel
  profile 需要显式提供 `runtime.correctionCodes` 的情况。

## 已实现的 Java 逻辑

- `Signer.getVersion()` 返回 `3.67.0`
- `Signer` 延迟初始化和全局错误锁定
- API 18-22 `SharedPreferences + RSA/ECB/PKCS1Padding` 包装密钥逻辑及 native JNI 桥接
- API 23+ AndroidKeyStore `HmacSHA256` 逻辑
- `activity_kind` / `client_sdk` 临时参数写入和清理
- HMAC、重试、KeyStore 清理、native 调用、Base64 回写
- SDK v5 Map 筛选、`a=b` 分支和 `authorization` 拼装
- 私有 `NativeLibHelper.nOnResume()` 与 `nSign(Context,Object,byte[],int)` 到 Unidbg 的桥接
- `RecoveredNativeBackend`：从 Java params 构造已恢复的 native plaintext，计算证书
  SHA-1，传入 runtime/correction 配置并调用独立 C++ signer

## 多套加密与动态切换的当前结论

当前已经通过原 SO 动态 JNI trace 证明两套 API 分支：API 23+ 直接从
AndroidKeyStore 取得 `key2` 做 `HmacSHA256`；API 18-22 从 SharedPreferences
读取 RSA/PKCS1 包装密钥，先用 AndroidKeyStore 私钥解包，再做
`HmacSHA256`。随后已恢复的 native 结果层仍为 custom-state SHA-256、
AES-256-CBC/PKCS#7 与 HMAC-SHA256。

`algorithm` metadata 的受保护 builder 已定位到 SO `+0x9954c`。API、环境、
activity kind、client SDK、请求版本、参数数量和多 correction 差分实验均从固定
静态编码表得到 `algorithm=adj8`；目前没有原 SO oracle 证明第二套最终 envelope。
新增确定性 native 直调矩阵还证明：API 36 下把 Java HMAC 参数改成
0/16/31/32/33/64 bytes 或改变内容，原 SO完整结果均不变；API 23→24 的差异是
新增环境 correction `0x3c`，导致 payload 跨 AES block 扩容，而不是切换最终算法。
完整调用点、27-case 矩阵和证据边界见 `SO_REVERSE_STATUS.md` 的
“`algorithm=adj8` selection evidence”。

对应源码：

- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/Signer.java`
- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/c.java`
- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/d.java`
- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/NativeLibHelper.java`

## 直接运行

```bash
cd /Users/sanbo/Desktop/api/qbdi
./run-java.sh
```

`run-python.py` is a legacy optional adapter only. Supported execution is Java
with either the default Unidbg backend or the independent recovered C++ backend;
neither requires Python, ADB, a device, or an Android emulator.

默认依次在独立 JVM 中验证：

1. 直接 `nOnResume -> nSign`
2. 自实现的 v4 `Signer.sign(Context,Map,String,String)`
3. 自实现的 v5 `Signer.sign(Context,Map,Map,Map)`

独立 JVM 用于规避 Unidbg Unicorn backend 在 macOS arm64 同一 JVM 连续销毁和创建 emulator 时可能触发的 `SIGBUS`。

只运行某一层：

```bash
./run-java.sh --mode=native
./run-java.sh --mode=v4
./run-java.sh --mode=v5
```

成功标志包括：

```text
Signer.getVersion OK version=3.67.0
nOnResume OK
nSign OK len=176
Signer.sign v4 OK raw_len=176
SIGNER_V4_SIGNATURE_BASE64=...
Signer.sign v5 OK
SIGNER_V5_AUTHORIZATION=...
```

## Java 调用

v4：

```java
System.setProperty("adjust.project.root", "/Users/sanbo/Desktop/api/qbdi");

Signer signer = new Signer();
signer.onResume();
signer.sign(context, params, "session", "android4.38.5");

String signature = params.get("signature");
NativeLibHelper.closeBridge();
```

v5：

```java
Map<String, String> request = new LinkedHashMap<>();
request.put("activity_kind", "session");
request.put("client_sdk", "android5.0.0");
request.put("a", "not-b");
request.put("network_payload", payload);
request.put("endpoint", endpoint);

Map<String, String> output = new LinkedHashMap<>();

Signer signer = new Signer();
signer.onResume();
signer.sign(context, params, request, output);

String authorization = output.get("authorization");
NativeLibHelper.closeBridge();
```

`onResume()` 可以先调用一次，之后在同一个 `Signer`/Unidbg runner 上连续调用 `sign(...)`。

### 返回值说明

- 原版两个 `Signer.sign(...)` 的 Java 返回类型都是 `void`。
- v4 会把结果写回第二个 `Map`：`signature`、`headers_id`、`adj_signing_id`、`native_version`、`algorithm`。
- v5 会把 `authorization`、请求参数、`network_payload` 和 `endpoint` 写入第四个 `Map`。
- 真正的 native `nSign(Context,Object,byte[],int)` 返回 `byte[]`；当前样例通常为 176 字节。

### 推荐：直接传设备资料并返回结构化结果

新增 facade 不改变原始 `Signer` API：

- `local.DeviceProfile`：App、证书、KeyStore key、传感器、屏幕和 SDK 信息。
- `local.SignerRequest`：v4/v5 签名请求。
- `local.SignerEngine`：构造时自动先调用一次 `onResume()`，之后可连续签名。
- `local.SignerResult`：同时返回 raw `byte[]`、Base64、metadata、authorization 和最终 Map。

```java
import local.DeviceProfile;
import local.SignerEngine;
import local.SignerRequest;
import local.SignerResult;

DeviceProfile device = DeviceProfile.builder()
        .packageName("com.example.app")
        .androidApi(35)
        .baseApk(new File("/path/to/real-app.apk"))
        .certificateDer(Files.readAllBytes(Path.of("/path/to/certificate.der")))
        .signingKey(Files.readAllBytes(Path.of("/path/to/android-keystore-hmac-key")))
        .sensor("LSM6DSO", "STMicroelectronics", 1, 3)
        .display(1440, 3120, 560, 3.5f, 3.5f, 560.0f, 560.0f)
        .appUid(10234)
        .targetSdk(35)
        .nativeProcessId(4242)
        .nativeTimeSeconds(1760000000L)
        .nativeGettimeofday(1760000000L, 123000L)
        .nativeClockGettime(1760000000L, 123000000L)
        .nativeConnectRefusedEndpoint("127.0.0.1:27042")
        .build();

try (SignerEngine engine = new SignerEngine(
        new File("/Users/sanbo/Desktop/api/qbdi"), device)) {
    SignerResult result = engine.sign(
            SignerRequest.v4(params, "session", "android4.38.5"));

    byte[] raw = result.getRawSignature();
    String base64 = result.getSignatureBase64();
    String headersId = result.getHeadersId();
    String signingId = result.getAdjustSigningId();
    String algorithm = result.getAlgorithm();
    String nativeVersion = result.getNativeVersion();
    Map<String, String> finalOutput = result.getOutput();
}
```

一次性调用：

```java
SignerResult result = SignerEngine.signOnce(
        projectRoot, device,
        SignerRequest.v4(params, "session", "android4.38.5"));
```

v5：

```java
SignerResult result = engine.sign(SignerRequest.v5(params, request));
String authorization = result.getAuthorization();
```

同一个 JVM 同时只能有一个活动的 `SignerEngine`，但一个 engine 可以在一次 `onResume()` 后连续执行多次 v4/v5 签名。

可直接运行外部 JAR 调用示例：

```bash
./test-external-structured-api.sh
```

### 一键 JSON 生成

把设备环境和签名请求写到一个 JSON，然后执行：

```bash
cd /Users/sanbo/Desktop/api/qbdi
./generate-signer.sh examples/signer-job.json

# 不加载原 SO/Unidbg 的 Java -> C++ recovered backend，并严格比对冻结 reference
./generate-signer.sh examples/recovered-signer-job.json

# 可以格式化看
./generate-signer.sh examples/signer-job.json|jq
```

命令只输出最终结果 JSON：

```json
{
  "signed": true,
  "version": "V4",
  "rawSignatureHex": "...",
  "signatureBase64": "...",
  "metadata": {
    "adj_signing_id": "1400000",
    "algorithm": "adj8",
    "headers_id": "9",
    "native_version": "3.67.0"
  },
  "output": {}
}
```

完整模板位于 `/Users/sanbo/Desktop/api/qbdi/examples/signer-job.json`，支持：

- App：`packageName`、`androidApi`、`baseApk`、证书、KeyStore key、UID、targetSdk。
- `ApplicationInfo` 路径：`applicationInfo.sourceDir`、`publicSourceDir`、`dataDir`、`nativeLibraryDir`。
- 屏幕：分辨率、DPI、density、scaledDensity、xdpi、ydpi。
- 任意数量传感器：name、vendor、type、version。
- `Build` / `Build.VERSION` 字段。
- native `__system_property_get` 使用的 `ro.*` 系统属性。
- `Settings.Secure` / `Settings.System`。
- Android system service 名称到 JNI class 的映射。
- Locale 和 TimeZone。
- native runtime：`getpid()`、`time()`、`gettimeofday()`、`clock_gettime()` 返回值。
- native instrumentation：`runtime.signerCodeTrampolineDetected` 控制原 SO 对 signer
  代码入口 `LDR literal -> BR` trampoline 的可观察检测结果。冻结 Pixel 8 reference
  是在 Frida Interceptor 存在时采集的，因此该 fixture 配置为 `true`；普通无插桩环境默认 `false`。
- backend：`runtime.backend` 可取 `unidbg`（默认）或 `recovered`。`recovered` 不创建
  Unidbg emulator、不加载 AAR/SO；若 C++ 可执行文件不存在或源码更新，会用电脑已有
  `c++` 在项目目录内自动构建。
- correction events：`runtime.correctionCodes` 可显式传十六进制字符串数组，例如
  `["2b","36","25","05"]`。未提供时 recovered backend 根据
  Android API、APK manifest/package、`applicationInfo.publicSourceDir`、APK signer、
  `filesystem`、`signerCodeTrampolineDetected` 和 `correction05Enabled` 构造当前已由
  原 SO oracle 证实的 correction 序列。顺序为 `2b,34/09,37/29,38,2a,3c,35,36,25,05`：
  `0x2b` 是成功 `nOnResume` 初始化的固定首事件；`/proc/self/cmdline` 缺失或为空时产生
  `0x34`，非空但首个 NUL 结尾进程名与 runtime packageName 不同时产生 `0x09`；
  maps 找不到当前 package 的 `/base.apk` 行时产生 `0x37`，
  找到但首条路径与 `publicSourceDir` 不同时产生 `0x29`；`publicSourceDir` 不可访问时
  产生 `0x38`；`androidApi != 36` 时产生 `0x3c`，包括已验证的 API 18/21/22。
  `0x2a`、`0x35`、
  `0x36`、`0x25`、`0x05` 的含义见下文和 `SO_REVERSE_STATUS.md`。
- APK certificate correction：当提供 `device.baseApk` 时，recovered backend 会用
  Maven APK parser 读取 v1/v2 signer certificate；对于 v3-only/v3.1 signing block，
  使用项目内纯 Java `ApkSigningBlockCertificates` 直接解析，无需 Android SDK、
  `apksigner` 或外部进程。解析出的证书与
  `device.certificateFile/certificateHex/certificateText` 模拟的 PackageManager 证书比较。
  不一致时按原 SO 顺序在 `2b` 后自动追加 correction `0x2a`；匹配时不追加。
  对无法读取签名证书的 APK 不做猜测，可用 `runtime.correctionCodes` 显式校准。
- 慢执行/时序 correction：`runtime.correction05Enabled` 可显式控制是否产生
  correction `0x05`。原 SO 在 `0xd184` 使用 `gettimeofday` 和 `clock_gettime`
  做时序检查，写入 `context+0x8`，随后 `0xf224` 根据该 byte 决定是否产生 `0x05`。
  该配置同时适用于 `unidbg` 和 `recovered` backend；默认不覆盖原 SO 检测结果，
  recovered 默认使用已观察到的 Pixel `true`。
- native 网络：`runtime.network.connectRefusedEndpoints` 可将指定 IPv4 `host:port` 的 native `connect` syscall 固定为 `ECONNREFUSED`，无需让宿主机网络参与；Pixel 8 reference 的已观察值是 `127.0.0.1:27042`。
- native 文件系统：`filesystem.files` 可按 `file`、`text` 或 `hex` 提供文件内容；`filesystem.missing` 可固定 ENOENT 路径。
- SharedPreferences：`device.sharedPreferences` 按 preference 文件名和 string key/value
  提供持久化状态，例如 `{"adjust_keys":{"encrypted_key":"..."}}`。API 18-22 的
  desktop legacy 流程已实现 `getSharedPreferences/getString/contains/edit/putString/remove/apply`、
  Android Base64、RSA private-key entry、`Cipher` 和 `SecretKeySpec` JNI 调用。
- legacy AndroidKeyStore：API 18-22 可通过 `device.legacyKeyStore` 导入与
  `encrypted_key` 配对的 RSA PKCS#8 private key 和 X.509 SubjectPublicKeyInfo public key。
  每个值均支持 `File` 或 `Hex` 后缀；必须成对提供。该导入完全在 Host JVM 内完成，
  不连接 Android Keystore 或真机。例如：

```json
{
  "device": {
    "androidApi": 18,
    "legacyKeyStore": {
      "privateKeyPkcs8File": "legacy-key2-private.pk8",
      "publicKeyX509File": "legacy-key2-public.der"
    },
    "sharedPreferences": {
      "adjust_keys": {
        "encrypted_key": "base64-rsa-pkcs1-wrapped-secret"
      }
    }
  }
}
```
- `libsigner.so` 的 dispatcher `0x14d9c` 会调用 helper `0xd78b8` 读取
  `/proc/self/maps`。当前原 SO 动态 oracle 已证明：成功条件是存在一行同时包含当前
  `packageName` 和 `/base.apk`。即使只保留这一行、修改地址/权限/inode，也不增加 `37`；
  空文件或任意不包含该 package/base.apk 组合的非空内容增加 `37`；路径缺失增加
  `37,35`；三种情况之后均产生 `36`。若找到了该行，但提取出的首条 APK 路径与
  `publicSourceDir` 不同，则产生 `0x29`。单独加入 `frida-server`、`gum-js-loop`、
  `libfrida-gadget.so`、`xposed`
  或 `/data/local/tmp` 并没有产生不同 code，因此不能把 `0x37` 命名成 Frida 关键词命中。
  需要复现实机环境时，
  应将对应 live maps 快照作为 `filesystem.files["/proc/self/maps"]` 传入，而不是让
  宿主机文件系统参与。
- 所有业务/设备请求字段：放入 `sign.parameters`，保留 JSON 字段顺序。
- 通用 JNI override：按完整 JNI 签名传入 `strings`、`ints`、`longs`、`floats`、`doubles`、`booleans`、`bytesHex`。

例如，未知的设备方法不需要新增 Java getter，可直接配置：

```json
{
  "jni": {
    "strings": {
      "android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;": "860000000000000"
    },
    "booleans": {
      "android/net/NetworkInfo->isConnected()Z": true
    }
  }
}
```

证书和 key 分别支持 `certificateFile/certificateHex/certificateText`、`signingKeyFile/signingKeyHex/signingKeyText`。相对路径以输入 JSON 所在目录为基准。v5 将 `version` 改为 `v5` 并提供 `sign.request` 即可。

### 确定性运行

`libsigner.so` 3.67.0 在签名路径中会读取进程 PID 和当前时间，并执行 `time -> srand -> rand`。因此只传相同业务参数、但不固定 native runtime 时，签名字节本来就可能不同。

要让相同输入在不同 JVM 中逐字节一致，在 `device.runtime` 中传入：

```json
{
  "runtime": {
    "processId": 4242,
    "timeSeconds": 1760000000,
    "gettimeofday": {
      "seconds": 1760000000,
      "microseconds": 123000
    },
    "clockGettime": {
      "seconds": 1760000000,
      "nanoseconds": 123000000
    },
    "signerCodeTrampolineDetected": false,
    "network": {
      "connectRefusedEndpoints": ["127.0.0.1:27042"]
    }
  }
}
```

当前 `/Users/sanbo/Desktop/api/qbdi/examples/signer-job.json` 已包含这组固定值。`test-one-click-signer.sh` 会启动两个全新 JVM，并要求完整结果 JSON 完全相同。

`examples/recovered-signer-job.json` 使用同一公开 `Signer` API 和固定
`onResume -> sign` 编排，但 backend 为独立 C++。运行 `./test-recovered-backend.sh`
会先校验冻结 reference 的 SHA-256，再要求完整 JSON 严格一致。

`device-reference/references/pixel8-api36/signer-job.json` 还将
`signerCodeTrampolineDetected` 设为 `true`，复现采集脚本在真机上对 `nOnResume` / `nSign`
安装 Interceptor 后被原 SO 自检观察到的 native code trampoline。电脑端只配置这个观察量，
不运行 Frida。

### 与 reference 严格比对

把真机产生的完整结果 JSON 单独保存，然后在任务 JSON 根节点引用：

```json
{
  "expectedResultFile": "/absolute/path/to/true-device-result.json"
}
```

`expectedResultFile` 的相对路径以任务 JSON 所在目录为基准。也可以把该 reference 文件中的完整对象原样放到根节点 `expectedResult`。`expectedResult` 和 `expectedResultFile` 二选一，且不能省略 reference 中的字段。

`expectedResult` / `expectedResultFile` 使用完整 JSON 严格比较；任何字段、字节、Map 内容或字段集合不一致，命令都会以非零状态退出，并报告第一个不一致路径，例如：

```text
expectedResult mismatch at expectedResult.rawSignatureHex expected=... actual=...
```

要证明“与某台真机逐字节一致”，reference 必须来自同一 APK、证书、AndroidKeyStore key、参数及顺序、设备环境，并同时记录该次调用实际观察到的 PID、`time()` 与 `gettimeofday()` 值。没有这组真机 reference 时，只能证明本地确定性和 API/协议行为一致，不能诚实声称已经完成真机逐字节验收。

## 自定义参数

```bash
./run-java.sh --mode=v4 \
  --activity-kind=session \
  --client-sdk=android4.38.5 \
  --params-json='{"environment":"sandbox","app_token":"tok","created_at":"2026-07-10T00:00:00.000+0800","gps_adid":"11111111-1111-1111-1111-111111111111","device_type":"phone","os_name":"android","os_version":"15"}'
```

配置真实 App 环境：

```bash
ADJUST_PACKAGE='你的包名' \
ADJUST_ANDROID_API=35 \
ADJUST_BASE_APK='/path/to/real/app.apk' \
ADJUST_CERT_HEX='真实签名证书 DER 十六进制' \
ADJUST_KEY='AndroidKeyStore HMAC key' \
ADJUST_NATIVE_PROCESS_ID=4242 \
ADJUST_NATIVE_TIME_SECONDS=1760000000 \
ADJUST_NATIVE_GETTIMEOFDAY_SECONDS=1760000000 \
ADJUST_NATIVE_GETTIMEOFDAY_MICROSECONDS=123000 \
ADJUST_NATIVE_CLOCK_GETTIME_SECONDS=1760000000 \
ADJUST_NATIVE_CLOCK_GETTIME_NANOSECONDS=123000000 \
ADJUST_NATIVE_CORRECTION_05_ENABLED=true \
./run-java.sh --mode=v4
```

还支持 `ADJUST_KEY_HEX`、传感器、DisplayMetrics、UID 和 targetSdk 等环境参数；`DeviceProfile.fromEnvironment()` 会读取同一套变量。

这里模拟的是当前 `libsigner.so` 实际读取到的 Android/JNI 环境面，不是完整 Android Framework。已观察到的字符串、整数、长整数、浮点、布尔、`byte[]`、Build、Settings、system property、传感器、屏幕、service、PID 和时间入口都可传入；如果未来 `.so` 新增此前未访问过的复杂 Android 对象图，仍需增加对应对象适配，不能把通用标量 override 误称为完整 Android 系统。

要复现指定真机，需要保证 package、真实 APK、证书 DER、Android API、参数值及顺序、传感器、屏幕、UID、targetSdk、native runtime 和 API 23+ AndroidKeyStore HMAC key 一致。API 18-22 的电脑路径既可自行生成 RSA entry，也可通过 `device.legacyKeyStore` 导入与既有 `adjust_keys/encrypted_key` 配对的 PKCS#8 private key 和 X.509 public key；只复制 `encrypted_key` 而没有配对 private key 仍无法解包。

## 验证

```bash
mvn -f unidbg-adjust-runner/pom.xml clean test package
./test-run-all.sh
./test-external-structured-api.sh
./test-one-click-signer.sh
./test-device-reference.sh
./run-java.sh
```

Maven runtime classpath 不包含原 AAR 的 `classes.jar`。

测试和脚本默认增加 `-XX:TieredStopAtLevel=1`。这是为了避开旧 JDK 11 C2 与 Unidbg/Unicorn 在 macOS arm64 上已复现的退出阶段 `SIGBUS`；不改变签名算法或 API。
`generate-signer.sh` 在 macOS 已安装 JDK 17 时会优先用它执行 signer；否则回退到
`java`。可用 `SIGNER_JAVA_BIN=/absolute/path/to/java` 显式选择运行时，不会自动安装 JDK。

## 独立 C++ 逆向工作台

```bash
./native-reimplementation/build-and-test.sh
```

该命令只使用已有的 C++ 编译器，不加载 Java、Unidbg 或原 SO。当前已独立验证：

- signer 固定 AES-256 key schedule 和 Pixel 首个 body block；
- `libsigner.so+0x13531c` 的 codeword encoder 与 `0x13548c` correction helper；
- `0x2b -> 0xd49d`、`0x36 -> 0xb5d3`、`0x25 -> 0xcacc`、
  `0x05 -> 0x6ee6`。

该目录已经能根据 correction 数量动态构造 field 0、payload、PKCS#7 ciphertext 和最终
signature，不是硬编码最终结果。8 halfwords 对应 113-byte payload/176-byte result；
9 corrections 会扩为 16 halfwords，对应 129-byte payload/192-byte result；
17 corrections 会扩为 24 halfwords，对应 145-byte payload/208-byte result。它已通过
frozen Pixel、time+1、trampoline=false、correction05=false、
空 `/proc/self/maps`、缺失 `/proc/self/maps`、修改 plaintext、缺失 Java 字段、
APK/PackageManager 证书不一致、cmdline mismatch `0x09`、cmdline 缺失/空 `0x34`，以及
九/十七 correction 动态扩容共十三类完整原 SO oracle。
默认 signer 仍由 Unidbg 执行原 ARM64 `libsigner.so`；可选
`runtime.backend=recovered` 则完全走该 C++ 源码实现。
