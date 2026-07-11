# adjust signature 3.67.0 self-contained Java + Unidbg runner

本工程不在运行时加载 `adjust-android-signature-3.67.0/classes.jar`。AAR 中的 Java 逻辑已经在源码中重新实现，只有原生 `libsigner.so` 由 Unidbg 执行。

`SO_REVERSE_STATUS.md` 记录 native 已验证行为、已定位地址和仍未恢复的
环境密钥派生边界；它不会把未验证的伪代码表述成完整 SO 源码。

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
  -> AdjustSignatureRunner
  -> Unidbg 0.9.9
  -> arm64-v8a/libsigner.so
```

`SignerEngine` 的顺序固定为：构造时调用一次 `Signer.onResume()`，成功后才允许调用 `sign(...)`。不会出现跳过 `onResume` 直接签名的路径。

## 已实现的 Java 逻辑

- `Signer.getVersion()` 返回 `3.67.0`
- `Signer` 延迟初始化和全局错误锁定
- API 18-22 RSA 包装密钥逻辑
- API 23+ AndroidKeyStore `HmacSHA256` 逻辑
- `activity_kind` / `client_sdk` 临时参数写入和清理
- HMAC、重试、KeyStore 清理、native 调用、Base64 回写
- SDK v5 Map 筛选、`a=b` 分支和 `authorization` 拼装
- 私有 `NativeLibHelper.nOnResume()` 与 `nSign(Context,Object,byte[],int)` 到 Unidbg 的桥接

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

`run-python.py` is a legacy optional adapter only; the signer, reference
verification, and supported normal execution path are Java + Unidbg and do
not require Python, ADB, a device, or an Android emulator.

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
- native 网络：`runtime.network.connectRefusedEndpoints` 可将指定 IPv4 `host:port` 的 native `connect` syscall 固定为 `ECONNREFUSED`，无需让宿主机网络参与；Pixel 8 reference 的已观察值是 `127.0.0.1:27042`。
- native 文件系统：`filesystem.files` 可按 `file`、`text` 或 `hex` 提供文件内容；`filesystem.missing` 可固定 ENOENT 路径。
- `libsigner.so` 会读取 `/proc/self/maps`；需要复现实机环境时，应将对应 live maps 快照作为 `filesystem.files["/proc/self/maps"]` 传入，而不是让宿主机文件系统参与。该项会影响 native body，必须与目标参考环境一起校准。
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
./run-java.sh --mode=v4
```

还支持 `ADJUST_KEY_HEX`、传感器、DisplayMetrics、UID 和 targetSdk 等环境参数；`DeviceProfile.fromEnvironment()` 会读取同一套变量。

这里模拟的是当前 `libsigner.so` 实际读取到的 Android/JNI 环境面，不是完整 Android Framework。已观察到的字符串、整数、长整数、浮点、布尔、`byte[]`、Build、Settings、system property、传感器、屏幕、service、PID 和时间入口都可传入；如果未来 `.so` 新增此前未访问过的复杂 Android 对象图，仍需增加对应对象适配，不能把通用标量 override 误称为完整 Android 系统。

要复现指定真机，需要保证 package、真实 APK、证书 DER、Android API、参数值及顺序、传感器、屏幕、UID、targetSdk、native runtime 和 API 23+ AndroidKeyStore HMAC key 一致。API 18-22 还依赖设备上的 RSA KeyStore 与 `SharedPreferences` 包装密钥状态，仅传一个 HMAC key 不能保证逐字节复现。

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
- `libsigner.so+0x13531c` 的完整 16-halfword codeword encoder；
- `0x2b -> 0xd49d`、`0x36 -> 0xb5d3`、`0x25 -> 0xcacc`、
  `0x05 -> 0x6ee6`。

这仍是可运行的恢复 primitive，不是完整 SO 替代；普通 signer 当前仍由 Unidbg 执行原
ARM64 `libsigner.so`。
