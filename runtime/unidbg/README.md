# `libsigner.so` 纯 PC 本地运行

该工程用 unidbg 在 PC 上加载并执行原始 ARM64 Android ELF：

```text
src/main/resources/arm64-v8a/libsigner.so
SHA-256 fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736
Adjust Signature 3.62.0
```

它不需要 Android 真机、模拟器 App、ADB、Android SDK/NDK、真机证书或真机 AndroidKeyStore。`Context`、package、certificate、SDK、`key2`、display、sensor、stack、`/proc`/fd 等边界都由本地 strict JNI/runtime bridge 提供，最终仍由原始 `libsigner.so` 执行受保护 VM 并返回 304 字节。

## 依赖

- JDK 11 或更高版本；当前验证使用 JDK 17。
- Maven 3.8 或更高版本；首次构建需要取得 Maven 依赖，依赖缓存后可离线构建。
- macOS 或 Linux shell。

不需要 Android Studio、Android SDK、NDK、QEMU、Frida 或连接手机。

## 一键运行

可在任意目录执行，不依赖当前 working directory：

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh
```

无请求参数时，`run.sh` 自动使用：

```text
/Users/sanbo/Desktop/p/runtime/unidbg/src/test/resources/request-sandbox.json
```

成功输出包含：

```text
signature_length=304
signature_hex=<608 个大写 HEX 字符>
signature_base64=<Base64>
native_headers_id=8
native_adj_signing_id=1300000
native_native_version=3.62.0
native_algorithm=adj7
```

## 自定义请求

请求参数保持插入顺序；这很重要，因为 Java wrapper 使用 `LinkedHashMap.toString()` 生成 HMAC 输入，没有排序/canonicalization。

直接传有序参数：

```bash
./run.sh \
  --param environment=sandbox \
  --param app_token=test_token \
  --param event_token=event_123 \
  --activity-kind event \
  --client-sdk android5.4.1
```

或者使用只含字符串值的平面 JSON object：

```bash
./run.sh --request-json /absolute/path/request.json
```

`activity_kind` 和 `client_sdk` 如果出现在 JSON 中，会进入 wrapper 配置；其余键按文件顺序进入参数 Map。

## 完整 CLI

```text
--param key=value              追加一个有序请求参数，可重复
--request-json PATH            合并平面 JSON string-to-string object
--activity-kind VALUE          wrapper 注入字段，默认 event
--client-sdk VALUE             wrapper 注入字段，默认 android5.4.1
--hmac-key-hex HEX             本地 key2 fixture，并按 Java Map.toString 规则计算 HMAC
--hmac-hex HEX                 覆盖 nSign 的第三个 JNI byte[] 参数
--certificate-hex HEX          本地 Package Signature.toByteArray fixture
--sdk N                        传给 native 的 Android SDK level，当前 harness 接受 >= 23
--package NAME                 本地 package identity，默认 com.adjust.fixture
--output hex|base64|both       输出编码，默认 both
--trace-jsonl PATH             记录有上限的 module-relative JSONL 指令 trace
--max-trace-events N           trace 事件上限，默认 10000
--verbose                      打开 unidbg/JNI 诊断
--help                         显示帮助
```

查看运行时最新帮助：

```bash
./run.sh --help
```

SDK 23（legacy `PackageInfo.signatures`）和 SDK 30（`PackageInfo.signingInfo` / 单签名 `SigningInfo`）均已在纯 PC fixture 下跑通完整 304 字节路径：

```bash
./run.sh --sdk 30
```

## `key2`、HMAC 与本地模式

默认使用固定的纯本地 `key2`：

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

默认 certificate 是 ASCII：

```text
adjust-signature-fixture-certificate
```

所以开箱即用，不依赖设备 KeyStore。

`--hmac-key-hex` 同时定义 Java-side HMAC key 和 native 通过 `AndroidKeyStore/key2` 取得的本地 key。`--hmac-hex` 只覆盖 JNI 第三个参数；原始 `.so` 在后续路径仍会访问 `key2`，因此若不同时提供 `--hmac-key-hex`，native 会继续使用内置 fixture key。这仍是完整可运行的本地流程，只不是某台设备的 byte-for-byte 状态复刻。

## 输出为何可能每次不同

完整 JNI 路径会在进入受保护 VM 前构造变化的 Blob 1、4、5，而且 direct replay 证明 VM/context/global mutable state 也是输入的一部分。因此相同本地配置的两次 304 字节结果可能不同。这是原始 native 行为，不是 harness 返回随机占位数据。

fresh emulator 的首次直接 VM 调用回归为：

```text
recovered/vm-zero-vector.json
length=304
SHA-256=d43a36f81b41cebd016c03e7e7e075e4df5741f46efc33380eabc2182272f1e2
```

live 9-Blob 与隐式状态纠偏见 `recovered/vm-live-inputs.md`。完整 JNI 路径的稳定不变量是非空 `byte[]`、长度 304、metadata、严格无 unsupported JNI，而不是每次相同的签名字节。

## Trace

```bash
./run.sh \
  --trace-jsonl /tmp/libsigner-trace.jsonl \
  --max-trace-events 256
```

校验：

```bash
~/.codex/skills/android-so-reversing/scripts/validate_trace \
  /tmp/libsigner-trace.jsonl
```

trace schema 为 `libsigner.trace/v1`，地址同时记录绝对 PC 与 `libsigner.so` module-relative PC，且事件数受上限约束。

## 构建和测试

```bash
cd /Users/sanbo/Desktop/p/runtime/unidbg
mvn test
mvn package
```

依赖已经缓存时，可显式离线：

```bash
mvn -o test
mvn -o package
```

直接运行 fat jar：

```bash
java -jar target/libsigner-unidbg-1.0-SNAPSHOT.jar \
  --request-json src/test/resources/request-sandbox.json
```

## Java 代码中直接调用

```java
byte[] localKey2 = SignerCli.parseHex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "key2");
SignerConfig config = new SignerConfig(
        "com.adjust.fixture", 23, localKey2, null, false);

LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
parameters.put("environment", "sandbox");
parameters.put("app_token", "test_token");
parameters.put("event_token", "event_123");

try (LibSignerEmulator signer = new LibSignerEmulator(config)) {
    SignerResult result = signer.signDetailed(
            new SignerRequest(parameters, "event", "android5.4.1"));
    byte[] raw304Bytes = result.signature();
    Map<String, String> metadata = result.nativeMetadata();
}
```

`SignerCli.parseHex` 是 package-private；跨 package 集成时可自行解析 HEX，或直接传 `byte[]`。

## 边界

- 已验证的主路径是 **PC + unidbg + 原始 Android `.so`**；不需要安卓真机。
- 官方 Java wrapper 还支持 SDK 18-22，但该分支依赖 legacy `SharedPreferences("adjust_keys")`、RSA AndroidKeyStore `key2` 包装/解包。当前本地 harness 会明确拒绝 `<23`，而不是用 permissive 空 stub 伪造成功；这不影响默认 SDK 23/30 的纯 PC 主路径。
- `recovered/signer_pipeline.cpp` 是证据分级的源码级恢复模型；完整 protected VM program 仍由原始 `.so` 执行，未伪装成已经完全脱离二进制的独立算法实现。
- `runtime/qbdi` 是可选的 Android/Linux 进程内观测后端。当前 macOS 只验证 stub、trace schema 和 environment checker；它不是本地签名主路径，也不影响本工程开箱运行。
