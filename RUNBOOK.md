# `libsigner.so` 工程运行手册

本文只说明如何部署、运行和接入本工程。逆向原理与证据请看 `recovered/native-analysis.md`。

## 1. 先理解运行模型

这不是“读取一个固定签名常量”的脚本，而是一个完整运行工程：

```text
请求参数
  -> Java Map/HMAC 前处理
  -> unidbg 创建本地 Android/JNI 环境
  -> 加载原始 ARM64 libsigner.so
  -> 执行原始 nSign
  -> 返回 304 字节结果和 native metadata
```

每次调用都真实执行原始 `.so`。native 内部存在 mutable VM/context/global state，因此相同业务参数的签名字节也可能不同。业务系统应在需要签名时调用本工程，**不要把某一次 `signature_hex` 当成永久常量保存后反复使用**。

本工程不需要：

- Android 真机或模拟器 App；
- ADB；
- Android Studio；
- Android SDK/NDK；
- 真机 AndroidKeyStore；
- 联网的移动设备。

## 2. 工程位置

```text
/Users/sanbo/Desktop/p
```

运行工程：

```text
/Users/sanbo/Desktop/p/runtime/unidbg
```

重要文件：

| 路径 | 用途 |
|---|---|
| `runtime/unidbg/run.sh` | 一键构建并执行 |
| `runtime/unidbg/pom.xml` | Maven 工程配置 |
| `runtime/unidbg/src/main/resources/arm64-v8a/libsigner.so` | 被执行的原始 SO |
| `runtime/unidbg/src/test/resources/request-sandbox.json` | 默认本地请求 |
| `runtime/unidbg/target/libsigner-unidbg-1.0-SNAPSHOT.jar` | 打包后的可执行 fat jar |
| `runtime/unidbg/vectors/` | 已验证的运行结果和 trace |
| `analysis/verification.md` | 完整验证记录 |

## 3. 环境要求

必须安装：

```text
JDK >= 11
Maven >= 3.8（只在源码构建时需要）
```

当前验证环境：

```text
JDK 17.0.5
Maven 3.8.6
macOS
```

检查：

```bash
java -version
mvn -version
```

第一次 Maven 构建若本机没有依赖缓存，需要联网下载依赖。fat jar 构建完成后，只用 `java -jar` 即可运行，不再要求 Maven。

## 4. 最快运行方式

### 4.1 使用默认本地 fixture

可从任意目录执行：

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh
```

`run.sh` 会：

1. 编译并打包 Maven 工程；
2. 自动读取默认 `request-sandbox.json`；
3. 使用 SDK 23、本地 package/certificate/`key2`；
4. 加载并执行原始 `libsigner.so`；
5. 输出 HEX、Base64 和 native metadata。

### 4.2 运行 SDK 30 分支

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh --sdk 30
```

SDK 23 和 SDK 30 都已验证。当前工程明确要求：

```text
SDK >= 23
```

SDK 18–22 需要额外实现 legacy SharedPreferences + RSA AndroidKeyStore 完整链，当前会明确报错，不会返回伪造结果。

## 5. 输入请求

### 5.1 使用 JSON 文件

创建 `/tmp/request.json`：

```json
{
  "environment": "sandbox",
  "app_token": "test_token",
  "event_token": "event_123",
  "activity_kind": "event",
  "client_sdk": "android5.4.1"
}
```

运行：

```bash
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh \
  --request-json /tmp/request.json
```

JSON 限制：

- 只能是单层 object；
- key 和 value 都必须是字符串；
- 不支持数组、数字、boolean、null 或嵌套 object；
- 文件中的字段顺序会被保留。

字段顺序非常重要。原 Java wrapper 使用：

```text
LinkedHashMap.toString().getBytes("UTF-8")
```

计算 HMAC，没有自动排序参数。

### 5.2 直接传有序参数

```bash
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh \
  --param environment=sandbox \
  --param app_token=test_token \
  --param event_token=event_123 \
  --activity-kind event \
  --client-sdk android5.4.1
```

`--param` 可以重复，顺序就是进入 Map 的顺序。

## 6. 本地身份和密钥参数

默认配置完全本地化：

```text
package=com.adjust.fixture
sdk=23
certificate=ASCII "adjust-signature-fixture-certificate"
key2=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

### 6.1 修改 package

```bash
./run.sh --package com.example.local
```

### 6.2 修改 certificate

传入 `Signature.toByteArray()` 对应字节的 HEX：

```bash
./run.sh --certificate-hex 30820122300d06092a...
```

### 6.3 修改本地 `key2`

```bash
./run.sh --hmac-key-hex 00112233445566778899aabbccddeeff
```

该参数同时用于：

- Java-side `Map.toString()` HmacSHA256；
- native 内部通过本地 `AndroidKeyStore/key2` 获取的 key。

### 6.4 直接覆盖 JNI HMAC 参数

```bash
./run.sh --hmac-hex <通常为32字节HMAC的HEX>
```

注意：`--hmac-hex` 只覆盖 `nSign` 的第三个 JNI 参数。原始 `.so` 后续仍会访问 `key2`；若未同时传 `--hmac-key-hex`，它会使用工程内置的本地 fixture key。

## 7. 输出说明

典型输出：

```text
signature_length=304
signature_hex=<608个大写HEX字符>
signature_base64=<Base64字符串>
native_headers_id=8
native_adj_signing_id=1300000
native_native_version=3.62.0
native_algorithm=adj7
```

字段含义：

| 字段 | 含义 |
|---|---|
| `signature_length` | 原始 native byte[] 长度，当前应为 304 |
| `signature_hex` | 304 字节的大写 HEX 表示 |
| `signature_base64` | 同一 304 字节的 Base64 表示 |
| `native_headers_id` | native 写回的协议字段 |
| `native_adj_signing_id` | native signing ID |
| `native_native_version` | 当前应为 `3.62.0` |
| `native_algorithm` | 当前应为 `adj7` |

只输出 HEX：

```bash
./run.sh --output hex
```

只输出 Base64：

```bash
./run.sh --output base64
```

### 为什么每次结果可能不同

原始 `.so` 在 VM 前构造变化输入，并维护 mutable native state。完整路径的正确验收条件是：

```text
exit code = 0
signature_length = 304
HEX 长度 = 608
四个 metadata 正确
没有 Unsupported JNI call
```

不能以“同一请求每次 HEX 必须完全相同”作为验收条件。

## 8. 构建一次，直接运行 fat jar

### 8.1 构建

```bash
cd /Users/sanbo/Desktop/p/runtime/unidbg
mvn test
mvn -DskipTests package
```

生成：

```text
target/libsigner-unidbg-1.0-SNAPSHOT.jar
```

该 fat jar 已包含：

- unidbg 运行依赖；
- Unicorn backend；
- 原始 ARM64 `libsigner.so`；
- CLI 和本地 Android/JNI bridge。

### 8.2 从任意目录直接运行

```bash
cd /tmp
java -jar /Users/sanbo/Desktop/p/runtime/unidbg/target/libsigner-unidbg-1.0-SNAPSHOT.jar \
  --request-json /tmp/request.json \
  --sdk 30 \
  --output hex
```

### 8.3 部署到其他目录

只部署 fat jar 和业务请求文件即可：

```bash
mkdir -p /opt/libsigner
cp /Users/sanbo/Desktop/p/runtime/unidbg/target/libsigner-unidbg-1.0-SNAPSHOT.jar \
  /opt/libsigner/libsigner-pc.jar

java -jar /opt/libsigner/libsigner-pc.jar \
  --request-json /opt/libsigner/request.json
```

新环境仍需要兼容的 JDK。建议部署前执行一次完整 smoke test。

## 9. 业务系统如何调用

### 推荐方式：子进程调用

由于原始库存在 mutable native/global state，默认推荐每个独立任务启动一次 CLI 进程：

```bash
java -jar /opt/libsigner/libsigner-pc.jar \
  --request-json /path/request.json \
  --output hex
```

业务程序读取 stdout 中的：

```text
signature_hex=
native_headers_id=
native_adj_signing_id=
native_native_version=
native_algorithm=
```

这种模式的优点：

- 每次有独立 emulator 生命周期；
- native 状态不会跨业务任务意外共享；
- 崩溃或超时容易隔离；
- Java、Python、Go、Node.js 等语言都能接入。

建议为子进程设置超时，并检查退出码。

### 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 成功 |
| `64` | CLI 参数或请求格式错误 |
| `70` | native/unidbg 执行失败 |

### Java 进程内调用

也可以直接使用：

```text
SignerConfig
SignerRequest
LibSignerEmulator
SignerResult
```

但不要无审计地把一个 `LibSignerEmulator` 永久复用给所有请求。建议：

```text
一个任务创建一个 LibSignerEmulator
-> signDetailed(...)
-> 读取结果
-> close()
```

若需要连接池或高并发，必须先验证 native mutable state、线程安全、超时和资源回收行为。

## 10. Trace 和故障分析

生成有上限的指令 trace：

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

开启 JNI 详细日志：

```bash
./run.sh --verbose
```

正常情况下 stderr 可能存在 unidbg syscall warning 和 signer begin/end 日志；只要没有以下内容且退出码为 0，就不应当直接判失败：

```text
Unsupported JNI call
native signing failed
Exception
```

## 11. 常见问题

### `java: command not found`

安装 JDK 11+，然后确认：

```bash
java -version
```

### `mvn: command not found`

只在源码构建时需要 Maven。也可以直接使用已经生成的 fat jar。

### Maven 首次构建下载失败

检查 Maven Central 网络和本机 Maven 配置。依赖缓存完成后可尝试：

```bash
mvn -o test
mvn -o package
```

### `provide at least one --param or --request-json entry`

直接运行 fat jar 时必须显式提供请求；只有 `run.sh` 会在没有请求参数时自动注入默认 JSON。

### JSON 解析失败

确保 JSON 是单层 string-to-string object，不要传数字、数组或嵌套结构。

### `sdkLevel must be at least 23`

当前本地工程只完整支持 SDK 23+。改用：

```bash
--sdk 23
```

或：

```bash
--sdk 30
```

### 相同参数输出不同

这是已确认的原始 native 状态行为，不是自动失败。检查长度、metadata、退出码和 unsupported JNI，而不是比较固定 HEX。

### `--hmac-hex` 出现 fixture key2 warning

表示只覆盖了 JNI HMAC 参数，但 native 内部仍使用默认本地 `key2`。如需同时统一二者，额外传：

```bash
--hmac-key-hex <你的本地key>
```

## 12. 修改或升级工程

当前嵌入样本固定为：

```text
Adjust Signature 3.62.0
ARM64 SHA-256:
fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736
```

不要直接用其他版本 `.so` 覆盖资源后假设 bridge 仍然兼容。升级时至少要重新验证：

```bash
cd /Users/sanbo/Desktop/p/runtime/unidbg
mvn test
mvn package
```

并检查：

- JNI descriptor；
- certificate/SigningInfo 路径；
- KeyStore/Mac 调用；
- Map 参数表；
- 返回长度和 metadata；
- trace schema；
- 原始样本 SHA-256。

## 13. 上线前检查清单

```text
[ ] java -version 正常
[ ] fat jar 存在
[ ] request JSON 为单层字符串 object
[ ] 参数顺序符合调用方要求
[ ] SDK 为 23 或更高
[ ] package/certificate/key2 使用预期 fixture
[ ] 退出码为 0
[ ] signature_length=304
[ ] signature_hex 长度=608（使用 HEX 时）
[ ] native_version=3.62.0
[ ] algorithm=adj7
[ ] stderr 无 Unsupported JNI call
[ ] 业务方没有把某一次签名当永久常量
```

## 14. 已验证证据

完整命令和结果见：

```text
analysis/verification.md
```

已保存的运行结果：

```text
runtime/unidbg/vectors/final-sdk23-run.txt
runtime/unidbg/vectors/final-sdk23-trace-64.jsonl
runtime/unidbg/vectors/final-sdk30-run.txt
```
