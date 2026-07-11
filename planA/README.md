# `libsigner.so` 逆向与纯 PC 运行交付

## 最短运行命令

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh
```

该命令在 PC 上通过 unidbg 执行原始 ARM64 Android `libsigner.so`，不需要 Android 真机、ADB、Android Studio、SDK/NDK 或设备 KeyStore。默认本地 fixture 会返回真实非空 304 字节及 native metadata。

完整使用说明：[`runtime/unidbg/README.md`](runtime/unidbg/README.md)

面向部署和业务接入的独立手册：[`RUNBOOK.md`](RUNBOOK.md)

## 交付 1：逆向代码与分析

| 文件 | 内容 |
|---|---|
| [`recovered/native-analysis.md`](recovered/native-analysis.md) | 样本、Java/JNI、`nSign`/`nOnResume`、97 参数、VM、LLVM/反分析、证据边界 |
| [`recovered/address-map.md`](recovered/address-map.md) | ARM64/x86_64 关键 relative PC、跨 ABI 角色映射和置信度 |
| [`recovered/jni_contract.h`](recovered/jni_contract.h) | 精确 JNI C header |
| [`recovered/signer_pipeline.cpp`](recovered/signer_pipeline.cpp) | 证据分级的源码级恢复模型、32 位 VM stack/frame 语义与 outer pipeline |
| [`recovered/strings.json`](recovered/strings.json) | 四 ABI 实样本校验的 XOR 字符串、偏移、key、guard 元数据 |
| [`recovered/signature-vm-calls-arm64.tsv`](recovered/signature-vm-calls-arm64.tsv) | ARM64 VM call/handler 证据 |
| [`recovered/signature-vm-calls-x86_64.tsv`](recovered/signature-vm-calls-x86_64.tsv) | x86_64 VM call/handler 交叉验证 |
| [`recovered/vm-zero-vector.json`](recovered/vm-zero-vector.json) | fresh emulator 首次 VM 调用向量及完整 304-byte 输出 |
| [`recovered/vm-live-inputs.md`](recovered/vm-live-inputs.md) | live 9-Blob、隐式 mutable state 与非确定性纠偏 |

关键结论：

- 样本精确对应 `com.adjust.signature:adjust-android-signature:3.62.0`。
- JNI：`nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B`、`nOnResume()V`。
- Java 边界：有序 Map → 注入 `activity_kind/client_sdk` → `Map.toString()` UTF-8 → `key2` HmacSHA256 → native → 大写 HEX。
- ARM64 `0x8b510` 是 `Map.get("environment")` 路径，不是 hash core。
- protected signature program：ARM64 `0xb6c50` / x86_64 `0x9dcf0`，是 32 位栈式 VM program/orchestrator；固定输出边界 304 字节。
- native 写回：`headers_id=8`、`adj_signing_id=1300000`、`native_version=3.62.0`、`algorithm=adj7`。

`signer_pipeline.cpp` 不冒充供应商原始源码：outer flow、JNI、副作用、VM 数据结构/handler 语义按证据恢复；尚未完整独立重写的 protected VM program 继续由精确哈希的原始 `.so` 执行。这使本地结果是真实 native 结果，而不是猜测算法或占位实现。

## 交付 2：纯 PC 可运行工程

```text
runtime/unidbg/
```

主要入口：

- `run.sh`：一键构建并运行。
- `SignerCli.java`：请求、key/HMAC、证书、SDK、package、输出和 trace CLI。
- `LibSignerEmulator.java`：原始 ELF 加载、JNI 调用、strict result gate、`/proc/fd` 修复。
- `AndroidRuntimeJni.java`：本地 Context/package/certificate/SigningInfo/KeyStore/Mac/display/sensor/stack/Map bridge。
- `TraceRecorder.java`：有上限的 `libsigner.trace/v1` module-relative trace。
- `src/test/`：JNI、SDK 23/30、CLI、VM 零向量、trace 和样本身份回归。

自定义运行示例：

```bash
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh \
  --param environment=sandbox \
  --param app_token=test_token \
  --param event_token=event_123 \
  --sdk 30 \
  --package com.example.local \
  --output both \
  --trace-jsonl /tmp/libsigner.jsonl \
  --max-trace-events 256
```

## QBDI / 指令观测

```text
runtime/qbdi/
```

当前 macOS 已验证：CMake stub、公共 trace schema、CTest 和环境检查。真实 QBDI callback/`vm.run()` 需要 Android/Linux 兼容 loader 或进程；它是可选观测后端，不是纯 PC 签名运行的依赖。PC 主路径使用已真实工作的 unidbg/Unicorn trace。



## 重要边界

- 默认 key、certificate、package、display/sensor 等均为本地 fixture；无需手机。
- 若只要求 PC 获得同一原始 `.so` 的签名效果，当前工程已经满足。
- 若将来要求和某一指定手机的某一次结果逐字节相同，才需要提供该设备对应的有序参数、certificate、持久化 `key2`/HMAC 和状态 oracle。
- 当前严格支持 SDK >=23；SDK 18-22 需要 legacy `SharedPreferences` + RSA AndroidKeyStore 完整桥接，工程会明确拒绝而非返回伪造结果。
