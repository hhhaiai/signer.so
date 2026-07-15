# JNI `MessageDigest.getInstance(String)` helper `0xaf438..0xb081c`

## 1. 文件概况与范围

```text
ARM64:        0xaf438..0xb081c
x86_64:       0xa87cf..0xa91a3
caller ARM64: 0x1e578..0x1f058, call at 0x1ec14
caller x86:   0x2335e..0x23d51, call at 0x23859
```

当前 C++ 源码：

```text
native-reimplementation/recovered_primitives.cpp
SHA-256 7a5e394cb21dae986b7c2157973f0a663f6f28f794945a9e5a8fa55a27a88bac
```

## 2. 固定 Java contract

ARM64 与 x86_64 的一次性 XOR 常量均独立解码为：

```text
class:     java/security/MessageDigest
method:    getInstance
signature: (Ljava/lang/String;)Ljava/security/MessageDigest;
```

helper 接收 caller-supplied algorithm C string。父函数 `0x1e578` 在两个 ABI 中均解码并
传入：

```text
SHA1
```

调用顺序为：

```text
FindClass(java/security/MessageDigest)
GetStaticMethodID(getInstance, signature)
NewStringUTF(algorithm)
CallStaticObjectMethod(MessageDigest, getInstance, algorithmString)
```

四个 JNI 阶段后均调用 exception consumer。

## 3. 状态、输出与 ownership

```text
algorithm == null:
    status = 3

FindClass 或 GetStaticMethodID 失败/异常:
    status = 18

NewStringUTF 失败/异常:
    status = 27

CallStaticObjectMethod 异常或返回 null:
    status = 28
```

成功返回的 `MessageDigest` local reference 转交 caller，不在 helper 中删除。临时 local
reference 的原 SO 动态顺序为：

```text
DeleteLocalRef(MessageDigest class)
DeleteLocalRef(algorithm Java String)
```

即 `class -> string`。incoming status 非零仍执行 JNI 流程，但最终 status 非零时 output
slot 清零；新的 lookup/call failure 可以按原 SO 覆盖 status。

## 4. 关键函数与证据位置

```text
native-reimplementation/recovered_primitives.cpp:9846
  RecoveredJniMessageDigestGetInstanceOperationsAf438
native-reimplementation/recovered_primitives.cpp:9870
  runRecoveredJniMessageDigestGetInstanceAf438
native-reimplementation/recovered_primitives.cpp:10038
  recoveredJniMessageDigestGetInstanceAf438Regression
native-reimplementation/recovered_primitives.cpp:29833
  executable regression guard
```

专用跨 ABI verifier：

```text
.omx/static-audit-20260713/analyze_jni_message_digest_get_instance_af438.py
```

该 verifier 固定检查 FDE、四组明文常量、四个 JNI vtable 调用、四个 exception consume、
status `3/18/27/28`、两个 cleanup block、incoming-status output clear、父级 `SHA1`
转发、C++ regression guard 和 coverage 状态。

## 5. 原 SO observation-only 动态证据

专用测试：

```text
unidbg-adjust-runner/src/test/java/local/JniMessageDigestGetInstanceNativeIntegrationTest.java
```

本轮离线重跑日志：

```text
.omx/static-audit-20260713/revalidate-af438-original-dynamic-20260715.log
```

关键输出：

```text
af438 entries=1 status=0->0 algorithm=SHA1
class=java/security/MessageDigest
method=getInstance
signature=(Ljava/lang/String;)Ljava/security/MessageDigest;
exceptions=[0, 0, 0, 0]
cleanup=class,string
```

测试只观察原 SO 的入口、JNI 参数、exception 结果和 cleanup 事件；未修改寄存器、分支、
返回值、JNI object、status 或 digest 数据。

## 6. 验证结果

```text
cross-ABI constants/JNI/status/ownership analyzer: PASS
original-SO observation-only dynamic test: 1/1 PASS
clang++ -Wall -Wextra -Werror syntax-only: PASS
O2 executable regression: PASS
build-and-test / 15 oracle vectors: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen recovered backend exact match: PASS
all static analyzers: 153/153 PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
```

本函数计入后的最终本轮覆盖与父函数共同汇总为：

```text
all FDEs:      346 recovered / 0 partial / 42 unknown
JNI reachable: 297 recovered / 0 partial / 24 unknown
```

## 7. 尚不能确认的事项

- 动态测试仅覆盖父级真实 `SHA1` 成功路径；各 failure status 由双 ABI 静态证据和 C++
  故障注入回归确认。
- 本 helper 的恢复不代表剩余 24 个 JNI-reachable unknown 已闭合。
