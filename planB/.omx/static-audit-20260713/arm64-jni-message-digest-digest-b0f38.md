# JNI `MessageDigest.digest` overload helper `0xb0f38..0xb1e40`

## 1. 范围

```text
ARM64:  0xb0f38..0xb1e40
x86_64: 0xa9783..0xaa064
caller ARM64:  0x1e578..0x1f058, call at 0x1ede0
caller x86_64: 0x2335e..0x23d51, call at 0x23a6d
```

当前 C++ SHA-256：

```text
fb0ba6c27b136bfdfad96c39cf6f164514d6d88941faebe33aa4a2fab6aa720e
```

## 2. 固定 Java contract

两个 ABI 的 XOR-once 常量均解码为：

```text
method:               digest
no-argument signature: ()[B
byte-array signature:   ([B)[B
```

接口为 caller-supplied status、JNIEnv、`java.security.MessageDigest` object、optional
input byte array 和 output byte-array slot。optional input 为 null 时调用 no-arg
`digest()`；非 null 时调用 `digest(byte[])` 并原样转发该引用。

父函数 `0x1e578` 的自然签名流程传入 null，因此真实 signer 路径选择 no-arg overload。

## 3. 状态与 ownership

```text
MessageDigest == null:
    status = 3
    output = null

GetObjectClass(MessageDigest)
consume exception
class null or exception:
    status = 18

GetMethodID(class, "digest", selected signature)
consume exception
method null or exception:
    status = 18

input == null:
    CallObjectMethod(MessageDigest, method)
else:
    CallObjectMethod(MessageDigest, method, input)
publish returned byte[]
consume exception
exception or null result:
    status = 28

DeleteLocalRef(MessageDigest class)
final status != 0:
    output = null
```

成功的 digest byte-array local reference 转交 caller，不在 helper 内删除。临时
MessageDigest class 由 helper 删除。incoming status 非零不会跳过 JNI 流程，但在 cleanup
后清空 output；新的 class/method/call failure 会按原 SO 覆盖为 `18` 或 `28`。

## 4. 证据位置

```text
native-reimplementation/recovered_primitives.cpp:9665
  RecoveredJniMessageDigestOperationsB0f38
native-reimplementation/recovered_primitives.cpp:9689
  runRecoveredJniMessageDigestB0f38
native-reimplementation/recovered_primitives.cpp:9847
  recoveredJniMessageDigestB0f38Regression
native-reimplementation/recovered_primitives.cpp:28486
  executable regression guard
```

专用 verifier：

```text
.omx/static-audit-20260713/analyze_jni_message_digest_digest_b0f38.py
```

## 5. 原 SO 本地动态观察

API 18 observation-only 日志：

```text
.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log
```

自然顺序：

```text
GetMethodID(MessageDigest$Delegate.digest()[B)
    return PC libsigner.so+0xb1998
CallObjectMethod(MessageDigest.digest())
    return PC libsigner.so+0xb17f8
```

动态日志只自然覆盖 no-arg overload；byte-array overload 由两个 ABI 的独立 FDE 反汇编、
固定 method signature 和当前 C++ 转发回归共同覆盖。动态观察未修改目标 SO 的寄存器、
分支、返回值、JNI object、status 或 digest bytes。

## 6. 验证

```text
cross-ABI constants and FDEs: PASS
cross-ABI JNI/status/ownership and parent flow: PASS
original-SO natural no-arg JNI path: PASS
C++ syntax -Wall -Wextra -Werror: PASS
O2 executable regression smoke: PASS
15 original-SO oracle vectors including 176/192/208 bytes: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen recovered backend exact match: PASS
all static analyzers: 148/148 PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
```

当前正式覆盖：

```text
all FDEs:      341 recovered / 0 partial / 47 unknown
JNI reachable: 292 recovered / 0 partial / 29 unknown
```
