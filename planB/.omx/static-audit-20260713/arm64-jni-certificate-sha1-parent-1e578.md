# JNI certificate `Signature[0]` SHA1 parent `0x1e578..0x1f058`

## 1. 文件概况与范围

```text
ARM64:        0x1e578..0x1f058
x86_64:       0x2335e..0x23d51
caller ARM64: 0xcc398
caller x86:   0xbb487
```

当前 C++ 源码：

```text
native-reimplementation/recovered_primitives.cpp
SHA-256 7a5e394cb21dae986b7c2157973f0a663f6f28f794945a9e5a8fa55a27a88bac
```

该 FDE 是 API-dependent `Signature[]` selector `0x1dde0` 的直接父级消费者，输出为
caller-provided 20-byte certificate SHA1 buffer。

## 2. 程序模块和执行流程

两个 ABI 均锁定以下顺序：

```text
0x1dde0 选择 Signature[]
    -> GetObjectArrayElement(Signature[], 0)
    -> 0xc2248 Signature.toByteArray()[B
    -> 0xaf438 MessageDigest.getInstance("SHA1")
    -> 0xb081c MessageDigest.update(certificateBytes)
    -> 0xb0f38 MessageDigest.digest(), optional input = null
    -> 0x95110 GetArrayLength + GetByteArrayElements
    -> digestLength == 20 ? publish : status 20
    -> 0x95834 ReleaseByteArrayElements(mode=0)
    -> local-reference cleanup
```

父级调用 `digest` 时固定传 null，因此真实 signer 路径选择 no-argument `digest()` overload。

## 3. 关键函数及证据位置

```text
native-reimplementation/recovered_primitives.cpp:12012
  RecoveredJniCertificateSha1Operations1e578
native-reimplementation/recovered_primitives.cpp:12057
  runRecoveredJniCertificateSha11e578
native-reimplementation/recovered_primitives.cpp:12361
  recoveredJniCertificateSha11e578Regression
native-reimplementation/recovered_primitives.cpp:29893
  executable regression guard
```

专用跨 ABI verifier：

```text
.omx/static-audit-20260713/analyze_jni_certificate_sha1_parent_1e578.py
```

关键 ARM64 静态证据：

```text
0x1e5ec  call 0x1dde0 selector
0x1ef1c  GetObjectArrayElement(Signature[], 0)
0x1eec4  call 0xc2248 Signature.toByteArray
0x1ec14  call 0xaf438 MessageDigest.getInstance
0x1ee24  call 0xb081c MessageDigest.update
0x1ede0  call 0xb0f38 no-arg digest
0x1efc4  call 0x95110 byte-array elements helper
0x1ead4  compare digest length with 0x14
0x1ee6c..0x1ee80  16-byte vector plus 4-byte publication
0x1ec8c  call 0x95834 release helper
```

x86_64 `0x2335e..0x23d51` 独立验证同一 call、status、20-byte gate、16+4 publication 和
release 流程。

## 4. 输入、输出和数据结构

输入：

```text
status pointer
JNIEnv handle
Android Context object
signed Android API level
caller-owned 20-byte output address
```

中间 JNI object：

```text
Signature[]
Signature element index 0
certificate byte[]
MessageDigest
digest byte[]
digest elements pointer + uint32 length
```

输出规则：

```text
GetObjectArrayElement 返回 null 或 exception:
    status = 28
    caller output 不修改

digestLength != 20:
    status = 20
    caller output 不修改

digestLength == 20:
    精确发布 20 bytes
    ARM64/x86_64 原生布局均表现为 16 + 4 bytes
```

incoming status 非零时仍先调用 selector；随后阶段跳过，caller output 保持不变。

## 5. ownership 与 cleanup

成功路径的原 SO 顺序为：

```text
ReleaseByteArrayElements(digestBytes, elements, mode=0)
DeleteLocalRef(MessageDigest)
DeleteLocalRef(certificate byte[])
DeleteLocalRef(digest byte[])
DeleteLocalRef(Signature[])
```

`GetObjectArrayElement` 返回的单个 `Signature` 没有显式 `DeleteLocalRef`。恢复实现故意保持
这一原 SO 行为，不增加“优化式”删除。只有已取得的非空父级 local references 才参与
cleanup；取得 digest elements 后，即使 20-byte length gate 失败，也先 release elements。

## 6. 原 SO observation-only 动态证据

专用测试：

```text
unidbg-adjust-runner/src/test/java/local/JniCertificateSha1ParentNativeIntegrationTest.java
```

本轮离线重跑日志：

```text
.omx/static-audit-20260713/revalidate-1e578-original-dynamic-20260715.log
```

关键输出：

```text
status=0->0 api=35
length=20
sha1=c0cfa6f8ecb636b7d03915227b2ce6517c514ef6
events=[copy20, release-elements, delete-1eb04, delete-1ee98,
        delete-1ecd0, delete-1f008]
```

四个 delete PC 分别对应 MessageDigest、certificate byte[]、digest byte[]、Signature[]。
测试没有修改原 SO 的寄存器、控制流、返回值、JNI object、status 或 digest bytes。

## 7. 安全发现及严重程度

- **低/兼容性风险：** 原 SO 未显式删除 `Signature` element local reference。单次调用通常
  不构成可利用问题，但高频或嵌套 JNI 调用可能增加 local-reference 压力。恢复实现为了
  行为一致没有擅自修复；产品源码可在独立兼容性测试后补充删除。
- **低/调用方初始化风险：** 失败路径不清零 20-byte output。调用方若忽略 status 并复用
  未初始化/旧 buffer，可能消费陈旧证书摘要。修复应在更上层先初始化输出并强制检查
  status，而不是改变本兼容实现的原 SO contract。

## 8. 验证结果

```text
cross-ABI call/status/publication flow: PASS
original-SO 20-byte publication and ownership order: PASS
C++ implementation/regression/coverage analyzer: PASS
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

正式覆盖：

```text
all FDEs:      346 recovered / 0 partial / 42 unknown
JNI reachable: 297 recovered / 0 partial / 24 unknown
```

## 9. 修复与回归建议

1. 产品级重写应让 caller 初始化 20-byte output，并在使用前强制验证 status 为零。
2. 若修复单个 Signature local-ref 泄漏，必须增加 API 18/27/28+/35 与
   `hasMultipleSigners` 两分支差分测试，确认不会改变 local-ref lifetime 假设。
3. 保留 digest length `19/20/21`、element null/exception、各 child helper failure、
   release-before-cleanup 和 incoming-status 回归。

## 10. 尚不能确认的事项

- observation-only 动态测试覆盖 API 35 成功路径；failure branches 和其他 API 由双 ABI
  静态证据及 C++ 故障注入回归确认，尚未逐分支动态触发。
- `hasMultipleSigners()==true` 的真实原 SO 动态路径仍缺独立自然样本。
- 剩余 42 个全文件 unknown、其中 24 个 JNI-reachable unknown 仍需逐 FDE 恢复。
