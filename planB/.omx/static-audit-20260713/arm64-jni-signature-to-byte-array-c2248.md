# JNI `Signature.toByteArray()` helper `0xc2248..0xc2b78`

## 1. 范围

```text
ARM64:  0xc2248..0xc2b78
x86_64: 0xb392f..0xb3ff9
caller ARM64:  0x1e578..0x1f058, call at 0x1eec4
caller x86_64: 0x2335e..0x23d51, call at 0x23c0b
```

当前 C++ SHA-256：

```text
f9bb23156bd6eb6cb1f0584361b02695132bb139503d71e4c8fd22ba5accb707
```

## 2. 固定 Java contract

两个 ABI 的 XOR-once 常量均解码为：

```text
method:    toByteArray
signature: ()[B
```

caller 传入 status、JNIEnv、`android.content.pm.Signature` object 和 caller-owned
byte-array output slot。该 FDE 与独立的 BigInteger helper `0x93fd0..0x94bc0` 具有相同
observable JNI/status/ownership contract，因此 C++ 复用同一已验证 core，而保留独立
FDE wrapper、回归 guard 和 coverage entry。

## 3. 状态与 ownership

```text
Signature == null:
    status = 3
    output = null

GetObjectClass(Signature)
consume exception
class null or exception:
    status = 18

GetMethodID(class, "toByteArray", "()[B")
consume exception
method null or exception:
    status = 18

CallObjectMethod(Signature, method)
publish returned byte[]
consume exception
exception or null result:
    status = 28

DeleteLocalRef(Signature class)
final status != 0:
    output = null
```

成功的 byte-array local reference 转交 caller，不在 helper 内删除。临时 object class 由
helper 删除。incoming status 非零不会跳过 JNI 流程，但最终会清空 output。

## 4. 证据位置

```text
native-reimplementation/recovered_primitives.cpp:8527
  RecoveredJniSignatureToByteArrayOperationsC2248
native-reimplementation/recovered_primitives.cpp:8535
  runRecoveredJniSignatureToByteArrayC2248
native-reimplementation/recovered_primitives.cpp:8545
  recoveredJniSignatureToByteArrayC2248Regression
native-reimplementation/recovered_primitives.cpp:28144
  executable regression guard
```

专用 verifier：

```text
.omx/static-audit-20260713/analyze_jni_signature_to_byte_array_c2248.py
```

## 5. 原 SO 本地动态观察

API 18 observation-only 日志：

```text
.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log
```

自然顺序：

```text
GetObjectArrayElement(Signature[], 0)  return PC 0x1ef20
GetMethodID(Signature.toByteArray()[B) return PC 0xc2984
CallObjectMethod(Signature.toByteArray) return PC 0xc28d4
```

该日志证明 `0xc2248` 的对象与方法角色，也证明数组元素选择属于 caller `0x1e578`。

## 6. 验证

```text
cross-ABI constants and FDEs: PASS
cross-ABI JNI/status/ownership flow: PASS
original-SO natural JNI path: PASS
C++ syntax -Wall -Wextra -Werror: PASS
O2 executable regression smoke: PASS
15 original-SO oracle vectors: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen recovered backend exact match: PASS
all static analyzers: 147/147 PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
```
