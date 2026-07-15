# JNI caller-selected String-field reader `0xb2978..0xb3230`

## 1. 文件概况

```text
ARM64:
  adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so
  FDE 0xb2978..0xb3230
  sole caller 0x181c0 in 0x179f8..0x18540

x86_64:
  adjust-android-signature-3.67.0/jni/x86_64/libsigner.so
  FDE 0xaa8bb..0xaae64
  sole caller 0x19728 in 0x18fe3..0x19bdf
```

当前 C++：

```text
native-reimplementation/recovered_primitives.cpp
SHA-256 7a5e394cb21dae986b7c2157973f0a663f6f28f794945a9e5a8fa55a27a88bac
```

正式覆盖：

```text
all FDEs:      346 recovered / 0 partial / 42 unknown
JNI reachable: 297 recovered / 0 partial / 24 unknown
```

## 2. 程序模块和执行流程

函数 ABI：

```text
x0 = uint32_t* status
x1 = JNIEnv-like handle
x2 = caller-supplied Java object
x3 = caller-supplied field-name C string
x4 = uint64_t* output String local-reference slot
```

ARM64 和 x86_64 共同锁定以下 JNI 流程：

```text
if object == null or fieldName == null:
    status = 3
    output = null
else:
    objectClass = GetObjectClass(object)
    consumeException()

    fieldId = GetFieldID(
        objectClass,
        fieldName,
        "Ljava/lang/String;")
    consumeException()

    output = GetObjectField(object, fieldId)
    consumeException()

    DeleteLocalRef(objectClass)
    if status != 0:
        output = null
```

JNI vtable slots：

```text
+0x0f8  GetObjectClass
+0x2f0  GetFieldID
+0x2f8  GetObjectField
+0x0b8  DeleteLocalRef
```

固定 field signature 在两个 ABI 中分别由独立 once-XOR storage 解码：

```text
ARM64:
  VMA 0x145110
  file offset 0x13d110
  length 19
  XOR 0xaf

x86_64:
  VMA 0x13dbb0
  file offset 0x135bb0
  length 19
  XOR 0xea

decoded:
  Ljava/lang/String;\0
```

状态语义：

```text
object == null or fieldName == null:
  status = 3

GetObjectClass null/exception:
  status = 18

GetFieldID null/exception:
  status = 18

GetObjectField exception or null result:
  status = 28
```

原 SO 在 GetObjectField 后先把 jobject 写入 caller output，再消费 exception；若最终
status 非零再清 output。incoming status 非零不会阻止 JNI 执行，但即使取得有效 String，
最终也会清 output。

唯一 caller `0x179f8` 在调用前通过一次性 XOR decoder 获得
`publicSourceDir`，Java object 来自 PackageManager/ApplicationInfo 链。该 caller 只在
自身 status 为零时进入本 helper；成功返回的 String handle 随后原样传给
`0x92b24` GetStringUTFChars helper。

## 3. 关键函数及证据位置

```text
native-reimplementation/recovered_primitives.cpp:6124
  runRecoveredJniStringFieldReaderB2978

native-reimplementation/recovered_primitives.cpp:6256
  recoveredJniStringFieldReaderB2978Regression

native-reimplementation/recovered_primitives.cpp:29783
  executable regression guard
```

专用静态 verifier：

```text
.omx/static-audit-20260713/analyze_jni_string_field_reader_b2978.py
```

它检查：

- 双 ABI FDE 和唯一 caller；
- ARM64 `0x181c0` / x86_64 `0x19728` caller edge；
- `publicSourceDir` caller forwarding；
- 两个 ABI 的 `Ljava/lang/String;` 独立 XOR 解码；
- 四个 JNI vtable slot 和三次 exception consumer；
- status `3/18/28`；
- GetObjectField publication、null-result gate、class cleanup 和 final output clear；
- C++ implementation/regression/main guard；
- generator/inventory recovered 状态；
- 原 SO 自然 observation-only 动态 token。

当前门禁：

```text
dedicated analyzer: PASS
ANALYZER_SUMMARY total=153 pass=153 fail=0
clang++ -std=c++17 -Wall -Wextra -Werror -fsyntax-only: PASS
O2 executable regression, 125 main guards: PASS
unique bool *Regression definitions: 130
build-and-test / 15 original-SO oracle vectors: PASS
ASan+UBSan: PASS
LeakSanitizer: not run; macOS unsupported
frozen Pixel recovered backend exact match: PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
JniStringFieldReaderNativeIntegrationTest: 1/1 PASS
```

## 4. 输入、输出和数据结构

输入 object、field name、JNI environment 和 status/output storage 全部由 caller 提供。
恢复实现不构造 Android object、不伪造 `ApplicationInfo`、不注入默认 path。

成功输出是 Java String local reference 的 ownership transfer：

```text
temporary objectClass:
  helper DeleteLocalRef

returned String:
  helper does not delete
  transferred to caller
  known caller forwards it to GetStringUTFChars
```

原 SO 不检查 `status`、`outputString` 或 JNIEnv-like pointer 本身是否有效；这些是内部
ABI preconditions。C++ compatibility layer 保持该边界。

回归覆盖：

- null object；
- null field name；
- success 和精确 field/signature forwarding；
- incoming nonzero status 仍执行 JNI但清输出；
- class null；
- class exception；
- field-ID null；
- field exception；
- object-field null result；
- object-field exception；
- class cleanup 和每条 failure publication。

## 5. 安全发现及严重程度

1. **低/兼容性风险：`publicSourceDir` 缺失会使环境初始化失败。**
   字段缺失、JNI lookup 差异或 null value 最终产生 status 18/28；上层不会得到 path。
   不同 Android/兼容层若改变 `ApplicationInfo` 字段可见性，可能影响签名初始化。

2. **低/潜在 local-reference 压力：incoming status 非零成功取值后清 output。**
   helper 不删除刚取得的 returned String；若以非零 incoming status 调用且 JNI 成功，
   output 随后被清零，caller 无法再删除该 reference。当前唯一自然 caller 先检查
   status==0，因此该路径没有在已证明主链触发。

3. **低/内部健壮性风险：storage/JNIEnv pointer 无 null gate。**
   非法内部调用可导致解引用错误；当前没有证据表明这些 pointer 可由外部不可信输入直接
   控制。

未发现该 FDE 进行 native heap allocation、文件写入、网络通信、权限修改或越界 copy。

## 6. 修复建议

1. 产品重写应把 `ApplicationInfo.publicSourceDir` 缺失与权限/兼容性故障明确分类，
   不要把所有 lookup/null failure 合并为难以诊断的签名失败。
2. 若允许 incoming nonzero status 调用，应在丢弃成功 returned String 前
   `DeleteLocalRef`；兼容实现当前保持原 SO observable behavior。
3. 对公开封装增加 non-null status/output/JNIEnv preconditions，或改用 typed result
   返回 status 和 jobject。
4. 回归保留 Android API 18/27/28+/35、field missing/null、pending exception、
   incoming-status、local-ref cleanup 和 exact `publicSourceDir` forwarding。

## 7. 尚不能确认的事项

- observation-only 动态测试覆盖 API 35 的自然成功路径；failure statuses 由双 ABI 静态
  证据和 C++ fault-injection regression 确认，尚未逐项修改 JNI 环境动态触发。
- 尚未在真实设备 ART/CheckJNI 模式下量化 incoming-status 丢弃 returned String 的
  local-reference 压力。
- 唯一静态 caller 使用 `publicSourceDir`；没有发现其他 field name 的自然运行样本。
- 剩余 42 个全文件 unknown、其中 24 个 JNI-reachable unknown 仍需逐 FDE 恢复。

原 SO 动态证据：

```text
test:
  unidbg-adjust-runner/src/test/java/local/JniStringFieldReaderNativeIntegrationTest.java

log:
  .omx/static-audit-20260713/current-b2978-original-dynamic.log

observed:
  entries=1
  status=0->0
  field=publicSourceDir
  signature=Ljava/lang/String;
  output == forwardedString != 0
  exceptions=[0,0,0]
  cleanup=class
  configured path=/data/app/~~audit/com.adjust.test-audit/base-public.apk
```

hook 只读取入口、JNI call arguments/returns、exception return bits、cleanup argument 和
caller forwarding；没有修改寄存器、分支、返回值、JNI object、status、path 或目标代码。
