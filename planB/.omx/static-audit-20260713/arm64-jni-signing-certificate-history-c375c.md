# ARM64 JNI `SigningInfo.getSigningCertificateHistory()` reader (`0xc375c`)

## 1. 文件概况

- ARM64 目标：
  `adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so`
- ARM64 FDE：`0xc375c..0xc4064`，大小 `0x908`
- x86_64 对照 FDE：`0xb46d8..0xb4dad`，大小 `0x6d5`
- JNI reachable：`yes`
- inventory 状态：`recovered`
- 唯一直接 parent：
  - ARM64 `0x1dde0..0x1e578`，call site `0x1e220`
  - x86_64 `0x22cf9..0x2335e`，call site `0x23050`

该 helper 只负责在 caller 提供的 `SigningInfo` 对象上调用
`getSigningCertificateHistory()`，并把 JNI 返回的整个
`Signature[]` local reference 发布到 caller 的输出槽。它不创建
`SigningInfo`，不生成证书，不内置证书字节，也不选择或复制数组元素。

## 2. 程序模块和执行流程

### 2.1 Caller-supplied ABI

ARM64：

```text
x0  uint32_t* status
x1  JNIEnv / JNI operation context
x2  caller-supplied SigningInfo jobject
x3  caller-owned jobjectArray output slot
```

x86_64：

```text
rdi uint32_t* status
rsi JNIEnv / JNI operation context
rdx caller-supplied SigningInfo jobject
rcx caller-owned jobjectArray output slot
```

跨 ABI caller forwarding 证据：

```text
ARM64  0x1e210..0x1e220:
       x0=status, x1=JNIEnv, x2=SigningInfo, x3=output

x86_64 0x2303f..0x23050:
       rdi=status, rsi=JNIEnv, rdx=SigningInfo, rcx=output
```

恢复后的等价状态机：

```text
if SigningInfo == null:
    status = 3
    output = null
    return

class = GetObjectClass(JNIEnv, SigningInfo)
classException = consumeException(JNIEnv)
if class == null or classException:
    status = 18
    if class != null:
        DeleteLocalRef(JNIEnv, class)
    output = null
    return

method = GetMethodID(
    JNIEnv,
    class,
    "getSigningCertificateHistory",
    "()[Landroid/content/pm/Signature;"
)
methodException = consumeException(JNIEnv)
if method == null or methodException:
    status = 18
    DeleteLocalRef(JNIEnv, class)
    output = null
    return

output = CallObjectMethod(JNIEnv, SigningInfo, method)
callException = consumeException(JNIEnv)
if callException or output == null:
    status = 28

DeleteLocalRef(JNIEnv, class)
if status != 0:
    output = null
```

Incoming status 非零不会跳过 JNI 调用。若本次 JNI 序列没有产生新的错误，原有 status
保持不变，但成功返回的数组仍会在 class cleanup 后从输出槽清零。

## 3. 关键函数及证据位置

### 3.1 ARM64 指令证据

| 地址 | 证据 |
|---:|---|
| `0xc37f8` | `SigningInfo` null gate |
| `0xc3cec..0xc3cf0` | JNI vtable `+0xf8`：`GetObjectClass` |
| `0xc3d0c` | class lookup 后 exception consumer `0x92a20` |
| `0xc3d7c` / `0xc3d84` | method name / descriptor 指针 |
| `0xc3d9c..0xc3da0` | JNI vtable `+0x108`：`GetMethodID` |
| `0xc3dbc` | method lookup 后 exception consumer |
| `0xc3c78..0xc3c7c` | JNI vtable `+0x110`：`CallObjectMethod` |
| `0xc3c84` | 先把返回的 `Signature[]` 写入 caller output |
| `0xc3c9c` | object call 后 exception consumer |
| `0xc3e20..0xc3e24` | 返回数组 null 检查 |
| `0xc3bb8..0xc3bbc` | JNI vtable `+0xb8`：`DeleteLocalRef` |
| `0xc3bd8..0xc3bf0` | cleanup 后读取并检查最终/incoming status |
| `0xc3e54` | 非零 status 清空 caller output |
| `0xc3e64` | null input status `3` |
| `0xc3f04` / `0xc3fb0` | class/method failure status `18` |
| `0xc3b54` | call exception/null result status `28` |

### 3.2 x86_64 独立对照

| 地址 | 证据 |
|---:|---|
| `0xb472c` | `SigningInfo` null gate |
| `0xb4b19` | `GetObjectClass`，vtable `+0xf8` |
| `0xb4b38` | class exception consumer `0x96a44` |
| `0xb4bb9` / `0xb4bc0` | method name / descriptor 指针 |
| `0xb4bc7` | `GetMethodID`，vtable `+0x108` |
| `0xb4bdd` | method exception consumer |
| `0xb4a98` | `CallObjectMethod`，vtable `+0x110` |
| `0xb4aa3` | 返回数组写入 caller output |
| `0xb4ab3` | call exception consumer |
| `0xb4c3d` | 返回数组 null 检查 |
| `0xb49de` | `DeleteLocalRef`，vtable `+0xb8` |
| `0xb4a1b` | cleanup 后最终/incoming status 检查 |
| `0xb4c59` | 非零 status 清空 caller output |
| `0xb4c71` | status `3` |
| `0xb4cdf` / `0xb4d4d` | status `18` |
| `0xb49a1` | status `28` |

### 3.3 C++ 与 verifier

文件：
`native-reimplementation/recovered_primitives.cpp`

```text
RecoveredJniSigningCertificateHistoryOperationsC375c
runRecoveredJniSigningCertificateHistoryC375c
recoveredJniSigningCertificateHistoryC375cRegression
```

专用 verifier：

```text
.omx/static-audit-20260713/analyze_jni_signing_certificate_history_c375c.py
```

当前直接执行结果：

```text
cross-ABI SigningInfo certificate-history constants: PASS
cross-ABI certificate-history JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
```

### 3.4 原 SO 自然观察

日志：

```text
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

该离线原 SO 日志三次记录同一自然顺序：

```text
lines 40..45
lines 1347..1352
lines 2655..2660

SigningInfo.hasMultipleSigners() -> false
GetMethodID(
    SigningInfo.getSigningCertificateHistory()
    [Landroid/content/pm/Signature;
) return PC = libsigner.so+0xc3da4
CallObjectMethod(...) -> non-null one-element Signature[]
return PC = libsigner.so+0xc3c80
GetObjectArrayElement(Signature[], 0)
return PC = libsigner.so+0x1ef20
```

`0xc3da4` 和 `0xc3c80` 分别是本 FDE 的
`GetMethodID` / `CallObjectMethod` 返回点；后续
`0x1ef20` 位于下一 FDE `0x1e578..0x1f058`。这证明原 SO
把本 helper 返回的整个数组继续交给 parent/next stage，而不是在
`0xc375c` 内部提取或制造证书元素。

该日志只证明自然成功路径的 method resolution、非 null 数组返回和后续使用；它没有
逐条记录 status output slot 或 `DeleteLocalRef`，因此 failure/status/
cleanup 的精确结论仍以双 ABI 静态控制流和 C++ regression 为主。

## 4. 输入、输出和数据结构

### 4.1 Caller 提供的运行时数据

- `JNIEnv` / JNI operation context；
- `SigningInfo` object handle；
- caller-owned `uint32_t status` storage；
- caller-owned `jobjectArray` output storage；
- JNI callbacks 最终返回的真实 `Signature[]`。

恢复实现通过 caller-supplied operations 调用 JNI；它不应内置
`SigningInfo`、certificate bytes、`Signature[]` 或设备身份数据。

### 4.2 原 SO 固定的 Java 方法协议

| ABI | VMA | ELF file offset | 长度 | XOR key | 解码值 |
|---|---:|---:|---:|---:|---|
| ARM64 | `0x1455f0` | `0x13d5f0` | 29 | `0x34` | `getSigningCertificateHistory\0` |
| ARM64 | `0x1455c0` | `0x13d5c0` | 34 | `0x0c` | `()[Landroid/content/pm/Signature;\0` |
| x86_64 | `0x13e090` | `0x136090` | 29 | `0x3a` | `getSigningCertificateHistory\0` |
| x86_64 | `0x13e060` | `0x136060` | 34 | `0x49` | `()[Landroid/content/pm/Signature;\0` |

ARM64 的两个 XOR-once lock bytes 位于 `0x146a08` 和
`0x146a0c`；x86_64 对照位于 `0x13f06c` 和
`0x13f06e`。

这些 method name/descriptor 是原二进制固定的 Java ABI contract，不是设备、证书或
用户身份字段。若产品需要让用户传任意 method name/descriptor，应另建明确命名的
generic JNI adapter；不要把 generic 行为误标成 `0xc375c` 的精确恢复。

### 4.3 Ownership

- temporary `SigningInfo class` local ref 由本 helper 管理并删除；
- 成功返回的 `Signature[]` local ref 转交 caller，本 helper 不删除；
- output slot 本身由 caller 所有；
- null class 不执行 `DeleteLocalRef`；
- class 非 null 但 exception、method failure、call completion 均清理 class ref。

## 5. 安全发现及严重程度

1. **低：native ABI 指针前置条件。** 原 helper 假定 `status`、output、
   `JNIEnv` 和 operation table 可用；直接把无效地址传入会导致 native
   crash。当前恢复保持原 ABI，而不是伪造缺失对象。
2. **低：incoming nonzero status 仍产生 JNI side effects。** 该行为是双 ABI
   一致语义。自然 parent 在调用前检查 status，但独立调用者应保证初始 status 为零。
3. **低、条件性 local-ref 丢失风险。** 若独立调用时 incoming status 已非零，或 JNI
   异常模型同时返回非 null object，helper 最终清空 output，却只删除 class ref；
   非 null 返回数组不会在本 helper 内删除。正常 JNI/parent 路径通常不会组合出该状态，
   但 hardened wrapper 应显式管理。
4. **未发现 helper 内构造证书或伪造 signer state。** 证书数组来自 caller 提供的
   JNI environment/object graph。

## 6. 修复建议

1. 对外产品 API 在进入 faithful primitive 前验证 `status`、output、
   `JNIEnv` 和 operation callbacks，并把 status 初始化为零。
2. `SigningInfo`、certificate bytes 和 signer history 必须由用户配置、
   真机 Android 对象或调用方 JNI adapter 提供，不能在精确恢复函数里写死。
3. 保留固定 method name/descriptor 作为 `0xc375c` 的兼容实现；需要自定义
   Java contract 时使用单独 generic adapter，并分别测试。
4. 回归至少覆盖：null input、class null/exception、method null/exception、
   call null/exception、incoming nonzero status、success transfer、事件顺序和 class
   local-ref cleanup。
5. 若增加 hardened cleanup，在 output 被错误状态清空前保存并删除异常的非 null
   returned local ref；该模式应与 bit-exact compatibility 模式分开，避免静默改变
   原 SO lifetime。

## 7. 尚不能确认的事项

- 尚未在原 SO/真机上逐分支 fault-inject class、method 和 call exception/null；
  这些分支目前由 ARM64/x86_64 静态一致性和 C++ failure regression 确认。
- 现有 Unidbg 日志没有直接记录本 helper 的 status pointer 值和 class-ref deletion。
- 现有自然样本是 `hasMultipleSigners()==false` 的 history 分支；真实
  multi-signer profile 会选择 `getApkContentsSigners()`，不自然进入本
  helper。
