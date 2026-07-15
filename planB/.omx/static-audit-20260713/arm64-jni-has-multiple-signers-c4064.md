# ARM64 JNI `SigningInfo.hasMultipleSigners()` reader (`0xc4064`)

## 1. 文件概况

- ARM64 目标：
  `adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so`
- ARM64 FDE：`0xc4064..0xc4ae4`，大小 `0xa80`
- x86_64 对照 FDE：`0xb4dad..0xb5413`，大小 `0x666`
- JNI reachable：`yes`
- inventory 状态：`recovered`
- 唯一直接 parent：
  - ARM64 `0x1dde0..0x1e578`，call site `0x1e1ec`
  - x86_64 `0x22cf9..0x2335e`，call site `0x23015`

该 helper 在 caller 提供的 `SigningInfo` 对象上调用
`hasMultipleSigners()Z`，并把 JNI 返回的原始 `jboolean` byte 写入
caller-owned output。它不创建 `SigningInfo`，不统计证书，也不自行决定
single-signer/multi-signer 状态。

## 2. 程序模块和执行流程

### 2.1 Caller-supplied ABI

ARM64：

```text
x0  uint32_t* status
x1  JNIEnv / JNI operation context
x2  caller-supplied SigningInfo jobject
x3  caller-owned uint8/jboolean output slot
```

x86_64：

```text
rdi uint32_t* status
rsi JNIEnv / JNI operation context
rdx caller-supplied SigningInfo jobject
rcx caller-owned uint8/jboolean output slot
```

跨 ABI caller forwarding：

```text
ARM64  0x1e1dc..0x1e1ec:
       x0=status, x1=JNIEnv, x2=SigningInfo, x3=output

x86_64 0x23001..0x23015:
       rdi=status, rsi=JNIEnv, rdx=SigningInfo, rcx=output
```

恢复后的等价状态机：

```text
if SigningInfo == null:
    status = 3
    output = 0
    return

class = GetObjectClass(JNIEnv, SigningInfo)
classException = consumeException(JNIEnv)
if class == null or classException:
    status = 18
    if class != null:
        DeleteLocalRef(JNIEnv, class)
    output = 0
    return

method = GetMethodID(
    JNIEnv,
    class,
    "hasMultipleSigners",
    "()Z"
)
methodException = consumeException(JNIEnv)
if method == null or methodException:
    status = 18
    DeleteLocalRef(JNIEnv, class)
    output = 0
    return

output = CallBooleanMethod(JNIEnv, SigningInfo, method)
callException = consumeException(JNIEnv)
if callException:
    status = 28

DeleteLocalRef(JNIEnv, class)
if status != 0:
    output = 0
```

关键语义：`false`（byte `0`）是合法成功结果，不等同于 object-returning helper
中的 null result。只有第三次 exception consume 非零才把 call stage 标记为
status `28`。

Incoming status 非零不会抑制 JNI 调用；若没有新错误，原 status 保持，最终 byte
在 class cleanup 后清零。

## 3. 关键函数及证据位置

### 3.1 ARM64 指令证据

| 地址 | 证据 |
|---:|---|
| `0xc40a0` | `SigningInfo` null gate |
| `0xc4568..0xc456c` | JNI vtable `+0xf8`：`GetObjectClass` |
| `0xc4588` | class lookup 后 exception consumer `0x92a20` |
| `0xc4458` / `0xc4460` | method name / descriptor 指针 |
| `0xc4478..0xc447c` | JNI vtable `+0x108`：`GetMethodID` |
| `0xc4498` | method lookup 后 exception consumer |
| `0xc46d0..0xc46d4` | JNI vtable `+0x128`：`CallBooleanMethod` |
| `0xc46dc` | 把返回寄存器 `w0` 的低 byte 原样写入 caller output |
| `0xc46f4` | boolean call 后 exception consumer |
| `0xc48f0..0xc48f4` | JNI vtable `+0xb8`：`DeleteLocalRef` |
| `0xc4910..0xc4974` | cleanup 后读取并检查最终/incoming status |
| `0xc4668` | 非零 status/error path 清空 output byte |
| `0xc46b4` | null input status `3` |
| `0xc464c` / `0xc4674` | class/method failure status `18` |
| `0xc48c8` | call exception status `28` |

该 FDE 没有对 `CallBooleanMethod` 返回的零值执行 null/error 检查；零值直接发布，
随后仅检查 exception consumer。

### 3.2 x86_64 独立对照

| 地址 | 证据 |
|---:|---|
| `0xb4df7` | `SigningInfo` null gate |
| `0xb5114` | `GetObjectClass`，vtable `+0xf8` |
| `0xb5120` | class exception consumer `0x96a44` |
| `0xb5074` / `0xb507b` | method name / descriptor 指针 |
| `0xb5082` | `GetMethodID`，vtable `+0x108` |
| `0xb508e` | method exception consumer |
| `0xb5245` | `CallBooleanMethod`，vtable `+0x128` |
| `0xb5250` | `al` 原始 byte 写入 caller output |
| `0xb5255` | call exception consumer |
| `0xb5351` | `DeleteLocalRef`，vtable `+0xb8` |
| `0xb53a2` | cleanup 后最终/incoming status 检查 |
| `0xb51b8` | output byte 清零 |
| `0xb5220` | status `3` |
| `0xb51ac` / `0xb51cf` | status `18` |
| `0xb532e` | status `28` |

### 3.3 C++ 与 verifier

文件：
`native-reimplementation/recovered_primitives.cpp`

```text
RecoveredJniNoArgBooleanMethodOperationsC4064
runRecoveredJniHasMultipleSignersC4064
recoveredJniHasMultipleSignersC4064Regression
```

专用 verifier：

```text
.omx/static-audit-20260713/analyze_jni_has_multiple_signers_c4064.py
```

当前直接执行结果：

```text
cross-ABI SigningInfo.hasMultipleSigners constants: PASS
cross-ABI hasMultipleSigners JNI/status/ownership flow: PASS
C++ regression and recovered JNI coverage: PASS
```

Regression 明确覆盖：

- nonzero/raw true byte（`0x7f`）原样发布；
- false byte（`0`）在 status `0` 下合法成功；
- incoming nonzero status 仍执行完整 JNI 序列并最终清 output；
- null input；
- class null/exception；
- method null/exception；
- call exception；
- exact event order、argument forwarding 和 conditional class-ref cleanup。

### 3.4 原 SO 自然观察：false 是成功分支值

日志：

```text
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

该离线原 SO 日志三次记录：

```text
lines 40..45
lines 1347..1352
lines 2655..2660

GetMethodID(SigningInfo.hasMultipleSigners()Z)
return PC = libsigner.so+0xc4480

CallBooleanMethod(SigningInfo.hasMultipleSigners()) -> false
return PC = libsigner.so+0xc46d8

随后继续：
SigningInfo.getSigningCertificateHistory()
```

`0xc46d8` 是 `CallBooleanMethod` 后的本 FDE 返回点。parent 在 ARM64
`0x1e1f0..0x1e1f4`（x86_64 `0x2301a`）读取 status；自然执行随后进入
`0xc375c` history helper，说明原 SO 把 `false` 当作 status-zero 的合法 branch
selector，而不是错误。

现有 runner profile 提供的是 false，因此该日志验证 false semantics 与 history
分支，不证明真实 multi-signer/true 自然路径。日志也没有直接暴露本 helper 的 status
slot 和 `DeleteLocalRef` 事件；这些细节由双 ABI 静态流和 C++ regression 闭合。

## 4. 输入、输出和数据结构

### 4.1 Caller 提供的运行时数据

- `JNIEnv` / JNI operation context；
- `SigningInfo` object handle；
- caller-owned `uint32_t status` storage；
- caller-owned one-byte output storage；
- `CallBooleanMethod` callback/真实 Android 对象返回的 signer multiplicity。

C++ recovery 的 boolean 来自 caller-supplied operation callback；它没有把 false、
true、证书数量或 signer state 写死在 helper 中。用户配置或真机对象应通过这一边界
提供实际值。

### 4.2 原 SO 固定的 Java 方法协议

| ABI | VMA | ELF file offset | 长度 | XOR key | 解码值 |
|---|---:|---:|---:|---:|---|
| ARM64 | `0x145610` | `0x13d610` | 19 | `0xdf` | `hasMultipleSigners\0` |
| ARM64 | `0x145624` | `0x13d624` | 4 | `0x0f` | `()Z\0` |
| x86_64 | `0x13e0b0` | `0x1360b0` | 19 | `0xa0` | `hasMultipleSigners\0` |
| x86_64 | `0x13e0c4` | `0x1360c4` | 4 | `0xde` | `()Z\0` |

这些字符串是原 SO 固定的 Java ABI contract，不是运行时设备字段。需要让用户提供
其他 method name/descriptor 时，应使用单独 generic boolean-method adapter；精确
`0xc4064` primitive 应保留上述 contract。

### 4.3 Publication 与 ownership

- 输出是一个 raw `jboolean` byte，不执行 `0/1` normalization；
- `0` 是成功 false；任意非零 byte 会被 parent 作为 true branch 使用；
- temporary `SigningInfo class` local ref 由本 helper 删除；
- `SigningInfo` object 和 output slot 均由 caller 所有，本 helper 不删除对象；
- class null 时不执行 `DeleteLocalRef`；class 非 null 的后续路径均 cleanup。

## 5. 安全发现及严重程度

1. **低：native ABI 指针前置条件。** 原 helper 假定 `status`、output、
   `JNIEnv` 和 operation table 有效；外部错误指针会导致 native crash。
2. **低：raw noncanonical jboolean。** 原实现原样发布低 byte；异常 callback 返回
   `0x7f` 等值时 parent 会按 true 处理。正常 JNI 返回 `JNI_FALSE/JNI_TRUE`，但通用
   callback 边界应明确是否验证/normalize。
3. **低：incoming nonzero status 仍执行 JNI。** 自然 parent 只在 status zero 时调用，
   独立调用者不应依赖 helper 自动短路。
4. **未发现 helper 内伪造 signer multiplicity。** 最终 byte 来自 caller 提供的
   JNI object/callback，而不是恢复代码构造。

## 6. 修复建议

1. 产品外层 API 验证 `status`、output、`JNIEnv` 和 callbacks，并初始化 status。
2. 让用户配置、真机 `SigningInfo` 或调用方 provider 返回实际
   `hasMultipleSigners`；不要在 faithful C++ helper 中写死 false/true。
3. 保留 method name/descriptor 作为 `0xc4064` 精确实现；任意方法调用需求放入单独
   generic adapter。
4. 若产品层只接受 canonical boolean，可在进入/离开 compatibility primitive 的边界
   normalize 为 `0/1`；bit-exact 模式仍应保留 raw byte publication。
5. 回归同时覆盖 false、true、noncanonical nonzero、incoming status、三个 exception
   stage、class cleanup，以及 parent 的 false→history / true→APK-contents 选择。

## 7. 尚不能确认的事项

- 尚无原 SO 的真实 multi-signer/`true` 自然动态样本；现有 runner 路径返回 false。
- 尚未在原 SO/真机上逐分支 fault-inject class、method 和 call exception；failure
  branches 目前由 ARM64/x86_64 静态一致性和 C++ regression 确认。
- 现有 JNI verbose 日志未直接记录 status output 和 class-ref deletion。
