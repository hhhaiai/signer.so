# ARM64 JNI certificate-array selector `0x1dde0..0x1e578`

## 1. 范围与结论

- 目标：`adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so`
- ARM64 FDE：`0x1dde0..0x1e578`
- x86_64 对照 FDE：`0x22cf9..0x2335e`
- 恢复名称：JNI API-dependent `PackageInfo` certificate-array selector
- 当前状态：`recovered`
- JNI reachable：`yes`
- 当前 C++ SHA-256：`f9bb23156bd6eb6cb1f0584361b02695132bb139503d71e4c8fd22ba5accb707`

该函数负责按 signed Android API level 选择并返回整个
`android.content.pm.Signature[]`。它不提取数组元素；动态日志中的
`GetObjectArrayElement(Signature[], 0)` 返回 PC 为 `libsigner.so+0x1ef20`，属于下一
FDE `0x1e578..0x1f058`。

## 2. 调用接口

ARM64 入参：

```text
x0  uint32_t* status
x1  JNIEnv / JNI operation context
x2  android.content.Context object
w3  signed int32 Android API level
x4  uint8_t* outputHasMultipleSigners
x5  jobjectArray* outputSignatures
```

x86_64 对照：

```text
rdi status*
rsi JNIEnv
rdx Context
ecx signed int32 Android API level
r8  outputHasMultipleSigners*
r9  outputSignatures*
```

`w3/ecx` 必须按 signed `int32_t` 解释。ARM64 的 `cmp w3,#27` 加 signed `gt` 与
x86_64 signed `>=28` 分支一致，因此负 API level 进入 legacy 路径。

## 3. 直接 helper 集合

父 FDE 的直接 helper 集合在两个 ABI 上一致：

```text
0xb3230 Context.getPackageName
0xb3bf4 Context.getPackageManager
0xba914 PackageManager.getPackageInfo
0xb8830 PackageInfo.signatures
0xb9424 PackageInfo.signingInfo
0xc4064 SigningInfo.hasMultipleSigners
0xc2b78 SigningInfo.getApkContentsSigners
0xc375c SigningInfo.getSigningCertificateHistory
```

专用 verifier 对直接 call 集合、父 FDE 边界、六参数 caller contract 和跨 ABI 分支均做
精确匹配：

```text
.omx/static-audit-20260713/analyze_jni_certificate_selector_1dde0.py
```

## 4. 恢复后的状态机

```text
always:
    getPackageName(status, env, context, &packageName)

if status == 0:
    getPackageManager(status, env, context, &packageManager)

if status == 0 and signed androidApi < 28:
    *outputHasMultipleSigners = false
    getPackageInfo(status, env, packageManager, packageName, 0x40, &packageInfo)
    if status == 0:
        getLegacySignatures(status, env, packageInfo, outputSignatures)

if status == 0 and signed androidApi >= 28:
    getPackageInfo(status, env, packageManager, packageName,
                   0x08000000, &packageInfo)
    if status == 0:
        getSigningInfo(status, env, packageInfo, &signingInfo)
    if status == 0:
        hasMultipleSigners(status, env, signingInfo,
                           outputHasMultipleSigners)
    if status == 0 and *outputHasMultipleSigners != 0:
        getApkContentsSigners(status, env, signingInfo, outputSignatures)
    if status == 0 and *outputHasMultipleSigners == 0:
        getSigningCertificateHistory(status, env, signingInfo,
                                     outputSignatures)
```

关键 publication 语义：

1. incoming status 非零时，父函数仍调用一次 `getPackageName`，之后停止。
2. legacy 路径只在进入 `getPackageInfo(...,0x40)` 前写
   `*outputHasMultipleSigners = 0`。
3. API 28+ 路径不会在父函数入口统一清零该 byte。
4. 尚未到达 producer 时，父函数不主动清空 caller 的 `Signature[]` output。
5. 成功返回的整个 `Signature[]` 转交 caller；父函数不 `DeleteLocalRef` 该数组。

## 5. Ownership 与 cleanup

父函数拥有并按以下精确顺序清理 local refs：

```text
SigningInfo
PackageInfo
PackageManager
packageName String
```

每个删除条件均为：

```text
reference != 0 && JNIEnv != 0
```

父函数不消费 `DeleteLocalRef` 后可能产生的异常，也不因 cleanup 改写 status。

## 6. C++ 证据位置

文件：`native-reimplementation/recovered_primitives.cpp`

```text
RecoveredJniCertificateSelectorOperations1dde0   line 10434
runRecoveredJniCertificateSelector1dde0          lines 10476..10537
recoveredJniCertificateSelector1dde0Regression   line 10709 起
main executable guard                            line 28209 起
```

回归覆盖：API 27 legacy、API 28 history、API 35 multiple-signers、负 API、incoming
status、每个 producer/helper failure、caller output 保持、两个 flags、参数转发、数组
transfer、精确 cleanup 顺序及 `JNIEnv == 0` cleanup skip。

## 7. 原 SO 本地动态观察

### API 18 legacy 自然路径

日志：

```text
.omx/static-audit-20260713/current-337-51-b8830-legacy-api18-jni-trace-attempt-1.log
```

观察顺序：

```text
Context.getPackageName
Context.getPackageManager
PackageManager.getPackageInfo(..., 0x40)
PackageInfo.signatures
```

该日志随后在 `libsigner.so+0x1ef20` 观察到 `GetObjectArrayElement(...,0)`，证明元素选择
属于下一 FDE，而不是本父函数。

### API 28+ / `hasMultipleSigners() == false` 自然路径

日志：

```text
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

观察顺序：

```text
Context.getPackageName
Context.getPackageManager
PackageManager.getPackageInfo(..., 0x08000000)
PackageInfo.signingInfo
SigningInfo.hasMultipleSigners() -> false
SigningInfo.getSigningCertificateHistory()
```

`hasMultipleSigners() == true` 到 `getApkContentsSigners()` 当前仅有 ARM64/x86_64 静态
证据和恢复后 C++ 状态机回归，尚无原 SO 自然动态 true-branch 记录。

## 8. 验证结果

在上述 C++ SHA 上：

```text
dedicated 0x1dde0 verifier: PASS
all static analyzers: 147/147 PASS
clang++ -Wall -Wextra -Werror syntax-only: PASS
standalone O2 regression smoke: PASS
build/original-SO oracle set: PASS
ASan+UBSan: PASS (LeakSanitizer disabled on macOS)
frozen Pixel recovered-backend exact match: PASS
RecoveredNativeBackendIntegrationTest: 21/21 PASS
SignerNativeIntegrationTest with local original SO: 1/1 PASS
```

动态测试仅验证已覆盖 profile 与 runner 行为，不替代未执行分支的静态证明，也不把
`0x1e578` 的元素提取和后续证书 byte-array 处理计入本 FDE。
