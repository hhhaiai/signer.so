# arm64 JNI GetStringUTFLength helper `0x927c4`

本报告只执行静态 ARM64 指令解释，不加载目标 SO。

## ABI

```text
x0 = uint32_t* status
x1 = JNIEnv*
x2 = jstring
x3 = uint64_t* outputLength
```

## 完整行为

- 先把 `*outputLength` 清零；
- `jstring == null` 时不调用 JNI，覆盖 `*status = 3`；
- 非空 string 即使已有非零 status，也调用 JNI vtable `+0x540`
  `GetStringUTFLength`，把 signed `jint` 符号扩展到 64 bits；
- 随后调用 `0x92a20`；pending exception 覆盖 status 为 `28`；
- 任意非零 final status 都把 output length 再清零；
- 成功时保留符号扩展结果，因此 JNI 返回 `-1` 会发布
  `0xffffffffffffffff`。

直接 C++：

```text
RecoveredJniStringUtfLengthOperations927c4
runRecoveredJniStringUtfLength927c4(...)
```

可重复证据：

```bash
python3 .omx/static-audit-20260713/analyze_jni_string_utf_length_927c4.py
```
