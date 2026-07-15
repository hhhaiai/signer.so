# arm64 reserved Map value helper `0x8af4`

本报告只读取目标 ELF，并用自制 ARM64 指令解释器执行静态反汇编；不加载目标 SO。

## ABI

唯一业务调用点 `0x11cd98..0x11cda8` 证明入口为：

```text
x0 = uint32_t* status
x1 = JNIEnv*
x2 = decoded native Map key C string
x3 = jobject* output Java string
```

## 六个一次性 XOR literal

| VMA | XOR | plaintext |
|---:|---:|---|
| `0x142e90` | `0xa6` | `secret_id` |
| `0x142ea0` | `0x4d` | `1400000` |
| `0x142ea8` | `0x26` | `headers_id` |
| `0x142eb4` | `0xa4` | `9` |
| `0x142eb8` | `0x7c` | `native_version` |
| `0x142ec8` | `0xd9` | `3.67.0` |

解释器对 fresh encoded globals 和 already-decoded globals 都得到相同结果，排除了
一次性 decoder 对业务返回的影响。

## 完整可观察语义

函数做精确、大小写敏感匹配：

```text
secret_id      -> NewStringUTF("1400000")
headers_id     -> NewStringUTF("9")
native_version -> NewStringUTF("3.67.0")
```

其他 key、空字符串和 null key：

```text
return false
status 不变
output 不变
不调用 JNI
```

命中时，`0x9468..0x9490`：

1. 用选中的固定 value 调用 `NewStringUTF` (`JNIEnv` vtable `+0x538`)；
2. 无条件先把返回 reference 写入 `*output`；
3. 调用 `0x92a20` 消费 pending exception；
4. 有异常则写 `*status = 34` 并返回 false；
5. 无异常返回 true。

一个容易遗漏的边界：`NewStringUTF` 返回 null、但 `ExceptionOccurred` 返回 null 时，
原函数仍返回 true。输入 `status` 的既有非零值不阻止调用，成功路径也不改写它。

## 对 plaintext composition 的修正

100-key 表第 80 项本来就是 `secret_id`。因此冻结向量中的固定 `1400000` 来自本 helper
对 `secret_id` 的 special emit，而不是把表外 `adj_signing_id` 插到第 96 项之前。
同理，caller 提供的 `headers_id` 和 `native_version` 也被固定值覆盖。

等价 C++：

```text
recoveredReservedMapValue8af4(...)
runRecoveredReservedMapValue8af4(...)
buildNativePlaintext(...)
```

## 可重复证据

```bash
python3 .omx/static-audit-20260713/analyze_new_string_utf_helper_8af4.py
```

预期：

```text
arm64 reserved Map value helper 0x8af4 evidence: PASS
```
