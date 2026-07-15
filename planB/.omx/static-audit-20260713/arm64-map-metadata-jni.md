# arm64 Map metadata and JNI helper proof

本报告只读取 ELF 数据和现有 objdump 文本，不加载或执行目标 SO。

## Metadata pairs inserted by `0xaf3c`

`0x9954c` 的 JNI 调用形态是 `Map.put(String,String)`：它使用 `GetObjectClass(0xf8)`、`GetMethodID(0x108)`、`CallObjectMethod(0x110)`、`NewStringUTF(0x538)` 和 `DeleteLocalRef(0xb8)`；其 method name/signature 解码为 `put` / `(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`。

| key | key VMA / file offset | XOR | value | value VMA / file offset | XOR | `Map.put` call |
|---|---:|---:|---|---:|---:|---:|
| `headers_id` | `0x142ea8` / `0x13aea8` | `0x26` | `9` | `0x142eb4` / `0x13aeb4` | `0xa4` | `0xc544` |
| `native_version` | `0x142eb8` / `0x13aeb8` | `0x7c` | `3.67.0` | `0x142ec8` / `0x13aec8` | `0xd9` | `0xbffc` |
| `adj_signing_id` | `0x142ed0` / `0x13aed0` | `0x11` | `1400000` | `0x142ea0` / `0x13aea0` | `0x4d` | `0xc7f4` |
| `algorithm` | `0x142ee0` / `0x13aee0` | `0xcc` | `adj8` | `0x142eec` / `0x13aeec` | `0xdb` | `0xc6a4` |

由于 `0xaf3c` 是 flattened state machine，call-site 地址不能当作运行顺序；但每个 call-site 的 `x3=key`、`x4=value` 配对是直接静态证据。

## Selected Map-value walker helpers

- `0xacd90`: method name/signature 解码为 `containsKey` / `(Ljava/lang/Object;)Z`，并使用 `CallBooleanMethod(0x128)`。
- `0xadbf4`: method name/signature 解码为 `get` / `(Ljava/lang/Object;)Ljava/lang/Object;`，并使用 `CallObjectMethod(0x110)`。
- `0x11ba78` 从 `0x145a30` 的 100-key CSV 表开始解析 key，逐项执行 `containsKey -> get -> callback`。

## Important correction about `adj_signing_id`

`0x11ba78..0x11d408` 没有引用 standalone `adj_signing_id` buffer `0x142ed0`，而 100-key 表也不包含该 key。因此 `0x11d798` 的两遍 materializer 只能证明 100-key selected Map values 的拼接，不能静态证明 `adj_signing_id` 是在这个 walker 内插入的。

独立 `adj_signing_id=1400000` 的已确认角色之一，是 `0xaf3c` 通过 `Map.put` 写入 native result metadata Map；它在最终被签名 logical plaintext 中的精确拼接层仍需继续从 `0x11da64 -> 0xf1ec8` 的九 descriptor 数据流证明。

这不会推翻已有 exact output：当前 C++ 把该值放到已验证的位置仍能复现冻结 oracle；修正的是对 `0x11d798` 角色的过度归因。
