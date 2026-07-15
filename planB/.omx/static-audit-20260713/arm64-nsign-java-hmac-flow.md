# arm64 nSign Java-HMAC integrity path

本报告只解析已有 `javap` 与 `objdump` 文本，不加载或执行目标 SO。

## Proven Java source

```text
Map.toString()
-> UTF-8 bytes
-> com.adjust.sdk.sig.c.a(Context, byte[])  // HmacSHA256
-> byte[] local 5
-> NativeLibHelper.nSign(Context, Map, byte[], api)
```

JNI 第三个业务参数 `byte[]` 是 Java 侧对 `Map.toString()` 结果计算的 HMAC 完整性值，
而不是待签名 Map plaintext 本身。

## Proven native path

```text
0xcbbf4  save nSign byte[]
0xcbd40  reload as x4
0xcbd44  call 0xe6c0
0xedc4  reload byte[]
0xedcc  call 0x94bc0

0x94f04  obtain array length through helper 0x92ddc
0x94e50  calloc native storage
0x94ddc  JNIEnv vtable +0x640 = GetByteArrayRegion
0x94eb0  return copied length
0x94eb8  return copied buffer

0xef00/0xef04/0xef08  compare supplied and expected bytes
0xf150/0xf15c/0xf168  decrement remaining length and advance both cursors
0xecc8/0xeccc          emit correction 0x07 through 0x13548c
0xefd8/0xefdc          free the copied supplied-HMAC buffer
```

## Corrected descriptor conclusion

在严格的 `0xe6c0..0xf1c4` 范围内，复制出的 supplied-HMAC buffer 用于比较并在
返回前释放；没有找到把该 buffer 直接写入 native context `+0x118/+0x120` 的 store。
因此此前“final descriptor 8/9 就是 nSign supplied Java HMAC”的说法不能成立。
独立的完整 context producer 分析进一步证明这两个字段保持 `0/null`。

结合独立的 expected producer 报告，当前可安全固化的语义为：

```text
nSign byte[] = Java HMAC integrity input
expected     = Mac.HmacSHA256(Map.toString().getBytes(), API-selected Key)
mismatch     = correction code 0x07
slot 8/9     = reserved zero-length descriptor pair
```

API-selected Key 的 AndroidKeyStore/legacy resolver 异常状态仍需在 platform adapter
中逐项实现；但成功路径 expected HMAC 算法与输入已经闭合。
