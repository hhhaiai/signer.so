# Recovered C++ 输入契约

本目录的权威结构位于 `../src/recovered_primitives.cpp` 的 `NativeInputs`：

| CLI/配置字段 | C++ 字段 | 类型 | 规则 |
|---|---|---|---|
| `TIME_SECONDS` | `timeSeconds` | `uint32_t` | 十进制，允许合法的 0 |
| `CORRECTION_CODES` | `correctionCodes` | `vector<uint16_t>` | 逗号分隔，显式传入 |
| `URANDOM_HEX` | `field2` | 4 bytes | 至少提供 4 bytes，前四字节进入字段 |
| `CERTIFICATE_SHA1` | `certificateSha1` | 20 bytes | 40 个十六进制字符 |
| `NATIVE_PLAINTEXT_HEX` | `nativePlaintext` | byte vector | 可为空，但键必须存在 |
| `STATE` | `state` | bool | `true` 或 `false`，false 不等于未提供 |

程序通过 `NativeInputPresence` 单独记录 presence，所以 `0`、`false`、空字节序列和未提供
不会混淆。调用脚本不启用 `--use-regression-fixture`，也不合成缺失字段。

成功执行时，本目录 CLI 输出：

```text
SIGNATURE_HEX=<hex bytes>
```

该输出仅用于授权审计和本地回归。
