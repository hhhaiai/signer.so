# 最终验证记录

日期：2026-07-10（Asia/Shanghai）

## 本地环境

```text
JDK 17.0.5
Apache Maven 3.8.6
macOS
```

验证目标是纯 PC、自包含运行；未连接 Android 真机或 ADB。

## unidbg 测试与打包

```bash
cd runtime/unidbg
mvn -q test
mvn -q -DskipTests package
```

结果：

```text
Surefire classes=9
tests=18
failures=0
errors=0
skipped=0
fat jar=target/libsigner-unidbg-1.0-SNAPSHOT.jar
```

fat jar 已确认包含：

```text
arm64-v8a/libsigner.so
com/adjust/research/SignerCli.class
```

## 从项目外目录执行

SDK 23：

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh \
  --sdk 23 \
  --trace-jsonl /tmp/libsigner-final-sdk23.jsonl \
  --max-trace-events 64 \
  --output both
```

结果：

```text
exit=0
signature_length=304
signature_hex chars=608
signature_base64 chars=408
headers_id=8
adj_signing_id=1300000
native_version=3.62.0
algorithm=adj7
unsupported JNI=0
trace records=64
trace relative PC=0xa95ac..0xa984c
```

SDK 30：

```bash
cd /tmp
/Users/sanbo/Desktop/p/runtime/unidbg/run.sh --sdk 30 --output hex
```

结果：

```text
exit=0
signature_length=304
signature_hex chars=608
headers_id=8
adj_signing_id=1300000
native_version=3.62.0
algorithm=adj7
unsupported JNI=0
```

持久化证据：

- `runtime/unidbg/vectors/final-sdk23-run.txt`
- `runtime/unidbg/vectors/final-sdk23-trace-64.jsonl`
- `runtime/unidbg/vectors/final-sdk30-run.txt`

## Python 逆向脚本

```bash
/usr/bin/python3 -m unittest discover -s analysis/tests -v
```

结果：`9 tests`, `OK`。

`decode_xor_strings.py` 重新生成的 JSON 与 `recovered/strings.json` 逐字节一致；共 11 条记录，每条在四 ABI 实样本中复核。

`recovered/vm-zero-vector.json`：完整输出长度 304，HEX 自算 SHA-256 与声明值一致：

```text
d43a36f81b41cebd016c03e7e7e075e4df5741f46efc33380eabc2182272f1e2
```

该值的前置条件是 fresh emulator/module/context 的首次直接 VM 调用。

## QBDI 可选后端

```bash
cmake -S runtime/qbdi -B /tmp/libsigner-qbdi-final -DCMAKE_BUILD_TYPE=Release
cmake --build /tmp/libsigner-qbdi-final --parallel
ctest --test-dir /tmp/libsigner-qbdi-final --output-on-failure
```

结果：

```text
QBDI not found: building the explicit unavailable-backend stub
1/1 tests passed
0 tests failed
```

`TraceEvent` 的 `module_size`、PC/relative-PC 关系和 JSON escaping 测试通过；生成的 QBDI schema sample 通过同一 `validate_trace`。

`runtime/qbdi/check-environment.sh` 在当前 macOS 退出 `2`，正确报告：

- macOS 不能直接 `dlopen` Android ELF；
- 缺 QBDI headers/library；
- 缺 Android/Linux in-process target。

真实 `LIBSIGNER_HAVE_QBDI=1` callback/`vm.run()` 未在本机执行；这是可选观测后端，不阻塞 unidbg 本地签名主路径。

## Skill

验证目录：

```text
~/.codex/skills/android-so-reversing
~/.claude/skills/android-so-reversing
```

结果：

- system Skill Creator `quick_validate.py`：两端 `Skill is valid!`；
- bundled tests：两端各 `4 tests`, `OK`；
- 两个目录 `diff -qr` 无差异；
- Codex forward-test 已保存于 `analysis/skill-eval/forward-test.md`；
- Claude Code CLI 因未登录，未做模型级 forward-test，但安装目录和脚本已验证。

## 原始样本保全

```text
arm64-v8a   fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736
armeabi-v7a ab68f112fffdb090015cef48ff123e34f4dc7819cbdf0f913dc19e331ac1484d
x86         a33c2cf24bcd6d3f9666aac0d4dcf5d84f37f44738310f1ab2c2c614dc9ae6db
x86_64      b00272e389cc33ecc7255adfb918871bb01cc34f6701877258c4f32ae011fb5c
```

`py/libsigner.so` 与 `jni/arm64-v8a/libsigner.so` 逐字节相同。原始样本哈希未变化。

## 恢复代码编译 smoke

AppleClang，全部使用 `-Wall -Wextra -Werror -pedantic`：

- `recovered/jni_contract.h` 作为 C11 include 编译通过；
- 同一 header 作为 C++17 include 编译通过；
- `recovered/signer_pipeline.cpp` 与严格 9-Blob VM stub link/run 通过；
- smoke 验证 304-byte shape 及四个 metadata。

该 smoke 只证明恢复接口/模型可编译，不把 stub 当作真实 protected VM 算法；真实本地结果由原始 `.so` 执行。
