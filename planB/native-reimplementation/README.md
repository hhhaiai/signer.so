# Native C++ reimplementation workbench

这里是从 ARM64 `libsigner.so` 恢复出的独立 C++17 signer 核心。编译和执行时不加载：

- Java / JNI；
- Unidbg / Unicorn；
- 原始 `libsigner.so`；
- Android Emulator、ADB、Frida 或真机。

只使用 macOS 已有的 Apple Clang/C++ 标准库，不自动安装系统插件。

## 构建和确定性验证

```bash
cd /Users/sanbo/Desktop/api/qbdi
./native-reimplementation/build-and-test.sh
```

该命令会验证：

1. AES-256 key expansion、14 轮 block encryption；
2. AES-256-CBC + PKCS#7；
3. SHA-256、HMAC-SHA256；
4. Bionic `srandom/random` 兼容 PRNG 和 IV；
5. correction encoder 与按 8-halfword 分块的 field-0 扩容；
6. field 0 的 base codeword + ordered correction 覆盖规则；
7. field 4 的 custom-state SHA-256；
8. 从结构化输入构造动态 payload（已验证 113 / 129 / 145 bytes）；
9. 176-byte Pixel、192-byte 九 correction 与 208-byte 十七 correction 结果；
10. 冻结 Pixel、`timeSeconds+1`、trampoline=false、correction05=false、空
    `/proc/self/maps`、缺失 `/proc/self/maps`、修改 device name/native plaintext、
    缺失 Java 字段、APK/PackageManager 证书不一致并观察到 correction `0x2a`，以及
    `/proc/self/cmdline` mismatch `0x09`、cmdline 缺失/空 `0x34`，以及九 correction
    触发 16-halfword/192-byte 扩容，以及十七 correction 触发
    24-halfword/145-byte payload/208-byte result，共十三组完整向量；变体均先由
    原 SO 产生 oracle，再要求 C++ 逐字节完全一致。

## 已恢复的完整动态结果路径

```text
timeSeconds
  -> Bionic random, pairwise XOR
  -> 16-byte IV

observed correction codes
  -> encodeCorrection
  -> environment halfwords 按 8 个一组扩容：8、16、24、32...

certificate SHA1 + environment halfwords + field2 + SHA256(empty)
+ state + native plaintext
  -> SHA-256 with recovered custom initial state
  -> 32-byte field 4

payload fields 0..6
  -> 113 bytes（8 halfwords）、129 bytes（16）或 145 bytes（24）
  -> AES-256-CBC + PKCS#7
  -> 128-byte、144-byte 或 160-byte ciphertext
  -> HMAC-SHA256(ciphertext)
  -> 32-byte tag

IV || ciphertext || tag
  -> 176-byte、192-byte 或 208-byte signature
```

### field 0

先生成：

```text
encode(0x40), encode(0x41), ... encode(0x47)
```

然后把环境检测产生的 correction codes 按发生顺序编码，并覆盖前 N 个槽位。初始为
8 个 halfword；当 correction 数量超过 8 时，原 SO 会扩为 16，base pattern 每 8 个重复。

```text
Pixel / trampoline=true  corrections = 2b,36,25,05
Pixel / trampoline=false corrections = 2b,36,05
Pixel / correction05=false corrections = 2b,36,25
Pixel / empty proc maps  corrections = 2b,37,36,25,05
Pixel / missing proc maps corrections = 2b,37,35,36,25,05
APK/package certificate mismatch = 2b,2a,36,25,05
nine-correction combined profile = 2b,09,37,2a,3c,35,36,25,05
```

前九类完整 176 bytes 和最后一类完整 192 bytes 均已与原 SO oracle 精确一致。maps
三种已观察状态中均有 `0x36`，所以它是 maps probe/scan 基线完成事件；`0x37` 对应
没有找到同时包含当前 package 和 `/base.apk` 的映射行，`0x29` 对应找到的首条 APK
路径与 `publicSourceDir` 不同，`0x35` 对应 maps 路径缺失/访问失败。单行精简 oracle 已证明
地址、权限、inode、空格及 Frida/Xposed 关键词不是该分支的决定因素。

### field 4

field 4 不是普通 `SHA256(material)`。SO 先加载固定 source words，再逐 word XOR
`0xcccccccc`，得到自定义 SHA-256 chaining state：

```text
cd46a0de d5c62fe0 02cb3985 fd4a15a3
07cad499 63840dbf 51698010 ca03ff52
```

随后对下列 material 使用标准 SHA-256 padding 和 compression：

```text
certificateSha1 (20)
+ 00 <halfword count> + environment halfwords
+ field2 in forward order 00 01 02 03 (4)
+ SHA256(empty) (32)
+ state byte (1)
+ native plaintext (Pixel: 154)
= Pixel 229 bytes；16-halfword profile 相应增加 16 bytes
```

Pixel 四个 block 的 chaining state 和最终
`fef6ae81ab7a34b0...2e105380` 均与原 SO 动态 trace 一致。

## 当前 CLI

构建后：

```bash
./native-reimplementation/build/recovered-primitives \
  --time-seconds=1760000001

./native-reimplementation/build/recovered-primitives \
  --signer-code-trampoline-detected=false
```

可配置参数：

```text
--time-seconds=<uint32>
--signer-code-trampoline-detected=true|false
--correction-codes=2b,36,25,05
--certificate-sha1=<40 hex chars>
--native-plaintext-hex=<even-length hex>
--state=true|false
```

输出中的 `SIGNATURE_HEX=` 是独立 C++ 计算结果。

## 尚未完成的边界

C++ 算法路径已经能直接产生完整结果，不再使用固定 113-byte payload 或固定最终
176 bytes。原 SO oracle 已证明 field 0 按 8 halfwords 分块扩容，并闭合
8→16→24；源码按同一规则支持后续 32 等容量。仍不能把整个项目宣称为
“任意 Android 环境的完整 SO replacement”：

1. 已观察到的 correction code 可以传入，trampoline 检测已映射；其他 Android/native
   probe 到 correction code 的全部分支仍需逐个映射；
   当前已进一步证明 `0x05` 来自 `0xd184` 的 `gettimeofday/clock_gettime` 时序检查，
   该检查写入 native context byte `+0x8`，`0xf224` 再据此产生 correction；`0x2b`
   来自初始化 wrapper；dispatcher `0x14d9c` 调用 `0xd78b8` 读取 `/proc/self/maps`，
   当前已将 package/base.apk 映射存在性、mapped path/publicSourceDir 差异与 maps
   缺失映射到 `0x29/0x35/0x36/0x37`；并已证明 `/proc/self/cmdline` 缺失/空产生
   `0x34`，非空进程名与 runtime packageName 不一致产生 `0x09`，`0x38` 是
   publicSourceDir 不可访问，`0x3c` 是 androidApi 不等于 36（含 API 18-22）。
   关闭 `0x05` 的原 SO
   payload 仍为 field 6=`01`，所以该 timing flag 与 payload state 不是同一字段；
   `0x2a` 已证明是 `baseApk` 实际 signer certificate 与 PackageManager 模拟证书不一致，
   Java recovered backend 已自动解析 v1/v2/v3/v3.1 APK signer 并产生该 correction；
2. Java `RecoveredNativeBackend` 已按恢复顺序直接拼接参数，并用原 SO oracle 验证完整
   Pixel、缺失字段、maps 分支、timing correction 和 APK 证书匹配分支；尚未观察到的
   新 SDK 字段仍需按新 oracle 扩展；
3. Java 默认 backend 为 `unidbg` 以保持兼容，但 JSON 可配置
   `runtime.backend=recovered`，该路径已通过冻结 Pixel 完整严格比对。

因此当前准确表述是：**动态算法核心已独立源码运行，176/192/208-byte 十三类 oracle 已通过；
剩余工作是把尚未命名的环境 probe 完整映射到 correction code。**
