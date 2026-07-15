# 物理源码快照

记录时间：2026-07-15。以下文件均为普通文件，不是软链接；三个构建系统只读取各自编号
目录中的源码。

## 01 — Recovered C++

```text
src/recovered_primitives.cpp
lines: 31,213
bytes: 1,282,156
sha256: abafec344a954689d9ec30953fa6d24c8ddc5c21480d92720371b976e4f336fa
```

复制时与 `native-reimplementation/recovered_primitives.cpp` 逐字节一致。

## 02 — Vendor JNI bridge

| 本地文件 | SHA-256 |
|---|---|
| `include/fake_signer_backend.h` | `3a03ee444db52408d047573adaf246251c7aaa764a92fa7afc6e0b76098ce5f9` |
| `include/signer_backend.h` | `9c4647c92d9f4491db3b3737fc030e0275709ef34d6c3e1f2c2290198134d8af` |
| `include/signer_jni_bridge.h` | `7e6eec8ae677a986f66ca8268450b549284855e144b6ab17321d08ff436f5867` |
| `src/fake_signer_backend.cpp` | `c8c08b0f52267dc82c3c21c0a2caf9f155f815d6dc3e1fa8de1b1ba7b29a97df` |
| `src/signer_backend.cpp` | `9a9e13cf9d44543173b7fb85a2e2d1462478ef91eedf9df9852f1f2e18288231` |
| `src/signer_jni_bridge.cpp` | `12c88f913c7f0a81f68fb86b004e6fd31328378bbc6058f2dfcc6b88dbbd7411` |
| `tests/signer_backend_test.cpp` | `7b9d4d7eb8e53e8d06351c81e415020ac320e828b4f1efb7d8354a6bd332644d` |
| `tests/signer_bridge_config_test.cpp` | `6c7d3b591d3500d07686b08fcb416fe2cb4b68703dd6032bfdafe2461f04bf7d` |
| `tests/signer_bridge_production_config_test.cpp` | `9ccd9049e924042678f7dbeae3a68aa66e453279a0460b7bd186b3e0f1e6e324` |

九个 C++/header 文件复制时与 `native-reimplementation/` 对应文件逐字节一致。

## 03 — Unidbg runner

```text
pom.xml
src/main/java: 31 files
src/test/java: 21 files
total Java sources: 52 files
```

源码文件集合与原 `unidbg-adjust-runner/src` 一致。31 个 production Java 文件保持原样；
两项 APK/AAR parser 测试仅调整 artifact-root 发现方式，使复制后的 Maven 工程能在当前目录
和临时目录独立测试：

```text
src/test/java/com/adjust/sdk/sig/ApkManifestReaderTest.java
src/test/java/com/adjust/sdk/sig/ApkSigningBlockCertificatesTest.java
```

清理前最后一次独立构建验证产生的 JAR 指纹：

```text
target/unidbg-adjust-runner-1.0-SNAPSHOT.jar
sha256: 305dc9737be7de870e867d84e10b66eb26d3002f1f6cdecce4da205b3f92f972
```

该 `target/` 已按要求清理；重新执行 `03-unidbg-runner/build.sh` 会重新生成产物。

## 同步规则

这些目录现在是物理快照，不会自动跟随原源码更新。后续如从原路径重新复制，应重新运行
三个目录的本地构建/测试并更新本文件指纹；不能只覆盖源码而沿用旧的构建结论。
