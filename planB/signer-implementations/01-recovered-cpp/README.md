# 01 — Recovered C++

这一目录物理包含完整的 C++ 源码、CMake 工程、构建脚本、调用脚本和契约文档。目录内的
构建不引用项目中其他源码目录；本包的构建权威源码是：

```text
src/recovered_primitives.cpp
```

该文件最初从项目内恢复源码快照复制而来，当前快照 SHA-256 为：

```text
abafec344a954689d9ec30953fa6d24c8ddc5c21480d92720371b976e4f336fa
```

复制后，本目录可以独立编译；后续若上游分析源码变化，需要显式同步，不能假定两个副本会
自动保持一致。

## 定位

- 直接 C++ 实现已恢复的 native primitives 和签名组合路径；
- 不加载官方 `libsigner.so`；
- 当前不是官方 SO 的完整 JNI/ABI drop-in replacement；
- audit-only、production-ineligible。

这里的“完整源码”表示构建所需的代码已经物理放入本目录，不表示官方 SO 的全部函数已经
100% 恢复；当前覆盖边界见 [恢复覆盖率](docs/COVERAGE.md)。

## 检查

```bash
./check.sh
```

只执行：

```text
C++17 + -Wall -Wextra -Werror + -fsyntax-only
```

## 构建

```bash
./build.sh
```

脚本使用本目录的 `CMakeLists.txt` 和 `src/recovered_primitives.cpp`，要求 CMake 3.16+ 与
C++17 编译器，并启用 `-Wall -Wextra -Werror`。

输出：

```text
01-recovered-cpp/build/recovered-primitives
```

## 显式调用

先复制并修改合成输入配置：

```bash
cp config/input.env.example /tmp/recovered-input.env
$EDITOR /tmp/recovered-input.env
./run-example.sh /tmp/recovered-input.env
```

`run-example.sh` 会真正调用 recovered signer，因此与 compile-only 检查分开。配置缺少任意
必填字段时立即失败，不会使用回归设备数据补齐。

## 文档

- [输入契约](docs/INPUT_CONTRACT.md)
- [恢复覆盖率](docs/COVERAGE.md)
- [安全边界](docs/SECURITY_BOUNDARY.md)
