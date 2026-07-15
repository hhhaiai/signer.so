# Signer implementations

本目录把项目中三条不同的 signer 路线分开。每个编号目录都物理包含其完整源代码、构建
配置、测试和调用脚本，不需要引用项目中另一个源码目录才能编译。它们不是必须串联的
三层，而是面向不同目标的三种独立实现。

| 目录 | 是否用 C++ 重写算法 | 是否加载官方 SO | 是否仿真 ARM64 | 用途 | production 状态 |
|---|---:|---:|---:|---|---|
| [`01-recovered-cpp`](01-recovered-cpp/) | 是，当前仍有未知函数 | 否 | 否 | 静态恢复、算法审计、回归 | audit-only |
| [`02-vendor-jni-bridge`](02-vendor-jni-bridge/) | 否 | 是 | 否 | JNI/ABI 兼容和本机委托 | vendor 输出可用于生产协议 |
| [`03-unidbg-runner`](03-unidbg-runner/) | 否，执行 ARM64 机器码 | 是 | 是 | 隔离观察、地址级验证、差异对比 | lab-only |

## 快速选择

- 要阅读或验证恢复出的 C++ 行为：进入 `01-recovered-cpp/`。
- 要让兼容 JNI 转发给调用方提供的官方库：进入 `02-vendor-jni-bridge/`。
- 要在 JVM 中模拟 Android ARM64 环境运行本地 SO：进入 `03-unidbg-runner/`。

## 安全默认验证

```bash
cd /Users/sanbo/Desktop/api/qbdi
./signer-implementations/verify-all.sh
```

该命令不会调用 recovered 签名入口，也不会通过 Unidbg 加载目标 SO。它只做布局、编译、
非敏感 bridge 测试、边界审计、JSON 校验和不触发 native integration 的 Java 单元测试。

## 源码快照

三个目录分别包含从下列项目源复制的授权审计快照：

```text
native-reimplementation/recovered_primitives.cpp
native-reimplementation/signer_jni_bridge.{h,cpp}
native-reimplementation/signer_backend.{h,cpp}
unidbg-adjust-runner/
```

复制后，`signer-implementations/*` 的构建脚本只使用各自目录内文件。原位置只用于记录
来源和后续人工比对，不是编译依赖。官方 SO、Android NDK、JDK、Maven 本地依赖和实验
JSON 仍属于明确的工具链或运行时输入，不复制为源码。

详细调用链见 [`ARCHITECTURE.md`](ARCHITECTURE.md)。
物理复制清单和文件指纹见 [`SOURCE_SNAPSHOTS.md`](SOURCE_SNAPSHOTS.md)。
