# 安全和部署边界

分类：

```text
Critical / audit-only / production-ineligible
```

原因：当前源码包含恢复的签名组合、固定核心材料引用、完整格式回归向量、独立 `main()` 和
`SIGNATURE_HEX` 输出。它只能用于经过授权的本地静态分析、隔离实验和回归。

本目录已经物理包含 `../src/recovered_primitives.cpp` 并可独立编译；自包含性不会改变上述
安全分类，也不构成 production 部署许可。

禁止：

- 链接进 production `libsigner_compat.so`；
- 将 CLI 暴露为线上签名服务；
- 把合成或回归数据描述成真实设备数据；
- 提取、打印或传播密钥、设备秘密、私钥或认证状态；
- 用 unknown 函数的缺口掩盖“完整实现”声明。

production compatibility target 只使用 `signer_backend.cpp` 和 `signer_jni_bridge.cpp`，由
`VendorSignerBackend` 调用调用方提供的官方本地库。
