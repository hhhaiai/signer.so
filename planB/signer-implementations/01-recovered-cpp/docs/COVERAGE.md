# 当前恢复覆盖率

本报告对应本目录的 `../src/recovered_primitives.cpp` 源码快照。目录内代码可独立构建，
但以下覆盖数字仍用于说明算法恢复边界，不能据此宣称官方 SO 已 100% 逐函数恢复。

机器可读权威表：

```text
.omx/static-audit-20260713/arm64-function-inventory.csv
```

当前统计：

| 指标 | 数量 |
|---|---:|
| ARM64 FDE ranges | 388 |
| recovered | 348 |
| partial | 0 |
| unknown | 40 |
| JNI statically reachable | 321 |
| reachable recovered | 299 |
| reachable unknown | 22 |

函数数量恢复率为 89.69%，JNI 可达函数恢复率为 93.15%。`sign(const NativeInputs&)` 已连通
payload、IV、AES-CBC、HMAC 和 envelope，但 40 个 unknown 意味着不能宣称整个官方 SO
逐函数完整恢复，也不能把该单文件描述为完整 JNI drop-in shared library。
