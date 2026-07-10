# libsigner.so 3.62.0 地址映射

地址均为模块相对虚拟地址（RVA）。`confirmed` 表示有运行时或跨 ABI 直接验证；`inferred` 表示结构/调用关系可靠但语义尚未完整动态重放。

| 角色 | ARM64 | x86_64 | 证据 | 状态 |
|---|---:|---:|---|---|
| JNI `nOnResume` 导出 | `0x0a894c` | `0x092730` | 动态符号；均为尾跳/跳板 | confirmed |
| JNI `nSign` 导出 | `0x0a95ac` | `0x093200` | 动态符号、官方 descriptor、unidbg 实跑 | confirmed |
| `Map.get("environment")` helper | `0x08b510` | 未命名 | JNI trace 到 `Map.get`，不是 hash | confirmed |
| native buffer → `jbyteArray` | `0x0a8dec` | 未命名 | `NewByteArray(304)`/`SetByteArrayRegion` trace | confirmed |
| resume/timer shared init | `0x0b0a48` | `0x099100` | `nOnResume` 跳转目标、timer 调用 | confirmed |
| timer/detector callback | `0x0b0d08` | `0x099390` | `SIGEV_THREAD` callback 地址与同步调用 | confirmed |
| signature VM program/orchestrator | `0x0b6c50` | `0x09dcf0` | 直接调用、跨 ABI handler 序列、9 Blob 差分 | confirmed |
| VM context allocator | `0x111a18` | `0x103bc0` | 直接实跑；分配 `0xa0` context | confirmed |
| VM output length | `0x111904` | `0x103aa0` | ARM64 直接实跑；x64 结构对齐 | ARM64 confirmed / x64 inferred |
| VM output copy | `0x111910` | `0x103ab0` | ARM64 直接实跑；x64 结构对齐 | ARM64 confirmed / x64 inferred |
| operand push | `0x110978` | `0x102640` | 独立栈探针 | confirmed |
| operand pop | `0x110a94` | `0x102700` | 独立栈探针；空栈 `error=3` | confirmed |
| operand dup | `0x111018` | `0x102f50` | 独立栈探针 | confirmed |
| operand pick(depth) | `0x110bc8` | `0x1027d0` | 独立栈探针；越界 `error=4` | confirmed |
| operand roll(depth) | `0x1111c0` | `0x1030a0` | 独立栈探针；越界 `error=4` | confirmed |
| frame-relative store32 | `0x10fe08` | `0x101db0` | handler 入参与 frame 差分 | confirmed |
| current frame length | `0x1104e8` | `0x1022b0` | 直接调用/跨 ABI 序列 | confirmed |
| frame seek/set length | `0x110504` | `0x1022c0` | 直接调用/跨 ABI 序列 | confirmed |
| push frame | `0x1102f0` | `0x102150` | frame depth 变化 | confirmed |
| lazy atomic guard helper | `0x112730` | 未命名 | LDXR/STXR/CAS 语义 | confirmed |

## 其他 ABI JNI 导出

| ABI | `nOnResume` | `nSign` |
|---|---:|---:|
| armeabi-v7a | `0x0a4330` | `0x0a4fa0` |
| x86 | `0x09b6d0` | `0x09c330` |

## VM 程序证据

- ARM64 的 `0xb6c50` 实际代码约 4–5 KB，但因错误/尾块远跳，通用分析器会把函数范围误扩到约 150 KB。
- 入口原型经直接寄存器/栈断点验证为 `program(error*, vm*, count=9, Blob* x9)`；64 位 `Blob={u32 byte_len; u32 pad; u8* data}`。
- 输入按 big-endian 32 位 word 装载到 frame。零值形状探针的 9 个长度为 `8,40,8,512,4,4,32,4,32` 字节。
- 输出 helper 返回 304 字节；不要把该程序仅凭形态重命名为单一“crypto core”。

完整静态 handler 调用序列保存在：

- `recovered/signature-vm-calls-arm64.tsv`
- `recovered/signature-vm-calls-x86_64.tsv`

