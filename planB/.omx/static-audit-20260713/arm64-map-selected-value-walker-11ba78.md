# arm64 Map selected-value walker `0x11ba78`

本报告只执行静态 ARM64 指令解释，不加载目标 SO。

## ABI

```text
x0 = uint32_t* status
x1 = JNIEnv*
x2 = Map object
x3 = callback
x4 = opaque callback state
```

## 表与所有权

函数通过 once gate 解码 `0x145a30` 的 1363 bytes（XOR `0x52`），随后执行一次
`malloc(1363)`，把完整 CSV 复制到可写 scratch，并逐个把逗号替换成 NUL。

这不是 100 次 per-key allocation；整个调用只有一个 allocation 和一个统一 `free`。
即使入口 status 已非零，函数仍会分配/复制 scratch，然后在 Map 操作前退出并释放。
allocation 失败覆盖 status 为 `2`，并调用 `free(nullptr)`。

## 每个 key 的选择规则

1. 调用 `0x8af4`：
   - `secret_id -> 1400000`
   - `headers_id -> 9`
   - `native_version -> 3.67.0`
2. special miss 时调用 `Map.containsKey`；
3. contains 为 false 时跳过该 key；
4. contains 为 true 时调用 `Map.get`；
5. 调用 caller callback：

```text
callback(status, JNIEnv, nativeKey, selectedJavaValue, opaque)
```

一个关键边界：contains 为 true 时，即使 `Map.get` 返回 null，只要 helper status 仍为
零，callback 仍会收到 null。

## cleanup 与失败

- callback 返回后，只要 selected reference 和 JNIEnv 都非空，就调用 `DeleteLocalRef`；
- callback 写入非零 status 后，仍先删除该 reference，再停止；
- `0x8af4` 或 `Map.get` 在发布 reference 后写入失败 status 时，不进入 callback，也不
  删除该 reference；这两个失败边界保留 native leak；
- `containsKey` 失败不调用 get/callback；
- 所有正常/错误循环出口最终释放 1363-byte native scratch。

直接 C++：

```text
RecoveredMapSelectedValueWalkerOperations11ba78
runRecoveredMapSelectedValueWalker11ba78(...)
```

可重复证据：

```bash
python3 .omx/static-audit-20260713/analyze_map_selected_value_walker_11ba78_full.py
```

脚本覆盖：fresh decoder、steady-state decoder、空 Map、普通 present/null value、
allocation failure、contains/get/callback failure、special exception 与 preexisting status。
