# `android-so-reversing` 无 Skill 基线

基线代理在 Skill 创建前面对同一类受保护 Android SO 任务时暴露了以下可复现缺口：

- 容易根据函数形态把 ARM64 `0x8b510` 过早命名为“核心哈希”，而运行时证明它执行 `Map.get("environment")`。
- 未优先锁定官方 artifact/精确 JNI descriptor，曾把返回类型保留为字符串猜测；真实 descriptor 是 `...[BI)[B`。
- 容易把 unidbg 退出码 0、空输出或吞掉异常当作成功，而旧 harness 实际在首个 `Context.getPackageName()` 边界停止。
- 对 AndroidKeyStore `key2`、应用证书、Map 顺序、SDK/包身份和移动端 oracle 的一致性条件描述不足。
- 未把 `nOnResume` 的周期 timer、stack/fd/Frida/emulator 检测和受保护 VM 输出中间向量设为完成门槛。

这些缺口构成 Skill 的 RED 阶段；新 Skill 的 strict JNI loop、证据等级和完成门槛直接针对它们。

