# 执行进度

## 2026-07-15 本轮

- 已接管最新目标，并明确停止继续恢复生产签名算法。
- 已读取适用工作流技能并建立文件化执行计划。
- 已确认当前目录不是 Git 仓库，因此改用文件哈希、构建输出和测试日志做证据。
- 已列出当前兼容层文件、旧 recovered 构建产物和关键 SHA-256。
- 已确认 `build-and-test.sh` 仍是旧 production-format recovered 执行入口，需默认隔离。
- 已建立最新本地基线（Apple Clang 21、OpenJDK 19）：
  - backend/Fake/stub vendor 测试：PASS；
  - bridge 配置测试：PASS；
  - `recovered_primitives.cpp` `-fsyntax-only`：PASS，未执行；
  - production `libsigner_compat.dylib`：构建 PASS。
- 已并行派发：安全构建/审计 gate 实现、backend/JNI 只读复审、三份合同/审计文档。
- 已完成 backend 回归红→绿：
  - Vendor 原样转发 null receiver、null Context/Object/byte[]；
  - `jint` 覆盖 `0/-1/INT32_MIN/INT32_MAX`；
  - vendor 一旦进入 `nOnResume`，即使 pending Java exception，close 也不卸载 DSO。
- 已把 CMake 测试从 1 个扩展为 3 个：backend、test-enabled bridge、production bridge 拒绝 Fake；最新 `ctest` 为 3/3 PASS。
- 已重新核对官方四 ABI 文件格式、SONAME、依赖和两个 JNI exports，并用 `javap` 核实 descriptor。
- 已修复 CMake production DSO 额外导出内部 C++ ABI 的问题；当前导出精确为 7 个，CMake 3/3 继续 PASS。
- 已使用本机 Android NDK 24 对 arm64-v8a、armeabi-v7a、x86_64、x86 四 ABI 交叉编译；全部生成 `libsigner_compat.so`，SONAME 正确，导出均精确为 7 个。
- 已修复 Android 静态 libc++ 初次泄露 571 个全局符号的问题，使用 linker archive exclusion 收敛导出。
- ASan+UBSan 首轮因 Apple 平台不支持 `detect_leaks=1` 在测试前中止；这是工具能力限制，不是测试断言或 sanitizer finding，下一轮改用 `detect_leaks=0`。
- 最终安全入口 `build-compatibility-layer.sh`：exit 0；3 个普通测试 PASS、3 个 ASan+UBSan 测试 PASS、production export/marker gate PASS、recovered compile-only PASS。
- 最终 host CMake：3/3 CTest PASS，production dylib 7 个导出。
- 最终 Android API 21 / NDK 24 四 ABI：全部构建 PASS、SONAME `libsigner_compat.so`、各 7 个导出、禁止 marker 0 命中，且 Android configure 未使用 host FindJNI。
- 独立代码 re-review：0 Critical、0 Important、0 Minor。
- legacy `build-and-test.sh` 直接 `bash -x` 复测：默认在编译前拒绝并 exit 1，历史 recovered executable 未执行。
- 三份最终文档已完成并校准 203 个 `file:line` 引用：
  - `NON_SENSITIVE_COMPATIBILITY.md`：239 行，SHA-256 `b40c6bacd06c208018cfe2bb25577492980501a25945bbe1278634ef06455a9b`；
  - `FUNCTION_DELEGATION_MATRIX.md`：100 行，SHA-256 `64a5931258bdc7bea5c7aae13057e7aef24a5c4339d89b4b3ad6a597eaa544ef`；
  - `RECOVERED_PRIMITIVES_AUDIT.md`：194 行，SHA-256 `3543b6e8b154f062b5c5a22129008b9cdf7a4f50e4ca6a08ac85366d00e7eace`。
- 文档陈旧锚点、placeholder 和敏感操作参数扫描无命中；唯一长 hex 为 recovered 文件 SHA-256。
- 仓库级只读残留审计确认：`test-recovered-backend.sh`、Java `NativeLibHelper` 的 `recovered` 分支以及 `RecoveredNativeBackend.ensureExecutable()` 仍可构建/调用历史 recovered signer；它们不进入新 `.so`，但必须在最终报告列为 Critical repository-level gap。
- 最终证据门禁 `FINAL_VERIFICATION=PASS`：安全脚本重跑成功、host CTest 3/3、四 ABI 各 7 exports/0 forbidden markers/正确 SONAME、shell 语法和 reflection JSON 均通过；最终 production dylib SHA-256 `ef8630121487480c823dcba57207bc6ad0a716048c2a03e8151cc9b4fe7d1146`。
- 下一步：等待独立复审并处理 findings，再进行 sanitizer/string gate 和最终仓库残留审计。
