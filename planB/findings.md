# 调查发现

## 当前权威快照（2026-07-15）

- `native-reimplementation/recovered_primitives.cpp`
  - 31,213 行
  - SHA-256 `abafec344a954689d9ec30953fa6d24c8ddc5c21480d92720371b976e4f336fa`
  - 仍含生产格式签名组合、固定认证/加密 material、AES/HMAC、`SIGNATURE_HEX` CLI 和 exact-oracle 历史回归。
  - 当前安全结论：Critical、audit-only，不得进入新 production target，也不得在本轮执行。

- 当前新增兼容层文件已经存在：
  - `signer_backend.h/.cpp`
  - `signer_jni_bridge.h/.cpp`
  - `fake_signer_backend.h/.cpp`
  - `signer_backend_test.cpp`
  - `signer_bridge_config_test.cpp`
  - `CMakeLists.txt`

- 当前 `CMakeLists.txt` 的 production target 未列入 `recovered_primitives.cpp`，Fake 也被设计为测试单独链接；仍需实测 CMake、production DSO 和字符串 gate。

- 旧 `native-reimplementation/build-and-test.sh` 仍直接编译和执行 `recovered_primitives.cpp`，并比较多组 production-format exact oracle；这是当前最明显的默认入口冲突。

- `native-reimplementation/build/` 仍保留大量旧 recovered 可执行产物。这些是历史产物，不应被新的安全构建脚本调用；是否删除需避免未经说明破坏用户历史证据，当前优先隔离而非删除。

## 已确认接口合同

- JNI exports：
  - `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume`
  - `Java_com_adjust_sdk_sig_NativeLibHelper_nSign`
- Java descriptors：
  - `nOnResume: ()V`
  - `nSign: (Landroid/content/Context;Ljava/lang/Object;[BI)[B`
- `Object` descriptor 不得收窄为 `Map`；自然 Java 调用虽传 `Map<String,String>`，Vendor 模式仍必须把原对象引用原样转发。
- 输入 JNI references 为调用期 borrowed refs；不得删除传入 refs、缓存 `JNIEnv*` 或跨调用持有 local refs。
- Vendor `jbyteArray` 返回必须保持 opaque；不得读取、复制、解析、比较或编码。
- Vendor `null + no pending exception` 是普通可观察结果，不能自动改成 wrapper 异常。
- Vendor pending exception 不得 clear 或覆盖。

## 待验证重点

- `signer_backend.cpp` 在 vendor sign 后如何表示 pending exception/null，并且 bridge 是否确实不覆盖。
- vendor DSO 在 sign 返回 null 或 exception 后是否仍被视为已经进入可能安装 timer/callback 的路径，从而不卸载。
- bridge 配置替换、close 和并发调用的锁顺序是否存在死锁或对象生命周期竞态。
- C API `last_error` 的线程局部/全局语义是否文档化且不会记录敏感输入。
- production shared library 的实际 export set 与敏感字符串内容。
- CMake 在当前 macOS/JDK 环境能否正确找到 JNI。

## 最新基线验证

- 工具链：Apple Clang 21.0.0；`JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-19.0.1/Contents/Home`。
- `signer_backend_test`：PASS。
- `signer_bridge_config_test`：PASS。
- `recovered_primitives.cpp`：`-std=c++17 -Wall -Wextra -Werror -fsyntax-only` PASS，未执行。
- 最新 production dylib 能构建；尚未完成 export/strings/sanitizer/CMake gate，因此不能据此声称全部验收完成。

## 主线程初步代码风险（待回归测试确认）

- `VendorSignerBackend::onResume()` 只在 vendor 返回且无 pending exception 后设置 `resumed_`；如果已经进入 vendor 但留下 Java exception，随后 `close()` 仍可能 `dlclose`。安全合同要求“一旦进入 nOnResume/nSign 就保留 DSO”，因此需要用 vendor-entered 状态与回归测试修正。
- backend/layer 当前把 `nativeLibHelper` receiver 为 null 当作 wrapper `InvalidArgument`；原 JNI receiver 不参与已确认的业务参数合同，Vendor 模式更精确的做法是只验证 `JNIEnv*` 并原样转发 receiver，包括 null，不在 wrapper 发明额外业务校验。
- CMake 当前只注册 `signer_backend_test`，尚未注册 `signer_bridge_config_test`，所以 `ctest` 不能覆盖 production 拒绝 Fake/配置边界。

## 已修复并验证

- 将 vendor 生命周期标记从“成功 resume”改为“已经进入 vendor export”；标记在调用前设置，因此 pending Java exception 后也不会 `dlclose`。
- Vendor/compatibility layer 只要求有效 `JNIEnv*`；receiver 和所有业务对象保持 opaque，可为 null 并交由官方 vendor 决定行为。
- 增加 null 引用与 `jint` 极值回归，当前 backend test PASS。
- CMake 新增 test-enabled bridge 与 production bridge 两个测试目标；production 目标不链接 Fake，并明确验证 fake installer 返回 `InvalidState`。最新 CMake configure/build/ctest 3/3 PASS。
- 官方 `classes.jar` 已用 `javap -private -s` 重新确认 descriptor：`nOnResume ()V`、`nSign (Landroid/content/Context;Ljava/lang/Object;[BI)[B`。
- 四个官方 Android ELF（arm64-v8a、armeabi-v7a、x86_64、x86）均为 stripped shared object，SONAME `libsigner.so`，动态导出只观察到两个目标 JNI 函数，无 `JNI_OnLoad/JNI_OnUnload`。
- 首次 CMake production dylib 审计发现 static core 的 C++ 符号被额外导出；已给 core 增加 hidden visibility。重建后实际全局导出精确收敛为 7 个：2 个 JNI + 5 个配置 C API，CMake 测试仍 3/3 PASS。
- Android NDK 24 首次 arm64 构建仍因静态 libc++ 带出 571 个全局定义；已对非 Apple production target 增加 `-Wl,--exclude-libs,ALL`。修复后四 ABI 均成功生成纯 C++ `libsigner_compat.so`，SONAME 正确且每个仅 7 个全局导出：
  - arm64-v8a / AArch64：7；
  - armeabi-v7a / ARM：7；
  - x86_64 / AMD64：7；
  - x86 / i386：7。
- legacy gate 的一次外层 command-substitution 包装返回了不一致的空输出/exit 0；随后以 `/usr/bin/env -u ... /bin/bash -x` 直接复测，脚本在第 6-10 行明确拒绝并 exit 1，且无效 `CXX` 未被调用。以直接 trace 作为当前证据。

## 仓库级残留（不属于新 production SO 的链接闭包）

- `test-recovered-backend.sh:8-11` 仍通过 `generate-signer.sh` 执行 recovered backend 的冻结结果验证。
- `unidbg-adjust-runner/src/main/java/local/DeviceProfile.java:144-147` 仍允许 `runtime.backend=recovered`。
- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/NativeLibHelper.java:121-129` 仍把该配置路由到 `RecoveredNativeBackend`。
- `unidbg-adjust-runner/src/main/java/com/adjust/sdk/sig/RecoveredNativeBackend.java:302-317` 仍会按需把 `recovered_primitives.cpp` 编译成 executable。
- 结论：`native-reimplementation/libsigner_compat` 的 production target 已安全隔离，但整个仓库尚未移除历史 recovered production-format 执行能力；最终报告必须把它列为 Critical repository-level gap。
