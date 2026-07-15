# 三条实现路线的架构

## 1. Recovered C++

```text
调用方字段
  -> recovered executable CLI
  -> NativeInputPresence（区分缺失与 0/false/empty）
  -> NativeInputs
  -> buildPayload()
  -> deriveIv()
  -> AES/CBC/PKCS#7 + HMAC
  -> sign(const NativeInputs&)
  -> byte vector / SIGNATURE_HEX
```

这是源码层恢复路线，不加载官方 SO。当前函数清单为 348/388 recovered，不能描述成整个 SO
逐函数 100% 完成。该文件包含敏感恢复边界，仅用于授权审计和回归，不能链接到 production
`libsigner_compat.so`。

## 2. Vendor JNI bridge

```text
Java NativeLibHelper.nOnResume/nSign
  -> libsigner_compat.so 的同名 JNI exports
  -> SignerCompatibilityLayer
  -> VendorSignerBackend
  -> dlopen(调用方提供的官方库绝对路径)
  -> dlsym(nOnResume/nSign)
  -> 官方 libsigner.so
  -> 原始 jobject/jbyteArray 返回
```

bridge 不读取 `Map` 内容、不构造签名、不提取证书或设备秘密。它恢复 ABI、生命周期和错误
映射，将无法安全重写的业务交给官方本地库。

## 3. Unidbg runner

```text
JSON DeviceProfile + SignerRequest
  -> SignerOneClick / AdjustSignatureRunner
  -> ConfigurableAndroidARM64Emulator
  -> 虚拟 Android/JNI/文件/属性/网络观察
  -> 加载项目内 ARM64 libsigner.so
  -> 仿真执行 nOnResume/nSign
  -> structured JSON / diagnostic output
```

Unidbg 路线执行原始 ARM64 机器码，不等于 C++ 重写，也不等于真机 JNI 委托。它用于隔离
实验、分支观察和原 SO/C++ 的差异验证。

## 关系

```text
                 ┌─ 01 Recovered C++：源码重写
同一行为契约 ────┼─ 02 Vendor bridge：本机委托
                 └─ 03 Unidbg：ARM64 仿真
```

三条路线可以用相同的合成输入做对比，但不应在 production 中互相 fallback。特别是：

- production bridge 不链接 recovered C++；
- Unidbg 不作为 production backend；
- Fake backend 只用于测试，输出明确不可作为生产签名。

## 物理自包含边界

```text
01-recovered-cpp/
  CMakeLists.txt + src/recovered_primitives.cpp

02-vendor-jni-bridge/
  CMakeLists.txt + include/ + src/ + tests/

03-unidbg-runner/
  pom.xml + src/main/ + src/test/
```

每套构建都只读取本目录中的源码。下列内容是允许的外部输入而不是源码依赖：

- 编译器、CMake、Android NDK、JDK 和 Maven 本地缓存；
- Vendor bridge 的调用方提供官方 SO 绝对路径；
- Unidbg 的本地目标 SO、APK、证书测试文件和 JSON profile；
- 调用方传入的运行时字段。
