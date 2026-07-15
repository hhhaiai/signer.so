# 02 — Vendor JNI bridge

这一目录物理包含非敏感 JNI/ABI compatibility layer 的完整 C++ 源码、
CMake 构建定义、测试和边界审计，不依赖项目中的其他源码目录即可编译。

它不实现生产签名算法，而是通过 `VendorSignerBackend` 加载调用方明确提供的官方本地
`libsigner.so`，解析官方 JNI exports 并原样转发 JNI 参数。

## 调用链

```text
NativeLibHelper.nSign
  -> libsigner_compat JNI wrapper
  -> SignerCompatibilityLayer
  -> VendorSignerBackend
  -> dlopen + dlsym
  -> caller-supplied official libsigner.so
```

## Host 构建

```bash
./build-host.sh
```

输出在本目录 `build/host/`。

源码布局：

```text
include/  公共头文件
src/      backend、JNI bridge 和测试专用 Fake backend 实现
tests/    三个 host 测试程序
```

## Android 构建

```bash
export ANDROID_NDK_HOME=/absolute/path/to/android-ndk
./build-android.sh arm64-v8a
```

支持 `arm64-v8a`、`armeabi-v7a`、`x86_64`、`x86`。输出在：

```text
build/android/<abi>/libsigner_compat.so
```

## 安装 Vendor backend

调用方必须在进入 `nOnResume`/`nSign` 前调用：

```cpp
libsigner_compat_install_vendor(absoluteOfficialSoPath);
```

完整示例见 `examples/native_install_example.cpp`。路径必须是绝对路径，compatibility SO 与
官方 SO 必须使用不同文件名，避免递归加载自己。

## 验证

```bash
./check.sh
```

执行自包含布局检查、host build、3 个 CTest，以及 production artifact 的
export/forbidden-marker 边界审计。

## 文档

- [JNI 与 ABI](docs/JNI_ABI.md)
- [生命周期](docs/LIFECYCLE.md)
- [错误模型](docs/ERROR_MODEL.md)
