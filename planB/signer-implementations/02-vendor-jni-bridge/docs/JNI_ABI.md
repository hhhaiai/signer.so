# JNI 和 C ABI

## JNI exports

```text
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume
Java_com_adjust_sdk_sig_NativeLibHelper_nSign
```

`nSign` Java descriptor 保持：

```text
(Landroid/content/Context;Ljava/lang/Object;[BI)[B
```

参数顺序：

1. `JNIEnv*`；
2. `NativeLibHelper` receiver；
3. Android `Context`；
4. `Object` 参数对象；
5. 输入 `byte[]`；
6. Android API `int`。

Vendor backend 不枚举或转换参数对象，保持 `Object` handle 原样交给官方函数。

## 配置 C exports

```text
libsigner_compat_install_vendor(const char*) -> int32
libsigner_compat_install_fake_for_testing_only() -> int32
libsigner_compat_close() -> int32
libsigner_compat_backend_kind() -> int32
libsigner_compat_last_error() -> const char*
```

production build 中 fake 安装函数仍保持 ABI export，但返回 `InvalidState`，因为 production
artifact 没有链接 `FakeSignerBackend` 实现。
