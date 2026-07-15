# 错误模型

| `SignerError` | 数值 | 典型条件 | JNI 映射 |
|---|---:|---|---|
| `Ok` | 0 | 成功 | 无异常 |
| `InvalidArgument` | 1 | 空路径、空 JNIEnv、相对路径 | `IllegalArgumentException` |
| `InvalidParameterFormat` | 2 | 参数格式错误 | `IllegalArgumentException` |
| `InvalidState` | 3 | production 请求 fake backend 等 | `IllegalStateException` |
| `BackendClosed` | 4 | close 后调用 | `IllegalStateException` |
| `BackendNotConfigured` | 5 | 未安装 backend | `IllegalStateException` |
| `LibraryOpenFailed` | 10 | `dlopen` 失败 | `UnsatisfiedLinkError` |
| `SymbolMissing` | 11 | 官方 JNI export 缺失 | `UnsatisfiedLinkError` |
| `VendorExceptionPending` | 12 | 官方函数留下 Java exception | 保留现有 pending exception |
| `VendorSelfReference` | 14 | 路径解析回 compatibility wrapper | `UnsatisfiedLinkError` |
| `InternalError` | 100 | C++ 异常或内部契约错误 | `RuntimeException` |

`libsigner_compat_last_error()` 返回当前线程最近一次 C 配置 API 错误文本。JNI 路径不会覆盖
已经 pending 的 Java exception。
