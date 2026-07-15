# arm64 JNI exception consumer `0x92a20`

本报告只读取目标 ELF 与静态反汇编，不加载目标 SO。

## ABI 与 JNI slots

入口只有一个业务参数：

```text
x0 = JNIEnv*
```

`0x92a38..0x92a54` 读取 `JNIEnv` vtable `+0x78` 并调用，slot 对应
`ExceptionOccurred`。返回的 throwable reference 保存在 `x20`。

如果 reference 非空，`0x92ac8..0x92ae4` 严格按以下顺序调用：

```text
JNIEnv vtable +0x80 = ExceptionDescribe
JNIEnv vtable +0x88 = ExceptionClear
```

没有 `DeleteLocalRef`。`0x92b04..0x92b10` 最终返回
`exceptionReference != nullptr` 的 0/1。

## 等价伪代码

```cpp
jthrowable exception = env->ExceptionOccurred();
if (exception != nullptr) {
    env->ExceptionDescribe();
    env->ExceptionClear();
}
return exception != nullptr;
```

对应直接 C++：

```text
RecoveredJniExceptionOperations92a20
runRecoveredJniExceptionConsumer92a20(...)
```

## 可重复证据

```bash
python3 .omx/static-audit-20260713/analyze_jni_exception_consumer_92a20.py
```

预期：

```text
arm64 JNI exception consumer 0x92a20 evidence: PASS
```
