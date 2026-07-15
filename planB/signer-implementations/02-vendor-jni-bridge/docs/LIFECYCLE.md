# 生命周期

状态：

```text
Created -> Resumed -> Closed
```

默认 `VendorCompatible` policy 允许 `nSign` 自己完成官方库所需的初始化路径，因此显式
`nOnResume` 不是底层强制条件。需要高层严格顺序时可使用
`RequireOnResumeBeforeSign` policy。

安装新 backend 时：

1. 配置锁串行化 replacement；
2. 从全局 slot 取出旧 layer；
3. 关闭旧 layer；
4. 安装新 layer。

官方 JNI entry 一旦进入过，`close()` 不立即 `dlclose` DSO，因为官方库可能注册进程级
callback 或 timer。compat layer 会清空自身函数指针并进入 Closed，底层 handle 留到进程
结束，避免悬空回调。

官方路径必须由调用方提供且为绝对路径。bridge 会拒绝解析结果指向自身 JNI wrapper 的
self-reference 配置。
