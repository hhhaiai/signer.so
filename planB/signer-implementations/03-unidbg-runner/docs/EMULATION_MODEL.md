# Unidbg 仿真模型

## 自包含源码布局

本实现的 `pom.xml`、`src/main/java`、`src/test/java` 和 Maven `target` 都位于
`signer-implementations/03-unidbg-runner`。构建和测试不读取仓库中另一份 Java 源码。

工作区 project root 只在实际运行时作为本地目标 artifact 根目录传给 runner，例如目标
`libsigner.so`、APK 和 `unidbg-rootfs`；它不参与本实现的 Java 编译。

核心组件：

| 类 | 职责 |
|---|---|
| `SignerOneClick` | 解析一份 JSON，构造 profile/request，输出结构化结果 |
| `SignerEngine` | 管理一次签名流程和 V4/V5 结果包装 |
| `AdjustSignatureRunner` | 加载 SO、实现 JNI 回调和直接 native 调用 |
| `ConfigurableAndroidARM64Emulator` | 配置 ARM64 syscall、文件和 socket 行为 |
| `DeviceProfile` | 保存调用方给出的虚拟设备观测 |
| `SignerDirectRunner` | 从自实现 Java Signer 路径进入 NativeLibHelper/Unidbg |

仿真环境可以模型化 Android Build、系统属性、settings、PackageManager、证书、APK 路径、
传感器、显示参数、文件内容、缺失路径、时间、随机输入、socket 响应和 JNI 特定返回。

它的证据价值是观察原始 ARM64 指令在受控输入下的分支、寄存器、内存和 JNI 交互；不能把
Unidbg 环境等同于真实 Android 内核、ART、SELinux 或厂商设备。
