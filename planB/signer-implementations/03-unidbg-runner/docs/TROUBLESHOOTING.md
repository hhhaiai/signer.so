# Unidbg 故障排查

## Maven offline 依赖缺失

```text
Cannot access ... in offline mode
```

表示本机 Maven cache 不包含 `pom.xml` 声明的依赖。安全默认脚本不会联网下载；应从公司
批准的离线依赖缓存或内部制品流程准备依赖。

本实现只读取当前目录的 `pom.xml` 和 `src/`。若错误路径中出现仓库根目录下另一份
`unidbg-adjust-runner/pom.xml`，说明调用的不是本目录脚本。

## Java 版本

项目 compiler source/target 为 Java 11。检查：

```bash
java -version
mvn -version
```

## 找不到本地 SO/APK

默认 project root 是：

```text
/Users/sanbo/Desktop/api/qbdi
```

也可以显式设置：

```bash
export SIGNER_PROJECT_ROOT=/absolute/local/artifact-root
```

并检查 JSON 中的相对路径是相对于输入 JSON 所在目录解析，project artifact 路径存在于当前
workspace。脚本不下载缺失文件。

`check.sh` 中的 APK parser 测试也通过同一 `SIGNER_PROJECT_ROOT` 找到冻结测试 APK/AAR；它们
只进行 Java 文件解析，不执行目标 SO。

## JVM native crash

Unicorn/Unidbg 在同一 macOS ARM64 JVM 重复创建 emulator 时可能产生 native crash。现有
Surefire 设置使用单 fork 且不复用 fork。一次调用只创建所需 runner，故障日志按 Maven
配置写入本目录的 `target/hs_err_pid*.log`。

## 行为与真机不同

优先核对 Android API、Build、system properties、文件内容/缺失路径、certificate/APK、
时间、urandom、socket responses 和 JNI overrides。Unidbg 结果只能证明当前 profile 下的
仿真行为，不能直接扩展为所有真机行为。
