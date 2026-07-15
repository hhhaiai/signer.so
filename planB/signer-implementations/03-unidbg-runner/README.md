# 03 — 自包含 Unidbg runner

这一目录物理包含完整的 Java/Maven 源码快照，不再从项目中的其他源码目录编译：

```text
03-unidbg-runner/
├── pom.xml
├── src/main/java/       # 31 个生产源码文件
├── src/test/java/       # 21 个测试源码文件
├── config/
├── docs/
├── build.sh
├── check.sh
├── run-one-click.sh
└── run-direct.sh
```

Maven 的 `pom.xml`、`src/` 和生成的 `target/` 全部位于本目录。构建过程不引用
`../../unidbg-adjust-runner` 或项目内其他 Java 源码树。

Unidbg runner 在 JVM 中构造虚拟 Android/JNI 环境，并在调用方明确执行运行脚本时加载本地
ARM64 目标 SO。它既不是 C++ 算法重写，也不是真机上的 `dlopen` bridge。

## 依赖边界

源码是自包含的，但仍需要以下工具和运行时输入：

- Java 11 或更高版本；
- Maven，以及本机 Maven cache 中已经存在的离线依赖；
- 实际仿真时由调用方提供的本地 `libsigner.so`、APK、profile 和参数文件；
- 目标 artifact project root。默认是本仓库根目录，也可通过 `SIGNER_PROJECT_ROOT` 指定。

这些是构建工具或运行时输入，不是对其他源码目录的依赖。脚本使用 Maven offline 模式，不会
联网下载文件。

## 构建

### 首次下载依赖

如果需要准备一份属于本目录的 Maven 离线缓存：

```bash
./download-dependencies.sh
```

默认下载到：

```text
dependencies/m2-repository/
```

缓存存在时，`build.sh` 和 `check.sh` 会自动使用它。也可以通过：

```bash
MAVEN_REPO_LOCAL=/absolute/local/m2-repository ./build.sh
```

覆盖缓存位置。

也可以指定目录：

```bash
./download-dependencies.sh /absolute/local/m2-repository
```

该脚本只下载 `pom.xml` 声明的 Maven dependencies、transitive dependencies 和 build
plugins，并在下载后切换到 Maven offline 模式验证。它不会下载官方 SO、AAR、证书、密钥
或设备 profile。

### 编译

```bash
cd /Users/sanbo/Desktop/api/qbdi/signer-implementations/03-unidbg-runner
./build.sh
```

等价的直接 Maven 命令：

```bash
mvn -o -DskipTests package
mvn -o dependency:build-classpath \
  -Dmdep.outputFile=target/runtime-classpath.txt
```

本目录生成：

```text
target/classes/
target/test-classes/
target/unidbg-adjust-runner-1.0-SNAPSHOT.jar
target/runtime-classpath.txt
```

## 非 native 安全检查

```bash
./check.sh
```

该脚本只运行 8 个选定的 Java 测试类，共 46 个测试，不加载或执行目标 SO：

```text
ApkManifestReaderTest
ApkSigningBlockCertificatesTest
SignerContractTest
AdjustSignatureRunnerDiagnosticsTest
BionicRandomTest
DeviceProfileFlexibleTest
SignerEngineTest
SignerOneClickTest
```

其中 APK parser 测试读取 `SIGNER_PROJECT_ROOT` 下已经存在的冻结测试 artifact；默认值是本仓库
根目录。这些测试只解析文件，不加载 native SO。

完整 `src/test/java` 也已复制到本目录，其中名称带 `NativeIntegrationTest` 的测试会加载本地
native artifact，默认 `check.sh` 故意不运行这些测试。

## One-click JSON 调用

```bash
cp config/request.example.json /tmp/unidbg-request.json
$EDITOR /tmp/unidbg-request.json
./run-one-click.sh /tmp/unidbg-request.json
```

如果目标 SO/APK 不在默认仓库根目录，显式传入 artifact root：

```bash
SIGNER_PROJECT_ROOT=/absolute/local/artifact-root \
  ./run-one-click.sh /tmp/unidbg-request.json
```

Java 入口：

```text
local.SignerOneClick
```

输出前缀：

```text
SIGNER_RESULT_JSON=
```

## Direct 调用

```bash
./run-direct.sh native /absolute/path/to/params.json
./run-direct.sh v4 /absolute/path/to/params.json
./run-direct.sh v5 /absolute/path/to/params.json
./run-direct.sh both /absolute/path/to/params.json
```

指定目标 artifact root：

```bash
SIGNER_PROJECT_ROOT=/absolute/local/artifact-root \
  ./run-direct.sh native /absolute/path/to/params.json
```

Java 入口：

```text
local.AdjustSignatureRunner
```

运行脚本的 classpath 只由本目录的 `target/classes` 和
`target/runtime-classpath.txt` 组成。`SIGNER_PROJECT_ROOT` 只提供目标 SO/APK/rootfs 等运行时
artifact，不提供 Java 源码。

## 文档

- [仿真模型](docs/EMULATION_MODEL.md)
- [输入契约](docs/INPUT_CONTRACT.md)
- [故障排查](docs/TROUBLESHOOTING.md)
