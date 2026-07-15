# Unidbg 输入契约

`SignerOneClick` 接受：

```text
SignerOneClick <input.json> [project-root]
```

包装脚本从本目录 `target/classes` 启动该入口，并将 `SIGNER_PROJECT_ROOT` 作为可选的
`project-root`：

```bash
SIGNER_PROJECT_ROOT=/absolute/local/artifact-root \
  ./run-one-click.sh /absolute/local/input.json
```

未设置时，脚本默认使用当前仓库根目录。`project-root` 是 SO/APK/rootfs 等目标 artifact 的
运行时根目录，不是 Maven 源码路径。

顶层 JSON：

| 字段 | 必需 | 说明 |
|---|---:|---|
| `device` | 否 | `DeviceProfile`；缺失时使用 builder 的非敏感默认值 |
| `sign` | 是于实际签名 | V4/V5 请求、参数和调用语义 |
| `expectedResult` | 否 | 内联结果 parity oracle |
| `expectedResultFile` | 否 | 本地结果文件；与 `expectedResult` 互斥 |

重要 `device` 子域：

```text
packageName, androidApi, baseApk, certificateFile/certificateText,
signingKeyText, build, systemProperties, settings, sharedPreferences,
locale, timezone, sensors, display, applicationInfo, runtime, filesystem, jni
```

`runtime` 和 `filesystem` 中的值均来自 JSON 调用方。示例只包含合成数据；真实审计输入应由
授权实验采集流程提供，不能由 runner 推测或虚构。

Direct runner 接受：

```text
AdjustSignatureRunner <project-root> --mode=native|v4|v5|both
  [--params-file=/absolute/local/params.json]
  [--activity-kind=session]
  [--client-sdk=android4.38.5]
```

对应包装脚本：

```bash
SIGNER_PROJECT_ROOT=/absolute/local/artifact-root \
  ./run-direct.sh native /absolute/local/params.json
```
