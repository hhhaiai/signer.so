# Adjust Signature SDK 自动下载脚本设计

## 目标

在 `adjust_signature_sdk` 目录中提供一个只依赖 Python 3 标准库的下载脚本。脚本每次运行时从 GitHub 自动发现 `adjust/adjust_signature_sdk` 的全部 Releases 和附加资产，下载本地缺少或不完整的资产，并跳过已经完整下载的文件。

## 范围

脚本必须：

- 读取 GitHub Releases API 的全部分页结果，包括正式版本和 beta 版本。
- 下载每个 Release 的全部附加资产，不包含 GitHub 自动生成的 Source code ZIP/TAR。
- 将资产保存到 `adjust_signature_sdk/<release-tag>/<asset-name>`。
- 以脚本所在目录作为固定输出根目录，不受调用时工作目录影响。
- 避免重复下载已经完整存在的资产。
- 支持中断文件的断点续传，并安全处理不支持 Range 请求的服务器。
- 在可用时校验 GitHub 提供的 SHA-256 摘要，否则至少校验精确字节数。
- 单个资产失败时继续处理其他资产，最后以非零退出码报告整体失败。

脚本不负责：

- 删除 GitHub 已撤下的本地历史资产。
- 自动解压 AAR 或 ZIP。
- 定时运行或安装系统计划任务。
- 使用 GitHub 登录凭据上传或修改任何远端内容。

## 文件与命令

主脚本：

```text
adjust_signature_sdk/download_all.py
```

测试：

```text
adjust_signature_sdk/tests/test_download_all.py
```

从仓库根目录运行：

```bash
python3 adjust_signature_sdk/download_all.py
```

从下载目录运行：

```bash
cd adjust_signature_sdk
python3 download_all.py
```

两种调用方式必须产生相同的输出位置。

## 架构

实现保持为一个小型模块，但将职责分为可独立测试的函数：

1. `fetch_releases`
   - 请求 Releases API。
   - 解析响应中的分页 `Link` 头，直到没有下一页。
   - 返回 Release 标签及其资产元数据。

2. `plan_asset`
   - 根据脚本目录、Release 标签和官方资产名构造目标路径。
   - 验证标签和资产名不会逃逸输出目录。
   - 根据正式文件和 `.part` 文件状态决定 `skip`、`resume` 或 `download`。

3. `download_asset`
   - 下载到 `<asset-name>.part`。
   - 存在部分文件时发送 `Range: bytes=<offset>-`。
   - 仅在服务器返回匹配的 `206 Partial Content` 时追加。
   - 服务器返回完整内容或 Range 不可用时，清空临时文件并重新下载。
   - 下载完成并通过校验后，使用原子替换生成正式文件。

4. `verify_asset`
   - 首先检查精确字节数。
   - GitHub 元数据包含 `sha256:<hex>` 时，再流式计算并比较 SHA-256。

5. `main`
   - 自动发现全部 Releases。
   - 顺序处理资产，打印可读状态。
   - 汇总发现、跳过、下载和失败数量。
   - 有任一失败时返回非零退出码。

## 数据流

```text
GitHub Releases API
        |
        v
分页发现 Release 与 assets
        |
        v
<script-dir>/<tag>/<asset-name>
        |
        +-- 完整正式文件 --------> SKIP
        |
        +-- 可信 .part ----------> 尝试 Range 续传
        |
        +-- 正式文件错误 --------> 从零下载
        |
        +-- 文件不存在 ----------> 从零下载
                                      |
                                      v
                             大小与摘要校验
                                      |
                         +------------+------------+
                         |                         |
                       通过                      失败
                         |                         |
                  原子改为正式文件          保留 .part 并记录失败
```

## 不重复下载规则

脚本不能仅凭“文件名存在”就跳过，因为中断或损坏文件也可能使用正式文件名。规则如下：

- 正式文件存在，大小等于 GitHub `asset.size`，且可用的 SHA-256 也匹配：打印 `SKIP`，不请求资产下载 URL。
- 正式文件存在但大小错误：删除不可信内容并从零重新下载。脚本不能证明任意现有文件是远端资产的正确前缀，因此不能安全续传它。
- 正式文件大小正确但 SHA-256 错误：删除不可信的部分状态，从零重新下载。
- 只有由本脚本留下的 `.part` 存在且小于远端大小：尝试断点续传。
- `.part` 等于远端大小：直接执行完整性校验，成功后改为正式文件。
- `.part` 大于远端大小：从零重新下载。
- 下载完成前绝不生成新的正式文件。

因此，正常重复运行只访问轻量的 Releases API，并跳过全部已完成资产。

## HTTP 行为

- API 使用 `Accept: application/vnd.github+json`。
- 设置明确的 `User-Agent`，避免 GitHub 拒绝匿名请求。
- 支持环境变量 `GITHUB_TOKEN`；存在时发送 Bearer token，以提高 API 限额。匿名运行仍然可用。
- API 和资产请求设置有限超时，避免无限挂起。
- 对临时网络错误进行有限次数重试，并采用短暂递增退避。
- 不在日志中打印 token 或完整授权头。
- Release API 返回非成功状态、无效 JSON 或无效字段时，输出明确错误。

## 路径安全

Release 标签和资产名来自远端数据，不能未经检查直接拼接：

- Release 标签必须是单个目录名，拒绝空值、`.`、`..`、斜杠和反斜杠。
- 资产名必须等于其 basename，拒绝空值、`.`、`..`、斜杠和反斜杠。
- 解析后的目标路径必须位于脚本目录之下。

无效远端条目记为失败，但不阻止其他合法资产处理。

## 输出与退出状态

单项状态示例：

```text
SKIP     v3.67.0/adjust-android-signature-3.67.0.aar
DOWNLOAD v3.68.0/adjust-android-signature-3.68.0.aar
RESUME   v3.68.0/AdjustSigSdk-iOS-Static-3.68.0.a.zip from 524288 bytes
OK       v3.68.0/AdjustSigSdk-iOS-Static-3.68.0.a.zip
ERROR    v3.68.0/example.zip: size mismatch
```

最终汇总示例：

```text
Releases: 30, assets: 95, skipped: 91, downloaded: 4, failed: 0
```

退出状态：

- `0`：API 发现和全部资产处理成功。
- `1`：API 失败、元数据无效或至少一个资产失败。

## 错误处理

- API 发现失败时无法得到可信下载清单，立即终止且不修改现有 SDK 文件。
- 单个资产下载失败时保留 `.part`，继续处理后续资产。
- 校验失败时不得将 `.part` 改为正式文件。
- `Ctrl+C` 保留当前 `.part`，以便下次运行续传，并以中断状态退出。
- 磁盘、权限及路径错误必须包含相关 Release/资产路径，但不得泄露凭据。

## 测试策略

测试只使用 Python 标准库，在临时目录启动本地 HTTP 服务，不依赖 GitHub 网络状态。测试先于实现编写，并逐项经历失败和通过：

1. 分页 API 自动发现多个 Release 和资产。
2. 输出根目录固定为脚本目录。
3. 正确创建 `<tag>/<asset-name>`。
4. 已存在且完整的文件不请求资产 URL。
5. `.part` 文件通过合法 `206` 响应断点续传。
6. 服务器忽略 Range 并返回 `200` 时安全地从零重下，不重复拼接内容。
7. 大小不符时保留 `.part` 并返回失败。
8. SHA-256 不符时不生成正式文件。
9. 单个资产失败后继续下载其他资产，最终返回非零状态。
10. 恶意标签或资产路径被拒绝，不能写出输出目录。
11. 对当前已经下载完整的目录运行时，91 个资产全部跳过且不重复下载。

## 验收标准

- 在仅安装 Python 3 的环境中可以运行。
- 能自动发现 GitHub 当前及未来新增的所有 Release 资产。
- 第二次运行不会重新下载任何未变化且校验通过的资产。
- 中断后再次运行能够安全续传或重新下载，不会产生拼接损坏文件。
- 本地最终正式文件的路径、字节数和可用 SHA-256 与 GitHub 元数据一致。
- 自动化测试全部通过，且使用真实本地 HTTP 请求验证下载行为。
