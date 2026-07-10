# `android-so-reversing` 安装后验证

## 目录与静态验证

- Codex：`~/.codex/skills/android-so-reversing`
- Claude Code：`~/.claude/skills/android-so-reversing`
- 两端内容使用逐文件 SHA-256 对比。
- `quick_validate.py`：两端均通过。
- bundled Python utilities：4 个单元测试通过。
- `scripts/elf_inventory`：在默认 `python3` 损坏的本机仍能自动选择健康解释器，正确输出四 ABI 哈希/架构，并确认无 RWX load segment。
- `scripts/validate_trace`：接受真实 schema fixture，校验 `pc-base=relative_pc` 和模块范围。

## 隔离代理

- 第一次 Codex CLI 运行在脚本解释器问题修复前启动，随后还遇到服务端 429；它成功加载了 Skill，但没有形成最终报告。该失败促成了 `python_runner.sh`/直接 shell wrapper。
- Claude Code CLI 能发现安装路径，但本机未登录，模型级 forward test 被 `/login` 阻塞；原始输出保存在 `.omx/artifacts/claude-android-so-forward-20260710.md`。
- 修复后另启 Codex native 子代理执行同一隔离场景，成功完成：
  - 通过 shipped `classes.jar` 恢复 `nSign(...)[B` 精确 descriptor 和 Java HMAC/key2 链；
  - 否定 NOTES 中“返回 String”“0x8b510 是主 hash”“退出 0+空签名算成功”“证书无关”四项假设；
  - 正确把无 oracle/key/certificate/trace 列为完成缺口，没有冒充移动端逐字节一致；
  - 实际运行 `scripts/elf_inventory` wrapper，正确得到 ARM64/x86_64 哈希、架构和 no-RWX 结论；
  - 结束时复核隔离夹具哈希，未修改样本。

该 forward test 只看到隔离夹具，没有看到本项目已完成的 unidbg/recovered 产物，因此它仍把“无 harness/trace”列为夹具缺口；这正是预期的上下文隔离，而不是 Skill 失败。
