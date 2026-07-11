# `libsigner.so` live 9-Blob VM 输入

## 结论

两次使用同一本地 fixture 的完整 JNI 调用，在进入 ARM64 `0xb6c50` 的 9-Blob signature VM program/orchestrator 之前，Blob 1、4、5 已经发生变化，最终 304 字节输出也变化。它们是明确的上游相关量，但后续 clean-context replay 证明 **9 个 Blob 不是完整状态边界**：VM context/全局 native 状态还参与结果。因此不能把全部非确定性只归因于 Blob 1、4、5。

这不影响纯 PC 运行：`runtime/unidbg/run.sh` 每次都在本地执行原始 `.so` 并返回合法 304 字节。`recovered/vm-zero-vector.json` 是 fresh emulator 的首次直接 VM 调用回归，而不是任意调用序列都不变的无状态向量。

## 捕获条件

- sample：Adjust Signature `3.62.0` ARM64，SHA-256 `fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736`
- package：`com.adjust.fixture`
- SDK：23
- 本地 `key2` fixture：`000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`
- certificate fixture：ASCII `adjust-signature-fixture-certificate`
- 有序参数：`environment=sandbox`、`app_token=test_token`、`event_token=event_123`
- wrapper 注入：`activity_kind=event`、`client_sdk=android5.4.1`
- 断点：module-relative PC `0xb6c50`
- 两次均为全新 `LibSignerEmulator`，`vm_count=9`
- 原始捕获：`runtime/unidbg/vectors/sandbox-vm-inputs-run-1.txt`、`sandbox-vm-inputs-run-2.txt`

固定 Java Map 的 Java-side HMAC-SHA256 可复算为：

```text
0153a16ace52f2ecdc9f8376e8d4964f65cc820a79bb487a32f6bb0b6a425f36
```

输入字符串为：

```text
{environment=sandbox, app_token=test_token, event_token=event_123, activity_kind=event, client_sdk=android5.4.1}
```

当前 9 个入口 Blob 中没有一个能仅凭长度和内容直接等同为该 32 字节 HMAC；它可能已被组合或变换，不能猜测命名。

## 逐 Blob 差分

| Blob | 长度 | run 1 SHA-256 | run 2 SHA-256 | 动态结果 |
|---|---:|---|---|---|
| 1 | 8 | `da4d4d930f5f5d9eeda095ff26841cd7bdc180dc86b3301156c2ee91d3166c5f` | `e8a59c313fff3650ce837f17e5c99487584bc91d572ddad5743a45a3dad06cf2` | 8/8 字节、29 bit 变化；`95a31aed32cfb16c` → `aac3822d70b48373` |
| 2 | 40 | `51e89ac4c60e8520ae3fc18cd4d0b4044523597f003977c1f04ba3f2835bee17` | 相同 | 稳定；ASCII `981BD94063A5BDFB85C41C9BA2C8DF8593A84123`，精确等于 certificate fixture 的 SHA-1 大写 HEX |
| 3 | 8 | `010025ab02e58d59745dd6080610cddf131ff72c580af247943d2975133d762c` | 相同 | 稳定；hex `bffffffffffffd1f`；业务语义未知 |
| 4 | 512 | `1bc22ae0c935eca8501c24126954f75dad1a803ca903370edae8e236b2f413f4` | `3ec3f08fcc060039da3bb597e76b2272c72fb2755f7e4d45ed124de005425c2b` | 443/512 字节、1399 bit 变化；仅共同前缀 4 字节 `00000000`，不能据两次样本命名内部字段 |
| 5 | 4 | `2fcf130cd413e2d21f56906fd72d03bf608a6114e944b372e696e1ca16ece02c` | `170d2f4f1d92f94a822ca3017e433bddb30a3decba06d34a1aeb8a7c7259a3a0` | 4/4 字节、17 bit 变化；`2864952c` → `35586f27` |
| 6 | 4 | `1fc244af2b96d0169a177e2559af29e0484744e4b8501d1044d76c9f7b3cf307` | 相同 | 稳定；hex `00000032`，big-endian 50，等于 Blob 7 字节长度 |
| 7 | 50 | `cc5c8ba7bf5e38046fe11f43bf6fb9113fda97e603f68c9d1810b70341d85c04` | 相同 | 稳定；ASCII `test_tokensandboxevent_1231300000eventandroid5.4.1`，即 `app_token + environment + event_token + 1300000 + activity_kind + client_sdk` |
| 8 | 4 | `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119` | 相同 | 稳定；hex `00000000`；语义未知 |
| 9 | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 相同 | 两次均为空 |

## 输出差分

| 运行 | 长度 | SHA-256 |
|---|---:|---|
| run 1 | 304 | `5e5873b4c64c1822d32493f4a4724b09bf758d1f9cbe4ff249c5191839d83e3e` |
| run 2 | 304 | `8085ca345ed8c5e740385389cd0a822cedd2e421d13781bf2b6dd972ebbf4ce3` |

两份输出有 302/304 字节、1242 bit 不同；仅 offset 159 的 `0x6d` 与 offset 272 的 `0x2b` 相同。强扩散只证明多字节依赖，不能据此把整个 `0xb6c50` 程序命名为某个 SHA/AES 原语。

## Clean-context replay 纠偏

将捕获的 9 个 Blob 直接传给 `VM_INIT(0x111a18)` 新建的 context，再调用 `0xb6c50`：

| replay | SHA-256 | 与 live 捕获相同 |
|---|---|---|
| run 1 blobs，fresh process 首次调用 | `3277d7580f37fea72f88e5b76cbf40a3bc4ba5c4e5c65b126f7bf3ddd52aad90` | 否 |
| run 2 blobs，同一 module 第二次调用 | `5f1ed6ea65ba8222b9e1bd2398d3861c1bc5d2ba5406e9a4a69889b731300e92` | 否 |

更关键的是，在另一个 fresh process 中对完全相同的 run 1 Blobs 连续调用两次：

```text
first  = 3277d7580f37fea72f88e5b76cbf40a3bc4ba5c4e5c65b126f7bf3ddd52aad90
second = 8256e0662758c2a26c000c7f23d4d2e708b56e9496d4fdc0cca54ccbe1404717
```

两次均 `error=0`、长度 304，却输出不同。这证明 `0xb6c50` 除显式 9 Blob 外还观察/推进 mutable native state，或者 live outer pipeline 在调用前预填充了 `VM_INIT` 单独不能恢复的 context/frame 状态。

此前逐一替换 Blob 1/4/5 的 mixed replay 也产生不同 hash，但因每次调用的隐式状态不相同，**这些 hash 不能作为单变量因果证据**。原始记录保存在：

- `runtime/unidbg/vectors/vm-replay-mixed-clean-context.txt`
- `runtime/unidbg/vectors/vm-replay-repeat-clean-context.txt`

## 证据边界与下一步

- 已确认：Blob 1、4、5 是 live 输出变化时同时变化的上游显式输入；9 Blob 之外还有隐式 VM/context/global state。
- 未确认：三者分别代表随机量、时间、检测状态、密钥材料或其他结构。
- 未确认：三者是否各自独立影响输出；当前 mixed replay 没有固定隐式状态，不能归因。
- 若继续做算法级因果归属，必须在 live `0xb6c50` 前捕获并恢复 `0xa0` context、其指向的 frame/stack 内存和相关 module globals，或从同一 emulator 内存快照 fork；只固定 9 Blob 不够。
- 对当前交付目标，原始 `.so` 已在 PC 上自行生成并消费这些值，不要求安卓真机参与。
