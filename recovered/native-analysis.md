# Adjust `libsigner.so` 3.62.0 完整分析

## 结论

样本是 Maven Central 官方 `com.adjust.signature:adjust-android-signature:3.62.0` 的原始四 ABI 产物，不是自解密壳。它通过静态 JNI 导出接收 `Context + Map + HMAC + SDK`，收集/校验应用与运行环境，将固定允许的 Adjust 参数和多个二进制输入交给受保护的 32 位栈式 VM 程序，返回 304 字节，并向输入 Map 写入协议元数据。

ARM64 `0x8b510` 已动态证实只是 `Map.get("environment")` 路径；真正的受保护签名程序是 ARM64 `0xb6c50` / x86_64 `0x9dcf0`。后者仍应称为 `signature VM program/orchestrator`，不能无证据称作单一 SHA/AES 核心。

## 样本身份

| ABI | SHA-256 |
|---|---|
| arm64-v8a | `fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736` |
| armeabi-v7a | `ab68f112fffdb090015cef48ff123e34f4dc7819cbdf0f913dc19e331ac1484d` |
| x86 | `a33c2cf24bcd6d3f9666aac0d4dcf5d84f37f44738310f1ab2c2c614dc9ae6db` |
| x86_64 | `b00272e389cc33ecc7255adfb918871bb01cc34f6701877258c4f32ae011fb5c` |

ARM64 为 stripped、RELRO/BIND_NOW、NX stack，无 RWX `PT_LOAD`，未观察到代码页解密、自修改或运行时壳释放。

## 精确 JNI 与 Java 前置链

```text
nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B
nOnResume()V
```

第二参数的实际运行类型是有序 `Map<String,String>`。官方 `classes.jar` 的已验证调用顺序：

```text
caller Map
  -> put activity_kind
  -> put client_sdk
  -> Map.toString().getBytes("UTF-8")
  -> AndroidKeyStore alias "key2" 的 HmacSHA256
  -> native nSign(context, map, hmac, Build.VERSION.SDK_INT)
  -> native byte[]
  -> Java 转大写 HEX 写回 signature
```

API >= 23 的 `key2` 是 AndroidKeyStore HMAC key；API 18–22 则使用 RSA 包装的随机 16 字节 key 和 `adjust_keys/encrypted_key`。因此“同参数 Map”不足以复制另一台手机；还必须匹配 key2、证书、包身份、SDK/环境和持久状态。

## `nOnResume`

ARM64 导出 `0xa894c` 尾跳到 `0xb0a48`。首次调用：

1. 清零临时状态；
2. 同步调用 `0xb0d08` 检测回调；
3. `timer_create(CLOCK_MONOTONIC, SIGEV_THREAD, callback)`；
4. `timer_settime` 设置 1 秒初始延迟和 1 秒周期；
5. 成功后设置全局 guard，后续调用幂等。

此 timer 服务持续反调试/运行环境检查，不是每次 `nSign` 新建。

## `nSign` 实际运行序列

以下步骤已由 unidbg 的真实 JNI/syscall 路径验证：

1. `Map.get("environment")`；等于 `sandbox` 时输出 begin/end 时间日志。
2. `Context.getPackageName()`。
3. `PackageManager.getPackageInfo(..., GET_SIGNATURES)` → 首个 `Signature.toByteArray()`。
4. `MessageDigest.getInstance("SHA1")` → 应用证书 SHA-1（20 字节）。
5. `SensorManager.getSensorList(-1).size()`。
6. `Resources.getSystem().getDisplayMetrics()` → width/height。
7. `Thread.currentThread().getStackTrace()`，遍历 class/method 名做 instrumentation/emulation 检测。
8. `KeyStore.getInstance("AndroidKeyStore")`、`load(null)`、`getKey("key2", null)`。
9. 再次对 `Map.toString().getBytes()` 执行 `Mac.getInstance("HmacSHA256")`。这说明 native 自身也依赖可用的 key2；仅提供第三 JNI 参数的 HMAC 并不等于复制全部设备态。
10. `PackageManager.getApplicationInfo()` → `ApplicationInfo.publicSourceDir`。
11. `/proc/self/fd/*`、进程/stack/property/socket 等反分析路径。
12. 对固定参数名表执行 `Map.containsKey/get`，组织 VM 输入。
13. 调用 9-Blob 签名 VM，复制 304 字节到 Java `byte[]`。
14. `Map.put` 写入：`headers_id=8`、`adj_signing_id=1300000`、`native_version=3.62.0`、`algorithm=adj7`。

## 参数白名单

动态执行观察到 97 个 `containsKey` 名称：

```text
activity_kind, ad_impressions_count, ad_revenue_network, ad_revenue_placement,
ad_revenue_unit, adgroup, android_id, android_uuid, api_level, app_secret,
app_token, app_version, app_version_short, att_status, bundle_id, callback_params,
campaign, click_time, click_time_server, client_sdk, country, created_at,
creative, currency, deduplication_id, default_tracker, details, device_known,
device_name, device_type, environment, event_callback_id, event_count, event_token,
external_device_id, fb_anon_id, fb_id, ff_app_set_id_disabled, ff_att_disabled,
ff_idfv_disabled, ff_odm_enabled, fire_adid, fire_tracking_enabled, found_location,
google_play_instant, gps_adid, gps_adid_src, granular_third_party_sharing_options,
hardware_name, idfa, idfv, initiated_by, initiating_package_name,
install_begin_time, install_begin_time_server, install_version, installed_at,
last_skan_update, mcc, measurement, mnc, needs_cost, odm_info, order_id,
originating_package_name, os_build, os_name, os_version, package_name, params,
partner_params, partner_sharing_settings, payload, primary_dedupe_token,
purchase_time, push_token, referrer, referrer_api, reftag, revenue, sales_region,
secondary_dedupe_token, seq, session_count, session_length, sharing,
skadn_registered_at, source, started_at, store_app_id_from_client,
store_name_from_client, store_name_from_system, subsession_count, time_spent,
tracker, tracking_enabled, updated_at
```

## 受保护 VM

直接探针证明：

- context allocator：ARM64 `0x111a18`，返回 `0xa0` 字节 context；主/辅助 frame 初始容量为 256 个 32 位 word。
- 程序入口：ARM64 `0xb6c50`，x86_64 `0x9dcf0`，参数为 `error*, vm*, count=9, Blob x9`。
- `Blob` 64 位布局为 `{u32 byte_len; u32 padding; u8 *data}`；输入按 big-endian word 装入 frame。
- 已独立验证 `push/pop/dup/pick/roll/store32/frame-length/seek/push-frame`；pop 空栈为错误 3，pick/roll 越界为错误 4。
- 零值形状的 9 个 Blob 长度是 `8,40,8,512,4,4,32,4,32`。
- output helper 返回 304 字节；显式 Blob 和 VM/context/global mutable state 共同决定结果。
- 两次同配置 live JNI 捕获的实际长度为 `8,40,8,512,4,4,50,4,0`；其中 Blob 1、4、5 在 VM 入口前变化，Blob 2、3、6、7、8、9 稳定。Blob 2 是 certificate SHA-1 的 40 字节大写 HEX，Blob 6 是 Blob 7 长度 50，Blob 7 是固定字段串联。完整差分见 `recovered/vm-live-inputs.md`。

零值直接探针的一次输出前缀为：

```text
59f066a1020fd01a6df980ae48bdcca6925a583d10826d4a2f3d115f4e89995f
```

完整零向量、304 字节输出和 SHA-256 `d43a36f81b41cebd016c03e7e7e075e4df5741f46efc33380eabc2182272f1e2` 保存在 `recovered/vm-zero-vector.json`。它只定义 fresh emulator/module/context 的首次直接调用；同一 9 Blob 在后续调用可因 mutable native state 得到不同结果，因此不是无状态算法 oracle。

## LLVM/反分析特征

- `nSign`、timer 初始化和多 helper 使用随机 64 位状态常量驱动的 CFG flattening。
- 字符串通过一次性 uniform-byte XOR 原地解密，guard 使用原子 CAS/LDXR-STXR helper `0x112730`。
- 已跨四 ABI 验证 `environment`、`sandbox`、日志、JNI descriptor、`TracerPid:`、`/proc/%d/status`、Map `get`、三种时间格式；机器可读偏移/key/guard 记录在 `recovered/strings.json`。
- 检测面包含 stack trace、`/proc`/fd、property、socket、timer、Frida/emulator 线索。PC harness 对必要边界做确定性建模，但报告中保留这些行为。

## PC 运行与一致性边界

`runtime/unidbg` 已真实加载原始 ARM64 ELF，命中导出，走完 JNI/证书/传感器/屏幕/stack/KeyStore/HMAC/参数扫描/VM/Map.put，并返回非空 304 字节。SDK 23 legacy certificate field 与 SDK 30 `SigningInfo` 单签名分支均已在 synthetic package/certificate/`key2` 下跑通。unidbg/Unicorn 是当前 macOS 上已验证的纯 PC 主路径，不需要真机或 ADB。

官方 Java wrapper 的 SDK 18–22 分支还依赖 `SharedPreferences("adjust_keys")` 和 RSA AndroidKeyStore 包装/解包。动态试探已命中该真实边界；当前 harness 为保持 strict 语义明确拒绝 `<23`，没有用空 preferences 或假 RSA 伪造成功。

QBDI 代码位于 `runtime/qbdi`，其语义是 Android/Linux x86_64 **进程内**插桩；当前主机没有 QBDI，也不能因为 CPU 同为 x86_64 就在 macOS 直接 `dlopen` Android ELF。环境检查会明确非零退出并列出缺项。

### 可以声称

- 使用固定 PC key/证书 fixture 时，原始 `.so` 可在 PC 上反复完整运行；native 自身构造的变化 Blob 可能使每次 304 字节内容不同。
- 提供同一 key2、证书、包名、SDK、参数顺序与移动端 HMAC 时，可用于逐字节 oracle 对照。

### 当前不能声称

- 已拥有目标手机不可导出的 AndroidKeyStore key2。
- 已获得目标应用真实签名证书和移动端输入/输出 oracle。
- 当前 macOS 已执行 QBDI 后端。
- 已把 `0xb6c50` 的全部保护程序机械翻译成可脱离原 `.so` 的无黑盒算法；现阶段完整可执行实现通过 unidbg 调用原始函数，源码恢复对未验证 helper 保持地址化。
