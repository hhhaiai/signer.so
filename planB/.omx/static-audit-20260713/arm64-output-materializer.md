# arm64 JNI Map plaintext materializer: `0x11d798`

本文件只基于 `.omx/libsigner-arm64-objdump.txt` 和目标 ELF 数据段做静态分析。
没有加载或执行目标 SO。

## Corrected role

`0x11d798` 不是 final ciphertext/output materializer。结合 `0xcc28c` 与 `0x11e924`
的参数传递可以恢复其实际输入：

```text
x0 = native status object
x1 = JNIEnv*（final consumer 原始 x0，保存在 sp+0x60）
x2 = Java Map/object（native context +0x10）
x3 = uint8_t** output
x4 = uint64_t* outputLength
```

它调用 `0x11ba78` 遍历 Java Map 中受支持的字段，把非 null 字符串值按 native 固定
字段顺序直接拼接成一段无分隔符 plaintext。

## Function boundaries

```text
0x11ba78..0x11d408  JNI Map field walker / value emitter
0x11d40c..0x11d524  emitted-value counting sink
0x11d528..0x11d794  bounded emitted-value copy sink
0x11d798..0x11da60  two-pass Map plaintext materializer
0x11da64             final consumer entry
```

两个 callback 以函数指针传入：

```asm
0x11da10: adr x3, 0x11d40c
0x11da18: bl  0x11ba78

0x11d978: adr x3, 0x11d528
0x11d980: bl  0x11ba78
```

由于 `0x11d798` 是 opaque-state dispatcher，真实执行顺序不能按地址判断。成功路径是：

```text
清零 sink
-> counting callback
-> calloc(length + 1)
-> copy callback
-> 返回 pointer + explicit length
```

## Sink context

`0x11d528` 的访存恢复出 24-byte context：

```cpp
struct PlaintextSink {
    uint64_t capacity;   // +0x00
    uint64_t offset;     // +0x08
    uint8_t* data;       // +0x10
};
```

关键证据：

```text
0x11d728: ldp x8, x20, [x19]       capacity, offset
0x11d6b0: ldr x8, [x19, #0x10]     data
0x11d6bc: add x0, x8, x20           data + offset
0x11d6c0: bl memcpy
0x11d6cc: ldr x9, [x19, #0x8]
0x11d6dc: add x8, x9, copiedLength
0x11d6f0: str x8, [x19, #0x8]
```

## Recovered materializer pseudocode

```cpp
bool materializeMapPlaintext(Status* status,
                             JNIEnv* env,
                             jobject map,
                             uint8_t** output,
                             uint64_t* outputLength) {
    PlaintextSink sink{};

    walkSelectedMapValues(status, env, map, countingSink_11d40c, &sink);
    if (status->error != 0) return false;

    sink.data = static_cast<uint8_t*>(calloc(sink.capacity + 1, 1));
    if (sink.data == nullptr) {
        status->error = 2;
        return false;
    }

    walkSelectedMapValues(status, env, map, copyingSink_11d528, &sink);
    if (status->error != 0) return false;

    *output = sink.data;
    *outputLength = sink.capacity;
    return true;
}
```

额外分配的 NUL byte 不进入签名 material；调用方使用显式长度。

## XOR-decoded field table

`0x11ba78` 使用虚拟地址 `0x145a30` 的 1363-byte 数据。对应文件偏移：

```text
LOAD file offset 0x13ae10, vaddr 0x142e10
table vaddr 0x145a30
table file offset = 0x13da30
```

初始化状态在 `0x11c81c..0x11cb78` 将 table 的每个 byte XOR `0x52`，并设置
`0x146b61` once flag；`0x139800` 的原子 CAS 用于并发初始化。解码结果是一个
NUL-terminated、逗号分隔的 100-key 列表：

```text
ad_impressions_count,ad_revenue_network,ad_revenue_placement,ad_revenue_unit,
adgroup,android_id,android_uuid,api_level,app_secret,app_token,app_version,
app_version_short,att_status,bundle_id,callback_params,campaign,click_time,
click_time_server,country,created_at,creative,currency,deduplication_id,
default_tracker,details,device_known,device_name,device_type,environment,
event_callback_id,event_count,event_token,external_device_id,fb_anon_id,fb_id,
ff_app_set_id_disabled,ff_att_disabled,ff_idfv_disabled,ff_odm_enabled,fire_adid,
fire_tracking_enabled,found_location,google_play_instant,gps_adid,gps_adid_src,
granular_third_party_sharing_options,hardware_name,idfa,idfv,initiated_by,
initiating_package_name,install_begin_time,install_begin_time_server,install_version,
installed_at,last_skan_update,mcc,measurement,mnc,needs_cost,odm_info,order_id,
originating_package_name,os_build,os_name,os_version,package_name,params,partner_params,
partner_sharing_settings,payload,primary_dedupe_token,purchase_time,push_token,
referrer,referrer_api,reftag,revenue,sales_region,secondary_dedupe_token,secret_id,seq,
session_count,session_length,sharing,skadn_registered_at,source,started_at,
store_app_id_from_client,store_name_from_client,store_name_from_system,
subsession_count,time_spent,tracker,tracking_enabled,updated_at,activity_kind,
client_sdk,headers_id,native_version
```

原始解码二进制保存在：

```text
.omx/static-audit-20260713/arm64-145a30-xor52.bin
```

同一个 1362-character/100-field 明文表已在四个 ABI 中静态交叉确认；各 ABI 使用
不同的一字节 XOR mask：

| ABI | file offset | XOR mask | decoded equality |
|---|---:|---:|---|
| arm64-v8a | `0x13da30` | `0x52` | reference |
| armeabi-v7a | `0x112bb0` | `0xc4` | identical |
| x86_64 | `0x1364d0` | `0x54` | identical |
| x86 | `0x1309b0` | `0x97` | identical |

各 ABI 解码结果保存在 `.omx/static-audit-20260713/<abi>-map-fields.txt`。

## `adj_signing_id` engine-level placement correction

解码表本身不含 `adj_signing_id`，但冻结 Pixel exact vector 明确包含值 `1400000`，位置在
普通字段（已出现的最后一个是 `os_version`）之后、尾部四个字段
`activity_kind/client_sdk/headers_id/native_version` 之前。当前 C++ 采用以下有效顺序：

```text
decoded table fields 0..95
fixed adj_signing_id value 1400000
decoded table fields 96..99
```

这是“静态表 + 已有逐字节 oracle”的组合结论，但不应继续表述为 `0x11ba78` 内的
special emit。对严格 walker 范围的新检查表明：它只从 `0x145a30` 的 100-key 表解析
key，没有引用 standalone `adj_signing_id` buffer `0x142ed0`。由于 native metadata
builder 固定覆盖该值，C++ composition 必须无条件使用 `1400000`，而不能接受调用者
同名字段作为 signed-material 输入。

`adj_signing_id` 和 `1400000` 又分别以独立的 XOR-encoded buffer 出现在全部四个 ABI，
而不是遗漏在 100-field 表内。例如 arm64 的静态命中为：

```text
1400000        file offset 0x13aea0, XOR 0x4d
adj_signing_id file offset 0x13aed0, XOR 0x11
```

`0xaf3c` 确实把该 pair 与另外三组 metadata 传给 `0x9954c`；`0x9954c` 的 JNI
method name/signature 解码为 Java `Map.put(String,String)`。这证明
`adj_signing_id=1400000` 被写入 native result metadata Map，但不能把这个写入等同于
signed plaintext walker。exact output 所证明的 logical placement 仍保留在 C++，其精确
descriptor 来源需要继续沿 `0x11da64 -> 0xf1ec8` 追踪。

可重复验证：

```text
.omx/static-audit-20260713/analyze_map_metadata_jni.py
.omx/static-audit-20260713/arm64-map-metadata-jni.md
```

## Relation to `0xf1ec8`

`0x11d798` 生成的 Map plaintext pointer/length 随后被包装成两个输入：

```text
4-byte reversed plaintext length descriptor
dynamic plaintext byte descriptor
```

它们是 `0x11e7f0 -> 0xf1ec8` 固定九输入 work object 的两个 slot。`0xf1ec8` 以固定
`count=9` 把所有 descriptor 转为 big-endian logical words；这里的 9 不是 algorithm id。

进一步的调用点追踪确定它们分别是 slot 6（4-byte reversed length）和 slot 7
（dynamic selected-Map bytes）。slot 8/9 是另一组 `context+0x118` length 与
`context+0x120` dynamic bytes；其余 slot 来自固定 context offsets。完整顺序见：

```text
.omx/static-audit-20260713/arm64-final-nine-descriptors.md
```

## Compatibility impact

旧的 `RecoveredNativeBackend.PLAINTEXT_FIELDS` 只有 15 个已观察字段，只能覆盖冻结
profile。完整表有 100 个 Map keys；另有 exact output 证明的 `adj_signing_id`
engine-level placement，但它不属于该 100-key walker。若请求包含
例如 `revenue`、`event_token`、`callback_params`、`partner_params` 或 `payload`，旧实现会
遗漏其值，最终 field 4、ciphertext 和 HMAC 都与原 SO 不一致。
