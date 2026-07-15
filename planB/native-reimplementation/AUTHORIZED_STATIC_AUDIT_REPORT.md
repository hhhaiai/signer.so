# libsigner.so 授权静态审计报告

> 报告日期：2026-07-15  
> 分析范围：`/Users/sanbo/Desktop/api/qbdi` 当前本地文件  
> 主目标：`adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so`  
> 方法边界：静态分析为函数级结论主证据；隔离动态验证仅执行本地 recovered path 和
> Unidbg 中的本地目标 SO，不连接网络或外部主机，不修改目标执行状态  
> 当前结论级别：**阶段性完整报告，不是“完整替代已完成”证明**

---

# 1. 文件概况

## 1.1 主目标标识

| 项目 | 结果 |
|---|---|
| 文件大小 | 1,304,840 bytes |
| 格式 | ELF 64-bit LSB shared object |
| CPU / ABI | AArch64 / ARM64，Android System V ELF |
| 链接 / 符号 | 动态链接，stripped |
| SONAME | `libsigner.so` |
| SHA-256 | `8be033d3423258ac6975c17813eae0ee41c9c743f90ab40e40fa9c1c58eef371` |
| GNU Build ID | `e3effad6e520baa84e5f29946b780b268258cc43` |
| Android note | 最低 API 21；NDK r26c build 11394342 |
| 编译器 | Android clang 17.0.2，基于 r487747e |
| 编译优化 | `+pgo, +bolt, +lto, -mlgo` |
| 链接器 | LLD 17.0.2 |

证据：

```text
.omx/static-audit-20260713/elf-metadata/arm64-file-headers.txt
.omx/static-audit-20260713/elf-metadata/arm64-private-headers.txt
.omx/static-audit-20260713/elf-metadata/arm64-section-headers.txt
```

AAR 同时包含 arm64-v8a、armeabi-v7a、x86、x86_64 四个 ABI。本报告以 ARM64 为权威目标，以 x86_64 做跨 ABI 静态互证。ARM64 目标与本地 Pixel reference APK 中对应 SO 的 SHA-256 相同，已排除“分析文件与 reference 文件不同”。

## 1.2 ELF 段与加固

| 段 | 大小 | 说明 |
|---|---:|---|
| `.text` | `0x131d2c` | 主代码 |
| `.rodata` | `0x150` | 很小，业务字符串多为运行时解码 |
| `.data.rel.ro` | `0x8a0` | 重定位后只读数据 |
| `.data` | `0x32ba` | 编码数据和状态 |
| `.bss` | `0xaf0` | 零初始化状态 |
| `.eh_frame` | `0x43ac` | 产生 388 个 FDE 范围 |

静态加固观察：

- GNU RELRO。
- NOW/BIND_NOW。
- GNU stack 为 `rw-`，不可执行。
- 无 RWX LOAD segment。
- 导入 `__stack_chk_fail`。
- 导入 `__memcpy_chk`、`__strlen_chk`。
- stripped、LTO、PGO、BOLT 和控制流扁平化增加审计成本，但不构成不可逆向的安全边界。

## 1.3 依赖、imports 和 exports

`DT_NEEDED`：

```text
liblog.so
libm.so
libdl.so
libc.so
```

共 59 个动态 undefined symbols，主要包括：

- 内存与字符串：`malloc/calloc/realloc/free/memcpy/memset/strlen/strcmp/strncmp/strdup/strchr/strtol/sscanf`。
- 文件目录：`access/fopen/fclose/fgets/fread/fseek/ftell/stat/fstat/opendir/readdir/closedir/readlink`。
- 系统：`mmap/munmap/syscall/__system_property_get/getauxval`。
- 时间随机：`clock_gettime/gettimeofday/time/srand/rand/timer_create/timer_settime/fmod/localtime/strftime`。
- 网络：`socket/connect/sendto/recvfrom/setsockopt/inet_aton`。
- Android 日志：`__android_log_print`。

完整列表：`.omx/static-audit-20260713/elf-metadata/arm64-dynamic-symbols.txt`。

仅有两个全局定义导出：

| 地址 | 符号 | 大小 |
|---:|---|---:|
| `0xcba8c` | `Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume` | 4 |
| `0xcc604` | `Java_com_adjust_sdk_sig_NativeLibHelper_nSign` | `0x1330` |

Java 声明：

```java
private native byte[] nSign(Context context, Object map, byte[] javaHmac, int api);
private native void nOnResume();
```

## 1.4 函数覆盖

函数范围来自 `.eh_frame` FDE，不是猜测序言：

| 范围 | recovered | partial | unknown |
|---|---:|---:|---:|
| 全部 388 FDE | 338 | 0 | 50 |
| JNI 静态可达 321 FDE | 289 | 0 | 32 |

新增恢复的 23 个非 JNI-reachable FDE 包括 20 个 `context+0xe0` 固定掩码
load/OR/store leaf，以及 `0x4afe4/0x4afe8/0x4afec` 三个单 `ret` no-op leaf。
每个地址、掩码和指令体均由独立 verifier 锁定；C++ 使用显式地址/掩码表和共享实现，
不把相同四指令算法复制二十次。
另外闭合了 `0x8070..0x80c0` 的五个编译器/runtime scaffold FDE，以及
`0x139d04` CPU-feature constructor wrapper。该 wrapper 的独立 `0x1398cc` feature
decoder callee 随后也按逐指令证据闭合；其 HWCAP/HWCAP2 与五个 `ID_AA64*` 字段均由
C++ 调用方显式提供，并以 presence gate 区分合法零值与缺失值，未使用宿主默认值。
随后闭合的 `0xb1e40..0xb21b4` 是非 JNI-reachable 的 exception helper；ARM64 与
x86_64 均解码同一 `java/lang/Exception`，执行 FindClass、单次 exception consume、
status 18、success-only ThrowNew(message) 和 non-null class cleanup。

原唯一 partial 已关闭：

```text
0xf1ec8..0x11ba78
size: 0x29bb0
ARM64 instructions: 42,732
direct helper calls: 7,223
unique direct targets: 17
```

纠正其第三个 16-byte context-flags descriptor 后，完整文本 VM 无补丁产出冻结
176-byte reference。整个 SO 仍因 39 个 JNI 可达 unknown 而不能声称完美替代。

最新恢复的 JNI 可达函数及相邻 owner wrapper 包括：

```text
0x13dc8 packed-transition filtered record stage
0x14078 fixed-loopback filtered record stage
0x34820 packed low-24 transition predicate
0x34954 detector record cross-match uint16 counter
0x34bf4 detector packed-transition cross-match uint16 counter
0x87158 display-dimension unordered-pair predicate
0x8f56c detector scratch owned string-pair appender
0x8fb44 detector scratch content destructor
0x96ea8 JNI Cipher.init(int,Key) helper
0xa8978 JNI size() int-method reader
0xa948c JNI indexed object-method reader
0xb081c JNI update(byte[]) void-method helper
0xb21b4 JNI int-field reader
0xb5828 JNI Context.getSystemService static-field getter
0xb9424 JNI PackageInfo.signingInfo object-field reader
0xbb5a0 JNI Resources.getSystem getter
0xbce98 JNI DisplayMetrics getter
0xbea74 JNI Sensor.getName getter
0xbf5fc JNI Sensor.getVendor getter
0xc0180 JNI SensorManager.getSensorList getter
0xd1a38 slice-to-owned-NUL-string materializer
0xd1bf4 indexed string-table owned clone
0xd2018 two-stage owned string-pair materializer
0xd22d4 recursive 0x30-byte metadata-node content destructor
0xd28d0 recursive metadata-node parser
0xd313c dot-separated metadata area-name resolver
0xd352c property-info mapped source creator
0xd6ed8 128-byte newline-stripping getline-compatible helper
0xd4220 recursive metadata-node owner destructor（当前不在 JNI reachable 集）
0x124c90 public-source parser-owner constructor
0x125074 composite parser-owner destructor
0x125210 ZIP EOCD signature matcher
0x125770 ZIP EOCD backward offset scanner
0x1259b8 APK Signing Block locator and footer/header validator
0x127194 APK Signing Block v2/v3/v3.1 entry dispatcher
```

均已完成 ARM64/x86_64 交叉静态取证、直接 C++ 实现和回归入口接线。其中
`0xd1a38` 的 allocation failure 会保留已前移的 slice cursor，并写 output null/status 2；
`UINT32_MAX` 长度对应的原生申请量为 `0x100000000` bytes。`0xd1bf4` 没有 index、
relative offset 或 NUL scan 边界检查；`0xd2018` 在任何非零 status 下按 first 后 second
顺序回滚，完整成功时把两块 ownership 保留给 caller。`0x124c90` 以 `R_OK` 检查路径，
解码 ABI 私有字符串为同一 `rb` 模式，打开后分配 `0x48` owner；access/fopen 失败写
status 2，allocation 失败写 status 1，并保留原生未关闭已打开流的行为。`0x125074`
对 null outer owner
无副作用；非空时先关闭并清零 `FILE*`，然后严格按 `+0x18/+0x28/+0x38/free`
顺序销毁。ARM64 与 x86_64 使用相同七个 opaque-state 常量。`0x125210` 的 ABI
私有 XOR 编码分别恢复为同一 `50 4b 05 06` marker；`0x125770` 使用 ZIP comment
上限对应的 65535 个候选 offset，并保留 seek/status 的原生停止语义。
`0x1259b8` 读取 EOCD Central Directory offset，校验 `50 4b 01 02` 和
`APK Sig Block 42`，将 footer offset/size 发布到 owner `+0x08/+0x10`，再以原生
模 64 位 `8-size` seek 定位初始 size，并用 status 3/5/6 区分 signature、magic 和
重复 size mismatch。成功时 stream 位于第一项 Signing Block ID-value entry。
`0x127194` 随后以 raw fread 读取 uint64 size/uint32 ID，将 v2/v3/v3.1 三个标准 ID
分别路由到 owner `+0x18/+0x28/+0x38`；recognized path 使用 low32(size)-4，unknown
path 使用 checked ftell 与 full64(size)-4 raw fseek，后者失败写 status 7。
`0xd6ed8` 与 x86_64 `0xc36c3` 共享 28 个 opaque states；null buffer 强制
capacity 128 并 `calloc(128,1)`，非空 buffer 按完整 incoming capacity 清零，随后以
128-byte `fgets` chunk 累积并去掉终止换行。初始 EOF 返回 -1，partial EOF 返回累计长度，
空行返回 0；扩容使用 `(required&~127)+128`，required 恰为 128 倍数时仍多一 block。
原生在 `realloc` 前发布新 capacity，并以返回值直接覆盖 pointer，失败会丢失旧 allocation。
`0xd22d4` 与 x86_64 `0xbfe08` 共享 21 个 opaque states；0x30-byte node 的字段为
`+0x00/+0x08` 两条 owned string、`+0x10/+0x18` 第一组 count/连续 child array、
`+0x20/+0x28` 第二组 count/连续 child array。它依次深度优先清理第一数组、释放并清零
pointer/count，再清理第二数组，最后按 first/second 顺序释放字符串。`0xd4220` 与
x86_64 `0xc1713` 在内容析构后释放同一个 outer node；null 仍到达 `free(nullptr)`。
`0xd28d0` 与 x86_64 `0xc0340` 共享 24 个 opaque states；它读取 0x1c-byte descriptor
中的 own-pair offset、两组 count 和两张 offset-table pointer。`+0x18` 数组通过
`calloc(count,0x30)` 后递归调用 parser，`+0x28` 数组只调用 `0xd2018` 构造 pair-only
leaf；两组 published count 都只在单个元素成功后递增。任一非零 status 或 allocation
failure（status 2）统一调用 `0xd22d4` 回滚。
`0xd313c` 与 x86_64 `0xc0912` 共享 14 个 opaque states；它以 `strchr('.')` 分段，
中间段按 `strncmp(segmentLength)` 在 `+0x18` 递归数组中选第一个匹配 child，最终段
按 `strcmp` 在 `+0x28` leaf array 中精确查找并返回 second owned string。中间段没有
child-string 等长/终止检查，空 segment 的长度零比较会选择第一项。
`0xd352c` 与 x86_64 `0xc0cdd` 共享 23 个 opaque states，并解码同一路径
`/dev/__properties__/property_info`。它执行 calloc/access/openat/fstat、24-byte 最小
长度检查和只读私有 mmap，把映射前 24 字节复制到 source `+0x18`；失败状态为
2/8/10/12。mmap 返回值没有在解引用复制前检查。
`0x13dc8/0x14078` 共享 kind-10 filter 与 15000ms timing；命中分别写 correction
`0x04/0x0a`，filter allocation failure 跳过 counter/timing 并写 correction `0x32`，
但仍提交各自最终 context mask、释放临时数组并按 `status==0` 返回。
`0x87158` 的 ARM64/x86_64 64-byte 固定表完全一致；它不检查 null scratch，
仅以首个正向或反向 pair 命中决定 true，否则扫描八项后返回 false。
`0x8f56c` 读取 scratch `+0x870` count，count>=127 返回 `0x26`；其余情况按两个
`{source,length}` 输入依次执行 `malloc(length+1)`、forward byte copy 和 NUL，只有双成功
才在 `+0x70+count*0x10` 发布 first/second pointer 并递增 count。任一 allocation failure
都无条件 first-then-second `free` 并返回 2，第一次失败也不会跳过第二次 allocation/copy。
`0x8fb44` 与之配对：按 `+08,+18,+20,+00,+30,+38,+10,+50` 释放八个固定 pointer，随后
逐 pair 释放 first/second，遇到首个全空 slot 停止；它不读取 count。appender 最多发布
127 项，从而保留第 128 项作为正常链路的全空 sentinel。
`0x8746c` 的非 property sensor/display 子流水线现已源级表达：
`getSystemService(SENSOR_SERVICE) -> getSensorList(-1) -> size() -> signed jint index<size ->
get/name/name UTF/vendor/vendor UTF/append`，sensor terminal cleanup 后才执行
`Resources.getSystem -> getDisplayMetrics -> widthPixels -> heightPixels`。ARM64 的 `lt` 和
x86_64 的 `cmovl` 共同证明 count/index 必须按有符号 32 位解释；C++ 回归覆盖
`size=0/-1/1/2`、所有第一轮 helper failure、appender `2/0x26` 和 display failure。
两 sensor observation-only trace 进一步证明第一轮三条 local ref 与两条 UTF pointer 在循环中
被覆盖，最终只释放最后一轮，并以 name UTF、vendor UTF、manager、list、last sensor、
last name、last vendor、DisplayMetrics、Resources 的顺序完成 cleanup。因此严格兼容模型
保留原 ownership 缺口，hardened profile adapter 则使用独立全量 cleanup。128-sensor
边界互证进一步确认 index 127 的 append 返回 `0x26`、count 保持 127、display stage
不执行，terminal cleanup 仍只处理最后一项的两条 UTF 和三条对象引用。
在兼容性原语之外，C++ 新增独立的 `RecoveredDetectorInputProfile8746c` 调用方输入层：
十三个 property value、display width/height 和 sensor name/vendor pair 均由调用方显式
提供。缺失 property 默认拒绝，只有调用方显式选择 `UseEmptyString` 才映射为空字符串；
display 和 sensor list 也分别要求 provided 标记，因此不会静默生成设备画像。该适配层在
输入发布前验证 property 的 95-byte 上限和 127-pair sentinel 上限，并使用独立安全 cleanup
释放全部十三个 property；这不是对原 `0x8fb44` 八字段释放行为的静默修改。`0x8746c`
现已迁移为 recovered：231-state x86_64 parser 与 ARM64 固定状态写入共同证明 service
failure 为 `0x24`、width/height failure 为 `0x1d`，其余 helper status 保留；原生
destructor-envelope 回归覆盖 success、13 个 property allocation failure、九类 sensor
failure、second-pair `0x26` 和四类 display failure，并保留五个兼容性未释放字段。
`0xb21b4` 与 x86_64 `0xaa362` 通过 vtable `+0xf8/+0x2f0/+0x320/+0xb8` 依次执行
`GetObjectClass`、`GetFieldID(name,"I")`、`GetIntField` 和 `DeleteLocalRef`，并在前三阶段后
调用 exception describe-and-clear consumer。producer 两个 call site 的 XOR 数据分别解码为
`heightPixels` 和 `widthPixels`；null input、class/field failure、int-field exception 对应 status
`3/18/28`。成功但 incoming status 非零时保留该 status、删除 class ref 并把 output 清零。
隔离 Unidbg profile 进一步观察到 `widthPixels=1440` 写入 scratch `+0x60`，随后
`heightPixels=3120` 写入 `+0x64`；三次 V4/V5 路径均以 producer status 0 返回，未修改
目标寄存器或返回值。该动态结果用于互证字段角色，recovered 结论仍以跨 ABI 静态证明为主。
`0xa8978` 与 x86_64 `0xa469c` 则固定解码 `size` / `()I`，通过 vtable
`+0xf8/+0x108/+0x188/+0xb8` 执行 GetObjectClass、GetMethodID、CallIntMethod 和
DeleteLocalRef。它复用同一 status `3/18/28`、三次 exception consume 和最终非零 status
输出清零规则，用于 producer 中 Java collection-like 对象的元素数读取。隔离 Unidbg
只观察 hook 在真实 caller edge 记录 status 0、返回值 1，随后 producer status 0 且 nSign
返回 176 bytes；动态结果与该 profile 的单 sensor pair 一致。

相邻 `0xa948c` 与 x86_64 `0xa4cd9` 进一步固定解码 `get` /
`(I)Ljava/lang/Object;`，通过 vtable `+0xf8/+0x108/+0x110/+0xb8` 执行
GetObjectClass、GetMethodID、CallObjectMethod(index) 和 DeleteLocalRef。null input、
class/method failure、call exception 或 null result 分别收敛为 status `3/18/28`；返回的
object local ref 交给 caller，只有 class local ref 在 helper 内删除。隔离 Unidbg 的
V4/V4-repeat/V5 三次观察均以 index 0、status 0 返回 `android/hardware/Sensor`，随后
producer 产出 `LSM6DSO | STMicroelectronics` 单 pair。该动态证据互证成功路径，失败
状态和 ownership 仍由跨 ABI 静态控制流与 C++ regression 证明。

`0xbce98` 与 x86_64 `0xb0994` 固定解码 `getDisplayMetrics` /
`()Landroid/util/DisplayMetrics;`，复用 `+0xf8/+0x108/+0x110/+0xb8` JNI 调用序列、
三次 exception consume 和 status `3/18/28`。它从 Resources-like object 返回
DisplayMetrics local ref 给 caller，只删除临时 class ref；null result 即使没有 exception
也写 status 28。隔离 Unidbg 的 V4/V4-repeat/V5 均返回
`android/util/DisplayMetrics`、status 0，该 handle 随后被 `0xb21b4` 读取
`widthPixels=1440`、`heightPixels=3120`，互证 producer 对象流。

`0xb5828` 与 x86_64 `0xac4d5` 进一步闭合 Context system-service 获取链：跨 ABI
解码 `android/content/Context`、`getSystemService`、
`(Ljava/lang/String;)Ljava/lang/Object;` 和 `Ljava/lang/String;`，caller 传入
`SENSOR_SERVICE`。JNI 顺序为 FindClass、GetMethodID、GetStaticFieldID、
GetStaticObjectField、CallObjectMethod，五个阶段后均消费 exception；null input、
class/method/field-ID、field object/final call 分别收敛到 status `3/18/28`，并按 service
String 后 Context class 的顺序删除临时 local ref。`0xbb5a0` 固定执行
`Resources.getSystem()`；`0xbea74/0xbf5fc` 固定执行 Sensor `getName/getVendor()`；
`0xc0180` 固定执行 `getSensorList(I)Ljava/util/List;`，且 call exception/null result 仍写
status 18，不使用 28。隔离 V4/V4-repeat/V5 三次均观察到
`SensorManager -> one-element ArrayList -> Sensor -> LSM6DSO/STMicroelectronics`，所有
helper 和最终 producer status 均为 0；动态证据只互证成功对象流，失败/cleanup 结论来自
跨 ABI 静态控制流和当前 125 个 executable regression guard。

---

# 2. 程序模块和执行流程

## 2.1 Java 模块

`classes.jar` 包含：

```text
com.adjust.sdk.sig.NativeLibHelper
com.adjust.sdk.sig.Signer
com.adjust.sdk.sig.a
com.adjust.sdk.sig.b
com.adjust.sdk.sig.c
com.adjust.sdk.sig.d
```

| 类 | 职责 |
|---|---|
| `Signer` | 公共 API、Map 整理、authorization 构造、同步调用 |
| `NativeLibHelper` | `System.loadLibrary("signer")`，转发 JNI |
| `c` | API 相关 Java HMAC key 创建、读取和计算 |
| `d` | 签名事务、最多两次 key 恢复重试、native 调用、Base64 输出 |
| `b` | API 不支持异常 |
| `a` | Native helper 标记接口 |

字节码证据位于 `.omx/static-audit-20260713/java-bytecode/`。

## 2.2 Java key 路由

```text
API >= 23:
  AndroidKeyStore alias "key2"
  -> KeyGenerator("HmacSHA256", "AndroidKeyStore")
  -> Mac("HmacSHA256")

API 18..22:
  AndroidKeyStore RSA keypair alias "key2"
  -> SharedPreferences "adjust_keys"/"encrypted_key"
  -> Base64 decode
  -> RSA/ECB/PKCS1Padding private-key unwrap
  -> SecretKeySpec
  -> Mac("HmacSHA256")

API < 18:
  throw com.adjust.sdk.sig.b
  -> process-local signer lockdown
```

Java HMAC 对 `Map.toString().UTF-8` 计算，结果作为 `nSign` 第三个参数传给 native。它与 protected engine 的最终 HMAC 层不是同一对象。

## 2.3 Java 签名事务

`com.adjust.sdk.sig.d.a(...)`：

```text
检查全局 lockdown
-> 校验 Context/Map/activity_kind/client_sdk
-> 临时写入 activity_kind/client_sdk
-> 创建或读取 Java HMAC key
-> 计算 Java HMAC
-> nSign(Context, Map, javaHmac, api)
-> 返回值非空时 Base64.NO_WRAP
-> Map["signature"] = Base64(nativeResult)
-> 移除 activity_kind/client_sdk
```

`InvalidKeyException` 或 `UnrecoverableKeyException` 会触发删除 AndroidKeyStore alias `key2` 和 SharedPreferences `encrypted_key` 后重试。连续失败后进入全局 lockdown。

## 2.4 Native 主调用链

```text
Java nSign
  -> 0xcc604 JNI wrapper
  -> 0xcbe98 signing-context orchestrator
       -> 0xcc47c CLOCK_REALTIME
       -> context/certificate/environment/correction stages
       -> 0xf224 timing correction gate
       -> 0x11da64 final consumer
            -> time -> srand
            -> 0x11d798 selected-Map plaintext materializer
            -> 9 descriptors
            -> 0x1393cc work-object allocator
            -> 0xf1ec8 protected engine
            -> 0x13927c big-endian export
            -> 0xaf3c JNI byte[] + metadata transaction
       -> context-owned cleanup
  -> Java byte[]
```

`0xcbe98` 有效阶段顺序：

```text
0xcc47c CLOCK_REALTIME
memset(context+0x08, 0, 0x120)
context/correction/certificate initialization
0xd466c
0x1e578 certificate/digest stage
0xcba90 init stage 1
0xcbbd4 init stage 2
0x143e8 environment dispatcher
0xd6888 post-environment stage
0xf224 timing correction gate
0x11da64 final consumer
```

环境阶段包含 procfs、cmdline、system property、ART/linker、文件目录、timing、publicSourceDir、证书和 loopback Frida-server 等观察。它们被编码为 correction slots 和 opaque flags，再进入 protected engine。

## 2.5 Final consumer

`0x11da64..0x11ea78`：

1. `time()` 传给 `srand()`。
2. 包装 correction、证书摘要、flags、basis、field2。
3. 两遍遍历 selected Map 生成 plaintext。
4. 构造固定 9 个 `{length,data}` descriptor。
5. 分配 0xa0-byte work object。
6. 调 `0xf1ec8`。
7. 读取输出长度、分配零化缓冲区并大端导出。
8. `0xaf3c` 构造 Java byte[] 并写入四项 metadata。
9. 所有路径按固定顺序销毁 work/descriptors/output/plaintext。

## 2.6 Protected engine

`0xf1ec8..0x11ba78` 是单一 flattened function：

- 42,732 条 ARM64 指令。
- 645 个条件/直接分支。
- 7,223 个直接调用点。
- 17 个唯一直接目标。
- 0 个 `blr` 间接调用。
- 两个固定 `rand@plt` call sites。
- evaluation stack、auxiliary schedule stack、counter chain、shared arena、16 个 framed lanes。

已恢复的固定流水线：

```text
custom-state SHA-256
-> AES-256-CBC + PKCS#7
-> HMAC-SHA256 over ciphertext
-> IV || ciphertext || 32-byte tag
```

未发现第二套 nonce/tag 布局、ChaCha20/Poly1305/AES-GCM 常量族或间接算法 dispatcher
的正面证据；`algorithm=adj8` 是固定 metadata。42,732 条指令和 17 个直接 helper target
均已由文本 VM 表示；真实 Pixel context flags 下完整路径静态通过，所以该 FDE 已更新为
recovered。其他 context flags、错误 status 与极端 descriptor 组合仍需要回归矩阵。

---

# 3. 关键函数及证据位置

## 3.1 入口和事务

| 地址范围 | 语义 |
|---|---|
| `0xcba8c` | JNI `nOnResume` |
| `0xcc604..0xcd934` | JNI `nSign` |
| `0xcc47c..0xcc600` | realtime 毫秒 helper，失败 status 14 |
| `0xcbe98` | native signing context orchestrator |
| `0x11da64..0x11ea78` | final consumer |
| `0x11d798` | selected-Map plaintext materializer |
| `0xaf3c..0xcde4` | JNI byte[] 和 metadata builder |
| `0xa334..0xaf3c` | metadata rollback |
| `0x9954c` | 单项 metadata builder |

## 3.2 Environment 与 correction

| 地址范围 | 语义 |
|---|---|
| `0xf328..0xfce0` | 七个 environment probes |
| `0xfce0..0x12a30` | emulator/automation 初始化和评分 |
| `0x12a30..0x13000` | 13-predicate aggregator |
| `0x143e8..0x14e10` | 第二 environment dispatcher |
| `0xd6ed8..0xd7890` | 128-byte newline-stripping getline-compatible helper |
| `0xa8978..0xa948c` | JNI `size()I` int-method reader |
| `0xa948c..0xa9d44` | JNI `get(int): Object` indexed object-method reader |
| `0xb21b4..0xb2978` | JNI `heightPixels` / `widthPixels` int-field reader |
| `0xbce98..0xbd6a8` | JNI `Resources.getDisplayMetrics()` getter |
| `0xd78b8` | `/proc/self/maps` 的 `frida-agent` scanner |
| `0x13063c..0x1309cc` | trampoline detector |
| `0x1309cc..0x1311f0` | `127.0.0.1:27042` loopback probe |
| `0x134a74..0x134dd8` | correction codeword transform |
| `0x134dd8..0x134f40` | 64-slot replacement finder |
| `0x135050..0x13531c` | basis transpose |
| `0x13531c..0x13548c` | correction writer |

## 3.3 容器 helper

| 地址范围 | 语义 |
|---|---|
| `0xd22d4..0xd28d0` | recursive 0x30-byte metadata-node content destructor |
| `0xd28d0..0xd313c` | recursive metadata-node parser |
| `0xd313c..0xd352c` | dot-separated metadata area-name resolver |
| `0xd352c..0xd3d90` | property-info mapped source creator |
| `0x8f56c..0x8fb44` | detector scratch owned string-pair appender |
| `0x8fb44..0x90714` | detector scratch content destructor |
| `0xd4220..0xd4244` | metadata-node content-then-outer-free wrapper |
| `0x137980..0x137a78` | counter push |
| `0x137a78..0x137b64` | counter decrement/pop |
| `0x138318..0x138560` | framed arena write/grow |
| `0x138560..0x138660` | frame push |
| `0x138660..0x138728` | frame pop |
| `0x138744..0x138818` | arena read |
| `0x138a70..0x138b74` | word-stack push |
| `0x138b74..0x138c8c` | word-stack pop |
| `0x138c8c..0x138e58` | duplicate one zero-based indexed word |
| `0x138e58..0x138e60` | duplicate-top wrapper，index 0 |
| `0x138e60..0x138fd4` | top/index swap |

`0x138c8c` 伪代码：

```cpp
if (stack->count <= index) {
    *status = 4;
    return;
}
Node* node = stack->head;
for (uint32_t i = 0; i < index; ++i) {
    node = node->next;
}
push(status, stack, node->value);
```

旧的 “reversed-prefix duplicate” 命名已修正。

## 3.4 `0x3e` 数据流已闭环

| 地址 | 证据 |
|---:|---|
| `0x11a110` | materialize auxiliary token `0x301` |
| `0x119e84` | token 入 auxiliary stack |
| `0xf23a4` | token 出栈 |
| `0xf3b4c..0xf5610` | 精确选择 `0x301` handler |
| `0x101c18/0x101c68/0x101c80` | 压入 `wordCount=0x20/sourceOffset=0x18/lane=2` |
| `0x101d14..0x101d4c` | 复制 32 个 shared words |
| `0x106d00` | fixed-frame builder |
| `0x1071a8` | 选择 lane-0 current frame |
| `0xf5a0c..0xf5b18` | 固定 frame 比较 |
| `0x101b90` | 显式 `mov w2,wzr` |
| `0x104414` | push explicit zero |
| `0xf4840..0xf4894` | `source==0` 时 push correction `0x3e` |

x86_64 具有对应 `0x301` token、builder、固定比较、explicit-zero 和 `0x3e` 分支，
已排除 ARM64 条件码、分支方向和邻接 XOR 误解释。真机 helper-entry trace 将最早差异
定位到第三个 protected-engine descriptor：它是完整 context `+0xe0` 16-byte flags，
不能简化成 Boolean `1`。

Pixel 真实输入：

```text
descriptor bytes = bf ff ff ff ff ff fd 1f 00 00 00 00 00 00 00 00
low uint64        = 0x1FFDFFFFFFFFFFBF
REV32 lane words = bfffffff fffffd1f 00000000 00000000
```

纠正输入后，静态 VM 在 `0x106d00` 得到与真机一致的 lane0/shared words：

```text
1ffdffff ffffffbf 00000000 00000000
```

随后固定比较相等，测试 source 为 `1`，原始 `source==0` 条件为 false，代码自然跳过
`0x3e`。没有修改 `0xf4884` 分支，也没有 patch lane 或最终输出。完整 VM 结果：

```text
executed instructions = 8,009,752
direct helper calls   = 1,316,791
output length         = 176
frozen output equal   = true
```

证据：

```text
.omx/static-audit-20260713/arm64-protected-engine-correction-3e.md
.omx/static-audit-20260713/arm64-schedule-to-106d00.md
native-reimplementation/PROTECTED_ENGINE_STATIC_RECOVERY.md
```

---

# 4. 输入、输出和数据结构

## 4.1 JNI 输入

```text
nSign(Context, Object map, byte[] javaHmac, int androidApi) -> byte[]
```

`0xcbe98` 接收内部 0x28-byte loaded-input descriptor：

| offset | 内容 |
|---:|---|
| `+0x00` | `JNIEnv*` |
| `+0x08` | Context ref pointer |
| `+0x10` | Map ref pointer |
| `+0x18` | Java-HMAC byte[] ref pointer |
| `+0x20` | Android API int pointer |

outer descriptor 和 slot pointer 先被解引用，之后才检查 pointee。有效条件是 API >= 1 且 JNIEnv、Context、Map、Java HMAC 非空。

## 4.2 Native context

| offset | 语义 |
|---:|---|
| `+0x00` | 初始 realtime ms |
| `+0x08` | timing/status 区域 |
| `+0x0c` | Android API |
| `+0x10` | Java Map |
| `+0x18` | 最终 Java result |
| `+0x20` | 4-byte field2 |
| `+0x30` | 32-byte correction basis |
| `+0x50` | 128-byte correction slots |
| `+0xe0` | 16-byte flags/opaque state |
| `+0xf0` | 20-byte certificate SHA-1 |
| `+0x108` | owned string |
| `+0x110` | publicSourceDir string |
| `+0x118` | reserved length，当前 producer 为 0 |
| `+0x120` | reserved data，当前 producer 为 null |

## 4.3 九个 descriptor

```cpp
struct ByteDescriptor {
    uint32_t length;
    uint32_t padding;
    const uint8_t* data;
};
```

| slot | 来源 | 长度 |
|---:|---|---:|
| 1 | context correction slots | 128 |
| 2 | certificate SHA-1 | 20 |
| 3 | flags/opaque state | 16 |
| 4 | correction basis | 32 |
| 5 | field2 | 4 |
| 6 | plaintext big-endian length | 4 |
| 7 | selected-Map plaintext | dynamic |
| 8 | reserved big-endian length | 4，当前为 0 |
| 9 | reserved bytes | 0/null |

engine 入口按 big-endian logical word 导入；1/2/3-byte tail 放入最终 word 高字节。固定 count 9 是 descriptor 数，不是算法编号。

## 4.4 Selected Map

`0x11d798` 对固定 100-key 表做计数和复制两遍。特殊值：

```text
secret_id      -> 1400000
headers_id     -> 9
native_version -> 3.67.0
```

`secret_id=1400000` 属于 protected plaintext；`adj_signing_id=1400000` 是结果 metadata builder 的独立输出，不能混淆。

## 4.5 Work object

```text
0xa0-byte owner
+0x00 evaluation stack
+0x08 shared arena
+0x10 counter chain
+0x18 auxiliary schedule stack
+0x20..+0x98 sixteen arena lanes
```

Word stack node 是 16-byte `{uint32 value; padding; Node* next}`。Arena 具有 capacity、word buffer、logical length、frame depth 和 frame-base buffer。

已确认状态：

| status | 语义 |
|---:|---|
| 2 | allocation failure |
| 3 | empty pop |
| 4 | stack index/require failure |
| 6 | export alignment/format failure |
| 7 | frame underflow |
| 8 | protected bounds failure |

## 4.6 输出

```text
16-byte IV
|| AES-256-CBC/PKCS#7 ciphertext
|| 32-byte HMAC-SHA256 tag
```

HMAC 输入只包含 ciphertext，不包含 IV。总长度：

```text
16 + PKCS7_padded_payload_length + 32
```

已知 176、192、208-byte 结果是 payload padding 长度变化，不是多套算法。

成功时写入 Map：

```text
headers_id     = 9
adj_signing_id = 1400000
native_version = 3.67.0
algorithm      = adj8
```

Java 再以 Base64 NO_WRAP 写 `signature`。Native 本身不上传远端；socket 导入中的已恢复用途之一是本地 loopback 探测。本轮未执行网络行为。

---

# 5. 安全发现及严重程度

## 5.1 高：客户端包含可静态恢复的固定 native 对称密钥

protected engine 的固定 AES-256 和 HMAC-SHA256 key materialization 已被恢复。为避免扩散敏感材料，本报告不复制具体 key bytes。

风险：

- 客户端固定秘密不能作为不可提取的信任根。
- 版本级共享 key 会扩大单点泄露影响。
- Java per-install HMAC 可增加设备绑定，但不能自动消除固定 native key 风险；需确认服务端实际信任链。

若服务端仅依赖该固定 key，应上调为严重/关键。

## 5.2 高：HMAC 不覆盖 IV

`tag = HMAC(ciphertext)`，而 output 是 `IV || ciphertext || tag`。CBC 第一块满足 `P1 = D_K(C1) XOR IV`；若接收端只验证 ciphertext tag，修改 IV 不改变 tag，却能翻转第一明文块。TLS 只能降低某些传输篡改，不能修复 envelope 自身缺少完整认证的问题。

## 5.3 中：IV 由秒级 `time -> srand -> rand` 生成

证据：

```text
0x11daa8 time()
0x11daac srand(timeSeconds)
0x11a62c/0x11a64c rand()
IV_word[i] = rand() XOR rand()
```

秒级 seed 可预测；同秒重置 PRNG 可能重复 IV；全局 `rand` 状态还可能受同进程其他组件干扰。与 5.2 联合后，整体密码构造风险为高。

## 5.4 中：API 19..22 使用 1024-bit RSA + PKCS#1 v1.5

Java bytecode明确调用 `setKeySize(1024)` 和 `Cipher.getInstance("RSA/ECB/PKCS1Padding")`。用途虽是本地 key wrapping，但强度和 padding 均已过时，长期存储、备份、迁移和错误处理存在风险。

## 5.5 中：key 异常重试会删除持久化材料

`InvalidKeyException` / `UnrecoverableKeyException` 会删除 KeyStore alias `key2` 和 SharedPreferences `encrypted_key`。瞬时 provider 故障、多进程竞争或迁移异常可能引发不可逆 key rotation，连续失败后还会全局 lockdown，造成签名可用性抖动。

## 5.6 低：内部 descriptor 在 null 检查前解引用

正常 JNI wrapper 下普通 Java 调用者通常不能伪造 outer descriptor；但未来 native 复用、错误 FFI 或不完整替代若传空 outer/slot pointer，会直接崩溃而非返回受控错误。这是鲁棒性和兼容性问题，当前未证明为远程输入漏洞。

## 5.7 低：环境/反插桩检测可能误报

procfs `frida-agent`、`127.0.0.1:27042`、ART/linker、timing、cmdline 等观察会进入 correction state。合法调试、企业监控、端口占用、OEM 差异或兼容层可能改变签名，造成同业务输入跨环境不一致。

## 5.8 待确认，中风险候选：arena read 以 capacity 而非 logical length 为界

`0x138744..0x138818` 以 capacity 判定读取是否越界；writer 扩容使用 `realloc`。若可达 schedule 存在 sparse write，并读取扩容后未写入 gap，可能使用未初始化 heap word。当前 vector 未证明触发；Python VM 将 arena 初始化为零，可能掩盖此差异。必须先做静态 definedness 证明，不能把它写成已证实漏洞。

## 5.9 低：parser-owner 分配失败泄漏已打开的文件流

`0x124c90..0x125074` 先通过 `fopen(path,"rb")` 获得 `FILE*`，之后才执行
`calloc(1,0x48)`。若 allocation 失败，ARM64 和 x86_64 都写 status `1` 并返回 null，
路径中没有 `fclose`。正常内存条件下不触发；在持续内存压力或故障注入下，重复调用可
耗尽文件描述符。直接 C++ 恢复为保持原生行为而保留该语义，产品修复不应保留。

## 5.10 待确认，中风险候选：APK Signing Block size/entry 长度校验不完整

`0x1259b8..0x127194` 校验 Central Directory signature、`APK Sig Block 42` magic
以及 header/footer 两个 uint64 size 相等，但没有显式要求 `size>=24`，也没有在
模 64 位计算 `8-size` 并执行相对 seek 前证明 `centralDirectoryOffset-size-8` 位于
文件范围内。checked `fseek/fread` 会拒绝许多畸形输入，但 seek-past-EOF 可以成功，
小 size 也可能把 header read 指向 footer 内部。

下游 `0x127194..0x127a78` 进一步确认：entry header 的 raw `fread` 零返回被当作正常
结束且不写 status；recognized v2/v3/v3.1 entry 把 uint64 size 截断为 low32 后再减 4，
没有验证高 32 位为零或 `size>=4`；unknown entry 只在 skip 前比较当前位置，随后按完整
uint64 `size-4` raw fseek，不证明目标仍在 Signing Block/file 范围内，且
`footerOffset+size` 本身是未检查溢出的模 64 位加法。当前已证实输入验证缺口，但嵌套
parser 仍有多层 section-size 检查；是否可形成越界/过大分配还是仅受控状态错误需继续
组合证明，因此列为中风险候选，不写成已证实内存破坏。

## 5.11 低：getline-compatible helper realloc failure 丢失旧 allocation

`0xd6ed8..0xd7890` 在容量不足时先写回按 128-byte block 计算的新 capacity，再把
`realloc(old,newCapacity)` 返回值直接写入 `*line`。ARM64 与 x86_64 都在 null 检查前完成
这两项 publication。若 `realloc` 失败，allocator 仍保留旧 allocation，但 caller pointer
已经变为 null，函数返回 `-1`，旧 allocation 因而泄漏。正常内存条件下不触发；在故障
注入或持续内存压力下，重复长行读取可造成额外 heap 消耗。恢复 C++ 保留该失败状态以
匹配原生，产品修复不应保留。

## 5.12 待确认，中风险候选：recursive metadata parser 缺少 source 边界

`0xd28d0..0xd313c` 直接从共享 cursor 读取 0x1c-byte descriptor，再把五个 uint32
字段作为 source-relative own-pair offset、两组 child count 和两张 uint32 offset table。
解析过程中没有 source length 参数，也没有验证 descriptor、table entry、relative offset
或嵌套 descriptor 是否仍位于映射范围内。两组 allocation 都直接执行
`calloc(uint32_count,0x30)`；libc 可拒绝乘法溢出，但 native parser 没有 count、总节点数
或递归深度上限。

正常失败原子性相对完整：array pointer 在 calloc 后立即发布，published count 仅在单个
child 成功后递增；当前 child 由嵌套 parser 或 `0xd2018` 自清理，parent 再通过 `0xd22d4`
只回滚已经计数的元素。风险主要来自畸形 source 导致的越界读取、过大分配或深递归。
当前尚未证明普通第三方应用能控制 system-property metadata source，因此列为中风险
候选，不写成已证实可利用内存破坏。

## 5.13 中：property-info mmap failure 未检查即解引用

`0xd352c..0xd3d90` 将 `mmap(nullptr,size,PROT_READ,MAP_PRIVATE,fd,0)` 返回值先发布到
source `+0x08`，随即从返回地址读取前 16 bytes 和后续 8 bytes，复制到 source
`+0x18`。ARM64 与 x86_64 在这些读取前都没有 null/`MAP_FAILED` gate。映射失败时不会
写入 status，也不会先调用 `0xd3d90` 关闭 fd，而会直接访问无效地址，形成稳定性和
可用性崩溃。当前没有证据表明该路径能转化为攻击者可控写入，因此按中等严重程度的
本地拒绝服务/兼容性缺陷记录。

## 5.14 待确认，中风险候选：scratch pair 长度和 sentinel 边界

`0x8f56c` 未检查两个 `uint64 length+1` 的回绕，也未验证非零长度对应 source 非空/可读；
回绕后 allocation size 与后续 copy/NUL 使用的原始长度不一致。`0x8fb44` 则不读取 count、
不设置 128-slot 上限，只依赖全空 pair sentinel。已知 appender 以 127-entry capacity 保留
最后一项 sentinel，所以正常主链的两个设计互相闭合；但畸形长度、scratch 损坏或其他
writer 是否可破坏该不变量，仍需继续分析上游 `0x8746c`，当前不写成已证实可利用漏洞。

## 5.15 正向观察

- RELRO、NOW、NX stack、stack canary 和部分 FORTIFY 均存在。
- 多数 allocation/JNI failure 有 status 和 rollback。
- 未发现明文第三方网络凭据、远端 C2 或第三方在线访问逻辑。
- 无间接 `blr` 算法 dispatcher，但这不消除普通内存破坏风险。

---

# 6. 修复建议

## 6.1 P0 密码协议

1. 迁移到标准 AEAD：AES-256-GCM 或 ChaCha20-Poly1305。
2. nonce 使用 CSPRNG 或严格唯一计数器，不使用 `rand/srand/time`。
3. 将 version、algorithm、IV/nonce、设备/会话标识和必要 metadata 纳入 AAD 或认证输入。
4. 不能立即迁移时，至少改为 `HMAC(version || algorithm || IV || ciphertext || metadata)`，并使用新协议版本。
5. 固定客户端 key 视为公开参数；改用 Android Keystore 非导出设备 key、短期服务端凭据、key ID、吊销和轮换。

## 6.2 P1 legacy key

1. API 18..22 不再新建 1024-bit RSA；至少 2048-bit。
2. 平台允许时使用 OAEP，隔离 PKCS#1 v1.5 legacy。
3. `SecretKeySpec` algorithm 与 Mac 对齐为 `HmacSHA256`，不要标成 `AES`。
4. key migration 做成事务：新 key 注册成功后再删旧 key，记录 generation/version，支持崩溃恢复。

## 6.3 P1 错误与可用性

1. 不在首次 key exception 时立即删除持久 key；先区分临时 provider 状态、锁屏、永久 invalidation 和数据损坏。
2. global lockdown 改成结构化状态，记录原因、时间和恢复条件。
3. `nSign` 入口先检查 outer descriptor 和 slot pointer，再解引用。
4. primary error 与 cleanup error 分开保存，cleanup 不能覆盖根因。

## 6.4 P1 内存安全

1. Arena read 同时验证 `frameBase+offset < logicalLength` 和 `< capacity`。
2. `realloc` 扩容成功后显式清零新增 words，或 new+copy+zero。
3. 所有 offset 加法用更宽类型先做溢出检查。
4. descriptor 统一验证：`length==0` 时 data 可 null；`length>0` 时 data 非 null；设置最大长度。
5. JNI local refs 使用 RAII；每个 New/Put/Remove/Set 后立即检查 exception。
6. parser-owner 构造使用 RAII 或在 owner allocation 失败时立即 `fclose` 已打开的流。
7. APK Signing Block parser 在减法前验证 `size>=24`、`size<=centralDirectoryOffset-8`，
   用 checked arithmetic 计算 block start，并验证 header/footer/entries 全部落在文件内。
8. 每个 entry 要求 `4<=entrySize<=remainingBytes` 且 recognized size 不得超过
   `UINT32_MAX`；unknown skip 使用 checked target-position 计算，raw EOF/short read 应写
   明确格式错误而不是静默成功。
9. getline-compatible helper 使用临时 pointer 接收 `realloc`；仅在成功后同时提交 pointer
   和 capacity，并为单行长度/容量增长设置上限和 checked arithmetic。
10. recursive metadata parser 在提交 child count/pointer 前验证 `count*0x30` 无溢出且
    完整落在 allocation/input 范围内；限制递归深度，拒绝 cycle，并让 count/pointer 成对
    原子发布，避免 failure rollback 进入不一致 destructor state。
11. property-info source 在 mmap 后先判断 null/`MAP_FAILED`；失败时写稳定 status，并通过
    owner destructor 关闭 fd。复制 header 前验证 mapping 至少覆盖 24 bytes，再校验 magic、
    version、string-table/root offsets 均位于映射范围内。
12. scratch pair appender 对 `length+1` 做 checked arithmetic，非零长度要求 source 非空且
    可读；限制单项和总 owned bytes，allocation/copy 全部成功后再事务发布。
13. scratch destructor 同时使用可信 count 与物理 128-slot bound，sentinel 只作为一致性
    检查，避免损坏对象导致越界读取或 invalid free。

## 6.5 P2 环境检测

1. 环境观察与密码 plaintext 分离，改为显式 versioned risk metadata。
2. loopback/procfs/timing detection 提供 false-positive 处理和稳定错误码。
3. 不把反插桩当作核心 key 保护手段；设计上假定客户端常量最终可被分析。

## 6.6 回归测试规格

当前仅提出规格，不执行目标 SO：

- API 18/19/22/23/当前最高 API。
- `onResume -> sign` 顺序、null Context/Map/HMAC/API。
- IV 改一 bit 必须导致 tag 失败。
- 同秒并发 nonce/IV 不重复。
- 176/192/208 长度、空输入、block 边界、最大长度。
- KeyStore missing/locked/temporary failure/permanent invalidation。
- preferences 缺失、Base64 损坏、RSA unwrap failure。
- stack empty、index==count、frame underflow。
- arena sparse write、扩容 gap read、整数溢出。
- 每个 JNI New/Put/Remove/Set failure 和 pending exception cleanup。
- procfs 不可读、cmdline empty、loopback port occupied、OEM 差异。
- EOCD/Central Directory offset 越界、Signing Block size `<24`、超大 size、header/footer
  size 不一致、magic 错误和 seek-past-EOF。
- entry size `<4`、高 32 位非零、unknown skip 跨 footer/file end、8/4-byte header 短读
  以及三个 v2/v3/v3.1 ID 的重复/乱序组合。
- getline helper 的初始 EOF、partial EOF、空行、127/128/255/256-byte 边界、预分配
  buffer、capacity zero、calloc/realloc failure 和容量算术溢出。
- recursive metadata node 的 null、零 count/非空 array、两组嵌套 child arrays、最大
  count、`count*0x30` 溢出、cycle、深度上限和 partial-parser rollback。
- property-info source 的 calloc/access/openat/fstat/短文件/mmap failure，以及映射成功但
  header magic、table/root offset 越界的组合；mmap failure 必须返回状态而不是崩溃。
- scratch pair 的 count 126/127 边界、零长度/null source、`UINT64_MAX` length、第一/第二
  allocation failure、partial-copy rollback、缺失 sentinel 和损坏 count/pointer 组合。

---

# 7. 尚不能确认的事项

## 7.1 覆盖缺口

```text
JNI reachable recovered: 282
JNI reachable partial:     0
JNI reachable unknown:    39
```

尚不能确认全部 JNI 可达函数、所有失败/JNI exception/cleanup 分支、所有 correction probe 和边缘 metadata/status 路径。

## 7.2 Protected engine 已关闭事项与剩余边界

文本解释器在真实 Pixel context-flags descriptor 下可静态终止并完整匹配：

```text
status = 0
rand consumed = 8
output length = 176
executed instructions = 8,009,752
direct helper calls = 1,316,791
frozen output equal = true
```

原 `0x3e` mismatch 的根因是把 16-byte context flags 错误简化为 Boolean `1`。
真实低 64-bit 为 `0x1FFDFFFFFFFFFFBF`。纠正后无需 PC skip、lane patch 或输出硬编码。

该 FDE 当前仍未穷举：

- 所有可能的 context flags 组合。
- 预置非零 status 与 allocation failure。
- 极端/畸形 descriptor length、null data 和 arena 增长失败。
- 全部设备/API/ROM profile 的差分矩阵。

## 7.3 完整 C++ 替代尚未成立

已有 C++ 覆盖 AES、custom SHA-256、CBC/PKCS#7、HMAC、Bionic-rand IV、176/192/208 layout、多项 correction、metadata、API18 legacy 和 JNI transaction。但当前仍不能证明：

- JNI-reachable `unknown=0`。
- 所有同输入逐字节等价。
- 所有 error/status/cleanup 等价。
- 可直接替换原 SO 而不改变 Java API、时序和环境行为。

结论：

> **核心算法和大量外围语义已经恢复，但完整静态闭环尚未完成；现在不能宣称完美替代 libsigner.so。**

## 7.4 后续恢复优先级

1. 按 JNI 可达度、调用者数和内存/系统 API 使用排序恢复 39 个 unknown；system-property
   metadata 主链、`0x8f56c/0x8fb44` scratch ownership pair 和 `0xb21b4` display-metrics
   int reader、`0xa8978` size reader、`0xa948c` indexed object reader、`0xbce98`
   DisplayMetrics getter，以及 `0xb5828/0xbb5a0/0xbea74/0xbf5fc/0xc0180` 的
   system-service、Resources、sensor-list、name/vendor 链已经闭合。producer
   `0x8746c..0x8f56c` 的十三个 property publication、`malloc(length+1)`、sensor signed
   loop、last-only UTF/local-ref cleanup、display 顺序和 appender `0x26` 边界均已完成
   跨 ABI/C++ 闭合，并新增 property-before-sensor 的 source-level composition。
   231-state failure-publication verifier 和全 failure-class 原生 destructor-envelope 回归现已
   完成，因此该 FDE 已迁移为 recovered；property 值仍由调用方 callback 提供，C++ 不
   内置设备 profile。
   `0x2c618..0x2cc9c` 的 Raspberry manufacturer probe 也已跨 ARM64/x86_64 闭合：
   两个属性名和 marker 的 XOR-once plaintext、两条 kind-3 record、固定 record count 2、
   `0x24444` match count 与 caller correction `0x28` 均由 C++、专用 verifier 和隔离
   Unidbg false/true profile 共同证明。
   相邻 `0x2cc9c..0x2e1d4` 的五属性 minical/vcloud/Scorpio probe 也已闭合：八个
   XOR-once property/marker 字符串、五条 kind-3 record、固定 count 5、布尔返回与 caller
   correction `0x2c` 均由跨 ABI verifier、C++ 回归和隔离 false/true profile 共同证明。
   非 JNI-reachable `0x93fd0..0x94bc0` 与 `0x917a8..0x91d2c` 已恢复为
   `BigInteger.toByteArray()` JNI helper 和 unsigned big-endian byte materializer，保留
   status `3/18/28/2`、单字节零 sign-prefix 移除、signed length widening、
   `calloc/memcpy`、release/delete ownership 和失败双 output 清零。
   `0x96ea8..0x975f0` 随后恢复为 `Cipher.init(int,Key)` helper：四段跨 ABI XOR-once
   常量、GetObjectClass/GetMethodID/CallVoidMethod、三次 exception consume、status
   `3/18/41`、caller mode `2`、signed jint forwarding、incoming-status preservation 和
   cipher-class cleanup 均由专用 verifier、C++ direct regression 与证据文档闭合；API 18
   原 SO observation-only hook 也确认自然调用一次、mode `2/2`、精确 method/signature、
   cipher/key 原样转发、status `0 -> 0`、零 call exception 和单次 class cleanup。
   `0x9816c..0x9885c` 随后恢复为 caller-supplied object/class-name assignability
   helper：GetObjectClass、FindClass、IsAssignableFrom、三次 exception consume、
   status `3/18/28`、jboolean 归一化、双 class-ref cleanup 和 incoming-status output
   clearing 均已跨 ABI 闭合。
   JNI-reachable `0xb081c..0xb0f38` 也已恢复为 `update(byte[])` void-method helper：
   跨 ABI once-lock 解码、GetObjectClass/GetMethodID/CallVoidMethod、三次 exception
   consume、status `3/18/28`、incoming-status 保留、byte-array 原样转发和 class-ref
   cleanup 均由 C++ 回归及专用 verifier 闭合；原 SO observation-only hook 还确认自然
   路径单次调用的精确 method/signature、参数转发、status 0、零 call exception 和单次
   class cleanup。
   相邻 `0xb0f38..0xb1e40` 现已恢复为 `MessageDigest.digest` 双 overload helper：
   optional byte array 为 null 时选择 `digest()()[B`，非 null 时选择 `digest([B)[B`；
   GetObjectClass、GetMethodID、两个 CallObjectMethod 调用形态、三次 exception consume、
   status `3/18/28`、class-ref cleanup、returned digest byte-array transfer 与 incoming-status
   output clearing 均已由 ARM64/x86_64 verifier 和直接 C++ 回归闭合。原 SO API 18
   observation-only 日志自然确认 no-arg lookup/call，byte-array overload 由双 ABI 静态证据
   和 C++ 参数转发回归覆盖。
   `0xb9424..0xb9cc8` 随后恢复为 caller-supplied PackageInfo 的 `signingInfo`
   object-field reader：跨 ABI 固定 field/signature、GetObjectClass/GetFieldID/
   GetObjectField、三次 exception consume、status `3/18/28`、class-ref cleanup、返回
   SigningInfo transfer 和 incoming-status output clearing 均已由专用 verifier 与直接
   C++ 回归闭合；实现不构造、猜测或替换运行时 `SigningInfo` 对象。
   同一父流程中的 `0xc2b78..0xc375c` 也已恢复为
   `SigningInfo.getApkContentsSigners()[Landroid/content/pm/Signature;` reader：跨 ABI
   固定 method/signature、三次 exception consume、status `3/18/28`、null-result
   failure、class-ref cleanup、返回 `Signature[]` transfer 和 incoming-status output
   clearing 均由专用 verifier 与直接 C++ 回归闭合。
   API 27 及以下的 `0xb8830..0xb9424` 也已恢复为
   `PackageInfo.signatures [Landroid/content/pm/Signature;` object-field reader：跨 ABI
   固定 field/signature、GetObjectClass/GetFieldID/GetObjectField、三次 exception
   consume、status `3/18/28`、null-result failure、class-ref cleanup、返回
   `Signature[]` transfer 和 incoming-status clearing 均已闭合。API 18 原 SO JNI verbose
   自然路径还两次记录到 `getPackageInfo(...,0x40)` 后的同一字段查找与数组返回；该带 trace
   JVM 在测试逻辑执行后发生已知 Unicorn teardown `Abort trap: 6`，因此只作为行为观察，
   不计作 Maven 测试通过。
   `0xba914..0xbb5a0` 随后恢复为
   `PackageManager.getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;`
   reader：父流程在 API 27 及以下转发 `0x40`，在 API 28+ 转发 `0x08000000`；跨 ABI
   固定 method/signature、GetObjectClass/GetMethodID/CallObjectMethod、三次 exception
   consume、status `3/18/35`、null-result failure、class-ref cleanup、返回 PackageInfo
   transfer 和 incoming-status output clearing 均已由专用 verifier 与直接 C++ 回归闭合。
   原 SO JNI verbose 自然路径同时记录过两个 flags 的 method lookup、参数和
   `libsigner.so+0xbae78` call return PC。父函数 `0x1dde0..0x1e578` 现也已按 ARM64/
   x86_64 共同证据独立恢复：signed API `<28` 进入 legacy `0x40`/`signatures` 路径并
   发布 `hasMultipleSigners=false`，API `>=28` 进入 `0x08000000`/`signingInfo` 路径，
   再按 `hasMultipleSigners()` 选择 APK contents signers 或 certificate history；保留
   incoming-status 仍调用 getPackageName、失败前 caller output 不主动清空、整个
   `Signature[]` transfer，以及 SigningInfo→PackageInfo→PackageManager→packageName
   cleanup。动态日志中的 `GetObjectArrayElement(Signature[],0)` 返回 PC 为 `0x1ef20`，
   属于下一 FDE `0x1e578..0x1f058`，不属于本父函数。
   下一 FDE 的直接 helper `0xc2248..0xc2b78` 现已恢复为
   `Signature.toByteArray()[B` reader。它与独立 `0x93fd0` FDE 共享相同 JNI/status/
   ownership contract：null Signature 为 status 3，class/method failure 为 18，call
   exception 或 null result 为 28；三次 exception consume、class local-ref cleanup、
   returned byte[] transfer 和 incoming-status output clearing 均已由跨 ABI verifier、
   C++ 回归及 API 18 原 SO 自然 JNI 日志闭合。
   `0xaf438..0xb081c` 现已恢复为
   `java.security.MessageDigest.getInstance(String)` helper。两个 ABI 均固定
   `java/security/MessageDigest`、`getInstance` 和
   `(Ljava/lang/String;)Ljava/security/MessageDigest;`，父级解码并转发 `SHA1`；实现保留
   FindClass/GetStaticMethodID/NewStringUTF/CallStaticObjectMethod、四次 exception consume、
   status `3/18/27/28`、MessageDigest class 后 algorithm String 的 cleanup 顺序、返回
   MessageDigest transfer 和 incoming-status output clearing。原 SO observation-only
   集成测试确认 `algorithm=SHA1`、四次 exception 均为零以及 `cleanup=class,string`。
   父函数 `0x1e578..0x1f058` 也已闭合：选择 `Signature[]` 后取 index 0，依次执行
   `Signature.toByteArray`、`MessageDigest.getInstance("SHA1")`、`update`、no-arg `digest`、
   `GetArrayLength/GetByteArrayElements`。元素失败写 status `28`，digest 长度不是 20 写
   status `20`；只有精确 20 bytes 才按 16+4 字节布局发布。原 SO 动态观察固定
   `copy20 -> ReleaseByteArrayElements -> MessageDigest -> certificate byte[] -> digest byte[] ->
   Signature[]`，且没有显式删除单个 Signature element；恢复实现保持同一 ownership 和
   失败不覆盖 caller 20-byte output 的边界。
   environment dispatcher 的首个 probe `0x1f058..0x1f95c` 现也已恢复。两个 ABI
   分别从一次性 XOR 常量解码出 `/dev/socket/qemud`、`/dev/qemu_pipe`、
   `/dev/socket/genyd`、`/dev/socket/baseband_genyd`，构造四指针表后按两组、每组
   两条调用已恢复的 path-existence counter `0x1f95c`。两次调用共享 caller-owned
   `uint16_t`，不清零 incoming 值并保留 modulo-2^16 累加；上层 `0xf328` 对 count!=0
   提交 correction `0x01`。原 SO observation-only 测试确认路径、两组 count 和本地
   `0->0->0` 结果，未修改目标控制流或文件系统判断。
   `0x24860..0x25068` 现也已恢复为 VirtualBox DMI file-content probe。跨 ABI
   解码得到 `/sys/devices/virtual/dmi/id/product_name` / `VirtualBox` 与
   `/sys/devices/virtual/dmi/id/sys_vendor` / `innotek`；函数构造两个 0x100-byte
   readable-file record，固定 kind 3、descriptorCount 1，并以 recordCount 2 转发到
   `0x23274/0x26286`，共享 caller-owned `uint16_t`。原 SO 直接隔离 observation-only
   测试确认两个 record 和本地 `0->0` 结果。虽然 flattened FDE 中存在
   `0xfbd4/0x1384b` caller edge，当前 `0xf328` sole-entry 状态证明未把该 block 纳入
   自然 signer 链；因此不把直接调用结果表述为默认成功路径自然执行。
   `0xb2978..0xb3230` 已进一步恢复为 caller-selected String-field reader。双 ABI
   固定解码 `Ljava/lang/String;` 并执行 GetObjectClass、GetFieldID、GetObjectField，
   每阶段消费 pending exception；null object/name 为 status 3，class/field acquisition
   failure 为 18，object-field exception/null result 为 28。成功 String local ref 转交
   caller，临时 class ref 清理；incoming status 不抑制 JNI，但最终非零 status 清输出。
   唯一 caller `0x179f8` 传入 `publicSourceDir`；原 SO 自然 observation-only 路径
   确认三次 exception 均为零、单次 class cleanup，并把同一 String handle 传给 UTF helper。
   `0x1709c..0x179f8` 已恢复为 `/proc/self/cmdline` owned-string producer。固定项仅为
   原 SO 的 OS path、R_OK/AT_FDCWD/O_RDONLY 和 4095-byte read capacity；cmdline
   bytes、I/O 结果、allocator 和内存动作都由 caller/profile 通过 C++ operations/context
   提供，不读取宿主 `/proc` 或伪造字段。双 ABI 证明 access/read-empty status 8、open
   status 12、allocation status 2、read 后无条件 close、terminator-before-copy 与 late
   output publication。原 SO 没有拒绝负 read；`read=-1` 可由 wrapping `malloc(0)` 进入
   allocation 前一字节写和巨量复制，列为 High 内存安全发现。回归用 memory-effect
   callbacks 保留兼容证据而不在审计进程触发未定义行为。
2. 为 protected VM 增加 context-flags、status、descriptor 边界组合回归。
3. 对 arena allocation/realloc failure、stack underflow 和 frame rollback 做故障注入证明。
4. 对 API 18–22、API 23+、metadata rollback、lockdown 和 JNI exception 做真机差分。
5. 每次恢复同步更新 inventory、coverage、分析文档和 C++ evidence。

## 7.5 已执行的隔离动态验证与后续规则

2026-07-15 已在本地重新完成静态/动态联动验证：当前 C++ 的 126 个 executable
regression guard（源码中 131 个唯一 `*Regression` 定义）均通过入口执行，15 组
176/192/208-byte 原 SO oracle 全部逐字节一致；ASan+UBSan
smoke 通过，但 macOS 不支持 LeakSanitizer，因此没有声称 leak 检查通过；冻结 Pixel recovered
JSON 完全一致；154/154 静态 analyzer 通过；本轮 Maven 离线 recovered backend
直接通过 21/21，原 SO `SignerNativeIntegrationTest` 为 1/1，新增
`JniStringFieldReaderNativeIntegrationTest` 为 1/1；此前 `0x24860` 批次首跑曾在
`libunicorn_java.dylib!tb_alloc_aarch64+0xd4` SIGBUS，但不属于本轮结果；隔离
Unidbg 直接加载本地 ARM64 `libsigner.so` 后 `nOnResume`、`nSign` 成功并返回 176-byte
`adj8` 结果。该动态证据只验证已覆盖 profile 和 runner 可用性，函数完成度仍以
347 recovered / 41 unknown、JNI 298 recovered / 23 unknown 的静态 FDE 矩阵为准。

最新静态批次另闭合了非 JNI-reachable 的 `0xa0640` JNI
`KeyPairGenerator.generateKeyPair()` helper 和 `0x91428` AndroidKeyStore key-pair
orchestrator。跨 ARM64/x86_64 证据锁定 method/signature、三个 JNI exception gate、
status `3/18/28`、class-ref cleanup、provider XOR-once byte lock，以及
`getInstance -> load(null) -> generateKeyPair` 的输出/失败所有权。Portable C++ 的
JNI handle、generator 和 output storage 均由调用方传入，不构造默认 Java/设备对象。

用户已明确允许对项目专用真机包 `local.qbdi.adjustreference` 动态验证。本轮只清理该包，
未访问外网或其他应用数据。原 SO 结果与冻结 JSON 完全相等；helper-entry trace 取得
descriptor 2 的真实四个 logical words。

Frida inline instrumentation 在结果文件写出后曾使测试进程 JIT thread `SIGSEGV`。
因此插桩运行只作为前置数据流证据，不计为稳定性通过；后续应保持单 helper、最小 hook
面，避免 mid-block hook，并把未插桩差分作为最终行为基线。

### A. 原 SO 与替代差分

- 无外网 emulator/专用测试机，仅本地 adb。
- 固定 APK、证书、API、locale、timezone。
- 只用公司合成 Map，不用生产账号/数据。
- 固定 PID/time/gettimeofday/clock_gettime/KeyStore/procfs 观察。
- 观察 JNI 入参、9 descriptors、correction slots、flags、output、metadata、status。
- 快照隔离，专用 alias/preferences；防止 retry 删除真实 key。

### B. helper caller-visible state

- 仅记录相同 call site 返回后的 `x0..x17/NZCV`。
- 不绕过检测，不修改控制流，不访问第三方数据。
- 插桩本身可能触发 correction，必须作为观察结果记录。

### C. arena definedness

- 先在公司自编译的恢复 C++ 上加 initialization bitmap/redzone。
- 验证 sparse write 后是否读未定义 word。
- 对原 SO 的任何实验另行授权。

## 7.6 静态证据索引

```text
native-reimplementation/SO_FUNCTION_COVERAGE.md
native-reimplementation/STATIC_ANALYSIS.md
native-reimplementation/PROTECTED_ENGINE_STATIC_RECOVERY.md
.omx/libsigner-arm64-objdump.txt
.omx/static-audit-20260713/arm64-function-inventory.csv
.omx/static-audit-20260713/arm64-final-nine-descriptors.md
.omx/static-audit-20260713/arm64-final-consumer-11da64.md
.omx/static-audit-20260713/arm64-native-signing-context-orchestrator.md
.omx/static-audit-20260713/arm64-protected-engine.md
.omx/static-audit-20260713/arm64-protected-engine-correction-3e.md
.omx/static-audit-20260713/arm64-schedule-to-106d00.md
.omx/static-audit-20260713/device-protected-descriptor-import.json
.omx/static-audit-20260713/device-lane2-init-frida.log
.omx/static-audit-20260713/arm64-map-metadata-jni.md
.omx/static-audit-20260713/arm64-legacy-key-resolver.md
.omx/static-audit-20260713/arm64-parser-owner-constructor-124c90.md
.omx/static-audit-20260713/analyze_parser_owner_constructor_124c90.py
.omx/static-audit-20260713/arm64-apk-signing-block-locator-1259b8.md
.omx/static-audit-20260713/analyze_apk_signing_block_locator_1259b8.py
.omx/static-audit-20260713/arm64-apk-signing-block-entries-127194.md
.omx/static-audit-20260713/analyze_apk_signing_block_entries_127194.py
.omx/static-audit-20260713/arm64-getline-helper-d6ed8.md
.omx/static-audit-20260713/analyze_getline_helper_d6ed8.py
.omx/static-audit-20260713/disasm-x86-c36c3-c3e4a.txt
.omx/static-audit-20260713/arm64-recursive-metadata-destructor-d22d4.md
.omx/static-audit-20260713/analyze_recursive_metadata_destructor_d22d4.py
.omx/static-audit-20260713/disasm-x86-bfe08-c0340.txt
.omx/static-audit-20260713/disasm-x86-c1713-c1725.txt
.omx/static-audit-20260713/arm64-recursive-metadata-parser-d28d0.md
.omx/static-audit-20260713/analyze_recursive_metadata_parser_d28d0.py
.omx/static-audit-20260713/disasm-d28d0-d313c.txt
.omx/static-audit-20260713/disasm-x86-c0340-c0912.txt
.omx/static-audit-20260713/arm64-metadata-area-resolver-d313c.md
.omx/static-audit-20260713/analyze_metadata_area_resolver_d313c.py
.omx/static-audit-20260713/disasm-d313c-d352c.txt
.omx/static-audit-20260713/disasm-x86-c0912-c0cdd.txt
.omx/static-audit-20260713/arm64-property-info-source-d352c.md
.omx/static-audit-20260713/analyze_property_info_source_d352c.py
.omx/static-audit-20260713/disasm-d352c-d3d90.txt
.omx/static-audit-20260713/disasm-x86-c0cdd-c1318.txt
.omx/static-audit-20260713/arm64-jni-size-method-reader-a8978.md
.omx/static-audit-20260713/analyze_jni_size_method_reader_a8978.py
.omx/static-audit-20260713/arm64-jni-indexed-object-method-reader-a948c.md
.omx/static-audit-20260713/analyze_jni_indexed_object_method_reader_a948c.py
.omx/static-audit-20260713/unidbg-detector-scratch-a948c-raw.log
.omx/static-audit-20260713/arm64-jni-display-metrics-getter-bce98.md
.omx/static-audit-20260713/analyze_jni_display_metrics_getter_bce98.py
.omx/static-audit-20260713/unidbg-detector-scratch-bce98-raw.log
.omx/static-audit-20260713/arm64-jni-int-field-reader-b21b4.md
.omx/static-audit-20260713/analyze_jni_int_field_reader_b21b4.py
.omx/static-audit-20260713/arm64-detector-jni-object-pipeline.md
.omx/static-audit-20260713/analyze_detector_jni_object_pipeline.py
.omx/static-audit-20260713/arm64-jni-system-service-getter-b5828.md
.omx/static-audit-20260713/analyze_jni_system_service_getter_b5828.py
.omx/static-audit-20260713/unidbg-detector-scratch-system-service-raw.log
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
.omx/static-audit-20260713/elf-metadata/
.omx/static-audit-20260713/java-bytecode/
```
