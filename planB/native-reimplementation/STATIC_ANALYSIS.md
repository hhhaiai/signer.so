# `libsigner.so` 3.67.0 静态分析与 C++ 重写边界

本文件只使用当前工作目录内的 AAR、四个 ABI 的 `libsigner.so`、`classes.jar`
字节码、反汇编和已有源码。静态分析仍是函数级结论的主要依据；隔离动态验证仅运行
本地 recovered executable 和 Unidbg 中的本地目标 SO，不连接手机、网络或外部主机，
也不修改目标寄存器、返回值、分支、JNI object 或代码字节。

## 1. 文件概况

目标来自 `adjust-android-signature-3.67.0.aar`，包含四个 stripped ELF：

| ABI | 格式 | JNI `nOnResume` | JNI `nSign` |
|---|---|---:|---:|
| arm64-v8a | ELF64 little-endian AArch64 | `0xcba8c` | `0xcc604`, size `0x1330` |
| armeabi-v7a | ELF32 little-endian ARM | `0xb1370` | `0xb1de8`, size `0x9dc` |
| x86_64 | ELF64 x86-64 | `0xbaca3` | `0xbb6ab`, size `0x9d9` |
| x86 | ELF32 i386 | `0xb1823` | `0xb2394`, size `0xaee` |

四个文件的 SONAME 均为 `libsigner.so`，直接依赖相同：

```text
liblog.so
libm.so
libdl.so
libc.so
```

编译器信息在四个 ABI 中一致：

```text
Android clang 17.0.2
toolchain build 11349228
+pgo +bolt +lto -mlgo
LLD 17.0.2
```

程序头显示不可执行栈、GNU RELRO 和 `FLAGS_1=NOW`；导入
`__stack_chk_fail`，说明关键函数具有栈保护。ELF 已 strip，动态导出只有：

```text
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume
Java_com_adjust_sdk_sig_NativeLibHelper_nSign
```

主要 libc/import 面包括文件与进程观测、网络、时间和内存操作：

```text
access, fopen, fread, fstat, stat, readlink, opendir, readdir
getpid, time, gettimeofday, clock_gettime, localtime
socket, connect, sendto, recvfrom, setsockopt
mmap, munmap, malloc, calloc, realloc, free
rand, srand, syscall, __system_property_get
```

完整静态清单位于 `.omx/static-audit-20260713/`。

为满足逐函数恢复目标，现已从 arm64 ELF 的 `.eh_frame` FDE 生成精确函数边界清单，
不再依赖猜测 prologue：共 **388** 个内部函数范围。当前状态为 **347 recovered、
0 partial、41 unknown**；其中通过直接 `bl` 和跨 FDE tail-`b` 从两个 JNI export
静态可达的函数为 **321** 个，细分为 **298 recovered、0 partial、23 unknown**。
完整逐项矩阵位于：

```text
native-reimplementation/SO_FUNCTION_COVERAGE.md
.omx/static-audit-20260713/arm64-function-inventory.csv
```

该数字明确说明当前实现还不是完整 SO replacement；后续每恢复一个函数都要更新此矩阵。
最新批次逐指令闭合了 20 个 `context+0xe0` load/OR/store flag leaf，以及
`0x4afe4/0x4afe8/0x4afec` 三个单 `ret` FDE。C++ 用一份显式地址/掩码表表达相同算法，
避免复制二十个同构函数体，同时通过回归验证 OR 结果与重复调用幂等性。
同一静态批次还恢复了 `0x8070..0x80c0` 的模块 DSO finalizer、两个 no-op、nullable
exit callback dispatcher 和 `__cxa_atexit` wrapper，以及 `0x139d04` 的 CPU-feature
constructor gate。其调用的独立 `0x1398cc` feature decoder 也已恢复：bit-62 descriptor
tag、HWCAP/HWCAP2 映射、HWCAP bit 11 的五个 `ID_AA64*` 输入、五处可能的 global
store 与最终 bit 58 均由逐指令 verifier 锁定。纯 C++ 输入结构为每个设备字段保留独立
presence gate，缺失值不会被默认零值替代。
`0xa0640..0xa1230` 已恢复为 JNI `KeyPairGenerator.generateKeyPair()` helper：两个 ABI
均固定解码相同 method/signature，执行 GetObjectClass/GetMethodID/CallObjectMethod，
三阶段消费异常，使用 status `3/18/28`，删除临时 class ref 并在成功时向 caller 转交
KeyPair ref。其外层 `0x91428..0x917a8` 使用 byte CAS 锁一次解码
`AndroidKeyStore`，按 `KeyStore.getInstance -> load(null) -> generateKeyPair` 顺序执行；
任何 helper status 非零都停止后续调用并清两个 output，但原 FDE 不 DeleteLocalRef 已
发布对象。C++ 保留该 ownership，同时只固定协议字符串，运行时 JNI/generator/output
均来自调用方。
相邻的非 JNI-reachable `0xb1e40..0xb21b4` 也已跨 ARM64/x86_64 恢复为
`java/lang/Exception` ThrowNew helper：原生 XOR-once lock/initialized 状态、FindClass、
单次 exception consumer、status 18、success-only ThrowNew 和 class local-ref cleanup 均
由直接 C++ 与逐指令 verifier 锁定。
JNI-reachable `0x2c618..0x2cc9c` 随后恢复为 Raspberry manufacturer property probe：
ARM64/x86_64 的三段 XOR-once 数据分别解码为两个 manufacturer 属性名和 `raspberry`，
两条 `0x100` record 均使用 kind 3 ASCII case-insensitive substring，固定 count 2 交给
`0x24444`，再将清零的 uint16 match count 转为布尔值。原 SO 隔离 CodeHook 进一步证明
Google/Google 返回 0 且不提交 `0x28`，混合大小写 Raspberry profile 返回 1 并提交一次
correction `0x28`。
紧邻的 JNI-reachable `0x2cc9c..0x2e1d4` 已恢复为五属性
minical/vcloud/Scorpio probe：八段跨 ABI XOR-once 数据解码为 manufacturer、vendor
manufacturer、model、vendor model、display id 与 `minical`、`vcloud`、
`Scorpio_rt OS`；五条 kind-3 record 固定 count 5 交给 `0x24444`，最终返回清零的
uint16 match count 是否非零。原 SO observation-only hooks 证明普通 Google profile
返回 0 且不提交 `0x2c`，混合大小写 `MiNiCaL` manufacturer 返回 1 并提交一次 `0x2c`。
非 JNI-reachable `0x93fd0..0x94bc0` 与 `0x917a8..0x91d2c` 也已闭合为
`BigInteger.toByteArray()` JNI helper 和 unsigned big-endian byte materializer，恢复
status `3/18/28/2`、sign-prefix 移除、signed length widening、allocation/copy、
element release、local-ref cleanup 和双 output failure clearing。
JNI-reachable `0x96ea8..0x975f0` 随后恢复为 `Cipher.init(int,Key)` helper：跨 ABI
固定解码 `init`/`(ILjava/security/Key;)V`，执行 GetObjectClass、GetMethodID、
CallVoidMethod，三阶段消费异常并使用 status `3/18/41`；唯一 caller 固定 mode `2`，
C++ 保留 signed `jint` 转发、incoming-status preservation 和 cipher-class cleanup。API 18
原 SO observation-only hook 进一步确认自然调用一次、entry/call mode `2/2`、
`init(ILjava/security/Key;)V`、cipher/key 原样转发、status `0 -> 0`、零 call exception 和
单次 class cleanup。
随后闭合的 `0x9816c..0x9885c` 是 caller-supplied object/class-name assignability helper：
跨 ABI 固定执行 GetObjectClass、FindClass、IsAssignableFrom，三阶段消费异常并使用 status
`3/18/28`；jboolean 被归一化到单字节 output，两个 non-null class local ref 按
object-class 后 target-class 顺序释放，incoming 非零 status 最终清 output。
JNI-reachable `0xb081c..0xb0f38` 随后闭合为 `update(byte[])` void-method helper：
两个 ABI 均通过独立 once-lock 解码 `update` 和 `([B)V`，执行
GetObjectClass/GetMethodID/CallVoidMethod、三次 exception consume、status `3/18/28`
和 object-class local-ref cleanup；成功时 incoming status 保留，input byte array 原样
转发且没有返回对象。原 SO observation-only hook 在自然签名路径确认单次 entry、
`update/([B)V`、object/byte-array 原样转发、零 call exception、status 0 和单次 class cleanup。
证据见
`.omx/static-audit-20260713/arm64-jni-byte-array-update-b081c.md`。
JNI-reachable `0xb0f38..0xb1e40` 随后闭合为 `MessageDigest.digest` 双 overload helper：
optional byte array 为 null 时选择 `digest()()[B`，非 null 时选择 `digest([B)[B`；跨 ABI
恢复 GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status
`3/18/28`、class local-ref cleanup、returned byte-array transfer 和 incoming-status output
clearing。API 18 原 SO 自然 JNI 日志进一步证明 parent 使用 no-arg overload。

当前静态清单也已和动态入口交叉复核：`build-and-test.sh` 在本次源码上完整通过 15 组
原 SO oracle；ASan+UBSan（macOS 上关闭不支持的 leak detector）smoke 通过；冻结 Pixel
recovered backend JSON 完全相等；Maven 离线的 recovered/original 两个 targeted integration
test 通过；隔离 Unidbg 原 ARM64 SO 的 `nOnResume -> nSign` 返回 176-byte `adj8` 结果。
这些运行结果证明已实现路径仍可执行，但函数完成度仍只以 388-FDE 静态矩阵为准，不能用
少量成功 profile 推导剩余 42 个 unknown 已完成。

### 最新关闭的 record/slice 与 parser-owner 函数

本轮对 ARM64 和 x86_64 的相同 opaque-state 常量与实际数据指令做了交叉验证，新增
三十个直接 C++ 恢复：

| ARM64 范围 | x86_64 对应范围 | 静态语义 |
|---|---|---|
| `0x13dc8..0x14078` | `0x1668d..0x168bd` | kind-10 filter + packed-transition counter；命中 correction `0x04`，失败 `0x32`，最终 mask `0x0004000000000010` |
| `0x14078..0x14338` | `0x168bd..0x16af8` | kind-10 filter + fixed-loopback counter；命中 correction `0x0a`，失败 `0x32`，最终 mask `0x0004000000000400` |
| `0x1709c..0x179f8` | `0x18909..0x18fe3` | `/proc/self/cmdline` owned-string producer；固定 OS path，caller-supplied access/openat/read/close/allocation/memory operations，read capacity 4095，status 8/12/2，read 后无条件 close、terminator-before-copy、late output publication；仅判 read==0，负 read 的 wrapping allocation 与 out-of-bounds copy 为 High 内存安全边界 |
| `0x24860..0x25068` | `0x27397..0x278f6` | VirtualBox DMI readable-file probe；两个 0x100-byte record 固定为 product_name/VirtualBox 与 sys_vendor/innotek，kind 3、descriptorCount 1、recordCount 2，共享 caller `uint16_t` 并转发到 `0x23274/0x26286`；直接隔离动态只观察函数自身，sole-entry `0xf328` 证明未把 flattened `0xfbd4` block 纳入自然 signer 链 |
| `0x2cc9c..0x2e1d4` | `0x2d13c..0x2dba0` | 五属性 minical/vcloud/Scorpio probe；五条 kind-3 record、count 5、uint16 match count 转 bool，true 路径 correction `0x2c` |
| `0x34820..0x34954` | `0x32955..0x32a17` | 低 24 位相等、second 高字节为 1、first 高字节不为 1 |
| `0x34954..0x34bf4` | `0x32a17..0x32c82` | `+0x10` key 双层交叉计数，candidate `+0x28==1`、`+0x08==0x0100007f` |
| `0x34bf4..0x34f9c` | `0x32c82..0x32f48` | 同一 key 双层计数，candidate `+0x28==1` 后调用 `0x34820(+0x08,+0x18)` |
| `0xd1a38..0xd1bf4` | `0xbf6d3..0xbf838` | 消费 `{uint32 offset,length}`，分配 `uint64(length)+1`，逐字节复制并加 NUL |
| `0xd1bf4..0xd2018` | `0xbf838..0xbfb83` | UINT32 index 或 `UINT32_MAX` 空串 sentinel，经 source `+0x24` offset table 克隆到 output `+0x08` |
| `0xd2018..0xd22d4` | `0xbfb83..0xbfe08` | 先 `0xd1a38`，status 为 0 才执行 `0xd1bf4`；失败 first 后 second 释放清零 |
| `0xd22d4..0xd28d0` | `0xbfe08..0xc0340` | 0x30-byte recursive metadata node：两组 count/连续 child array 按 ascending index 深度优先析构、释放 array、清 pointer/count，最后释放两条 owned string |
| `0xd28d0..0xd313c` | `0xc0340..0xc0912` | 0x1c descriptor；source-relative own/child offsets；递归 `+0x18` array、pair-only `+0x28` array、成功后 count publication、status 2/d22d4 rollback |
| `0xd313c..0xd352c` | `0xc0912..0xc0cdd` | 点分段 resolver：中间段首个 `strncmp(segmentLength)` 匹配下降 `+0x18`，最终段 `strcmp` 扫描 `+0x28` 并返回 second string |
| `0xd352c..0xd3d90` | `0xc0cdd..0xc1318` | `/dev/__properties__/property_info` access/openat/fstat、size>=24、read-only private mmap、前 24-byte header copy；status 2/8/10/12，mmap result 未检查即解引用 |
| `0xd4220..0xd4244` | `0xc1713..0xc1725` | 保存 outer node，调用 recursive content destructor，再 tail-call `free` 同一 pointer |
| `0xd6ed8..0xd7890` | `0xc36c3..0xc3e4a` | 128-byte `fgets` chunk、去换行、多 chunk 追加、initial/partial EOF、full incoming-capacity clear、128-byte growth 和 direct realloc failure publication |
| `0x87158..0x8746c` | `0x881ea..0x88475` | scratch display width `+0x60` / height `+0x64` 在八个固定分辨率 pair 中做正向或反向匹配；1440x3120 隔离动态 profile 已互证字段角色 |
| `0x8746c..0x8f56c` | `0x88475..0x93f86` | 13-property 延迟 publication/status 2；service failure 固定 0x24、width/height 固定 0x1d、其余 helper status 保留；signed sensor loop、last-only JNI cleanup、post-appender increment、display 流与最终 0x8fb44 ownership envelope |
| `0x8f56c..0x8fb44` | `0x93f86..0x94496` | count>=127 返回 0x26；两次独立 malloc(length+1)、forward byte copy/NUL；双成功才发布 pair/count，失败 first-then-second free 并返回 2 |
| `0x8fb44..0x90714` | `0x94496..0x94d5e` | null no-op；固定字段按 +08,+18,+20,+00,+30,+38,+10,+50 释放清零，再扫描 +0x70 pair 到首个全空 sentinel，不读取 +0x870 count |
| `0x917a8..0x91d2c` | `0x95bf1..0x9604f` | BigInteger byte-array 转 unsigned big-endian owned bytes；可选零 sign-prefix、signed length widening、calloc/copy、release/delete 顺序和双 output failure clearing |
| `0x93fd0..0x94bc0` | `0x97673..0x97d1e` | 固定 `toByteArray()[B`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、class cleanup 和 returned byte-array transfer |
| `0xaf438..0xb081c` | `0xa87cf..0xa91a3` | 固定 `java/security/MessageDigest.getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;`；caller-supplied algorithm，父级传 `SHA1`；FindClass/GetStaticMethodID/NewStringUTF/CallStaticObjectMethod、四次 exception consume、status 3/18/27/28、class→algorithm String cleanup、returned MessageDigest transfer 和 incoming-status output clear |
| `0xb081c..0xb0f38` | `0xa91a3..0xa9783` | 固定 `update([B)V`；GetObjectClass/GetMethodID/CallVoidMethod、三次 exception consume、status 3/18/28、incoming-status 保留、byte-array 原样转发和 class cleanup |
| `0xb0f38..0xb1e40` | `0xa9783..0xaa064` | optional byte array 为 null 时固定 `digest()()[B`，非 null 时固定 `digest([B)[B`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、class cleanup、returned digest byte[] transfer、incoming-status output clear；原 SO 自然路径动态确认 no-arg overload |
| `0xa8978..0xa948c` | `0xa469c..0xa4cd9` | 固定 `size()I`；GetObjectClass/GetMethodID/CallIntMethod、三次 exception consume、status 3/18/28、class local-ref cleanup、incoming-status 保留和最终输出清零；隔离原 SO caller edge 返回 status 0/value 1 |
| `0xa948c..0xa9d44` | `0xa4cd9..0xa53a9` | 固定 `get(I)Ljava/lang/Object;`；GetObjectClass/GetMethodID/CallObjectMethod(index)、三次 exception consume、status 3/18/28、null result failure、class local-ref cleanup、returned local-ref transfer、incoming-status 保留和最终输出清零；隔离原 SO index 0 返回 `android/hardware/Sensor` |
| `0xbce98..0xbd6a8` | `0xb0994..0xb1071` | 固定 `getDisplayMetrics()Landroid/util/DisplayMetrics;`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、null result failure、class local-ref cleanup、returned local-ref transfer 和最终 output clearing；隔离原 SO 返回 `android/util/DisplayMetrics` 并被后续 width/height reader 使用 |
| `0xb1e40..0xb21b4` | `0xaa064..0xaa362` | XOR-once `java/lang/Exception`；FindClass 后只消费 lookup exception，null/exception status 18，成功 ThrowNew(message) 且忽略返回；non-null class DeleteLocalRef |
| `0xb21b4..0xb2978` | `0xaa362..0xaa8bb` | `GetObjectClass`、`GetFieldID(name,"I")`、`GetIntField`；三次 exception consume，status 3/18/28，class local-ref cleanup，incoming-status 保留和最终非零 status 输出清零 |
| `0xb2978..0xb3230` | `0xaa8bb..0xaae64` | caller-selected String field reader；`GetObjectClass`、`GetFieldID(name,"Ljava/lang/String;")`、`GetObjectField`，三次 exception consume，status 3/18/28，null result failure、class local-ref cleanup、returned String transfer、incoming-status 保留和最终非零 status 输出清零；唯一 caller 传 `publicSourceDir`，原 SO 自然路径确认同一 String handle 继续进入 UTF helper |
| `0xb3230..0xb3bf4` | `0xaae64..0xab508` | 固定 `Context.getPackageName()Ljava/lang/String;`；caller 提供 Context/JNIEnv/status/output，GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、class cleanup、返回 String ref 转交和 incoming-status output clear；不构造 package name 或 Java object |
| `0xb3bf4..0xb479c` | `0xab508..0xabbd8` | 固定 `Context.getPackageManager()Landroid/content/pm/PackageManager;`；caller 提供 Context/JNIEnv/status/output，GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18、call/null-result failure、class cleanup、返回 PackageManager ref 转交和 incoming-status output clear |
| `0x1dde0..0x1e578` | `0x22cf9..0x2335e` | API-dependent `Signature[]` selector parent；signed API `<28` 使用 `getPackageInfo(...,0x40)`、发布 `hasMultipleSigners=false` 并读取 `PackageInfo.signatures`，API `>=28` 使用 `0x08000000`、`PackageInfo.signingInfo`、`hasMultipleSigners()` 后选择 APK contents signers/history；incoming-status 仍先调用 getPackageName，失败前 caller outputs 保持，成功数组转交 caller，SigningInfo→PackageInfo→PackageManager→packageName cleanup；不含下一 FDE 的 `GetObjectArrayElement` |
| `0x1e578..0x1f058` | `0x2335e..0x23d51` | `Signature[]` index 0 → `Signature.toByteArray` → `MessageDigest.getInstance("SHA1")` → `update` → no-arg `digest` → byte-array elements；element failure status 28、digest length !=20 status 20、成功 16+4 字节发布；ReleaseByteArrayElements 后按 MessageDigest→certificate byte[]→digest byte[]→Signature[] 清理，保持原 SO 不显式删除 Signature element 和失败不覆盖 caller output |
| `0xb5828..0xb70e4` | `0xac4d5..0xad0a5` | 固定 Context class/method/signatures，caller 传入 `SENSOR_SERVICE`；FindClass/GetMethodID/GetStaticFieldID/GetStaticObjectField/CallObjectMethod、五次 exception consume、status 3/18/28、service String 后 class local-ref cleanup；隔离原 SO返回 `SensorManager` |
| `0xb8830..0xb9424` | `0xadf2e..0xae5f4` | API 27 及以下固定 `PackageInfo.signatures [Landroid/content/pm/Signature;`；GetObjectClass/GetFieldID/GetObjectField、三次 exception consume、status 3/18/28、null-result failure、class cleanup、返回 Signature[] ref 转交和 incoming-status output clear；原 SO API 18 JNI verbose 自然路径两次互证 |
| `0xb9424..0xb9cc8` | `0xae5f4..0xaece3` | caller 提供 PackageInfo object/JNIEnv/status/output；固定 `signingInfo Landroid/content/pm/SigningInfo;`；GetObjectClass/GetFieldID/GetObjectField、三次 exception consume、status 3/18/28、class cleanup、返回 ref 转交和 incoming-status output clear；C++ 不构造 SigningInfo |
| `0xba914..0xbb5a0` | `0xaf3e2..0xafb26` | caller 提供 PackageManager/packageName/flags/JNIEnv/status/output；固定 `getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;`，父流程转发 `0x40` 与 `0x08000000`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/35、null-result failure、class cleanup、返回 PackageInfo ref 转交和 incoming-status output clear；原 SO JNI verbose 对两个 flag 分支均有自然路径互证 |
| `0xc2b78..0xc375c` | `0xb3ff9..0xb46d8` | 固定 `SigningInfo.getApkContentsSigners()[Landroid/content/pm/Signature;`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、null-result failure、class cleanup、返回 Signature[] ref 转交和 incoming-status output clear |
| `0xc375c..0xc4064` | `0xb46d8..0xb4dad` | 固定 `SigningInfo.getSigningCertificateHistory()[Landroid/content/pm/Signature;`；GetObjectClass/GetMethodID/CallObjectMethod、三次 exception consume、status 3/18/28、class cleanup、返回 Signature[] ref 转交和 incoming-status output clear |
| `0xc4064..0xc4ae4` | `0xb4dad..0xb5413` | 固定 `SigningInfo.hasMultipleSigners()Z`；GetObjectClass/GetMethodID/CallBooleanMethod、三次 exception consume、false 为合法成功结果、status 3/18/28、raw jboolean byte publication、class cleanup 和 incoming-status output clear |
| `0xbb5a0..0xbc3ac` | `0xafb26..0xb02c7` | 固定 `Resources.getSystem()Landroid/content/res/Resources;`；static method lookup/call、三次 exception consume、status 18/28、class cleanup 和返回 ref transfer |
| `0xbea74..0xbf5fc` | `0xb1a13..0xb20c2` | 固定 `Sensor.getName()Ljava/lang/String;`；status 3/18/28、class cleanup 和返回 String transfer |
| `0xbf5fc..0xc0180` | `0xb20c2..0xb278e` | 固定 `Sensor.getVendor()Ljava/lang/String;`；与 name getter 共享 JNI/status/ownership 模型 |
| `0xc0180..0xc0d84` | `0xb278e..0xb2e55` | 固定 `SensorManager.getSensorList(I)Ljava/util/List;`；producer 传 `-1`，class/method/call/null-result 均 status 18，不使用 status 28；隔离原 SO 返回单元素 List |
| `0xc2248..0xc2b78` | `0xb392f..0xb3ff9` | 固定 `Signature.toByteArray()[B`；与独立 FDE `0x93fd0` 共享 no-arg object-method contract，status 3/18/28、三次 exception consume、class local-ref cleanup、returned byte[] transfer 和 incoming-status output clear；`0x1e578` caller 参数转发及 API18 原 SO 自然 JNI 路径均已确认 |
| `0x124c90..0x125074` | `0x11cb9c..0x11cf06` | `access(path,R_OK)`、一次性解码 `rb`、`fopen`、`calloc(1,0x48)`，status 2/1 与 `+0x18/+0x28/+0x38` owner 初始化 |
| `0x125074..0x125210` | `0x11cf06..0x11d040` | null owner no-op；可选 `FILE*` close/clear 后依次析构 `+0x18/+0x28/+0x38` 并 free 外层 owner |
| `0x125210..0x125770` | `0x11d040..0x11d3b2` | checked fread 4 bytes 后精确匹配一次性解码的 ZIP EOCD marker `50 4b 05 06` |
| `0x125770..0x1259b8` | `0x11d3b2..0x11d585` | 从 EOF `-22` 扫描至 `-65556`；seek 失败或 EOCD 命中停止，耗尽返回 `-65557` |
| `0x1259b8..0x127194` | `0x11d585..0x11e1d8` | EOCD `+12` 读取 Central Directory offset，校验 `PK 01 02` 与 `APK Sig Block 42`，发布 footer offset/size，以 `8-size` 定位 header 并校验重复 size；mismatch status 3/5/6 |
| `0x127194..0x127a78` | `0x11e1d8..0x11e802` | raw `uint64 size + uint32 ID` entry loop；v2/v3/v3.1 ID 路由至 `+0x18/+0x28/+0x38`，recognized 用 low32(size)-4，unknown 用 checked-ftell bound 和 full64(size)-4 skip，fseek 失败 status 7 |

两个交叉计数器均以 `uint16_t` 模 `65536` 返回，重复 key 按笛卡尔积独立计数。

`RecoveredDetectorInputProfile8746c` 是建立在已恢复 property materializer 和 pair appender
之上的 C++ 调用方适配层，不是新增的原 SO FDE。它要求调用方显式提供十三个 property、
display dimensions 和 sensor list；缺失 property 默认拒绝，显式
`UseEmptyString` 才转为空串。适配器验证 property 的 `0x60` buffer 上限和 127-pair
sentinel 上限，并通过独立 cleanup 释放全部十三个 property 与所有 sensor pair。原
`0x8fb44` 只释放八个固定字段的兼容性行为保持不变。

`runRecoveredDetectorSensorDisplayPipeline8746c` 现已把非 property 主链恢复为直接 C++：
`getSystemService(SENSOR_SERVICE)`、`getSensorList(-1)`、`size()`、signed `jint`
`index<size`、逐项 `get/name/name-UTF/vendor/vendor-UTF/append`，terminal sensor cleanup，
随后 `Resources.getSystem/getDisplayMetrics/widthPixels/heightPixels` 和 display/resources
cleanup。ARM64 `cmp w27,w14` 后以 `lt` 选择循环态，x86_64 使用 `cmovl`，因此 C++
必须使用 `int32_t`；回归明确覆盖 `0/-1/1/2`。两 sensor observation-only trace 证明
第一项临时 Sensor/name/vendor refs 与两条 UTF pointer 被第二项覆盖，最终只清最后一项，
cleanup 顺序为 name UTF、vendor UTF、manager、list、last sensor、last name、last vendor，
然后才进入 display stage。专用 verifier 同时检查两个 ABI 的 helper、post-appender
increment、两个 UTF release、七个 DeleteLocalRef 和 C++ failure envelope。128-sensor
边界运行又证明第 128 次 append 在 count 127 时返回 `0x26`，producer 保留 127 项、
width/height 为零、只执行五个 sensor local-ref delete 并完全跳过 Resources/display。

`0x8746c` 整体 coverage 已迁移为 recovered。专用 verifier 从 x86_64 解析 231 个
flattened state literal，并由 ARM64 固定状态写入和最终 `w20` 返回互证：service failure
归一化为 `0x24`，width/height failure 归一化为 `0x1d`，其余 JNI/appender/display helper
status 保留。C++ 新增 success、13 个 property allocation failure、九类 sensor failure、
second-pair `0x26` 和四类 display failure 的原生 `0x8fb44` destructor-envelope 回归，确认
八个 owned fixed fields 与 pair 被清除，而五个兼容性未释放字段、count 和 display 值保持。
`0xd1a38` 在 allocation 前先把 cursor 增加 8；失败时不会回滚 cursor，而是
`*output=nullptr`、`*status=2`。`length=UINT32_MAX` 的请求大小是
`0x100000000`，不是 32 位加法回绕。`0x124c90` 在打开文件后才分配 owner；若
`calloc(1,0x48)` 失败，两个 ABI 都直接返回 null/status 1 而不关闭已经打开的流。
`0x1259b8` 成功后把 owner `+0x08/+0x10` 分别写为 Signing Block footer offset 和
footer size，并把 stream 留在初始 uint64 header size 之后；它没有额外执行
`size>=24` 或 block-start 文件范围检查，这一输入校验缺口的下游影响仍需结合
`0x127194` 继续确认。该下游现在证明 raw entry-header read 的零返回被视为正常结束，
recognized size 丢弃高 32 位且不检查 `size>=4`，unknown skip 只检查跳转前位置而不检查
目标位置；完整内存安全影响仍依赖更深层 section/allocation 边界组合。
`0x8f56c` 说明 scratch 物理上虽有 128 个 pair slot，但 appender 只允许发布 127 项，
因此为相邻 `0x8fb44` 的全空 sentinel scan 保留最后一项；任一 allocation failure 都不会
发布 partial slot。两个 ABI 同时证明长度使用未经检查的 `uint64 length+1`，copy loop 使用
原长度且不验证 source，因此超长/空 source 的实际风险仍取决于上游 `0x8746c` 参数来源。

对应实现和静态证据：

```text
native-reimplementation/recovered_primitives.cpp
.omx/static-audit-20260713/analyze_packed_transition_34820.py
.omx/static-audit-20260713/analyze_record_cross_match_34954.py
.omx/static-audit-20260713/analyze_packed_transition_counter_34bf4.py
.omx/static-audit-20260713/analyze_slice_string_materializer_d1a38.py
.omx/static-audit-20260713/analyze_indexed_string_materializer_d1bf4.py
.omx/static-audit-20260713/analyze_owned_string_pair_d2018.py
.omx/static-audit-20260713/analyze_recursive_metadata_destructor_d22d4.py
.omx/static-audit-20260713/analyze_recursive_metadata_parser_d28d0.py
.omx/static-audit-20260713/analyze_metadata_area_resolver_d313c.py
.omx/static-audit-20260713/analyze_property_info_source_d352c.py
.omx/static-audit-20260713/analyze_parser_owner_constructor_124c90.py
.omx/static-audit-20260713/analyze_parser_owner_destructor_125074.py
.omx/static-audit-20260713/analyze_zip_eocd_cluster_125210_125770.py
.omx/static-audit-20260713/analyze_apk_signing_block_locator_1259b8.py
.omx/static-audit-20260713/analyze_apk_signing_block_entries_127194.py
.omx/static-audit-20260713/analyze_detector_record_stages_13dc8_14078.py
.omx/static-audit-20260713/analyze_unordered_fixed_pair_matcher_87158.py
.omx/static-audit-20260713/analyze_detector_scratch_appender_8f56c.py
.omx/static-audit-20260713/analyze_detector_scratch_destructor_8fb44.py
.omx/static-audit-20260713/analyze_jni_size_method_reader_a8978.py
.omx/static-audit-20260713/analyze_jni_indexed_object_method_reader_a948c.py
.omx/static-audit-20260713/arm64-jni-indexed-object-method-reader-a948c.md
.omx/static-audit-20260713/unidbg-detector-scratch-a948c-raw.log
.omx/static-audit-20260713/analyze_jni_display_metrics_getter_bce98.py
.omx/static-audit-20260713/arm64-jni-display-metrics-getter-bce98.md
.omx/static-audit-20260713/unidbg-detector-scratch-bce98-raw.log
.omx/static-audit-20260713/analyze_jni_int_field_reader_b21b4.py
.omx/static-audit-20260713/analyze_detector_jni_object_pipeline.py
.omx/static-audit-20260713/arm64-detector-jni-object-pipeline.md
.omx/static-audit-20260713/analyze_jni_system_service_getter_b5828.py
.omx/static-audit-20260713/arm64-jni-system-service-getter-b5828.md
.omx/static-audit-20260713/unidbg-detector-scratch-system-service-raw.log
.omx/static-audit-20260713/unidbg-jni-order-b5828.log
```

## 2. 程序模块和执行流程

### Java 层

`classes.jar` 给出的原始 descriptor 是：

```text
NativeLibHelper.nOnResume()V
NativeLibHelper.nSign(Context,Object,byte[],int)[B

Signer.getVersion()Ljava/lang/String;
Signer.onResume()V
Signer.sign(Context,Map,String,String)V
Signer.sign(Context,Map,Map,Map)V
```

V4 静态字节码流程：

```text
验证参数
  -> Map.put("activity_kind", activityKind)
  -> Map.put("client_sdk", clientSdk)
  -> 最多两次初始化/获取 Java HMAC key
  -> UTF8(Map.toString())
  -> HmacSHA256
  -> NativeLibHelper.nSign(context, map, javaHmac, androidApi)
  -> Base64(nativeResult)
  -> Map.put("signature", ...)
  -> 删除 activity_kind/client_sdk
```

API 选择的 Java/JNI 密钥路径：

```text
API >= 23:
  AndroidKeyStore.getKey("key2")
  -> HmacSHA256

API 18..22:
  SharedPreferences["adjust_keys"]["encrypted_key"]
  -> Base64.decode
  -> AndroidKeyStore PrivateKeyEntry
  -> RSA/ECB/PKCS1Padding decrypt
  -> SecretKeySpec
  -> HmacSHA256

API < 18:
  抛出不支持异常并把进程内 signer 置为 lockdown
```

### Native 层

AArch64 `nSign` 静态调用骨架：

```text
0xcc604 exported JNI wrapper
  -> 0xcba90 / 0xcbbd4 初始化上下文
  -> 0x143e8 环境 dispatcher
  -> 0xd6888 后续环境/状态处理
  -> 0xf224 timing correction gate
  -> 0x11da64 payload/result consumer
       -> 0xa334 清除旧 result 并移除四个临时 metadata
       -> 0xaf3c / 0x9548c / 0x95680 创建并填充 Java byte[]
  -> 0xcbe98 从 context+0x18 取出 JNI 返回对象
  -> JNI byte[] 返回
```

ARMv7、x86 和 x86_64 的导出规模、外部依赖和 JNI surface 对应一致，说明它们是
同一逻辑的多架构编译产物，而不是按 ABI 提供不同公开算法。

对 arm64 全文件直接调用点进行静态枚举后，`0x11da64` 只有一个来自导出 `nSign`
编排器的直接调用点：`0xcc28c`。该 consumer 从 `0x11da64` 到统一 epilogue
`0x11ea70` 只有一个 `ret`，内部通过大量 opaque 64-bit state 常量分派。这支持“当前
成功输出集中经过同一个 consumer”的判断，但 opaque state 仍阻止纯静态分析证明
每一个内部状态的可达性，因此不能把单一直接入口误写成“绝对不存在隐藏算法状态”。

本轮重新限定反汇编边界后确认：现有原始文件在 `0x11ea74` 的 stack-check failure call
之后，还继续包含了**下一个函数**（入口 `0x11ea78`）。因此 final consumer 的严格范围是
`0x11da64..0x11ea74`，不能把文件尾部 `0x11ea78` 之后的第二个 opaque state machine
算入 signer consumer。静态解析得到 1029 条指令、84 个 basic block、117 条 CFG edge；
证据表位于 `.omx/static-audit-20260713/arm64-final-consumer-cfg.md`，生成器是同目录的
`analyze_final_consumer.py`。该生成器只解析 objdump 文本，不加载或执行目标 SO。

本轮继续严格划分 consumer 周边的受保护 helper，汇总位于：

```text
.omx/static-audit-20260713/arm64-opaque-helper-summary.md
```

边界和静态分类：

```text
0xa334..0xaf38      result metadata cleanup，清空 context+0x18 并 Map.remove 四项
0xaf3c..0xcde0      Java byte[] materializer + metadata builder，调用 0x9954c 恰好四次
0xf1ec8..0x11ba74   42,732-instruction protected crypto/data engine
0x11ba78..0x11d408  generic range/byte adapter
0x11d798..0x11da60  result concatenation wrapper
```

`0xa334/0xaf3c/0x11ba78/0x11d798` 现可从直接调用、callback 和
`memcpy/calloc(length+1)` 数据流归类为 metadata 或通用 buffer 适配；真正仍可能容纳
隐藏 crypto state 的主要范围收敛为 `0xf1ec8..0x11ba74`。

JNI 返回对象路径现已进一步闭合。`0xa334` 在 `0xaec8` 先把 `context+0x18`
清零，再通过 `0x9aa5c` 的 `Map.remove(Object)` 删除 `headers_id`、
`native_version`、`adj_signing_id` 和 `algorithm`。最终 native bytes 生成后，
`0xaf3c` 在 `0xaf7c` 取 `context+0x18` 地址：`0x9548c` 通过 JNI vtable
`0x580` 调 `NewByteArray`，`0x95680` 通过 vtable `0x680` 调
`SetByteArrayRegion`。创建异常/null 写 status `31`，copy 异常写 `32`，独立 null
target 写 `3`；copy 异常保留已创建 reference，但 pending Java exception 阻止正常返回。
`0x11ea38..0x11ea48` 仅在 status 为零时返回 true，`0xcbe98`
最终从 `context+0x18` 返回 Java `byte[]`。证据与可重复检查位于：

```text
.omx/static-audit-20260713/analyze_jni_result_materialization.py
.omx/static-audit-20260713/arm64-jni-result-materialization.md
```

`0xaf3c` 的 flattened transaction 顺序现已恢复为
`NewByteArray -> SetByteArrayRegion -> headers_id -> adj_signing_id -> native_version -> algorithm`。
四个 put 的 call-site 分别为 `0xc544/0xc7f4/0xbffc/0xc6a4`；地址顺序本身不是
运行顺序。创建、copy 或任一 put 失败都选择公共 rollback state
`0x43c03deaa70c8d82`，在 `0xc250` 调 `0xa334`。最后一次 put 成功则选择
`0x4c81a55be310eef5` 并在 `0xcdb8` 返回。C++ 已通过
`modelRecoveredNativeResultBuilder()` 建模成功提交、部分 put 次数、四次 rollback remove
以及 cleanup failure 覆盖原 status。证据：

```text
.omx/static-audit-20260713/analyze_native_result_builder_transaction.py
.omx/static-audit-20260713/arm64-native-result-builder-transaction.md
```

相邻 `0xcbe98` signing-context orchestrator 也已闭合。其外层 descriptor pointer slots
在门槛前被无条件解引用；已加载值要求 API 至少为 1，且 JNI env、Context、Map、supplied
Java-HMAC 均非空。`0xcc47c` 使用 `clock_gettime(CLOCK_REALTIME)`，失败时 status 非空则写
`14`，无 fallback。证书/摘要阶段的非零 status 在进入 `0xcba90` 前被清零，随后固定执行
`0xcba90 -> 0xcbbd4 -> 0x143e8 -> 0xd6888 -> 0xf224 -> 0x11da64`。
final consumer true/false 均收敛到 cleanup：条件 free/clear context `+0x108/+0x110`，
无条件 `free(+0x120)`，最后返回 `+0x18`。ARM64 时钟 helper 已与 x86_64
`0xbb5b8` 交叉确认。证据：

```text
.omx/static-audit-20260713/analyze_native_signing_context_orchestrator.py
.omx/static-audit-20260713/arm64-native-signing-context-orchestrator.md
```

相邻 `0x9aa5c` 的完整失败/status/cleanup 也已闭合。输入 `env/map/key` 任一为 null
写 status `3`；`GetObjectClass` 或 `GetMethodID` 的 exception/null 写 `18`；
`NewStringUTF` exception/null 写 `34`；`CallObjectMethod(Map.remove)` exception 写
`28`；成功不清零已有 status。class 与 key string local ref 会按可用性删除，但
`Map.remove` 返回对象只进入 `x19` 且不被删除。反而，创建 key string 的路径会对
flattened 初始 state anchor 执行一次 `DeleteLocalRef`；x86_64 存在相同 `%r13`
路径。`0xa334` 不检查四次 remove 之间的 status，因此后续失败可覆盖早先状态，后续
成功保留早先失败。C++ 通过状态数据记录 opaque-anchor deletion attempt，不在宿主 JNI
中主动执行无效引用删除。证据：

```text
.omx/static-audit-20260713/analyze_map_remove_cleanup.py
.omx/static-audit-20260713/arm64-map-remove-cleanup.md
```

## 3. 关键函数及证据位置

以下地址均为 arm64-v8a 模块相对地址：

| 地址 | 静态含义 | C++ 状态 |
|---:|---|---|
| `0xcc604` | `nSign` JNI 导出 | API/CLI 已建模 |
| `0xcbe98` | native signing-context orchestrator | 输入门槛、时钟/证书 fail-open、阶段顺序、owned cleanup 与 `+0x18` 返回已实现 |
| `0xcc47c` | `CLOCK_REALTIME` 毫秒采样器 | 失败 status `14`、null-status 和 ARM64/x86_64 行为已实现 |
| `0xcba8c` | `nOnResume` 导出跳板 | 单条无条件 tail branch 到 `0xd4908`，已由 `runRecoveredNOnResumeExport` 直接表示 |
| `0x9279c` | 设置 native context `+0xe0` bit，不是算法 dispatcher | 已更正 |
| `0x143e8` | 受保护环境 dispatcher | 部分恢复 |
| `0x14338` / `0x14350` / `0x14368` | 三个固定 `context+0xe0` flag-mask 叶函数 | 已实现 |
| `0x14380` / `0x143b4` | 两个独立 correction `0x32` + flag bit 0 wrapper | 已实现 |
| `0x13dc4` | 单条 tail branch 到 `0x14380` 的 correction `0x32` alias | 已实现 |
| `0x14e10` / `0x14e44` | correction `0x35` / `0x36` + flag bit 0 | 已实现 |
| `0x14e78` / `0x14eac` | 两个独立 correction `0x3a` + flag bit 0 wrapper | 已实现 |
| `0x14ee0` | `context+0xe0 |= 0x0460603c00000000` | 已实现 |
| `0x134dd8` | correction replacement-slot finder | 64 slots、8 项循环 sentinel、耗尽返回 64 已实现 |
| `0x13531c` | state-local correction codeword writer | 目标清零、逆 bit basis XOR、index 64 alias sentinel 0 已实现 |
| `0x13548c` | correction find-and-write wrapper | find 后 tail-call writer 的完整参数流已实现 |
| `0xf1c8` | correction `0x33` + flag bit 0 helper | correction 写入后 `context+0xe0 |= 1` 已实现 |
| `0xf1fc` | context flag-mask helper | `context+0xe0 |= 0x0008000000000080` 已实现 |
| `0xf214` | context stage-complete helper | `context+0xe0 |= 0x20` 已实现 |
| `0xf224` | timing correction gate | `context+0x08` 低字节控制 correction `0x05`/flag bit 0，最终无条件置 `0x20` 已实现 |
| `0x134d18` | correction 基础 codeword 变换区域 | 已恢复 `encodeCorrection` |
| `0xd428` | cmdline 缺失/空 wrapper | 已映射 `0x34` |
| `0xd22d4` / `0xd4220` | 0x30-byte recursive metadata-node content/owner destructor | 两组连续子数组按 ascending index 深度优先清理，array pointer/count、两条 owned string 和外层 owner 的严格释放顺序已跨 ARM64/x86_64 实现 |
| `0xd28d0` | recursive metadata-node parser | 0x1c descriptor、两张 source-relative offset table、递归 `+0x18` 数组、pair-only `+0x28` 数组、成功后 count publication 和 d22d4 rollback 已跨 ARM64/x86_64 实现 |
| `0xd313c` | dot-separated metadata area-name resolver | 中间段按首个 prefix-length 匹配下降递归数组，最终段 exact leaf lookup 并返回 second owned string 已跨 ARM64/x86_64 实现 |
| `0xd352c` | property-info mapped source creator | 固定路径 decode、access/openat/fstat、24-byte gate、mmap/header copy、status 2/8/10/12 与 failure destructor 已跨 ARM64/x86_64 实现 |
| `0x8f56c` | detector scratch owned string-pair appender | 127-entry capacity、两次独立 allocation/copy、NUL、success-only pair/count publication、status 2/0x26 和 first-then-second rollback 已跨 ABI 实现 |
| `0x8fb44` | detector scratch content destructor | 八个固定 owned pointer 顺序、pair first/second cleanup、全空 sentinel 终止和 count/opaque preservation 已跨 ABI 实现 |
| `0xa8978` | JNI `size()I` int-method reader | 固定 method/signature、GetObjectClass/GetMethodID/CallIntMethod、status 3/18/28、incoming-status 和 class-ref cleanup 已跨 ABI 实现 |
| `0xa948c` | JNI indexed object-method reader | 固定 `get(I)Ljava/lang/Object;`、GetObjectClass/GetMethodID/CallObjectMethod(index)、null result status 28、incoming-status、class-ref cleanup 和 returned local-ref transfer 已跨 ABI 实现；动态互证 index 0 返回 Sensor |
| `0xbce98` | JNI DisplayMetrics getter | 固定 `getDisplayMetrics()Landroid/util/DisplayMetrics;`、GetObjectClass/GetMethodID/CallObjectMethod、null result status 28、incoming-status、class-ref cleanup 和 returned local-ref transfer 已跨 ABI 实现；动态互证返回对象供 width/height reader 使用 |
| `0xb21b4` | JNI int-field reader | `heightPixels/widthPixels` 两个 producer 调用、field signature `I`、GetObjectClass/GetFieldID/GetIntField、status 3/18/28、exception 和 class-ref cleanup 已跨 ABI 实现；动态互证 width/height 写入 +0x60/+0x64 |
| `0xd6ed8` | 128-byte、去换行的 getline-compatible helper | null-buffer `calloc(128,1)`、完整 incoming-capacity 清零、重复 `fgets/__strlen_chk`、多 chunk 追加、空行/初始 EOF/partial EOF、精确 128-byte 扩容和 realloc failure 状态已跨 ARM64/x86_64 实现 |
| `0x1f058` | QEMU/Genymotion socket-path probe | 两个 ABI 均解码四条固定 `/dev` 路径，按 QEMU 两条、Genymotion 两条分两次调用 `0x1f95c`，共享 incoming `uint16_t` 累加值；environment caller 对 count!=0 提交 correction 0x01；原 SO observation-only 路径/分组/计数已互证 |
| `0x1f95c` | path-existence array counter | 精确 count-bounded pointer walk，逐项调用 `0xd7890`，仅存在时以 `uint16_t` 模 2^16 累加且不清零 incoming count |
| `0xd7890` | `access(path, F_OK) == 0` 路径存在 helper | 已实现 |
| `0xd78b8` | `/proc/self/maps` `frida-agent` scanner | R_OK/open status 8、逐行区分大小写 substring、命中早停、free-before-fclose 已完整实现 |
| `0x122fdc` / `0x124a18` | 两个 `{head=0, tailSlot=&head}` 空链表初始化叶函数 | 已实现 |
| `0x130128` | 独立 `ret` no-op FDE | 已实现 |
| `0xd184` | realtime threshold comparison | CLOCK_REALTIME、仅 `-ENOSYS` 回退、毫秒换算、baseline 与 strict `>` 低字节写入已实现 |
| `0xf18f4` | 两路径 `stat()` helper | 已映射 `0x2f` |
| `0x9954c` | metadata item builder | 四个静态 metadata 已恢复 |
| `0x9aa5c` | JNI `Map.remove(String)` helper | status `3/18/34/28`、调用阶段、引用 cleanup/泄漏与 opaque-anchor delete attempt 已恢复 |
| `0x9548c` | JNI `NewByteArray` output helper | status `31` 与 null/preexisting-status 清理已恢复 |
| `0x95680` | JNI `SetByteArrayRegion` helper | null status `3`、exception status `32` 已恢复 |
| `0x11a62c`, `0x11a64c` | `rand() XOR rand()` IV word 生成 | 已实现 |
| `0x115ca0..0x115ce8` | custom SHA-256 state XOR materialization | 已实现 |
| `0x10337c` | AES SubBytes 相关路径 | 已实现为标准 AES-256 |
| `0xfe130` family | AES MixColumns 相关路径 | 已实现 |
| `0x10ee84` | 按逻辑 index 读取最终 word | 已理解 |
| `0x10ee98` | 写入 JNI 输出 vector | 已理解 |
| `0x138318` | framed word-arena writer | 完整布局、128-word 扩容和 status `2` 已实现 |
| `0x138560` | word-arena frame push | frame-base 扩容和 status `2` 已实现 |
| `0x138660` | word-arena frame pop | length rollback 和 status `7` 已实现 |
| `0x138728` | current frame length | 已实现 |
| `0x138744` | framed word-arena reader | capacity bound/zero fallback 已实现 |
| `0x138a70` | linked word-stack push | 16-byte node、status `2` 已实现 |
| `0x138b74` | linked word-stack pop | status `3`、unlink/free 已实现 |
| `0x138c8c` | duplicate indexed stack word | strict bound/status `4` 已实现 |
| `0x138e58` | duplicate-top wrapper | tail-call indexed duplicate with index 0；空栈 status `4` |
| `0x138e60` | top/index swap | strict bound/status `4` 已实现 |
| `0x12e95c` | unsigned 96-bit comparator | 三 limb 顺序和 `-1/0/1` 已实现 |
| `0x12eb48` | final range-boundary predicate | low limb equality + upper pair ordering 已实现 |
| `0x13716c` | 32-byte boundary range lookup | 半开区间、final predicate 和 cookie/null 返回已实现 |
| `0x136a00` | string-array trailing-delimiter join | 两遍分配/复制、尾随空格与空数组行为已实现 |
| `0x12c12c` | `android` marker/triplet parser | 朴素 ASCII case-insensitive marker 搜索、连续点跳过、三段 dot/NUL token 扫描、单次 errno clear、三次 `strtol`、partial mutation/output 已闭合 |
| `0x135640` | marker/triplet range gate | 九参数 ABI、source copy、无条件 join、status `2/5`、两次 lookup、first-null/second-nonnull 与 free 顺序已实现 |
| `0x1392c4` | 0xa0-byte work-object destructor | 4 个固定成员 + 16 lanes 清理顺序已实现 |
| `0x1393cc` | 0xa0-byte work-object allocator | 子对象顺序、失败清理和 0x100 lane capacity 已实现 |
| C++ `deriveCorrectionCodes` | 已知 cmdline/maps/API/ART/timing 等观察的有序推导 | 本轮已实现，静态编译通过 |
| `0x11d798` | JNI Map plaintext 两遍 materializer | 本轮已恢复并更正角色 |
| `0x11d40c` | emitted Map-value counting sink | 本轮已恢复 |
| `0x11d528` | emitted Map-value bounded-copy sink | 本轮已恢复 |

### Final consumer 严格边界内的直接调用

严格截断后，除 `time/srand/calloc/free/stack_chk_fail` 外，consumer 只直接调用以下
内部 helper 家族：

```text
0x13917c  分配 16-byte descriptor，并记录 length/data pointer
0x139270  从对象 +0x28 取 reader，再转到 0x138744
0x13927c  reader-to-output copy wrapper
0x1392c4  销毁 0xa0-byte work object：4 个固定成员 + 16 个 arena lanes
0x1393cc  分配并初始化同一 work object，所有 arena 请求容量为 0x100
0xa334, 0xaf3c, 0xf1ec8, 0x11d798  受保护的数据变换/装配 helper
```

其中 `0xf1ec8` 静态调用的高频容器词汇已经恢复：`0x138318..0x138818` 是带 frame-base
栈的 32-bit arena，`0x138a70..0x138fd4` 是 linked word stack 的 push/pop、indexed
duplicate 和指定项交换；精确布局、分配粒度、边界返回和 status `2/3/4/7` 已写入
C++。文本 VM 已表示主函数全部 42,732 条 ARM64 指令与 17 个直接 helper target。
将第三个输入从错误 Boolean `1` 修正为真实 16-byte context flags
`bf ff ff ff ff ff fd 1f 00 00 00 00 00 00 00 00` 后，VM 无 PC skip、lane patch
或输出硬编码即可产出完整冻结 176-byte reference。完整证据见
`PROTECTED_ENGINE_STATIC_RECOVERY.md`。

`0x13917c` 的九个调用点传入的长度依次可静态读出为：

```text
0x80, dynamic, 0x04, 0x04, 0x20, 0x04, 0x14, dynamic, 0x10
```

对应调用点为 `0x11dac4, 0x11e0e0, 0x11e2c0, 0x11e418, 0x11e5fc,
0x11e664, 0x11e6bc, 0x11e768, 0x11e848`。入口阶段还明确形成原始 context
`+0x20/+0x30/+0x50/+0xe0/+0xf0` 地址，后续从保存的 context 读取 `+0x118`
长度和 `+0x120` data pointer。当前严格范围内未出现第二套 12-byte IV、16-byte tag
或不同 final-output descriptor 的直接证据；这增强了“已知成功路径统一使用 adj8
CBC+32-byte HMAC envelope”的静态判断，但仍不替代对 opaque helper 全状态的可达性证明。

### `gcm` 字符串片段的交叉 ABI 更正

x86/x86_64/ARMv7 strings 中的 `=gcm`/`=gcmj` 不是算法名，而是 opaque control-flow
state 常量的低字节：

```text
0x9224eb6a6d63673d
```

证据位置：

```text
arm64   0x6dcd8..0x6dce8  mov/movk materialization + cmp
x86_64  0x5e946            movabs 0x9224eb6a6d63673d + cmp
x86     0x5938d/0x5df6d    两个 32-bit half 的 xor/cmov state comparison
```

因此不能用这些 strings 命中推断 AES-GCM。对 protected engine 的直接调用统计还确认，
整个 `0xf1ec8..0x11ba74` 只有两个 `rand@plt` call site：`0x11a62c/0x11a64c`，
即已恢复 IV word 的 `rand() XOR rand()` 循环，没有第二组 nonce 生成调用族。

### `0x11d798` JNI Map plaintext materializer

结合 `0xcc28c` 参数传递和 `0x11e924` call site，`0x11d798` 的输入是 status、JNIEnv、
Java Map/object、output pointer 与 output length。它不是 final ciphertext 输出器，而是
从 Java Map 生成 native plaintext：

```text
清零 24-byte sink context
-> 0x11ba78 + counting callback 0x11d40c
-> calloc(calculatedLength + 1, 1)
-> 0x11ba78 + bounded-copy callback 0x11d528
-> 返回 plaintext data pointer + explicit length
```

copy callback 使用的 context 布局是：

```cpp
struct Sink {
    uint64_t capacity;
    uint64_t offset;
    uint8_t* data;
};
```

`0x11d528` 在复制前验证 `offset + chunkLength <= capacity`，随后执行
`memcpy(data + offset, chunk, chunkLength)` 并推进 offset。额外分配的一个零字节不属于
plaintext material，因为后续 descriptor 使用显式 length。完整地址证据和伪代码见：

```text
.omx/static-audit-20260713/arm64-output-materializer.md
```

`0x11ba78` 在首次使用时通过 `0x139800` 原子 once gate，把 `0x145a30` 开始的
1363-byte 数据逐 byte XOR `0x52`。解码结果是 NUL-terminated、逗号分隔的 **100 个
Map key 有序白名单**。旧 recovered backend 只处理 15 个已观察字段，因此只对冻结
profile 完整；请求包含 `revenue/event_token/callback_params/partner_params/payload` 等字段
时会漏入 plaintext。本轮已把完整表迁入 C++ 和 recovered Java backend。

可重复的离线解码器和完整编号表：

```text
.omx/static-audit-20260713/decode_map_key_table.py
.omx/static-audit-20260713/arm64-map-key-table.txt
```

ELF 映射证据为 `.data` VMA `0x142e10`/file offset `0x13ae10`，因此表 VMA
`0x145a30` 对应 file offset `0x13da30`；1363 bytes XOR `0x52` 后在 offset 1362
恰好出现 NUL，逗号拆分数量严格为 100。

解码表的末四项是：

```text
activity_kind,client_sdk,headers_id,native_version
```

`0x8af4` 的完整静态解释修正了此前对 `1400000` 来源的归因。100-key 表第 80 项
`secret_id` 会被该 helper 精确匹配并固定 materialize 为 Java string `1400000`；同一
helper 还把 `headers_id` 和 `native_version` 固定为 `9`、`3.67.0`。其他 key 不产生
special value，继续走 `containsKey/get`。因此 sparse oracle 中的固定 `1400000` 来自
`secret_id` 的 special emit，不是把表外 `adj_signing_id` 插入第 96 项之前。

`0x8af4` 命中后先写 `NewStringUTF` 返回 reference，再调用 `0x92a20`；pending exception
会被 `ExceptionDescribe/ExceptionClear` 消费、写 status `34` 并返回 false。无异常时即使
`NewStringUTF` 返回 null 也返回 true。完整证据：

```text
.omx/static-audit-20260713/analyze_new_string_utf_helper_8af4.py
.omx/static-audit-20260713/arm64-reserved-map-value-helper-8af4.md
.omx/static-audit-20260713/analyze_jni_exception_consumer_92a20.py
.omx/static-audit-20260713/arm64-jni-exception-consumer-92a20.md
```

`0xaf3c` 中四个 `0x9954c` call-site 已静态恢复为 Java `Map.put(String,String)`：

```text
0xc544 headers_id=9
0xc7f4 adj_signing_id=1400000
0xbffc native_version=3.67.0
0xc6a4 algorithm=adj8
```

`0x9954c` 使用 JNI `GetObjectClass/GetMethodID/NewStringUTF/CallObjectMethod`，method
name/signature 解码为 `put` / `(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;`。
因此这里证明的是 native result metadata Map 写入，不是 `0x11d798` 的 selected-value
拼接。`adj_signing_id` 在最终 crypto logical plaintext 中的精确 descriptor 拼接层，仍需
从 `0x11da64 -> 0xf1ec8` 九输入数据流继续闭合。完整证据：

```text
.omx/static-audit-20260713/analyze_map_metadata_jni.py
.omx/static-audit-20260713/arm64-map-metadata-jni.md
```

### `0xf1ec8` 固定九输入 logical-object 初始化

final consumer 在 `0x11e7f0` 以 `w2=9` 调用 `0xf1ec8`。它从 x3..x7 和栈上取得
九个 descriptor；入口循环把每个 descriptor 的 bytes 按 4-byte 分组转成 big-endian
logical words，并通过 `0x138318` 写入 `workObject+0x20+i*8` 指向的第 i 个 slot。
长度余数 1/2/3 分别放在最后一个 word 的高 8/16/24 bits。

`0x11d798` 产生的 plaintext bytes 与其 4-byte reversed length 是这九个 descriptor
中的两个。这里的“9”是同一个 crypto work object 的固定输入数量，不是九套 final
encryption 的 algorithm selector。`0x1393cc` 只分配一个 0xa0-byte work object，
但该对象内部实际有 **16 个** arena lanes（`+0x20..+0x98`）；九个 descriptor 只填充
其中前九个输入 lane，不能把“九输入”错误解释为对象只有九个 slot。

构造顺序已静态闭合为：`+0x00` stack、`+0x08` arena、`+0x10` counter chain、
`+0x18` stack、随后 16 个 arena lanes。任一 child allocation 通过共享 status 产生
错误后，立即进入 `0x1392c4` 对部分初始化对象做完整清理。

九个 descriptor 的调用顺序现已从 `0x11e7b8..0x11e7f0` 静态恢复：

| slot | source | length |
|---:|---|---:|
| 1 | context `+0x50` | 128 |
| 2 | context `+0xf0` | 20 |
| 3 | context `+0xe0` | 16 |
| 4 | context `+0x30` | 32 |
| 5 | context `+0x20` | 4 |
| 6 | reversed selected-Map plaintext length | 4 |
| 7 | selected-Map plaintext | dynamic |
| 8 | reversed context `+0x118` length | 4 |
| 9 | context `+0x120` bytes | context `+0x118` |

`context+0x118/+0x120` 的 initializer 数据流现已闭合。`0xcbec0` 建立 context base
`sp+0x88`，`0xcbf5c/0xcbf84` 保存 `context+0x08`，随后
`0xcc3e8..0xcc3f4` 执行 `memset(context+0x08, 0, 0x120)`，清零范围覆盖到
`context+0x128` 之前。对 stage 1/2、environment dispatcher、timing/correction stage、
final consumer 及其所有直接 context-bearing callee 做保守固定点 may-alias 分析，只发现
`context+0x00/+0x08/+0xe0` 的固定 offset 写入以及单独闭合的 correction indexed write，
没有 `+0x118/+0x120` producer。因此成功路径上 slot 8 是 `00 00 00 00`，slot 9 为空。

这也排除了 `adj_signing_id` 来自 slot 8/9；其 engine-level 来源进一步收敛到其他固定
context descriptor 或更早的 protected transformation，仍不能在证据不足时强行命名。
可重复检查：

```text
.omx/static-audit-20260713/analyze_final_descriptors.py
.omx/static-audit-20260713/arm64-final-nine-descriptors.md
.omx/static-audit-20260713/arm64-range-lookup.md
.omx/static-audit-20260713/arm64-opaque-helper-summary.md
.omx/static-audit-20260713/analyze_context_dynamic_pair.py
.omx/static-audit-20260713/arm64-context-dynamic-pair.md
```

行为兼容层现在有直接指令级来源：100-key walker 不消费调用者提供的
`adj_signing_id`；它在遍历到 `secret_id` 时由 `0x8af4` 无条件选择 `1400000`，并在
`headers_id/native_version` 处选择 `9/3.67.0`。所以 caller 对这三个表内字段的缺失或
覆盖都不改变 protected-engine plaintext，表外 `adj_signing_id` 也不会被 walker 读取。
`0xaf3c -> 0x9954c` 另行把 `adj_signing_id=1400000` 写回结果 metadata Map；两条链使用
相同常量，但角色不同。C++ `buildNativePlaintext()` 已按这个精确分工修正。

### `nSign byte[]` 是完整性校验输入，不是已证明的 slot 8/9

Java bytecode 直接闭合了第三个业务参数的来源：`Map.toString()` 经 UTF-8 编码后，由
`com.adjust.sdk.sig.c.a(Context, byte[])` 计算 `HmacSHA256`，结果作为 `byte[]` 传入
`NativeLibHelper.nSign`。

arm64 上，`0xcbbf4/0xcbd40/0xcbd44` 把该数组传入 `0xe6c0`；`0xedc4/0xedcc`
再调用 `0x94bc0`。后者通过 array-length helper、`calloc` 和 JNI vtable `+0x640`
的 `GetByteArrayRegion` 把数组复制到 native buffer。`0xef00..0xef08` 对 supplied 与
expected 两个 cursor 逐字节比较，`0xf150/0xf15c/0xf168` 递减长度并推进 cursor；
不匹配路径在 `0xecc8/0xeccc` 以 code `0x07` 调用 correction writer `0x13548c`。
复制出的 supplied buffer 最终在 `0xefd8/0xefdc` 被 `free`。

因此需要纠正此前候选命名：在严格 `0xe6c0..0xf1c4` 范围内，没有把 copied
supplied-HMAC buffer 直接 store 到 context `+0x118/+0x120`。结合上节完整 context
producer 分析，这两个字段保持初始化后的 `0/null`，不再标记为“producer 未闭合”。
可重复检查：

```text
.omx/static-audit-20260713/analyze_nsign_hmac_flow.py
.omx/static-audit-20260713/arm64-nsign-java-hmac-flow.md
.omx/static-audit-20260713/analyze_context_dynamic_pair.py
.omx/static-audit-20260713/arm64-context-dynamic-pair.md
```

### Expected Java-HMAC producer 已闭合

expected cursor 的上游现已从 JNI method strings 和调用参数完整恢复：`0x9b684` 通过
`GetMethodID/CallObjectMethod` 调用 `toString()Ljava/lang/String;`；`0x9c030` 调用
`getBytes()[B`。`0xc8ec0` 从 `context+0x0c` 读取 Android API，在 `0xc8f40` 与 22
比较：API >=23 调 `0xc9250`，解码常量为 `AndroidKeyStore` 和 `key2`；API 18..22 调
`0xc9988`，解码常量为 `adjust_keys`、`encrypted_key` 和 `AES`；`0xc91c4` 与 17
比较，闭合 API <18 unsupported 边界。

`0xca648` 的字符串和 helper 顺序为：

```text
javax/crypto/Mac
getInstance (Ljava/lang/String;)Ljavax/crypto/Mac;
init        (Ljava/security/Key;)V
update      ([B)V
doFinal     ()[B
```

算法常量为 `HmacSHA256`。`doFinal()` 的 byte array 经 `0x94bc0` 复制后成为
`0xef04` 的 expected cursor。因此在 platform 已解析出同一 Java Key 的前提下，C++
使用 raw key 执行 HMAC-SHA256 是密码学等价实现；但完整 drop-in 仍必须保留 Java 默认
charset、KeyStore exception、legacy unwrap、null/pending exception、retry/delete/lockdown。

```text
.omx/static-audit-20260713/analyze_expected_java_hmac.py
.omx/static-audit-20260713/arm64-expected-java-hmac.md
```

### API >=23 AndroidKeyStore resolver 的 null/ownership 边界

`0xc9250` 的三个 direct helper 已通过 class/method/signature 静态确认：

```text
0xa4450  KeyStore.getInstance(String)
0xa5308  KeyStore.load(KeyStore.LoadStoreParameter)
0xa6c9c  KeyStore.getKey(String,char[])
```

调用参数依次为 `"AndroidKeyStore"`、`load(null)`、`getKey("key2",null)`。每个 JNI
helper 的非零 status 都使 resolver 返回 false。`0xc9818..0xc9838` 则无条件复制 getKey
输出并把 success flag 置 1，没有对 Key object 做 null rejection，因此必须区分：

```text
JNI helper/pending-exception failure  -> resolver false
getKey call success, Java result null -> resolver true + null key
getKey call success, non-null key     -> resolver true + key object
```

临时 KeyStore local ref 在创建成功后的退出路径经 JNI vtable `+0xb8` `DeleteLocalRef`
释放；返回的 Key ref 转交 caller。C++ `modelRecoveredApi23KeyResolver()` 已源级表达上述
三态和 cleanup ownership。自动证据：

```text
.omx/static-audit-20260713/analyze_api23_keystore_resolver.py
.omx/static-audit-20260713/arm64-api23-keystore-resolver.md
```

### Java Mac producer 的 status 与 local-ref cleanup

`0xca648` 已从 method strings、call arguments 和 cleanup blocks 闭合为：

```text
Mac.getInstance("HmacSHA256")   0xa9d44
Mac.init(Key)                   0xab130
Mac.update(byte[])              0xab870
Mac.doFinal()                   0xac1d8
byte[] -> native copy           0x94bc0
```

任一 helper status 非零都会终止 producer；最终成功位等于 byte-array copy helper 成功。
Mac 和 doFinal result 的 non-null local ref 分别经 JNI vtable `+0xb8` 释放。native 不会把
null Key 或 null result 转换为备用值；它们进入下一 helper，由 JNI status/pending exception
形成失败。C++ `modelRecoveredJavaMacProducer()` 已表达阶段成功和 cleanup ownership。

```text
.omx/static-audit-20260713/analyze_java_mac_producer.py
.omx/static-audit-20260713/arm64-java-mac-producer.md
```

### Expected Java-HMAC 基础设施失败是 fail-open

`0xe6c0` 在 `0xebd0` 把 stage result 初始化为 0。只有完整 compare match，或者完成 compare
并确认 mismatch 后，才会把结果置 1；mismatch 唯一调用 `0x13548c` 写 correction `0x07`。
Key resolver、Object/String helper、Mac producer 或 byte-array copy 失败不会写 `0x07`，并
保持 stage result 为 0。

`0xcbbd4` 在 `0xcbd44` 调用 `0xe6c0` 并检查 false。false 分支调用 `0xf1fc`、把局部
status 重置为 0，然后仍继续 `context+0x108` 和 `context+0x110` 两段构造；这里没有
提前 return。上层 `0xcbe98` 在 `0xcc254` 调用这个 void stage 后，紧接着在 `0xcc25c` 调用
environment dispatcher，并在 `0xcc28c` 到达 final consumer。因此静态可观察语义为：

```text
infrastructure failure -> skip verdict and correction 0x07 -> continue signing
match                  -> continue without 0x07
mismatch               -> append 0x07 -> continue signing
```

`recovered_primitives.cpp` 现已直接实现完整 `0xe6c0..0xf1c8` orchestration，不再把该
FDE 委托给单一 opaque callback。直接回归覆盖 match、byte mismatch、length mismatch，
以及 key resolver、`Object.toString()`、`String.getBytes()`、Mac producer、supplied-copy
失败；同时检查三次 `15000ms` timing probe、`byte[] -> String -> Key` 的 local-ref 逆序
cleanup、correction `0x07`/flag bit 0 和 infrastructure failure 的 false/fail-open 返回。
ASan/UBSan smoke、全部 source-built oracle，以及 14 组成对原 SO/recovered job 均通过。

### Stage-1 environment dispatcher `0xf328` 已闭合

`0xf328..0xfce0` 的唯一入口状态经 ARM64/x86_64 常量传播后，真实可达路径收敛为 7 个
probe 与最后的 `0xfce0` stage。C++ 已按原顺序实现 `0x01/0x02/0x03/0x08/0x28/0x2c/0x1f`
correction 条件、7 次 `15000ms` timing、`0x878` 字节 scratch 初始化/销毁、成功专属
`0x12a30`、false return，以及所有出口无条件 `0x13000` fallback mask。地址命名 callback
仅保留给各 probe body 和仍单列 partial 的 `0xfce0` callee，不再以 `stageF328` 跳过整个
FDE。直接回归覆盖 threshold 边界、全 correction 顺序、初始化失败与 final-stage 失败；
ASan/UBSan、source-built oracle 和 14 组成对 parity（一次 Unicorn `exit=-6` 后独立重试）
全部通过。证据见 `.omx/static-audit-20260713/arm64-environment-stage-f328.md`。

`0xfce0..0x12a30` 已从“未知 initializer”进一步收敛为 emulator/automation detector
initializer。完整范围 trace 与 entry/exit data/BSS diff 证明 24 个 acquire-byte one-time
initializer 全部可达，解码 47 个 marker；其中传给 `0x7bbb0` 和 `0x868b4` 的 24 项表从
`Emulator` 到 `redfinger`，其余 23 项为 Android emulator build/product fingerprint。
这些明文已转为 C++ immutable arrays。后续主链为 `memset(0x90) -> 0x7ba5c ->
0x7bbb0(count=24) -> 0x868b4(count=24) -> 0x13044`，返回值为 `*status == 0`。
`0x7ba5c` fanout wrapper、`0x7bbb0` 八固定字段 matcher 与 `0x868b4` 动态槽 matcher 已
直接实现；`0x127a78` substring helper、`0x40c70` generic/correction `0x0b` stage、
`0x44c38` correction `0x13` wrapper 和 `0x42eb0` paired-descriptor any-match wrapper
也已独立闭合。`0x1354bc` correction-array writer 已跨 ABI 直接实现并回归，但 fanout
内其余 detector body 仍未逐函数闭合，因此 `0xfce0` 继续标记 partial。详见
`.omx/static-audit-20260713/arm64-environment-stage-fce0-progress.md`。

C++ 已新增 `RecoveredJavaHmacIntegrityOutcome`、`classifyRecoveredJavaHmacIntegrity()` 和
`applyRecoveredJavaHmacIntegrityOutcome()`，保留 `SkippedFailOpen`，不再把它误建模成
`NullNativeSignature`。

```text
.omx/static-audit-20260713/analyze_hmac_fail_open.py
.omx/static-audit-20260713/arm64-hmac-fail-open.md
```

### API 18..22 legacy wrapped-key resolver 已闭合完整 orchestrator

`0xc9988` 的五个 direct helper 已通过各自 class/method/signature 字符串确认，而不是按
调用地址猜测：

| 地址 | 静态恢复语义 |
|---|---|
| `0xb479c` | `Context.getSharedPreferences(String,int)` |
| `0xc0d84` | `SharedPreferences.getString(String,String)` |
| `0x93014` | `android.util.Base64.decode(String,int)` |
| `0xcac40` | `AndroidKeyStore/key2` 与 `RSA/ECB/PKCS1Padding` 私钥解包 |
| `0xbd6a8` | `new SecretKeySpec(byte[],String)` |

最终算法字符串为 `AES`，随后该 Key 传给 `0xca648` 的 `Mac.init`。完整 ARM64 解释器
现已进一步闭合 preexisting status、null forwarding、Base64 failure 固定 status `26`、
RSA boolean gate、success-only output publication，以及四个 local reference 的清理顺序：

```text
raw RSA bytes -> decoded Base64 bytes -> SharedPreferences -> encrypted String
```

RSA 返回 false 时不调用 SecretKeySpec；RSA 返回 true 时即使同时留下非零 status，仍会
调用 SecretKeySpec，最终再因 status 返回 false。所有 helper 都可能发布 null，外层不在
下一 helper 前增加 null guard。直接 C++ 是
`runRecoveredLegacyWrappedKeyResolverC9988()`。自动证据检查：

```text
.omx/static-audit-20260713/analyze_legacy_key_resolver.py
.omx/static-audit-20260713/analyze_legacy_key_resolver_c9988_full.py
.omx/static-audit-20260713/arm64-legacy-key-resolver.md
.omx/static-audit-20260713/analyze_java_retry_lockdown.py
.omx/static-audit-20260713/java-retry-lockdown.md
```

C++ `runRecoveredSignerFlow()` 已实现 Java wrapper 的可观察控制流：最多两次 key attempt；
只对 InvalidKey/UnrecoverableKey reset 后重试；两次失败设置 process lockdown；API 不支持
设置 lockdown 并重抛；其他异常清理临时字段后重抛；native null 只清理不 lockdown；成功
使用 Base64 NO_WRAP 写 `signature`。它还保留了一个容易遗漏的异常边界：若 `resetKey()`
本身抛异常，异常直接从 catch 内逃逸，`activity_kind/client_sdk` 不会执行后续清理。
Android adapter 仍需把真实 Java/JNI exception 精确映射为这些状态。

`.eh_frame` 进一步确认整个 `0xf1ec8..0x11ba78` 是**一个**大小 `0x29bb0` 的巨大
flattened function，而不是许多未识别的小密码函数。它包含 42,732 条指令、7,223 个
direct call site、17 个唯一 direct target、645 个 branch，且没有任何 `blr` 间接调用。
其中 5,346 次调用集中到 `0x138a70/0x138b74` logical node helper，另有固定两处
`rand()`。完整统计与 7,223-call schedule 位于：

```text
.omx/static-audit-20260713/arm64-protected-engine.md
.omx/static-audit-20260713/arm64-protected-engine-calls.csv
.omx/static-audit-20260713/arm64-opaque-helper-summary.md
```

高频调用并不代表 5,346 个不同密码步骤：`0x138a70` 是 word-stack push，`0x138b74`
是 pop。再加上已恢复的 arena reader/writer 后，protected engine 可被提升为“固定 word
stack + framed arena 上执行的 circuit schedule”，而不是把这些 helper 继续误标为候选
加密算法。

这证明当前恢复面是同一固定 adj8 circuit 中的 SHA/AES/HMAC 分层，而不是通过函数
指针选择多套 final envelope。42,732-instruction 文本 VM 已能按真实输入执行 645 个
branch 所形成的完整 Pixel 路径；其他 context flags、错误 status 与极端 descriptor
组合仍需差分回归，但 protected-engine FDE 不再保留 `partial` 标记。

### 静态伪代码：Java 签名入口

```cpp
bool signV4(Context& context, OrderedMap& params,
            string activityKind, string clientSdk) {
    if (params.empty() || activityKind == null || clientSdk == null) return false;

    params["activity_kind"] = activityKind;
    params["client_sdk"] = clientSdk;

    byte javaHmac[32];
    for (int attempts = 2; attempts > 0; --attempts) {
        try {
            ensureJavaKey(context, androidApi);
            javaHmac = hmacSha256(javaKey(context, androidApi),
                                  utf8(params.toString()));
            break;
        } catch (InvalidKeyOrUnrecoverableKey&) {
            deleteKey2AndEncryptedPreference();
        }
    }

    byte[] result = nSign(context, params, javaHmac, androidApi);
    if (result != null) params["signature"] = base64NoWrap(result);
    params.erase("activity_kind");
    params.erase("client_sdk");
    return result != null;
}
```

### 静态恢复后的 final envelope 伪代码

```cpp
Signature sign(const NativeInputs& in) {
    iv = deriveBionicRandIv(in.timeSeconds);       // 16 bytes
    field0 = encodeEnvironmentCorrections(in.correctionCodes);
    field4 = sha256WithRecoveredInitialState(
        certificateSha1 || field0 || field2 || sha256Empty ||
        state || nativePlaintext);

    payload = tag(0x01) ||
              tag(0x00, field0) ||
              tag(0x02, reverse(field2)) ||
              tag(0x03, certificateSha1) ||
              tag(0x04, field4) ||
              tag(0x05, sha256Empty) ||
              tag(0x06, state);

    ciphertext = aes256CbcPkcs7(recoveredAesKey, iv, payload);
    tag = hmacSha256(recoveredHmacKey, ciphertext);
    return iv || ciphertext || tag;
}
```

## 4. 输入、输出和数据结构

### `nSign` 输入

```text
Context                 Android package/application/file/key observations
Object                  实际为有顺序语义的 Map<String,String>
byte[]                  Java HMAC 完整性值
int                     Android API
```

Map 顺序是协议的一部分，因为原始 Java 直接对 `Map.toString()` 做 UTF-8 HMAC。

### Native payload

```text
01
00 <halfword-count> <encoded correction halfwords>
02 <4-byte field2, reversed>
03 <20-byte certificate SHA-1>
04 <32-byte custom-state SHA-256>
05 <32-byte SHA256(empty)>
06 <1-byte state>
```

冻结 profile 把 urandom 模式配置为 `0001020304050607`，此前本地 reference 证据中
field 2 为其前四字节 `00 01 02 03`。本轮 C++ 增加 `setField2FromUrandom()` 和
`--urandom-hex`，Java recovered adapter 同步把
`DeviceProfile.getNativeUrandomBytes()` 传入 C++。当前静态 consumer 明确处理该
4-byte field；“urandom read 到 native context field”的完整纯静态上游链仍需继续闭合，
因此这里标记为“已有本地 reference 证据，本轮未新增动态验证”。

field 0 容量按 8 halfwords 分块增长：

```text
8 -> 16 -> 24 -> 32 -> ...
```

### Native 返回

```text
16-byte IV || AES-256-CBC/PKCS#7 ciphertext || 32-byte HMAC-SHA256
```

已恢复实现支持动态长度，不把结果写死为 176 bytes。

### Metadata

`0x9954c` 的四个静态 key/value 项：

```text
headers_id=9
adj_signing_id=1400000
native_version=3.67.0
algorithm=adj8
```

静态数据表和所有当前已知调用点均指向 `adj8`。四个 ABI 中都没有清晰的
`AES-GCM`/`ChaCha` 等公开字符串或对应动态加密库依赖；字符串中的 `gcm` 片段位于
opaque state 常量 `0x9224eb6a6d63673d`，已经交叉 ABI 证明不是算法名。

## 5. 安全发现及严重程度

### nSign 前置 timer 与 Map 字符串复制

`0xd4908..0xd4e0c` 已跨 ARM64/x86_64 闭合为一次性周期 timer 安装器：每次调用先同步
执行 callback `0xd4e0c`，installed byte 未置位时才用 `CLOCK_MONOTONIC`、
`SIGEV_THREAD` 和 `{1s,0ns}` 的 initial/interval 创建并启动 timer。只有 create 和
settime 均成功才置 installed；失败不写 status，也不删除已创建但启动失败的 timer。

`0xaebf8..0xaf438` 已闭合为 Map 字符串 owned-copy helper。参数为
`status, JNIEnv, Map, key, output`；它调用已恢复的 `0xadbf4 Map.get` 和 `0x92b24`
modified-UTF helper，malloc `length+1` 后复制并补 NUL，最后通过 JNI vtable `+0x550`
释放 UTF chars、通过 `+0xb8` 删除 Map.get local ref。Map/key 无效写 status `2`，分配
失败写 status `3`，非零最终 status 清空 output。

证据分别记录于：

- `.omx/static-audit-20260713/arm64-nsign-periodic-timer.md`
- `.omx/static-audit-20260713/arm64-map-string-owned-copy.md`

`0xcc604..0xcd934 nSign` 已完整闭合：JNI env/context/map/HMAC/API 先写入独立
16-byte wrapper，0x30-byte descriptor 保存 env 值和其余四个 wrapper 指针；调用顺序为
timer、`environment` Map owned-copy、与小写 `sandbox` 做严格 C 字符串比较、第一次 outer
clock、可选 begin log、`0xcbe98`、清 status、第二次 outer clock、可选 end log、返回保存的
`jbyteArray`。Map copy 失败、null、空串或任意不等于 `sandbox` 的值都会置 environment
auxiliary flag 并跳过两次 log。第一次 clock failure 只跳过 begin log，不会带入第二次
判断；第二次 clock 在 status 清零后独立决定 end log。所有分支都返回 `cbe98` 保存的结果。
原生导出没有释放成功复制的 environment owned string，C++ 保留该泄漏边界。证据见
`.omx/static-audit-20260713/arm64-nsign-jni-orchestrator.md` 与
`.omx/static-audit-20260713/analyze_nsign_jni_orchestrator_full.py`。

周期 callback `0xd4e0c..0xd6888` 已跨 ARM64/x86_64 恢复为 TracerPid 探针。静态字符串
分别解码为 `/proc/%d/status` 和 `TracerPid:`；callback 使用直接 getpid/openat syscall、
access、最多 0x800-byte read、close、ASCII case-insensitive marker 搜索和 native atoi。
普通 access/open/read/marker failure 保持旧 verdict，非零 TracerPid 将全局 verdict sticky
置 1。`0xd6888..0xd6994` 在 environment dispatcher 后消费它：命中追加 correction
`0x26`/flag bit 0，所有路径均置 context flag bit 38。完整证据见
`.omx/static-audit-20260713/arm64-tracerpid-periodic-callback.md`。

`0x12ec1c..0x12f298` 已闭合为 epoch-millisecond timestamp log front end：
`trunc(ms/1000)`、`fmod(ms,1000)`、`localtime`、两个 `strftime`，再按
`%s: %s.%03dZ%s` 交给 `0x12fa24`。nSign 分别传入 begin/end outer clock sample，label
为 `Signing all the parameters begin` 与 `Signing all the parameters end  `（end 后两个
空格）。详细证据见 `.omx/static-audit-20260713/arm64-timestamp-log-frontend.md`；
`0x12fa24..0x13063c` 的 Android log routing 仍单列恢复，不能与前端完成状态混为一谈。

### 高：客户端内嵌最终 envelope 密钥材料

最终 AES/HMAC 密钥虽然经过控制流和常量混淆，但必须在客户端进程内恢复为明文才能
计算签名。当前 C++ 已证明可以独立重建。任何把此签名当作服务器端强认证凭据的设计
都存在克隆风险。混淆只能提高分析成本，不能形成可信密钥边界。

### 中：`Map.toString()` 是不稳定的协议序列化

签名依赖 Map 实现、插入顺序和字符串格式。跨 JVM、语言或无序容器重写时容易产生
不一致，也可能让调用方误以为语义相同的 Map 必然得到相同签名。

### 中：native Java-HMAC 完整性检查基础设施失败时 fail-open

若 expected-HMAC 所需的 KeyStore、JNI Object/String、Mac 或 byte-array copy 阶段失败，
native 不追加 mismatch correction `0x07`，也不直接终止 final signer，而是跳过该 verdict
后继续签名。正常 Java wrapper 通常会在自身 key/HMAC 异常时阻止进入 native，但直接 JNI
调用、平台行为差异或 native-only failure 仍会形成防御降级，且输出中没有专用 correction
区分“完整性匹配”和“检查未执行”。

### 中：进程全局 lockdown 带来可用性风险

原 Java 代码在 API 不支持或连续密钥错误后设置静态状态，后续签名直接拒绝。若异常
可由暂时性 KeyStore 故障触发，应用生命周期内可能持续失去签名能力。

### 中：大量环境探针扩大兼容性和误报面

cmdline、maps、APK signer、ART 文件、系统属性、时间和 socket 等观察被编码进
correction。ROM、APEX、ABI 或安装路径变化可能改变签名，而不代表真实攻击。

### 中：`Map.remove` helper 存在异常 JNI local-reference 处理

`0x9aa5c` 没有删除 `CallObjectMethod(Map.remove)` 返回的 local reference；在创建过 key
string 的路径上，反而把 flattened state anchor 传给 `DeleteLocalRef`。ARM64 与 x86_64
均存在同构行为。真实 ART 在未启用 CheckJNI 时对无效 local reference 的处理仍需隔离
验证；不同 ART/CheckJNI 配置可能表现为忽略、警告、pending failure 或 abort。C++ 重写
不能把该调用静默当作正常 returned-object cleanup，也不应在未验证前主动制造无效引用。
当前平台无关层仅记录该 attempt，并明确保留 returned-object local-ref leak 语义。

### 低：getline-compatible helper 在 realloc 失败时丢失旧 allocation pointer

`0xd6ed8..0xd7890`（x86_64 `0xc36c3..0xc3e4a`）先把按 128-byte block
计算的新 capacity 写回 caller，再直接以 `realloc` 返回值覆盖 `*line`。若 `realloc`
返回 null，旧 allocation 仍由 allocator 保留，但 caller-visible pointer 已变为 null，函数
返回 `-1`，因此该 allocation 无法再释放。恢复 C++ 为保持原生失败状态保留了此行为；
产品修复应使用临时 pointer，并仅在成功后同时提交 pointer/capacity。

### 中：property-info source 在 mmap 失败时直接解引用返回值

`0xd352c..0xd3d90`（x86_64 `0xc0cdd..0xc1318`）把
`mmap(nullptr,size,PROT_READ,MAP_PRIVATE,fd,0)` 返回值写入 source `+0x08` 后，立即从
该地址读取 16+8 bytes 并复制到 source `+0x18`，中间没有 null 或 `MAP_FAILED` 判断。
因此在地址空间压力、映射限制或其他 mmap failure 下，函数不会写 status 或进入正常
`0xd3d90` rollback，而会先解引用无效地址并导致进程崩溃。该缺陷影响本地稳定性和
可用性，当前未发现绕过为可控写入的证据。

### 待确认，中风险候选：scratch appender 未验证 source 和 length+1

`0x8f56c..0x8fb44` 对两个长度直接执行 64 位 `length+1` 后调用 `malloc`，没有 overflow
gate；copy loop 和末尾 NUL 写入仍使用原始长度。`length==UINT64_MAX` 时申请大小回绕为
零，而后续仍按巨大长度读取 source/写 destination。非零长度也没有 source null/readable
range 检查。当前五参数来自内部 `0x8746c` flattened producer，尚未证明普通外部输入可以
直接控制这些长度，因此记录为中风险候选而非已证实可利用内存破坏。

### 低/待确认：scratch destructor 依赖全空 sentinel 而不读 count

`0x8fb44..0x90714` 不使用 `+0x870` count，也没有 128-slot bound；若前 128 项都至少有
一个非空 pointer，会继续越过 0x878-byte scratch 读取并可能把相邻值传给 `free`。正常
生产链的 `0x8f56c` 在 count>=127 时拒绝追加并保留 slot 127 为全空 sentinel，因此已知
主链维持该不变量。风险主要来自 scratch 损坏、其他未恢复 writer 或不一致 count/pointer。

### 低/待确认：其他 native 内存安全

SO 导入原始分配、复制和字符串函数，但同时启用了 stack protector、RELRO、NOW 和
不可执行栈。当前静态检查尚未证明可控越界、UAF 或整数溢出，不能仅凭 imports 报告
内存破坏漏洞。现已闭合的 `0xd28d0` 证明 parser 直接信任 0x1c-byte descriptor、两张
source-relative uint32 offset table、两个 child count 和所有嵌套 descriptor；没有 source
长度、offset、table、`count*0x30` 或递归深度检查。它通过 `calloc(count,0x30)` 构造
零初始化数组并只在元素成功后递增 published count，因此正常 allocation failure 的
rollback 状态是一致的；但畸形或被破坏的 metadata source 可能造成越界读取、过大分配
或递归耗尽。外部是否能控制该 system-property metadata source 尚未证明，因此列为
中风险候选，不写成已证实可利用内存破坏。

## 6. 修复建议

1. 不要把客户端可恢复的固定密钥当作不可伪造认证根；服务端应使用设备注册、短期
   challenge、服务端 nonce、重放窗口和可吊销密钥。
2. 用明确 canonical serializer 替换 `Map.toString()`：固定 UTF-8、字段排序、长度前缀、
   null/空值规则和版本号。
3. 将 `algorithm` 设计成服务端协商且有版本绑定的枚举，不要让 metadata 与实际
   envelope 脱节。
4. 将 correction 作为可观测诊断字段，不应作为唯一安全判定；为 ROM/API/APEX 演进
   提供版本化规则和容错。
5. KeyStore 重试与全局 lockdown 应区分永久错误和暂时错误，并提供进程内恢复路径。
6. 对 native parser 增加长度上限、整数溢出检查、失败原子性和 fuzz regression。
7. `mmap` 后先检查 `MAP_FAILED`，映射失败写稳定 status 并通过 owner destructor 关闭 fd；
   只有验证 mapping 非空且至少覆盖 24-byte header 后才能复制 header。
8. scratch appender 对两个 `length+1` 使用 checked arithmetic，`length>0` 时要求 source
   非空且 readable range 足够；destructor 同时以 128 和可信 count 为上限，不只依赖 sentinel。
9. C++ 重写保留有序参数容器，并对每个 profile 使用固定 reference vector 回归。

## 7. 尚不能确认的事项

1. `0xf1ec8..0x11ba78` 已完成全部指令/直接 helper 的文本解释，并在真实 Pixel
   context flags 下无补丁复现冻结输出；尚未穷举所有 context flags、错误 status 和
   极端 descriptor 组合。其他 consumer helper 已收敛为 metadata 或通用 buffer adapter。
2. 尚未发现第二套成功 final envelope 的可靠静态证据。`gcm` strings 已证明为 opaque
   state 常量；直接 immediate-key scan 只找到 final HMAC、field-4 SHA source 和
   correction/environment 三组八 word materialization，但代数派生的隐藏 key 仍需完整
   数据流证明才能排除。存在 RSA、AES 和 HMAC 不等于存在多套最终签名格式。
3. `algorithm=adj8` 在已定位 builder 中为静态值，但仍不能仅凭有限静态切片排除隐藏
   failure/tamper metadata 分支。
4. 部分 correction 的 Android 业务名称仍未从静态控制流唯一恢复。
5. API 18..22 的 success path 与 Java retry/reset/lockdown 高层状态机已迁入 C++；仍需
   逐项对齐 AndroidKeyStore null、pending JNI exception、cast/alias/entry 缺失、RSA 失败、
   local-ref cleanup，以及异常类到 C++ 状态的精确映射。当前静态阶段没有运行 Android
   platform adapter，不能把这些失败分支标成行为已通过。
6. “完全一致”还包括 null、异常、重试、lockdown、内存分配失败和所有环境探针；当前
   C++ 已闭合成功 `adj8` 结果算法和十五类已知向量，但不能把未证明分支宣称完成。
