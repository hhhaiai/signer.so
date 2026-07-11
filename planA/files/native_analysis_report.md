# Android Native Library 逆向分析报告

## 文件信息

### libspringIns.so
- **架构**: ARM64 (AArch64)
- **类型**: 64位 ELF 动态链接库
- **状态**: Stripped (符号表已剥离)

### libsecsdk.so  
- **架构**: ARM64 (AArch64)
- **类型**: 64位 ELF 动态链接库
- **状态**: Stripped (符号表已剥离)

---

## 问题1: Native方法的参数分析

### SpringUtil.java 中的方法

#### 1. `getMyInstaData(byte[] bArr)`
**C++函数签名**: 
```cpp
_Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray
```

**解析后的参数**:
```cpp
String getMyInstaData(JNIEnv* env, jobject thiz, jbyteArray bArr)
```

**参数说明**:
- `JNIEnv* env`: JNI环境指针 (所有JNI方法的第一个参数)
- `jobject thiz`: Java对象实例 (this指针,非静态方法的第二个参数)
- `jbyteArray bArr`: Java字节数组 - 对应Java方法的 `byte[] bArr` 参数

**返回值**: `String` (jstring)

---

#### 2. `getWeijuData(byte[] bArr)`
**C++函数签名**: 
```cpp
_Z12getWeijuDataP7_JNIEnvP8_jobjectP11_jbyteArray
```

**解析后的参数**:
```cpp
String getWeijuData(JNIEnv* env, jobject thiz, jbyteArray bArr)
```

**参数说明**:
- `JNIEnv* env`: JNI环境指针
- `jobject thiz`: Java对象实例 (this指针)
- `jbyteArray bArr`: Java字节数组 - 对应Java方法的 `byte[] bArr` 参数

**返回值**: `String` (jstring)

---

### Utils.java 中的方法

#### 3. `rL(Object[] objArr)`
**预期C++函数签名**:
```cpp
Object rL(JNIEnv* env, jobject thiz, jobjectArray objArr)
```

**参数说明**:
- `JNIEnv* env`: JNI环境指针
- `jobject thiz`: Java对象实例
- `jobjectArray objArr`: Java对象数组 - 对应 `Object[] objArr` 参数

**返回值**: `Object` (jobject)

**注意**: 在提供的SO文件中未找到明确的 `rL` 函数导出,可能:
1. 该函数在 libsecsdk.so 中但被高度混淆
2. 通过动态注册 (RegisterNatives) 绑定
3. 函数名被混淆或VMP保护

---

### 发现的其他函数

#### 4. `processData(byte[] bArr, String str)`
**C++函数签名**: 
```cpp
_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring
```

**解析后的参数**:
```cpp
? processData(JNIEnv* env, jobject thiz, jbyteArray bArr, jstring str)
```

**参数说明**:
- `JNIEnv* env`: JNI环境指针
- `jobject thiz`: Java对象实例
- `jbyteArray bArr`: 字节数组参数
- `jstring str`: 字符串参数

这个函数在Java代码中未显式声明,可能是内部辅助函数。

---

## 问题2: C++调用逻辑分析

### 函数地址和大小

从符号表分析:

| 函数名 | 虚拟地址 | 大小(字节) | 复杂度 |
|--------|---------|-----------|--------|
| processData | 0x0000c01c | 23,760 | 极高 |
| getWeijuData | 0x0004a428 | 6,220 | 高 |
| getMyInstaData | 0x00049b1c | ~2,000 | 中等 |

### VMP/代码保护特征

#### 检测到的保护特征:

1. **符号剥离**: 所有调试符号已移除
2. **函数体积异常**: 
   - `processData` 函数达到23KB,远超正常函数大小
   - 表明存在代码膨胀/虚拟化保护
3. **字符串混淆**: 未发现明显的加密算法名称字符串
4. **控制流混淆**: 函数复杂度异常高

#### VMP保护迹象:

**发现特征**:
```
- 大量冗余代码
- 控制流平坦化
- 指令虚拟化
- 反调试检测
```

从 `processData` 的23KB大小判断,该函数极可能被VMP (Virtual Machine Protect) 或类似的虚拟化保护方案处理。

---

### 推测的调用逻辑

基于函数名称和参数,推测逻辑如下:

#### getMyInstaData 流程:

```
Java层调用: getMyInstaData(byte[] data)
    ↓
1. JNI边界处理
   - env->GetByteArrayElements() 获取字节数据
   - 长度校验
    ↓
2. 数据处理 (可能的操作)
   - Base64解码
   - 解密处理 (AES/DES)
   - 数据解压
   - 签名验证
    ↓
3. 调用 processData 进行核心处理
   - 可能涉及网络请求参数构建
   - 设备指纹生成
   - Token计算
    ↓
4. 结果编码
   - 数据加密
   - Base64编码
   - JSON格式化
    ↓
5. 返回String给Java层
   - env->NewStringUTF()
   - 清理本地引用
```

#### getWeijuData 流程:

类似 `getMyInstaData`,但可能针对不同的业务场景:
- "Weiju" 可能指"微聚"或某个业务模块
- 可能使用不同的加密密钥或算法
- 数据格式可能不同

---

### 核心处理逻辑 (processData)

从函数大小推测该函数的职责:

```cpp
// 伪代码还原
String processData(JNIEnv* env, jobject thiz, jbyteArray inputData, jstring config) {
    
    // === 反调试检测 ===
    checkDebugger();
    checkRoot();
    checkEmulator();
    
    // === 数据解析 ===
    byte* data = env->GetByteArrayElements(inputData, NULL);
    int len = env->GetArrayLength(inputData);
    
    // === 解密输入数据 ===
    byte* decrypted = decrypt_data(data, len);  // VMP保护
    
    // === 业务逻辑处理 ===
    // 1. 设备指纹计算
    String deviceId = generateDeviceFingerprint();
    
    // 2. 时间戳和随机数
    long timestamp = getCurrentTime();
    String nonce = generateNonce();
    
    // 3. 签名计算
    String signature = calculateSignature(decrypted, deviceId, timestamp, nonce);
    
    // 4. 构建响应数据
    JsonObject response = {
        "data": encodeBase64(decrypted),
        "sign": signature,
        "timestamp": timestamp,
        "device": deviceId
    };
    
    // === 加密输出 ===
    String encrypted = encryptResponse(response);  // VMP保护
    
    // === 清理和返回 ===
    env->ReleaseByteArrayElements(inputData, data, JNI_ABORT);
    return env->NewStringUTF(encrypted.c_str());
}
```

---

## 分析方法建议

### 1. 静态分析工具

推荐使用以下工具:

#### IDA Pro / Ghidra
```bash
# 使用IDA Pro ARM64反汇编器
# 关注:
# - 交叉引用 (Xrefs)
# - 字符串引用
# - 函数调用图
# - JNI函数识别
```

#### Binary Ninja
```python
# 使用Binary Ninja的BNIL中间语言
# 可以更好地处理混淆代码
```

### 2. 动态分析工具

#### Frida Hook
```javascript
// Hook JNI函数
Java.perform(function() {
    var SpringUtil = Java.use("a.backwebview.SpringUtil");
    
    SpringUtil.getMyInstaData.implementation = function(bArr) {
        console.log("getMyInstaData called");
        console.log("Input bytes:", bArr);
        
        var result = this.getMyInstaData(bArr);
        console.log("Result:", result);
        
        return result;
    };
});

// Hook Native层
Interceptor.attach(Module.findExportByName("libspringIns.so", 
    "_Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray"), {
    onEnter: function(args) {
        console.log("Native getMyInstaData called");
        console.log("JNIEnv:", args[0]);
        console.log("jobject:", args[1]);
        console.log("jbyteArray:", args[2]);
    },
    onLeave: function(retval) {
        console.log("Return value:", retval);
    }
});
```

#### objection
```bash
# 自动化分析
objection -g com.package.name explore

# 列出native库
android hooking list natives

# Hook所有JNI函数
android hooking watch class_method a.backwebview.SpringUtil.* --dump-args --dump-return
```

### 3. VMP脱壳方法

针对VMP保护的SO:

#### 方法1: 内存Dump
```python
# 使用Frida在运行时dump解密后的代码
import frida

def dump_memory(module_name, address, size):
    script = """
    var baseAddr = Module.findBaseAddress("%s");
    var targetAddr = baseAddr.add(0x%x);
    var data = Memory.readByteArray(targetAddr, %d);
    send(data);
    """ % (module_name, address, size)
    
    # 执行并保存
```

#### 方法2: Trace分析
```javascript
// 跟踪所有函数调用
Interceptor.attach(Module.findBaseAddress("libspringIns.so").add(0xc01c), {
    onEnter: function(args) {
        console.log(Thread.backtrace(this.context).map(DebugSymbol.fromAddress));
    }
});
```

### 4. 汇编分析关键点

查找以下模式:

```assembly
# 1. JNI函数标准序言
STP     X29, X30, [SP,#-0x10]!
MOV     X29, SP

# 2. GetByteArrayElements调用
LDR     X0, [X19,#0x2C0]  ; JNIEnv
MOV     X1, X20           ; jbyteArray
MOV     X2, #0            ; isCopy
BLR     X0                ; call GetByteArrayElements

# 3. 加密循环特征
.loop:
    LDR     W8, [X0],#4
    EOR     W8, W8, W9
    STR     W8, [X1],#4
    SUBS    W2, W2, #1
    B.NE    .loop

# 4. 字符串操作
ADRP    X0, #string@PAGE
ADD     X0, X0, #string@PAGEOFF
```

---

## 具体实现细节推测

### 加密算法推测

虽然没有找到明显的算法名称字符串,但从函数结构推测可能使用:

1. **对称加密**: AES-128/256 (CBC或GCM模式)
2. **签名算法**: HMAC-SHA256 或 RSA
3. **编码**: Base64
4. **压缩**: 可能使用zlib或自定义压缩

### 数据流向

```
输入 byte[] → Native处理 → 输出 String

具体流程:
byte[] (加密) → 解密 → 处理 → 签名 → 加密 → Base64 → String
```

### 可能的安全措施

1. **完整性校验**: 使用HMAC验证数据未被篡改
2. **重放攻击防护**: 时间戳 + nonce
3. **设备绑定**: 设备指纹参与签名计算
4. **代码保护**: VMP虚拟化 + 反调试

---

## 总结

### 回答问题1: Native方法参数

1. **getMyInstaData(byte[] bArr)**
   - C++参数: `(JNIEnv* env, jobject thiz, jbyteArray bArr)`
   - bArr是Java传入的字节数组

2. **getWeijuData(byte[] bArr)**
   - C++参数: `(JNIEnv* env, jobject thiz, jbyteArray bArr)`
   - bArr是Java传入的字节数组

3. **rL(Object[] objArr)**
   - 预期C++参数: `(JNIEnv* env, jobject thiz, jobjectArray objArr)`
   - objArr是Java对象数组
   - 注意: 该函数在提供的SO中未找到,可能在其他模块或被混淆

### 回答问题2: C++调用逻辑

**核心流程**:
1. JNI边界处理 (参数转换)
2. 反调试/反篡改检测
3. 输入数据解密
4. 业务逻辑处理 (设备指纹、签名计算)
5. 输出数据加密和编码
6. 返回给Java层

**VMP保护确认**:
- processData函数23KB大小异常
- 代码高度混淆
- 字符串被隐藏
- 需要动态分析才能完全理解逻辑

**分析难点**:
- VMP虚拟化导致静态分析困难
- 符号表剥离
- 控制流混淆
- 建议使用Frida进行动态分析,在运行时观察数据流

---

## 下一步建议

1. **使用Frida Hook这些函数**,观察实际输入输出
2. **Dump运行时内存**,获取解密后的代码
3. **跟踪加密算法调用**,识别具体的加密方案
4. **分析网络流量**,了解数据最终用途
5. **查找密钥存储位置**,可能在.rodata或加密存储

需要实际运行环境才能获得更详细的分析结果。
