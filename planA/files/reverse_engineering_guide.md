# SO文件逆向分析完整指南

## 快速开始

### 前提条件

1. **已Root的Android设备或模拟器**
2. **安装Frida**
   ```bash
   pip install frida-tools
   ```
3. **在设备上运行frida-server**
4. **目标应用已安装**

---

## 方法1: 使用Frida进行动态分析 (推荐)

### 步骤1: 启动应用并注入Frida

```bash
# 列出正在运行的应用
frida-ps -U

# 注入到目标应用
frida -U -f com.your.package.name -l frida_hook_script.js --no-pause

# 或者附加到已运行的应用
frida -U com.your.package.name -l frida_hook_script.js
```

### 步骤2: 观察输出

脚本会自动Hook以下内容:
- `SpringUtil.getMyInstaData()`
- `SpringUtil.getWeijuData()`
- `Utils.rL()`
- Native层的所有对应函数

输出示例:
```
[Java] SpringUtil.getMyInstaData 被调用
[Java] 输入字节数组长度: 128
[Java] 输入数据(hex前64字节):
48 65 6c 6c 6f 20 57 6f 72 6c 64 ...

[Native] getMyInstaData 被调用
[Native] JNIEnv*: 0x7fff1234
[Native] 输入数据长度: 128
[Native] 返回字符串: {"code":0,"data":"..."}
```

### 步骤3: 提取关键数据

修改Frida脚本,添加文件保存:

```javascript
// 在onLeave中添加
if (this.inputBytes) {
    var file = new File("/sdcard/input_" + Date.now() + ".bin", "wb");
    file.write(this.inputBytes);
    file.close();
}
```

---

## 方法2: 使用IDA Pro进行静态分析

### 步骤1: 在IDA中打开SO文件

```
File -> Open -> 选择 libspringIns.so
处理器类型: ARM64 (AArch64)
```

### 步骤2: 定位目标函数

```
View -> Open subviews -> Exports
搜索: getMyInstaData
```

或使用快捷键 `Shift+F7` 打开Exports窗口

### 步骤3: 分析函数

关键地址:
- `getMyInstaData`: 0x00049b1c
- `getWeijuData`: 0x0004a428
- `processData`: 0x0000c01c

在IDA中按 `G` 键跳转到地址

### 步骤4: 识别关键代码模式

查找这些模式:

#### 1. GetByteArrayElements调用
```assembly
LDR     X0, [X19,#0x2C0]    ; JNIEnv
MOV     X1, X20             ; jbyteArray
MOV     X2, #0              ; isCopy
BLR     X0                  ; GetByteArrayElements
```

#### 2. 加密循环
```assembly
.loop:
    LDRB    W8, [X0],#1
    EOR     W8, W8, W9      ; XOR操作
    STRB    W8, [X1],#1
    SUBS    W2, W2, #1
    B.NE    .loop
```

#### 3. NewStringUTF调用
```assembly
LDR     X0, [X19,#0x29C]    ; JNIEnv
MOV     X1, X20             ; char* string
BLR     X0                  ; NewStringUTF
```

---

## 方法3: 使用Ghidra进行分析

### 步骤1: 导入文件

```
File -> Import File -> 选择 libspringIns.so
Language: AARCH64:LE:64:v8A
```

### 步骤2: 自动分析

```
Analysis -> Auto Analyze
勾选所有选项
点击 Analyze
```

### 步骤3: 查找函数

```
Window -> Symbol Table
搜索: getMyInstaData
双击跳转
```

### 步骤4: 反编译

```
右键函数 -> Decompile
```

Ghidra的反编译输出通常比IDA更易读,尤其对于C++代码

---

## 方法4: 处理VMP保护

### 识别VMP特征

1. **异常大的函数体** ✓ (processData 23KB)
2. **大量无意义的跳转**
3. **间接调用**
4. **虚拟机解释器循环**

### 脱壳策略

#### 策略1: 动态Dump

使用Frida在运行时dump解密的代码:

```javascript
// dump_vmp.js
var processDataAddr = Module.findExportByName("libspringIns.so", 
    "_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring");

Interceptor.attach(processDataAddr, {
    onEnter: function(args) {
        // 在函数执行前dump
        console.log("[*] 准备执行processData");
    },
    onLeave: function(retval) {
        // 在函数执行后dump,此时代码已解密
        var module = Process.findModuleByName("libspringIns.so");
        var codeAddr = processDataAddr;
        var codeSize = 0x5CF0; // 23760字节
        
        var code = Memory.readByteArray(codeAddr, codeSize);
        
        send({
            type: 'code_dump',
            address: codeAddr.toString(),
            size: codeSize,
            data: code
        });
        
        console.log("[+] 已dump processData函数代码");
    }
});
```

保存dump的代码:

```python
# receive_dump.py
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload['type'] == 'code_dump':
            filename = f"processData_{payload['address']}.bin"
            with open(filename, 'wb') as f:
                f.write(data)
            print(f"[+] 已保存到 {filename}")

device = frida.get_usb_device()
pid = device.spawn(["com.your.package"])
session = device.attach(pid)

with open('dump_vmp.js', 'r') as f:
    script = session.create_script(f.read())

script.on('message', on_message)
script.load()
device.resume(pid)

sys.stdin.read()
```

#### 策略2: Trace执行流

记录所有执行的指令:

```javascript
// trace_execution.js
var processDataAddr = Module.findExportByName("libspringIns.so", 
    "_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring");

Stalker.follow({
    events: {
        call: true,
        ret: false,
        exec: false,
        block: false,
        compile: false
    },
    onReceive: function(events) {
        console.log(Stalker.parse(events));
    }
});

Interceptor.attach(processDataAddr, {
    onEnter: function() {
        Stalker.follow(this.threadId, {
            events: { call: true },
            onCallSummary: function(summary) {
                console.log(JSON.stringify(summary));
            }
        });
    },
    onLeave: function() {
        Stalker.unfollow(this.threadId);
    }
});
```

#### 策略3: 内存断点

在关键位置设置断点:

```javascript
// breakpoint.js
var targetAddr = Module.findBaseAddress("libspringIns.so").add(0xc01c);

Process.setExceptionHandler(function(details) {
    console.log("[!] 异常发生:", JSON.stringify(details));
    
    if (details.type === 'breakpoint' && details.address.equals(targetAddr)) {
        console.log("[*] 命中断点");
        console.log("寄存器状态:");
        console.log("  X0:", details.context.x0);
        console.log("  X1:", details.context.x1);
        console.log("  X2:", details.context.x2);
        console.log("  LR:", details.context.lr);
        
        // 继续执行
        return true;
    }
    
    return false;
});

// 设置软件断点
Memory.protect(targetAddr, Process.pageSize, 'r--');
```

---

## 方法5: 分析加密算法

### 查找加密常量

#### AES常量搜索

```python
# search_aes.py
import struct

def find_aes_sbox(data):
    # AES S-Box
    sbox = bytes([
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    ])
    
    idx = data.find(sbox)
    if idx != -1:
        print(f"[+] 找到AES S-Box at offset: {hex(idx)}")
        return idx
    return None

with open('libspringIns.so', 'rb') as f:
    data = f.read()
    find_aes_sbox(data)
```

#### RSA特征搜索

```javascript
// search_rsa.js
var module = Process.findModuleByName("libspringIns.so");

// RSA常用的大素数
var primes = [
    "10001",  // 常用公钥指数
    "D", "E", "F", "10", "11"  // 小素数
];

primes.forEach(function(prime) {
    Memory.scan(module.base, module.size, prime, {
        onMatch: function(address, size) {
            console.log("[+] 可能的RSA常量:", address);
        },
        onComplete: function() {}
    });
});
```

---

## 方法6: 自动化工具链

### objection自动化

```bash
# 安装
pip install objection

# 启动
objection -g com.your.package explore

# 常用命令
android hooking list classes
android hooking list class_methods a.backwebview.SpringUtil
android hooking watch class_method a.backwebview.SpringUtil.getMyInstaData --dump-args --dump-return

# 列出native库
android heap print_instances java.lang.System

# dump内存
memory dump all /sdcard/dump.bin
```

### r2frida集成

```bash
# 安装
pip install r2frida

# 启动
r2 frida://attach/usb//com.your.package

# 命令
\dm  # 列出模块
\dma libspringIns.so  # 分析模块
\dmi libspringIns.so~get  # 搜索导出函数
\pdf @ sym._Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray  # 反汇编
```

---

## 完整分析工作流

### 第1步: 信息收集

```bash
# 1. 获取APK
adb pull /data/app/com.package.name-1/base.apk

# 2. 解包APK
apktool d base.apk

# 3. 提取SO文件
cd base/lib/arm64-v8a/
ls -lh *.so

# 4. 静态信息
file libspringIns.so
readelf -h libspringIns.so
nm -D libspringIns.so
strings libspringIns.so
```

### 第2步: 静态分析

```
1. IDA Pro打开SO
2. 定位目标函数
3. F5反编译
4. 标注重要代码
5. 导出伪代码
```

### 第3步: 动态分析

```bash
1. 启动Frida
frida -U -f com.package.name -l frida_hook_script.js

2. 触发目标功能
3. 观察输入输出
4. 记录调用栈
5. Dump关键数据
```

### 第4步: 算法识别

```
1. 搜索加密常量
2. 识别标准算法
3. 提取密钥
4. 复现加密逻辑
```

### 第5步: 编写PoC

```python
# poc.py
import requests
import hashlib
import time
import base64

def encrypt_data(data):
    # 复现native加密逻辑
    # ...
    return encrypted

def call_api(data):
    encrypted = encrypt_data(data)
    response = requests.post(
        'https://api.example.com/endpoint',
        data={'data': encrypted}
    )
    return response.json()

# 测试
result = call_api(b'test data')
print(result)
```

---

## 常见问题

### Q1: Frida检测绕过

```javascript
// anti_frida.js
// 绕过Frida检测
function bypassFridaDetection() {
    // 1. 隐藏Frida端口
    Interceptor.replace(Module.findExportByName(null, "open"), new NativeCallback(function(pathname, flags) {
        var path = Memory.readUtf8String(pathname);
        if (path.indexOf("frida") !== -1) {
            return -1;
        }
        return this.open(pathname, flags);
    }, 'int', ['pointer', 'int']));
    
    // 2. 隐藏进程名
    // ...
}

bypassFridaDetection();
```

### Q2: Root检测绕过

```javascript
// bypass_root.js
Java.perform(function() {
    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    RootBeer.isRooted.implementation = function() {
        return false;
    };
});
```

### Q3: SSL Pinning绕过

```javascript
// bypass_ssl.js
Java.perform(function() {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
        console.log("[+] SSL Pinning绕过");
        return;
    };
});
```

---

## 推荐工具

### 静态分析
1. **IDA Pro** - 最强大的反汇编器
2. **Ghidra** - 免费开源,NSA开发
3. **Binary Ninja** - 现代化UI,中间语言好用
4. **radare2** - 命令行工具,强大但学习曲线陡

### 动态分析
1. **Frida** - 最流行的动态分析框架
2. **objection** - 基于Frida的自动化工具
3. **r2frida** - radare2 + Frida
4. **Xposed** - 需要重启,但功能强大

### 辅助工具
1. **apktool** - APK解包
2. **jadx** - Java反编译
3. **dex2jar** - DEX转JAR
4. **Wireshark** - 网络抓包
5. **mitmproxy** - HTTP(S)代理

---

## 总结

本指南涵盖了从基础到高级的SO文件逆向分析方法。对于你的具体问题:

### getMyInstaData / getWeijuData 参数
✓ 已确认: `(JNIEnv* env, jobject thiz, jbyteArray bArr)`

### C++调用逻辑
✓ 推测流程: 解密 → 处理 → 签名 → 加密 → 返回

### VMP保护
✓ 确认存在,需要动态分析

**下一步建议**:
1. 使用Frida脚本观察实际数据流
2. Dump运行时内存获取解密代码
3. 识别具体的加密算法
4. 编写Python PoC复现逻辑

祝分析顺利!
