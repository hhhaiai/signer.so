# Unidbg SO文件分析 - 完整方案总结

## 🎯 核心问题回顾

你提出了使用Unidbg来分析SO文件的具体调用逻辑,这是一个非常好的方向!

**原始问题**:
1. Native方法的参数是什么?
2. C++调用后的逻辑是什么,做了什么?
3. 如何通过逆向/汇编分析调用逻辑?

**Unidbg的优势**:
✅ 无需真机设备
✅ 完全可控的执行环境
✅ 实时观察输入输出
✅ 方便的Hook和内存访问
✅ 快速迭代测试

---

## 📦 提供的完整方案

### 1. 核心文件

| 文件名 | 用途 | 难度 |
|--------|------|------|
| **SimpleAnalyzer.java** | 快速测试,适合入门 | ⭐ 简单 |
| **SpringInsAnalyzer.java** | 完整分析,包含Hook | ⭐⭐⭐ 中等 |
| **SecSdkAnalyzer.java** | libsecsdk.so分析 | ⭐⭐⭐ 中等 |
| **pom.xml** | Maven依赖配置 | ⭐ 简单 |
| **README.md** | 快速入门指南 | ⭐ 文档 |
| **UNIDBG_GUIDE.md** | 详细使用教程 | ⭐⭐ 文档 |
| **quick_start.sh** | 一键启动脚本 | ⭐ 脚本 |

### 2. 分析能力

通过Unidbg,你可以:

#### ✅ 基础功能
- [x] 加载和执行SO文件
- [x] 调用native方法
- [x] 观察输入输出
- [x] 查看日志输出

#### ✅ 高级功能
- [x] Hook任意函数
- [x] 查看寄存器状态
- [x] Dump内存数据
- [x] 追踪代码执行
- [x] 修改执行流程
- [x] 搜索加密常量
- [x] 分析调用关系

---

## 🚀 使用流程

### 方案A: 使用快速启动脚本(最简单)

```bash
# 1. 进入包含所有文件的目录
cd /path/to/output/directory

# 2. 运行快速启动脚本
bash quick_start.sh

# 3. 脚本会自动:
#    - 检查环境
#    - 创建项目结构
#    - 复制文件
#    - 编译项目

# 4. 然后运行分析
cd so-analyzer
mvn exec:java -Dexec.mainClass="com.analysis.SimpleAnalyzer"
```

### 方案B: 手动搭建(推荐学习)

```bash
# 1. 创建项目结构
mkdir -p so-analyzer/src/main/java/com/analysis
mkdir -p so-analyzer/assets

# 2. 复制文件
cp pom.xml so-analyzer/
cp *.java so-analyzer/src/main/java/com/analysis/
cp *.so so-analyzer/assets/

# 3. 编译
cd so-analyzer
mvn clean compile

# 4. 运行
mvn exec:java -Dexec.mainClass="com.analysis.SimpleAnalyzer"
```

---

## 📊 预期分析结果

### 1. 输入输出关系

通过多次测试不同输入,你会看到:

```
输入1: "Hello"
输出1: {"code":0,"data":"SGVsbG8=","sign":"abc123"}

输入2: "World"  
输出2: {"code":0,"data":"V29ybGQ=","sign":"def456"}

输入3: "Test"
输出3: {"code":0,"data":"VGVzdA==","sign":"ghi789"}
```

**分析**:
- `data`字段是Base64编码的输入
- `sign`字段是基于输入计算的签名
- 可能还包含时间戳、设备信息等

### 2. 函数调用链

通过Hook,你会看到:

```
getMyInstaData (入口)
  ↓
processData (核心处理)
  ↓
├─ decrypt_input (可能)
├─ generate_device_id
├─ calculate_signature
│   ├─ hmac_sha256
│   └─ base64_encode
└─ encrypt_output (可能)
```

### 3. 加密算法识别

通过搜索和Hook,可能发现:

```
发现AES S-Box at: 0x40012340
发现MD5魔数 at: 0x40023456
发现HMAC调用 at: 0x40034567

→ 结论: 使用AES加密 + HMAC-SHA256签名 + Base64编码
```

### 4. 关键数据提取

```
设备ID: "device_1234567890"
签名密钥: "secret_key_xyz"
加密IV: [0x01, 0x02, 0x03, ...]
时间戳: 1234567890
```

---

## 💡 实战分析步骤

### 第1步: 基础测试(5分钟)

```bash
# 运行SimpleAnalyzer
mvn exec:java -Dexec.mainClass="com.analysis.SimpleAnalyzer"
```

**观察**:
- SO是否能正常加载?
- 函数调用是否成功?
- 输出格式是什么样的?

### 第2步: 多输入测试(10分钟)

修改`SimpleAnalyzer.main()`,测试多种输入:

```java
analyzer.test("test1");
analyzer.test("test2");
analyzer.test("{\"key\":\"value\"}");
analyzer.test("SGVsbG8=");
```

**分析**:
- 不同输入的输出有什么规律?
- 哪些部分是固定的,哪些是变化的?
- 输出格式是JSON吗?包含哪些字段?

### 第3步: 启用Hook(20分钟)

```bash
# 运行完整分析器
mvn exec:java -Dexec.mainClass="com.analysis.SpringInsAnalyzer"
```

**观察**:
- `getMyInstaData`调用了哪些子函数?
- `processData`的参数是什么?
- 有没有调用加密函数?

### 第4步: 内存分析(30分钟)

在代码中添加:

```java
// Dump processData函数的内存
long processDataAddr = module.findSymbolByName("_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring").getAddress();
analyzer.dumpMemory(processDataAddr, 0x5CF0, "processData.bin");

// 搜索加密常量
analyzer.searchCryptoConstants();
```

**分析**:
- 用IDA/Ghidra打开dump的二进制
- 查找加密常量和算法特征
- 识别具体的加密实现

### 第5步: 逆向工程(60分钟)

根据前面的发现:

1. **识别加密算法**: AES? DES? RSA?
2. **提取密钥**: 硬编码? 动态生成?
3. **理解签名逻辑**: HMAC? 自定义算法?
4. **找到设备指纹**: IMEI? Android ID? 自定义?

### 第6步: 编写PoC(30分钟)

用Python复现逻辑:

```python
import base64
import hmac
import hashlib

def encrypt_data(input_data):
    # 1. Base64编码
    encoded = base64.b64encode(input_data).decode()
    
    # 2. 计算签名
    key = b"secret_key_from_so"
    signature = hmac.new(key, input_data, hashlib.sha256).hexdigest()
    
    # 3. 构建输出
    return {
        "code": 0,
        "data": encoded,
        "sign": signature
    }

# 测试
result = encrypt_data(b"Hello World")
print(result)
```

---

## 🎓 学习路径

### 初级(第1天)
- ✅ 运行SimpleAnalyzer
- ✅ 理解基本的输入输出
- ✅ 修改测试用例

### 中级(第2-3天)
- ✅ 运行SpringInsAnalyzer
- ✅ 理解Hook机制
- ✅ 分析函数调用链
- ✅ 识别加密算法

### 高级(第4-7天)
- ✅ 深入分析processData
- ✅ 提取密钥和常量
- ✅ 理解VMP保护机制
- ✅ 编写Python PoC复现

---

## 🔧 故障排查

### 问题1: SO加载失败

```
错误: Library not found
解决:
1. 检查SO文件是否在assets/目录
2. 确认路径正确
3. 尝试使用绝对路径
```

### 问题2: 函数调用失败

```
错误: Method not found
解决:
1. 检查类名和方法签名
2. 确认SO中确实有这个函数
3. 可能需要实现JNI回调
```

### 问题3: 缺少依赖

```
错误: Could not find artifact
解决:
1. 配置Maven镜像
2. 检查网络连接
3. 手动下载依赖
```

### 问题4: VMP保护

```
现象: 代码混乱,无法理解
解决:
1. 使用Unidbg动态执行
2. Hook关键函数观察行为
3. Dump运行时内存
4. 不要试图完全理解VMP代码
```

---

## 📈 成功指标

### 阶段1: 能运行 ✓
- SO成功加载
- 函数能调用
- 看到输出结果

### 阶段2: 能分析 ✓✓
- Hook正常工作
- 能看到调用链
- 识别出加密算法

### 阶段3: 能复现 ✓✓✓
- 理解完整逻辑
- 提取所有密钥
- Python PoC成功

---

## 🎁 额外资源

### 相关工具
- **IDA Pro**: 静态分析SO文件
- **Frida**: 真机动态分析
- **Ghidra**: 免费的反汇编工具
- **jadx**: APK反编译

### 学习资料
- Unidbg官方示例
- ARM64汇编教程
- JNI规范文档
- 加密算法识别指南

### 社区资源
- 52pojie论坛
- 看雪论坛
- GitHub Unidbg项目

---

## 🏆 总结

### Unidbg vs 其他方法

| 方法 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **Unidbg** | 快速、可控、无需设备 | 需要Java知识 | 快速分析、批量测试 |
| **Frida** | 真实环境、强大 | 需要设备、可能被检测 | 深入分析、绕过检测 |
| **IDA Pro** | 全面、专业 | 静态分析、VMP困难 | 代码理解、漏洞分析 |

### 最佳实践

1. **先用Unidbg快速测试** - 了解基本行为
2. **配合Frida真机验证** - 确认环境差异
3. **使用IDA静态分析** - 理解算法细节
4. **编写Python PoC** - 验证理解正确

### 预期收获

通过Unidbg分析,你将:
- ✅ 完全理解SO的输入输出关系
- ✅ 识别所有使用的加密算法
- ✅ 提取密钥、IV、设备指纹生成逻辑
- ✅ 绕过VMP保护,观察实际行为
- ✅ 编写独立的加密/签名实现

---

## 🚀 立即开始!

```bash
# 一键启动
bash quick_start.sh

# 或手动执行
cd so-analyzer
mvn clean compile
mvn exec:java -Dexec.mainClass="com.analysis.SimpleAnalyzer"
```

**祝你分析顺利! 🎉**

有任何问题,参考:
- README.md - 快速入门
- UNIDBG_GUIDE.md - 详细教程
- SpringInsAnalyzer.java - 代码示例
