# SO文件Unidbg分析项目

通过Unidbg模拟执行分析libspringIns.so和libsecsdk.so的完整项目。

## 📁 项目结构

```
.
├── README.md                           # 本文件
├── UNIDBG_GUIDE.md                    # 详细使用指南
├── pom.xml                            # Maven配置
├── SpringInsAnalyzer.java             # libspringIns.so完整分析类
├── SecSdkAnalyzer.java                # libsecsdk.so分析类  
├── SimpleAnalyzer.java                # 简化版快速测试
└── assets/                            # 需要创建此目录
    ├── libspringIns.so               # 复制SO文件到这里
    ├── libsecsdk.so                  # 复制SO文件到这里
    └── app.apk (可选)                # 如果需要APK上下文

项目结构(Maven标准):
so-analyzer/
├── pom.xml
├── src/
│   └── main/
│       └── java/
│           └── com/
│               └── analysis/
│                   ├── SpringInsAnalyzer.java
│                   ├── SecSdkAnalyzer.java
│                   └── SimpleAnalyzer.java
└── assets/
    ├── libspringIns.so
    └── libsecsdk.so
```

## 🚀 快速开始

### 1. 环境准备

```bash
# 安装JDK 8+
java -version

# 安装Maven
mvn -version
```

### 2. 创建项目结构

```bash
# 创建目录
mkdir -p so-analyzer/src/main/java/com/analysis
mkdir -p so-analyzer/assets

cd so-analyzer
```

### 3. 复制文件

```bash
# 复制Maven配置
cp pom.xml so-analyzer/

# 复制Java源文件
cp *.java so-analyzer/src/main/java/com/analysis/

# 复制SO文件
cp /path/to/libspringIns.so so-analyzer/assets/
cp /path/to/libsecsdk.so so-analyzer/assets/
```

### 4. 编译项目

```bash
cd so-analyzer

# 下载依赖(第一次会比较慢)
mvn dependency:resolve

# 编译
mvn clean compile
```

### 5. 运行分析

#### 方式A: 简单测试(推荐新手)

```bash
mvn exec:java -Dexec.mainClass="com.analysis.SimpleAnalyzer"
```

#### 方式B: 完整分析(包含Hook)

```bash
mvn exec:java -Dexec.mainClass="com.analysis.SpringInsAnalyzer"
```

#### 方式C: 打包运行

```bash
# 打包
mvn clean package

# 运行
java -jar target/so-analyzer-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## 📊 预期输出

### 简单测试输出示例

```
正在加载 libspringIns.so...
✓ SO加载成功!
  基地址: 0x40000000
  大小: 1123200 bytes
✓ JNI_OnLoad 调用成功!

============================================================
测试输入: Hello World
============================================================

✓ 调用成功!
返回结果: {"code":0,"data":"SGVsbG8gV29ybGQ=","sign":"abc123xyz"}
结果长度: 45
```

### 完整分析输出示例

```
=================================================
Unidbg 初始化完成
模块加载: libspringIns.so
基地址: 0x40000000
=================================================

[Hook] 开始设置Hook
getMyInstaData 地址: 0x40049b1c
processData 地址: 0x4000c01c
[Hook] Hook设置完成

[测试] getMyInstaData
输入长度: 11
输入数据(Hex): 48 65 6C 6C 6F 20 57 6F 72 6C 64
输入数据(UTF-8): Hello World

>>> [Hook] getMyInstaData 调用
    X0(JNIEnv*): 0x7ffff123
    X1(jobject): 0x40001000
    X2(jbyteArray): 0x40002000

>>> [Hook] processData 调用
    X0(JNIEnv*): 0x7ffff123
    X1(jobject): 0x40001000
    X2(jbyteArray): 0x40002000
    X3(jstring): 0x40003000
<<< [Hook] processData 返回

<<< [Hook] getMyInstaData 返回
    返回值(jstring): 0x40004000

返回结果: {"code":0,"data":"...","sign":"..."}
返回长度: 45
```

## 🔍 分析目标

### libspringIns.so

**目标函数**:
1. ✅ `getMyInstaData(byte[] bArr)` - 已定位
2. ✅ `getWeijuData(byte[] bArr)` - 已定位
3. ✅ `processData(byte[], String)` - 核心处理函数(VMP保护)

**分析重点**:
- 输入输出格式
- 加密算法识别
- 签名计算逻辑
- 设备指纹生成

### libsecsdk.so

**目标函数**:
1. ⚠️ `rL(Object[] objArr)` - 需要进一步查找

**分析重点**:
- 函数注册方式(可能是动态注册)
- 参数处理逻辑

## 📝 测试用例

在`main()`函数中添加更多测试:

```java
public static void main(String[] args) {
    SimpleAnalyzer analyzer = new SimpleAnalyzer();
    
    try {
        // 1. 简单字符串
        analyzer.test("Hello World");
        
        // 2. JSON格式
        analyzer.test("{\"user\":\"test\",\"ts\":1234567890}");
        
        // 3. Base64数据
        analyzer.test("SGVsbG8gV29ybGQ=");
        
        // 4. 空字符串
        analyzer.test("");
        
        // 5. 特殊字符
        analyzer.test("!@#$%^&*()");
        
        // 6. 长字符串
        analyzer.test("A".repeat(1000));
        
        // 7. Unicode
        analyzer.test("你好世界🌍");
        
        // 8. 自定义测试
        analyzer.test("your custom input");
        
    } finally {
        analyzer.destroy();
    }
}
```

## 🛠️ 自定义修改

### 修改1: 改变输入格式

```java
// 测试二进制数据
byte[] binaryInput = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
DvmObject<?> result = obj.callJniMethodObject(
    emulator,
    "getMyInstaData([B)Ljava/lang/String;",
    binaryInput  // 直接传入byte[]
);
```

### 修改2: 添加更多Hook

```java
// Hook其他感兴趣的函数
long memcpyAddr = module.findSymbolByName("memcpy").getAddress();
hookZz.wrap(memcpyAddr, new WrapCallback<HookZzArm64RegisterContext>() {
    @Override
    public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
        long dst = ctx.getXLong(0);
        long src = ctx.getXLong(1);
        long len = ctx.getXLong(2);
        System.out.println("[memcpy] dst=0x" + Long.toHexString(dst) + 
                         ", src=0x" + Long.toHexString(src) + 
                         ", len=" + len);
    }
    
    @Override
    public void postCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
    }
});
```

### 修改3: 保存输出到文件

```java
// 在test()方法中添加
try (FileOutputStream fos = new FileOutputStream("output_" + System.currentTimeMillis() + ".txt")) {
    fos.write(output.getBytes());
    System.out.println("结果已保存到文件");
} catch (IOException e) {
    e.printStackTrace();
}
```

## 🐛 常见问题排查

### 问题1: 找不到SO文件

```
错误: java.io.FileNotFoundException: assets/libspringIns.so
解决: 
1. 确保assets目录存在
2. 检查SO文件路径
3. 使用绝对路径: new File("/full/path/to/libspringIns.so")
```

### 问题2: 依赖下载失败

```
错误: Could not resolve dependencies
解决:
1. 检查网络连接
2. 配置Maven镜像(aliyun等)
3. 使用VPN
```

Maven国内镜像配置(~/.m2/settings.xml):

```xml
<mirrors>
    <mirror>
        <id>aliyun</id>
        <mirrorOf>central</mirrorOf>
        <name>Aliyun Maven</name>
        <url>https://maven.aliyun.com/repository/public</url>
    </mirror>
</mirrors>
```

### 问题3: 内存不足

```
错误: OutOfMemoryError
解决: 增加JVM内存
mvn exec:java -Dexec.mainClass="..." -Dexec.args="-Xmx2g"
```

### 问题4: 符号找不到

```
错误: Symbol not found: xxx
解决:
1. 检查符号名称是否正确(大小写敏感)
2. 使用 nm -D libxxx.so 查看导出符号
3. 可能被混淆,尝试通过偏移调用
```

## 📚 进阶阅读

- [Unidbg官方文档](https://github.com/zhkl0228/unidbg)
- [UNIDBG_GUIDE.md](./UNIDBG_GUIDE.md) - 本项目详细指南
- [ARM64汇编参考](https://developer.arm.com/documentation)
- [JNI规范](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/)

## 🎯 下一步

1. ✅ 运行SimpleAnalyzer进行基础测试
2. ✅ 观察输入输出关系
3. ✅ 使用SpringInsAnalyzer启用Hook
4. ✅ 分析processData函数的行为
5. ✅ 识别加密算法
6. ✅ 提取密钥和签名逻辑
7. ✅ 编写Python PoC复现算法

## 📧 问题反馈

如果遇到问题:
1. 查看详细日志输出
2. 检查SO文件是否正确
3. 确认Java和Maven版本
4. 参考UNIDBG_GUIDE.md

## 📄 许可

本项目仅供学习研究使用。

---

**Happy Hacking! 🚀**
