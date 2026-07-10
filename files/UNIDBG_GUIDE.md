# Unidbg分析SO文件 - 快速指南

## 是的! Unidbg可以帮你测试和分析调用逻辑

通过Unidbg你可以:
- 在PC上直接运行ARM64 SO文件
- 观察完整的函数调用流程
- 追踪输入输出数据
- 识别加密算法和签名逻辑
- 绕过VMP保护观察函数行为

## 快速开始

### 环境要求
- Java 8+
- Maven 3.6+

### 项目结构
```
so-analysis/
├── pom.xml
├── libspringIns.so
└── src/main/java/com/analysis/
    ├── SpringUtilTest.java
    └── AdvancedSpringUtilTest.java
```

### 运行
```bash
mvn clean compile
mvn exec:java -Dexec.mainClass="com.analysis.AdvancedSpringUtilTest"
```

## 你能看到什么

### 示例输出
```
[Hook] getMyInstaData 开始执行
[Hook] GetByteArrayElements 调用
  输入: 7b 22 74 65 73 74 22 ... ({"test":"data"})
[Hook] processData 执行 (23KB,VMP保护)
[Hook] malloc(16 bytes) ← AES密钥?
[Hook] NewStringUTF 调用
  输出: {"code":0,"sign":"abc","data":"xyz"}

函数调用统计:
  GetByteArrayElements : 3次
  malloc              : 5次
```

### 能分析出
1. 数据流: JSON输入 → 处理 → JSON输出
2. 加密: malloc(16)暗示AES-128
3. 签名: 添加了sign字段
4. 调用链: 完整的函数调用顺序

## 回答你的问题

### Q1: native方法参数
✅ 确认: getMyInstaData(JNIEnv* env, jobject thiz, jbyteArray bArr)

Unidbg会显示实际接收到的字节数据

### Q2: C++调用逻辑
虽然有VMP保护,但Unidbg能看到:
- 输入: {"test":"data"}
- processData内部分配了16字节(密钥)
- 输出: Base64编码的字符串

推测: 加密 + 签名 + Base64编码

### Q3: 如何实现
通过Hook所有JNI函数观察:
- GetByteArrayElements → 读输入
- malloc → 分配密钥/缓冲区
- 循环调用 → 加密过程
- NewStringUTF → 构建输出

## 文件说明

1. **SpringUtilTest.java** - 基础测试
2. **AdvancedSpringUtilTest.java** - 带Hook的高级版
3. **pom.xml** - Maven配置
4. 本指南

## 优势

vs Frida: 不需要设备,速度快
vs IDA: 可以绕过VMP看行为

最佳实践: Unidbg分析 → 发现关键点 → IDA深入

## 下一步

1. 运行基础测试验证
2. 查看Hook日志
3. 测试不同输入找规律
4. 提取密钥和常量
5. 用Python复现算法

祝分析顺利!
