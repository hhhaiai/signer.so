#!/bin/bash

# SO文件Unidbg分析快速启动脚本

echo "=================================="
echo "SO文件Unidbg分析项目快速启动"
echo "=================================="
echo ""

# 检查Java环境
echo "1. 检查Java环境..."
if ! command -v java &> /dev/null; then
    echo "❌ 未找到Java,请先安装JDK 8+"
    exit 1
fi
java -version
echo "✓ Java环境正常"
echo ""

# 检查Maven
echo "2. 检查Maven..."
if ! command -v mvn &> /dev/null; then
    echo "❌ 未找到Maven,请先安装Maven"
    echo "Ubuntu/Debian: sudo apt install maven"
    echo "macOS: brew install maven"
    exit 1
fi
mvn -version | head -1
echo "✓ Maven环境正常"
echo ""

# 创建项目结构
echo "3. 创建项目结构..."
mkdir -p so-analyzer/src/main/java/com/analysis
mkdir -p so-analyzer/assets

echo "✓ 项目结构创建完成"
echo ""

# 复制文件
echo "4. 复制项目文件..."

# 复制Java源文件
cp SpringInsAnalyzer.java so-analyzer/src/main/java/com/analysis/ 2>/dev/null
cp SecSdkAnalyzer.java so-analyzer/src/main/java/com/analysis/ 2>/dev/null
cp SimpleAnalyzer.java so-analyzer/src/main/java/com/analysis/ 2>/dev/null

# 复制Maven配置
cp pom.xml so-analyzer/ 2>/dev/null

# 复制SO文件
cp libspringIns.so so-analyzer/assets/ 2>/dev/null
cp libsecsdk.so so-analyzer/assets/ 2>/dev/null

echo "✓ 文件复制完成"
echo ""

# 进入项目目录
cd so-analyzer

# 编译项目
echo "5. 编译项目(首次运行会下载依赖,可能需要几分钟)..."
echo ""
mvn clean compile

if [ $? -eq 0 ]; then
    echo ""
    echo "=================================="
    echo "✓ 项目编译成功!"
    echo "=================================="
    echo ""
    echo "可以使用以下命令运行分析:"
    echo ""
    echo "简单测试(推荐):"
    echo "  cd so-analyzer"
    echo "  mvn exec:java -Dexec.mainClass=\"com.analysis.SimpleAnalyzer\""
    echo ""
    echo "完整分析(包含Hook):"
    echo "  cd so-analyzer"
    echo "  mvn exec:java -Dexec.mainClass=\"com.analysis.SpringInsAnalyzer\""
    echo ""
    echo "或者直接运行:"
    echo "  cd so-analyzer"
    echo "  java -cp target/classes:~/.m2/repository/... com.analysis.SimpleAnalyzer"
    echo ""
else
    echo ""
    echo "=================================="
    echo "❌ 编译失败"
    echo "=================================="
    echo ""
    echo "可能的原因:"
    echo "1. 网络问题导致依赖下载失败"
    echo "2. 请配置Maven国内镜像(aliyun等)"
    echo "3. 检查Java版本是否为8+"
    echo ""
    echo "查看详细错误信息请运行:"
    echo "  cd so-analyzer && mvn clean compile"
    exit 1
fi
