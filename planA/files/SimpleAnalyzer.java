package com.analysis;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;

import java.io.File;

/**
 * 简化版 - 快速开始
 */
public class SimpleAnalyzer extends AbstractJni {
    
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    
    public SimpleAnalyzer() {
        // 1. 创建模拟器
        emulator = AndroidEmulatorBuilder.for64Bit().build();
        
        // 2. 设置内存
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        
        // 3. 创建VM
        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(true); // 打开详细日志
        
        // 4. 加载SO
        System.out.println("正在加载 libspringIns.so...");
        DalvikModule dm = vm.loadLibrary(new File("assets/libspringIns.so"), true);
        module = dm.getModule();
        
        System.out.println("✓ SO加载成功!");
        System.out.println("  基地址: 0x" + Long.toHexString(module.base));
        System.out.println("  大小: " + module.size + " bytes");
        
        // 5. 调用JNI_OnLoad
        dm.callJNI_OnLoad(emulator);
        System.out.println("✓ JNI_OnLoad 调用成功!\n");
    }
    
    /**
     * 测试 getMyInstaData
     */
    public void test(String input) {
        System.out.println("=".repeat(60));
        System.out.println("测试输入: " + input);
        System.out.println("=".repeat(60));
        
        try {
            // 获取类和创建实例
            DvmClass clazz = vm.resolveClass("a/backwebview/SpringUtil");
            DvmObject<?> obj = clazz.newObject(null);
            
            // 调用native方法
            DvmObject<?> result = obj.callJniMethodObject(
                emulator,
                "getMyInstaData([B)Ljava/lang/String;",
                input.getBytes()
            );
            
            // 输出结果
            String output = result.getValue().toString();
            System.out.println("\n✓ 调用成功!");
            System.out.println("返回结果: " + output);
            System.out.println("结果长度: " + output.length());
            
        } catch (Exception e) {
            System.err.println("\n✗ 调用失败!");
            System.err.println("错误信息: " + e.getMessage());
            e.printStackTrace();
        }
        
        System.out.println();
    }
    
    public void destroy() {
        emulator.close();
        System.out.println("模拟器已关闭");
    }
    
    /**
     * 主函数 - 快速测试
     */
    public static void main(String[] args) {
        SimpleAnalyzer analyzer = new SimpleAnalyzer();
        
        try {
            // 测试1: 简单字符串
            analyzer.test("Hello World");
            
            // 测试2: JSON
            analyzer.test("{\"user\":\"test\"}");
            
            // 测试3: Base64
            analyzer.test("SGVsbG8gV29ybGQ=");
            
            // 更多测试...
            // analyzer.test("your input here");
            
        } finally {
            analyzer.destroy();
        }
    }
}
