package com.analysis;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.utils.Inspector;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * libspringIns.so 分析
 * 目标函数:
 * 1. getMyInstaData(byte[] bArr)
 * 2. getWeijuData(byte[] bArr)
 */
public class SpringInsAnalyzer extends AbstractJni {
    
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    
    // 日志开关
    private static final boolean ENABLE_TRACE = true;
    private static final boolean ENABLE_HOOK = true;
    
    public SpringInsAnalyzer() {
        // 创建模拟器 - ARM64
        emulator = AndroidEmulatorBuilder
                .for64Bit()
                .setProcessName("com.test.app")
                .addBackendFactory(new DynarmicFactory(true))
                .build();
        
        // 获取内存
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // Android 6.0
        
        // 创建VM
        vm = emulator.createDalvikVM(new File("assets/app.apk"));
        
        // 设置JNI
        vm.setJni(this);
        vm.setVerbose(ENABLE_TRACE);
        
        // 加载SO文件
        DalvikModule dm = vm.loadLibrary(new File("assets/libspringIns.so"), true);
        module = dm.getModule();
        
        log("=================================================");
        log("Unidbg 初始化完成");
        log("模块加载: " + module.name);
        log("基地址: 0x" + Long.toHexString(module.base));
        log("=================================================\n");
        
        // 调用JNI_OnLoad
        dm.callJNI_OnLoad(emulator);
    }
    
    /**
     * 测试 getMyInstaData
     */
    public void testGetMyInstaData(byte[] input) {
        log("\n[测试] getMyInstaData");
        log("输入长度: " + input.length);
        log("输入数据(Hex): " + bytesToHex(input));
        log("输入数据(UTF-8): " + tryDecodeUtf8(input));
        
        try {
            // 获取类
            DvmClass SpringUtil = vm.resolveClass("a/backwebview/SpringUtil");
            
            // 创建对象
            DvmObject<?> instance = SpringUtil.newObject(null);
            
            // 调用方法
            String result = instance.callJniMethodObject(
                emulator,
                "getMyInstaData([B)Ljava/lang/String;",
                input
            ).getValue().toString();
            
            log("返回结果: " + result);
            log("返回长度: " + result.length());
            
            // 保存到文件
            saveToFile("getMyInstaData_output.txt", result);
            
        } catch (Exception e) {
            log("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 测试 getWeijuData
     */
    public void testGetWeijuData(byte[] input) {
        log("\n[测试] getWeijuData");
        log("输入长度: " + input.length);
        log("输入数据(Hex): " + bytesToHex(input));
        
        try {
            DvmClass SpringUtil = vm.resolveClass("a/backwebview/SpringUtil");
            DvmObject<?> instance = SpringUtil.newObject(null);
            
            String result = instance.callJniMethodObject(
                emulator,
                "getWeijuData([B)Ljava/lang/String;",
                input
            ).getValue().toString();
            
            log("返回结果: " + result);
            log("返回长度: " + result.length());
            
            saveToFile("getWeijuData_output.txt", result);
            
        } catch (Exception e) {
            log("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Hook关键函数进行分析
     */
    public void setupHooks() {
        if (!ENABLE_HOOK) return;
        
        log("\n[Hook] 开始设置Hook");
        
        IHookZz hookZz = HookZz.getInstance(emulator);
        
        // Hook getMyInstaData native函数
        long getMyInstaDataAddr = module.findSymbolByName("_Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray").getAddress();
        log("getMyInstaData 地址: 0x" + Long.toHexString(getMyInstaDataAddr));
        
        hookZz.wrap(getMyInstaDataAddr, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                log("\n>>> [Hook] getMyInstaData 调用");
                log("    X0(JNIEnv*): 0x" + Long.toHexString(ctx.getXLong(0)));
                log("    X1(jobject): 0x" + Long.toHexString(ctx.getXLong(1)));
                log("    X2(jbyteArray): 0x" + Long.toHexString(ctx.getXLong(2)));
                
                // 读取字节数组
                try {
                    long jbyteArrayPtr = ctx.getXLong(2);
                    if (jbyteArrayPtr != 0) {
                        // TODO: 解析jbyteArray
                        log("    字节数组指针: 0x" + Long.toHexString(jbyteArrayPtr));
                    }
                } catch (Exception e) {
                    log("    读取参数失败: " + e.getMessage());
                }
            }
            
            @Override
            public void postCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                log("<<< [Hook] getMyInstaData 返回");
                log("    返回值(jstring): 0x" + Long.toHexString(ctx.getXLong(0)));
            }
        });
        
        // Hook processData函数
        long processDataAddr = module.findSymbolByName("_Z11processDataP7_JNIEnvP8_jobjectP11_jbyteArrayP8_jstring").getAddress();
        log("processData 地址: 0x" + Long.toHexString(processDataAddr));
        
        hookZz.wrap(processDataAddr, new WrapCallback<HookZzArm64RegisterContext>() {
            @Override
            public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                log("\n>>> [Hook] processData 调用");
                log("    X0(JNIEnv*): 0x" + Long.toHexString(ctx.getXLong(0)));
                log("    X1(jobject): 0x" + Long.toHexString(ctx.getXLong(1)));
                log("    X2(jbyteArray): 0x" + Long.toHexString(ctx.getXLong(2)));
                log("    X3(jstring): 0x" + Long.toHexString(ctx.getXLong(3)));
            }
            
            @Override
            public void postCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                log("<<< [Hook] processData 返回");
            }
        });
        
        // Hook 一些关键的加密函数
        hookCryptoFunctions(hookZz);
        
        log("[Hook] Hook设置完成\n");
    }
    
    /**
     * Hook加密相关函数
     */
    private void hookCryptoFunctions(IHookZz hookZz) {
        // Hook可能的AES函数
        String[] cryptoSymbols = {
            "AES_set_encrypt_key",
            "AES_encrypt",
            "AES_decrypt",
            "MD5_Init",
            "MD5_Update",
            "MD5_Final",
            "SHA256_Init",
            "SHA256_Update",
            "SHA256_Final",
            "EVP_EncryptInit",
            "EVP_DecryptInit"
        };
        
        for (String symbol : cryptoSymbols) {
            try {
                long addr = module.findSymbolByName(symbol).getAddress();
                log("找到加密函数: " + symbol + " at 0x" + Long.toHexString(addr));
                
                hookZz.wrap(addr, new WrapCallback<HookZzArm64RegisterContext>() {
                    @Override
                    public void preCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                        log("[Crypto] " + symbol + " 被调用");
                    }
                    
                    @Override
                    public void postCall(Emulator<?> emulator, HookZzArm64RegisterContext ctx, HookEntryInfo info) {
                    }
                });
            } catch (Exception e) {
                // 符号不存在,忽略
            }
        }
    }
    
    /**
     * Trace执行流程
     */
    public void enableTrace() {
        log("\n[Trace] 启用代码追踪");
        
        // 设置代码追踪范围
        long start = module.base;
        long end = module.base + module.size;
        
        emulator.traceCode(start, end);
        
        // 或者追踪特定函数
        long getMyInstaDataAddr = module.findSymbolByName("_Z14getMyInstaDataP7_JNIEnvP8_jobjectP11_jbyteArray").getAddress();
        emulator.traceCode(getMyInstaDataAddr, getMyInstaDataAddr + 0x1000);
    }
    
    /**
     * 内存dump
     */
    public void dumpMemory(long address, int size, String filename) {
        log("\n[Dump] 导出内存");
        log("地址: 0x" + Long.toHexString(address));
        log("大小: " + size);
        
        byte[] data = emulator.getBackend().mem_read(address, size);
        
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
            log("已保存到: " + filename);
        } catch (IOException e) {
            log("保存失败: " + e.getMessage());
        }
        
        // 也打印十六进制
        log("内存内容(前256字节):");
        log(Inspector.inspectString(data, "Memory Dump"));
    }
    
    /**
     * 分析函数调用图
     */
    public void analyzeCallGraph() {
        log("\n[分析] 生成调用图");
        
        // 可以通过trace记录所有函数调用
        emulator.traceCode();
        
        // 执行测试
        testGetMyInstaData("test".getBytes());
        
        // 分析结果
        log("调用图分析完成");
    }
    
    // ==================== 辅助方法 ====================
    
    private void log(String msg) {
        System.out.println(msg);
    }
    
    private String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, 64); i++) {
            sb.append(String.format("%02X ", bytes[i]));
        }
        if (bytes.length > 64) {
            sb.append("...");
        }
        return sb.toString();
    }
    
    private String tryDecodeUtf8(byte[] bytes) {
        try {
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "[无法解码为UTF-8]";
        }
    }
    
    private void saveToFile(String filename, String content) {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            log("结果已保存到: " + filename);
        } catch (IOException e) {
            log("保存文件失败: " + e.getMessage());
        }
    }
    
    public void destroy() {
        emulator.close();
        log("\n模拟器已关闭");
    }
    
    // ==================== JNI回调实现 ====================
    
    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        log("[JNI] callObjectMethodV: " + signature);
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }
    
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        log("[JNI] callStaticObjectMethodV: " + signature);
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }
    
    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        log("[JNI] callIntMethodV: " + signature);
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }
    
    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        log("[JNI] getObjectField: " + signature);
        
        // 可能需要模拟一些字段
        switch (signature) {
            case "android/content/Context->packageName:Ljava/lang/String;":
                return new StringObject(vm, "com.test.app");
        }
        
        return super.getObjectField(vm, dvmObject, signature);
    }
    
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        log("[JNI] getStaticObjectField: " + signature);
        return super.getStaticObjectField(vm, dvmClass, signature);
    }
    
    // ==================== 主函数 ====================
    
    public static void main(String[] args) {
        SpringInsAnalyzer analyzer = new SpringInsAnalyzer();
        
        try {
            // 设置Hook
            analyzer.setupHooks();
            
            // 测试用例1: 简单字符串
            analyzer.testGetMyInstaData("Hello World".getBytes());
            
            // 测试用例2: JSON数据
            String jsonData = "{\"user\":\"test\",\"timestamp\":1234567890}";
            analyzer.testGetMyInstaData(jsonData.getBytes());
            
            // 测试用例3: Base64数据
            String base64Data = "SGVsbG8gV29ybGQ=";
            analyzer.testGetMyInstaData(base64Data.getBytes());
            
            // 测试用例4: 二进制数据
            byte[] binaryData = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
            analyzer.testGetMyInstaData(binaryData);
            
            // 测试getWeijuData
            analyzer.testGetWeijuData("Test Weiju".getBytes());
            
            // Dump关键内存区域
            long moduleBase = analyzer.module.base;
            analyzer.dumpMemory(moduleBase, 0x1000, "module_header.bin");
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            analyzer.destroy();
        }
    }
}
