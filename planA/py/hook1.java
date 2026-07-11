package com.adjust.simulation;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AdjustSigner extends AbstractJni implements IOResolver {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass nativeLibHelper;

    // ================= 地址常量 (基于你的分析) =================
    // 请确保 libsigner.so 的版本与你分析的一致，否则这些偏移量需要更新
    private static final long OFFSET_TIMER_CALLBACK = 0x0b0d08;

    public AdjustSigner(String soFilePath) throws IOException {
        // 1. 创建模拟器实例 (ARM64)
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.adjust.sandbox")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();

        // 2. 模拟内存与系统库
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23)); // Android 6.0 SDK 23

        // 3. 创建 Dalvik 虚拟机
        vm = emulator.createDalvikVM(null); // 不依赖 APK
        vm.setJni(this);
        vm.setVerbose(false); // 设置为 true 可以看到详细 JNI 调用日志

        // 4. 加载 SO 库
        DalvikModule dm = vm.loadLibrary(new File(soFilePath), false);
        module = dm.getModule();

        // 5. 注册 JNI 类
        // Adjust 的 native 方法通常在 com.adjust.sdk.sig.NativeLibHelper
        nativeLibHelper = vm.resolveClass("com/adjust/sdk/sig/NativeLibHelper");
        dm.callJNI_OnLoad(emulator);

        // 6. 设置文件系统拦截 (用于欺骗环境检测)
        emulator.getSyscallHandler().addIOResolver(this);

        // 7. Hook 系统函数 (timer_create)
        hookSystemCalls();
    }

    /**
     * Hook timer_create 和 timer_settime
     * 目的：防止程序因为创建线程失败而崩溃，同时接管控制权
     */
    private void hookSystemCalls() {
        HookZz hook = HookZz.getInstance(emulator);

        // Hook timer_create
        // int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
        hook.replace(module.findSymbolByName("timer_create"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                // 直接返回 0 (成功)
                // 我们不需要真的创建定时器，因为我们会手动触发回调
                System.out.println("[Hook] Intercepted timer_create, returning success.");
                return HookStatus.RET(emulator, originFunction);
            }
        });

        // Hook timer_settime
        hook.replace(module.findSymbolByName("timer_settime"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println("[Hook] Intercepted timer_settime, returning success.");
                return HookStatus.RET(emulator, originFunction);
            }
        });
    }

    /**
     * 步骤 1: 调用 nOnResume
     * 这会初始化内部结构体，但定时器被我们 Hook 了，所以不会自动触发检测
     */
    public void callOnResume() {
        System.out.println("[-] Calling nOnResume...");
        nativeLibHelper.callStaticJniMethodObject(emulator, "nOnResume()V");
    }

    /**
     * 步骤 2: 手动触发环境检测回调 (关键步骤！)
     * 模拟定时器到期，执行 sub_0x0b0d08
     */
    public void triggerEnvironmentCheck() {
        System.out.println("[-] Manually triggering timer callback (0x" + Long.toHexString(OFFSET_TIMER_CALLBACK) + ")...");

        long callbackAddr = module.base + OFFSET_TIMER_CALLBACK;

        // 准备参数：回调函数通常接收一个 sigval 联合体
        // void callback(union sigval sv);
        // ARM64 中参数在 X0
        List<Object> args = new ArrayList<>();
        args.add(0); // sigval (int/ptr) = 0

        // 直接调用函数
        module.callFunction(emulator, OFFSET_TIMER_CALLBACK, args.toArray());

        System.out.println("[+] Environment check finished. Global flags should be set.");
    }

    /**
     * 步骤 3: 调用 nSign 生成签名
     */
    public String callSign(String params) {
        System.out.println("[-] Calling nSign with params: " + params);

        // 构造参数
        // nSign(Context context, String params, ...)
        // 我们需要伪造一个 Context 对象
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        StringObject strParams = new StringObject(vm, params);

        // 注意：根据你的分析，nSign 的签名可能是 (Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;
        // 如果有更多参数（如 nonce, timestamp），需要在这里添加
        DvmObject<?> result = nativeLibHelper.callStaticJniMethodObject(emulator,
            "nSign(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
            context, strParams);

        String signature = (String) result.getValue();
        System.out.println("[*] Signature generated: " + signature);
        return signature;
    }

    /**
     * 文件系统模拟 (IOResolver)
     * 当 Native 代码读取 /proc/self/maps 等文件时，返回“干净”的内容
     */
    @Override
    public FileResult resolve(Emulator emulator, String path, int oflags) {
        if (path.equals("/proc/self/maps")) {
            // 返回一个假的 maps，不包含 frida/xposed 特征
            System.out.println("[IO] Redirecting /proc/self/maps check");
            return FileResult.success(new ByteArrayFileIO(oflags, path,
                "7f7e000000-7f7e001000 r-xp 00000000 00:00 0  /system/lib64/libc.so\n".getBytes()));
        }
        if (path.equals("/proc/self/status")) {
            // 隐藏 TracerPid
            System.out.println("[IO] Redirecting /proc/self/status check");
            return FileResult.success(new ByteArrayFileIO(oflags, path,
                "Name:\tcom.adjust.sandbox\nState:\tS (sleeping)\nTracerPid:\t0\n".getBytes()));
        }
        return null; // 其他文件使用默认处理
    }

    public void destroy() {
        try {
            emulator.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            // 替换为你的 libsigner.so 实际路径
            String soPath = "src/main/resources/libsigner.so";
            AdjustSigner signer = new AdjustSigner(soPath);

            // 1. 初始化
            signer.callOnResume();

            // 2. 关键：手动触发检测逻辑
            // 如果不执行这一步，nSign 可能会因为检测不到环境标志位而返回错误签名
            signer.triggerEnvironmentCheck();

            // 3. 签名
            // 模拟一些典型的 URL 参数
            String params = "app_token=abcdef123456&event_token=xyz789&os_name=android";
            String signature = signer.callSign(params);

            System.out.println("\n=== FINAL RESULT ===");
            System.out.println("Input: " + params);
            System.out.println("Output: " + signature);

            signer.destroy();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
