import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.memory.Memory;
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

    // ==========================================
    // 关键地址定义 (基于你的逆向分析)
    // ==========================================
    // 注意：如果 SO 版本变化，这些地址必须更新
    private static final long ADDR_TIMER_CALLBACK = 0x0b0d08;

    public AdjustSigner(String soFilePath) throws IOException {
        // 1. 创建模拟器 (ARM64)
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.adjust.sandbox")
                .addBackendFactory(new Unicorn2Factory(true)) // 使用 Unicorn2 引擎
                .build();

        // 2. 模拟内存
        Memory memory = emulator.getMemory();
        // 设置 Android SDK 版本 (Android 6.0 - 23 是比较通用的选择)
        memory.setLibraryResolver(new AndroidResolver(23));

        // 3. 创建 Dalvik 虚拟机
        vm = emulator.createDalvikVM(null);
        vm.setJni(this); // 设置 JNI 交互处理
        vm.setVerbose(true); // 开启日志，方便调试

        // 4. 加载 SO 库
        // 必须先加载 SO，才能 Hook 其中的函数
        DalvikModule dm = vm.loadLibrary(new File(soFilePath), false);
        module = dm.getModule();

        // 执行 JNI_OnLoad (如果有)
        dm.callJNI_OnLoad(emulator);

        // 5. 注册 Java 类
        // 对应 Java 层的类名
        nativeLibHelper = vm.resolveClass("com/adjust/sdk/sig/NativeLibHelper");

        // 6. 设置文件系统拦截 (用于欺骗环境检测)
        emulator.getSyscallHandler().addIOResolver(this);

        // 7. Hook 关键函数
        hookFunctions();
    }

    /**
     * 核心 Hook 逻辑
     * 拦截 timer_create 防止崩溃，并接管控制流
     */
    private void hookFunctions() {
        HookZz hook = HookZz.getInstance(emulator);

        // Hook timer_create
        // 原型: int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid);
        // 策略: 直接返回 0 (成功)，不让系统真的去创建定时器
        hook.replace(module.findSymbolByName("timer_create"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println(">>> [Hook] timer_create intercepted. Returning success(0).");
                // 修改返回值 X0 = 0
                // 注意：Unidbg 的 replace hook 默认会执行原函数，我们需要用 HookStatus.RET 阻止原函数执行
                return HookStatus.RET(emulator, 0);
            }
        });

        // Hook timer_settime
        // 原型: int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value);
        hook.replace(module.findSymbolByName("timer_settime"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emulator, HookContext context, long originFunction) {
                System.out.println(">>> [Hook] timer_settime intercepted. Returning success(0).");
                return HookStatus.RET(emulator, 0);
            }
        });
    }

    /**
     * 步骤 1: 调用 nOnResume
     * 这会初始化全局变量，并尝试启动定时器 (被我们 Hook 了)
     */
    public void doOnResume() {
        System.out.println("\n[1] Calling nOnResume()...");
        nativeLibHelper.callStaticJniMethodObject(emulator, "nOnResume()V");
    }

    /**
     * 步骤 2: 手动触发环境检测回调
     * 对应地址: 0x0b0d08
     * 必须执行这一步，否则全局标志位 (Integrity Flags) 不会被设置，导致签名无效
     */
    public void doManualCheck() {
        System.out.println("\n[2] Manually triggering timer callback at 0x" + Long.toHexString(ADDR_TIMER_CALLBACK));

        // 准备参数
        // 回调函数原型通常是: void callback(union sigval sv);
        // 在 ARM64 中，第一个参数在 X0 寄存器
        List<Object> args = new ArrayList<>();
        args.add(0); // sigval (int/ptr) = 0

        // 直接调用内部函数
        module.callFunction(emulator, ADDR_TIMER_CALLBACK, args.toArray());
        System.out.println(">>> Environment check completed.");
    }

    /**
     * 步骤 3: 调用 nSign 生成签名
     */
    public String doSign(String params) {
        System.out.println("\n[3] Calling nSign() with params: " + params);

        // 构造参数
        // nSign(Context context, String params)
        // 我们需要伪造一个 Context 对象 (虽然 Native 层可能只用它来获取包名等，Unidbg 会处理基本调用)
        DvmObject<?> context = vm.resolveClass("android/content/Context").newObject(null);
        StringObject strParams = new StringObject(vm, params);

        // 调用 JNI 方法
        // 注意：这里的签名 (Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String; 需要根据实际情况确认
        // 如果报错 "Method not found"，请检查 smali 代码确认参数类型
        DvmObject<?> result = nativeLibHelper.callStaticJniMethodObject(emulator,
            "nSign(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
            context, strParams);

        String signature = (String) result.getValue();
        System.out.println("\n[!!!] SIGNATURE GENERATED: " + signature);
        return signature;
    }

    /**
     * 文件系统模拟 (IOResolver)
     * 当 Native 代码读取 /proc 文件时，返回“干净”的数据
     */
    @Override
    public FileResult resolve(Emulator emulator, String path, int oflags) {
        // 1. 欺骗 Maps 检查 (隐藏 Frida/Xposed/Unidbg 特征)
        if (path.equals("/proc/self/maps")) {
            System.out.println(">>> [IO] Redirecting /proc/self/maps");
            String cleanMaps =
                "12c00000-12c40000 r-xp 00000000 00:00 0  /system/lib64/libc.so\n" +
                "7f7e000000-7f7e001000 r-xp 00000000 00:00 0  /data/app/com.example/lib/arm64/libsigner.so\n";
            return FileResult.success(new ByteArrayFileIO(oflags, path, cleanMaps.getBytes()));
        }

        // 2. 欺骗 Status 检查 (隐藏 TracerPid)
        if (path.equals("/proc/self/status")) {
            System.out.println(">>> [IO] Redirecting /proc/self/status");
            String cleanStatus =
                "Name:\tcom.adjust.sandbox\n" +
                "State:\tS (sleeping)\n" +
                "TracerPid:\t0\n" + // 关键：必须是 0
                "Pid:\t1234\n";
            return FileResult.success(new ByteArrayFileIO(oflags, path, cleanStatus.getBytes()));
        }

        return null; // 其他文件交给 Unidbg 默认处理
    }

    public void destroy() {
        try {
            emulator.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // ==========================================
    // 主程序入口
    // ==========================================
    public static void main(String[] args) {
        try {
            // 替换为你的 SO 文件实际路径
            String soPath = "src/main/resources/libsigner.so";

            AdjustSigner signer = new AdjustSigner(soPath);

            // 1. 初始化 (建立全局 Context)
            signer.doOnResume();

            // 2. 关键：手动触发检测 (填充 Integrity Flags)
            // 如果跳过这一步，nSign 可能会返回错误结果或 Crash
            signer.doManualCheck();

            // 3. 签名
            // 模拟业务参数
            String params = "app_token=test_token&event_token=event_123&created_at=1678888888";
            String sig = signer.doSign(params);

            System.out.println("Final Result: " + sig);

            signer.destroy();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
