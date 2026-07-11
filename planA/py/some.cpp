// 假设的全局上下文结构，位于 .bss 段
struct GlobalContext {
    bool is_initialized;
    int integrity_mask; // 0 = Clean, 1 = Root, 2 = Hook, etc.
    void* timer_id;
    char dynamic_secret[32]; // 运行时解密的密钥
};

GlobalContext* g_ctx = nullptr; // 全局指针

// ==========================================
// 1. 异步监控逻辑 (nOnResume)
// ==========================================

// 地址: 0x0b0d08 (被 timer 调用的回调)
void monitor_callback(union sigval sv) {
    // 1. 核心探测：读取文件系统
    // 实际汇编中这里会调用 open/read/fgets
    int current_flags = 0;

    if (check_file_content("/proc/self/maps", "frida")) current_flags |= 1;
    if (check_file_content("/proc/self/status", "TracerPid")) current_flags |= 2;

    // 2. 更新全局状态
    // nSign 计算哈希时会读取这个值。如果这里没跑，mask 就是初始值（可能导致签名错误）
    if (g_ctx) {
        g_ctx->integrity_mask = current_flags;
    }
}

// 地址: 0x0b0a48 (共享实现)
void internal_resume() {
    // 1. 初始化内存 (sub_0x0e38f8)
    if (!g_ctx) {
        g_ctx = (GlobalContext*)malloc(sizeof(GlobalContext));
        memset(g_ctx, 0, sizeof(GlobalContext));
    }

    // 2. 立即执行一次检测 (sub_0x0b0d08)
    // 确保在 timer 触发前，状态已经可用
    sigval sv;
    monitor_callback(sv);

    // 3. 启动定时器 (防 Hook 机制)
    // 这里的关键是 SIGEV_THREAD，它会在新线程执行回调
    struct sigevent sev;
    sev.sigev_notify = SIGEV_THREAD; // 2
    sev.sigev_notify_function = monitor_callback; // 0x0b0d08

    timer_create(CLOCK_REALTIME, &sev, &g_ctx->timer_id);

    struct itimerspec its;
    its.it_value.tv_sec = 1; // 1秒后触发
    its.it_interval.tv_sec = 1; // 每秒触发
    timer_settime(g_ctx->timer_id, 0, &its, NULL);
}

// JNI 入口: 0x0a894c
extern "C" void Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume(JNIEnv* env, jobject thiz) {
    internal_resume();
}

// ==========================================
// 2. 签名计算逻辑 (nSign)
// ==========================================

// 地址: 0x08b510 (核心哈希算法)
// 这通常是一个标准的 Hash 算法 (SHA256/MD5) 或其魔改版
void core_hash_func(const unsigned char* input, size_t len, unsigned char* output) {
    // 这里的汇编指令是对 input 进行位运算和轮函数处理
    // Output 通常是 32 字节 (SHA256) 或 16 字节 (MD5)
    SHA256_Custom(input, len, output);
}

// JNI 入口: 0x0a95ac
extern "C" jstring Java_com_adjust_sdk_sig_NativeLibHelper_nSign(JNIEnv* env, jobject thiz,
                                                                 jobject context, jstring params_str) {
    // 1. 确保监控在运行 (保活机制)
    // 如果攻击者只调 nSign 不调 nOnResume，这里会强制启动监控
    internal_resume();

    // 2. 收集输入数据
    const char* params = env->GetStringUTFChars(params_str, 0);

    // 获取时间戳 (0xaa2b4)
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long timestamp = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    // 获取设备指纹 (sub_0x112730)
    char* uuid = get_internal_id(TYPE_UUID);

    // 3. 拼接缓冲区 (Buffer Construction)
    // 这是逆向最关键的一步：弄清楚拼接顺序
    // 假设顺序是: Secret + Signature + Timestamp + UUID + IntegrityMask
    std::vector<unsigned char> buffer;
    append_string(buffer, g_ctx->dynamic_secret);
    append_string(buffer, params);
    append_long(buffer, timestamp);
    append_string(buffer, uuid);
    append_byte(buffer, g_ctx->integrity_mask); // 关键：混入监控结果

    // 4. 计算哈希 (0xaa23c -> 0x08b510)
    unsigned char hash_result[32];
    core_hash_func(buffer.data(), buffer.size(), hash_result);

    // 5. 格式化为 Hex 字符串
    char hex_output[65];
    bin2hex(hash_result, 32, hex_output);

    return env->NewStringUTF(hex_output);
}
