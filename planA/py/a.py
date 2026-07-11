import struct
from unicorn import *
from unicorn.arm64_const import *

# ================= 配置区域 =================
LIB_PATH = "./libsigner.so"
# 根据你的 Trace 填写的基址偏移
ADDR_N_ON_RESUME = 0x0a894c
ADDR_N_SIGN      = 0x0a95ac
ADDR_CALLBACK    = 0x0b0d08  # 定时器回调地址
ADDR_HASH_FUNC   = 0x08b510  # 核心哈希函数地址

# 内存布局
BASE_ADDRESS = 0x400000
STACK_ADDRESS = 0x800000
STACK_SIZE = 1024 * 1024

# ================= 模拟器辅助类 =================
class AdjustEmulator:
    def __init__(self, lib_path):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.lib_content = open(lib_path, 'rb').read()

        # 1. 映射代码段
        # 对齐到 4KB
        code_len = (len(self.lib_content) + 0x1000) & ~0xFFF
        self.uc.mem_map(BASE_ADDRESS, code_len)
        self.uc.mem_write(BASE_ADDRESS, self.lib_content)

        # 2. 映射栈
        self.uc.mem_map(STACK_ADDRESS, STACK_SIZE)
        self.uc.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + STACK_SIZE - 0x100)

        # 3. 映射数据段/BSS (简单起见，映射一大块可读写内存作为堆和全局变量)
        self.heap_base = 0x2000000
        self.uc.mem_map(self.heap_base, 1024 * 1024 * 4)

        # 4. Hook 系统调用 (PLT Hook)
        # 注意：你需要解析 ELF Header 找到 PLT 表的准确地址来 Hook
        # 这里为了演示，我们使用指令 Hook 拦截 BL 调用
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)

        # 状态追踪
        self.timer_callback_addr = 0

    def hook_code(self, uc, address, size, user_data):
        # 这里需要根据你的实际 PLT 地址进行 Hook
        # 既然你有详细地址，我们可以直接 Hook 关键函数的入口

        # 模拟 clock_gettime (返回固定时间，保证签名可复现)
        # 假设 clock_gettime@plt 跳转到了这里，或者我们在代码中拦截了它
        pass

    def start(self):
        print("[*] Emulator started")

        # =================================================
        # 步骤 1: 模拟 nOnResume (初始化环境)
        # =================================================
        print(f"[*] Calling nOnResume at {hex(BASE_ADDRESS + ADDR_N_ON_RESUME)}")

        # Hook timer_create 以捕获回调地址
        # 我们需要在 timer_create 被调用时，记录下 X2 (evp) 里的回调函数地址
        # 但根据你的分析，回调地址是硬编码的 0x0b0d08，所以我们可以直接用

        # 执行 nOnResume
        # 参数: JNIEnv* (X0), jobject (X1) -> 随便给个指针
        self.uc.reg_write(UC_ARM64_REG_X0, 0x0)
        self.uc.reg_write(UC_ARM64_REG_X1, 0x0)
        self.uc.reg_write(UC_ARM64_REG_LR, 0x0) # 返回地址设为0，触发异常结束

        try:
            # 运行直到函数返回 (LR=0 导致异常停止)
            self.uc.emu_start(BASE_ADDRESS + ADDR_N_ON_RESUME, 0)
        except UcError as e:
            if e.errno != UC_ERR_FETCH_UNMAPPED: # 忽略返回地址未映射的错误
                raise e

        print("[+] nOnResume finished. Environment initialized.")

        # =================================================
        # 步骤 2: 手动触发监控回调 (关键！)
        # =================================================
        # 因为 Unicorn 不支持多线程定时器，我们需要手动调用回调函数
        # 来填充全局变量 (integrity mask)
        print(f"[*] Manually triggering timer callback at {hex(BASE_ADDRESS + ADDR_CALLBACK)}")

        # 准备参数 (sigval)
        self.uc.reg_write(UC_ARM64_REG_X0, 0)
        self.uc.reg_write(UC_ARM64_REG_LR, 0)

        # Hook open/read 以欺骗环境检测
        # 当代码尝试读取 /proc/self/maps 时，我们需要返回干净的数据
        # (此处代码省略，需要在 hook_code 中实现对 SVC 0x38(openat) 的拦截)

        try:
            self.uc.emu_start(BASE_ADDRESS + ADDR_CALLBACK, 0)
        except UcError:
            pass

        print("[+] Environment check passed (Simulated).")

        # =================================================
        # 步骤 3: 模拟 nSign (生成签名)
        # =================================================
        print(f"[*] Calling nSign at {hex(BASE_ADDRESS + ADDR_N_SIGN)}")

        # 准备参数:
        # X0: JNIEnv* (需要伪造一个结构体，如果 nSign 调用了 JNI 函数)
        # X1: jobject
        # X2: context
        # X3: params (jstring) -> 这里需要传入一个指向字符串的指针

        # 伪造 params 字符串
        params_str = b"key=value&foo=bar"
        params_addr = self.heap_base + 0x100
        self.uc.mem_write(params_addr, params_str)

        # 设置寄存器
        self.uc.reg_write(UC_ARM64_REG_X0, self.heap_base) # JNIEnv
        self.uc.reg_write(UC_ARM64_REG_X1, 0)
        self.uc.reg_write(UC_ARM64_REG_X2, 0)
        self.uc.reg_write(UC_ARM64_REG_X3, params_addr) # 假设这里直接传了 char* (实际需要模拟 GetStringUTFChars)

        # Hook 核心哈希函数来查看输入数据 (Debug)
        self.uc.hook_add(UC_HOOK_CODE, self.hook_hash_input,
                        begin=BASE_ADDRESS + ADDR_HASH_FUNC,
                        end=BASE_ADDRESS + ADDR_HASH_FUNC + 4)

        try:
            self.uc.emu_start(BASE_ADDRESS + ADDR_N_SIGN, 0)
        except UcError:
            pass

        # 结果通常在 X0 (如果是 jstring，则是一个指针)
        res_ptr = self.uc.reg_read(UC_ARM64_REG_X0)
        print(f"[+] nSign finished. Result pointer: {hex(res_ptr)}")

    def hook_hash_input(self, uc, address, size, user_data):
        # 当执行到 0x08b510 时，打印参数
        # X0 = Buffer Pointer, X1 = Length
        buf_ptr = uc.reg_read(UC_ARM64_REG_X0)
        buf_len = uc.reg_read(UC_ARM64_REG_X1)

        data = uc.mem_read(buf_ptr, buf_len)
        print(f"\n[!!!] CAPTURED HASH INPUT (Len={buf_len}):")
        print(f"      Hex: {data.hex()}")
        try:
            print(f"      Str: {data.decode('utf-8', errors='ignore')}")
        except:
            pass
        print("------------------------------------------------\n")

# 运行
emu = AdjustEmulator(LIB_PATH)
emu.start()
