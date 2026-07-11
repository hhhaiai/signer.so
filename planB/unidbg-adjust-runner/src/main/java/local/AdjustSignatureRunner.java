package local;

import android.content.Context;
import com.adjust.sdk.sig.Signer;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.jni.ProxyDvmObject;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.hook.HookContext;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.HookZz;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.linux.file.RandomFileIO;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class AdjustSignatureRunner extends AbstractJni implements AutoCloseable {
    private static final boolean TRACE = Boolean.getBoolean("adjust.runner.trace") || "1".equals(System.getenv("ADJUST_TRACE"));
    private static final boolean BUFFER_TRACE = Boolean.getBoolean("adjust.runner.bufferTrace")
            || "1".equals(System.getenv("ADJUST_BUFFER_TRACE"));
    private static final String OUTPUT_WRITE_TRACE_ADDRESS = System.getenv("ADJUST_OUTPUT_WRITE_TRACE_ADDRESS");
    private static final String OUTPUT_WRITE_TRACE_SIZE = System.getenv("ADJUST_OUTPUT_WRITE_TRACE_SIZE");
    private static final String PRELOAD_WRITE_TRACE_ADDRESS = System.getenv("ADJUST_PRELOAD_WRITE_TRACE_ADDRESS");
    private static final String PRELOAD_WRITE_TRACE_SIZE = System.getenv("ADJUST_PRELOAD_WRITE_TRACE_SIZE");
    private static final String WATCH_MEMORY_ADDRESS = System.getenv("ADJUST_WATCH_MEMORY_ADDRESS");
    private static final boolean SOURCE_WORD_TRACE = "1".equals(System.getenv("ADJUST_SOURCE_WORD_TRACE"));
    private static final String VECTOR_WRITE_TRACE_ADDRESS = System.getenv("ADJUST_VECTOR_WRITE_TRACE_ADDRESS");
    private static final String VECTOR_STORE_WATCH_ADDRESS = System.getenv("ADJUST_VECTOR_STORE_WATCH_ADDRESS");
    private static final String VECTOR_STORE_WATCH_RAW_RANGE = System.getenv("ADJUST_VECTOR_STORE_WATCH_RAW_RANGE");
    private static final String VECTOR_READ_TRACE_CALLER_RANGE = System.getenv(
            "ADJUST_VECTOR_READ_TRACE_CALLER_RANGE");
    private static final String NATIVE_CONTEXT_WORD_WATCH_OFFSET = System.getenv(
            "ADJUST_NATIVE_CONTEXT_WORD_WATCH_OFFSET");
    private static final boolean NATIVE_ENVIRONMENT_DISPATCHER_TRACE = "1".equals(
            System.getenv("ADJUST_NATIVE_ENVIRONMENT_DISPATCHER_TRACE"));
    private static final String NATIVE_ENVIRONMENT_HELPER_RESULT_OVERRIDE = System.getenv(
            "ADJUST_NATIVE_ENVIRONMENT_HELPER_RESULT_OVERRIDE");
    private static final String VM_NODE_WATCH_ADDRESS = System.getenv("ADJUST_VM_NODE_WATCH_ADDRESS");
    private static final boolean CRYPTO_WORD_TRACE = "1".equals(System.getenv("ADJUST_CRYPTO_WORD_TRACE"));
    private static final boolean JNI_CRYPTO_TRACE = "1".equals(System.getenv("ADJUST_JNI_CRYPTO_TRACE"));
    private static final boolean RESULT_LAYOUT_TRACE = "1".equals(System.getenv("ADJUST_RESULT_LAYOUT_TRACE"));
    private static final boolean ACCESSOR_TRANSITION_TRACE = "1".equals(System.getenv("ADJUST_ACCESSOR_TRANSITION_TRACE"));
    private static final String WATCH_MEMORY_CHECKPOINTS = System.getenv("ADJUST_WATCH_MEMORY_CHECKPOINTS");
    private static final String WATCH_MEMORY_CHECKPOINT_LR = System.getenv("ADJUST_WATCH_MEMORY_CHECKPOINT_LR");
    private static final boolean WATCH_MEMORY_CHECKPOINT_REGISTERS = "1".equals(
            System.getenv("ADJUST_WATCH_MEMORY_CHECKPOINT_REGISTERS"));
    private static final String VM_STACK_TRACE_CALLER_RANGE = System.getenv("ADJUST_VM_STACK_TRACE_CALLER_RANGE");
    private static final String VM_STACK_SNAPSHOT_PC = System.getenv("ADJUST_VM_STACK_SNAPSHOT_PC");
    private static final String VM_STACK_SNAPSHOT_TOP_VALUE = System.getenv("ADJUST_VM_STACK_SNAPSHOT_TOP_VALUE");

    private final Config config;
    private final BionicRandom bionicRandom = new BionicRandom();
    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmObject<?> helper;

    public AdjustSignatureRunner(File projectRoot) {
        this(Config.from(projectRoot));
    }

    public AdjustSignatureRunner(File projectRoot, DeviceProfile profile) {
        this(Config.from(projectRoot, profile));
    }

    private AdjustSignatureRunner(Config config) {
        this.config = config;
        prepareBaseApk(config);
        if (config.nativeConnectRefusedEndpoints.isEmpty() && config.nativeLocalSocketResponses.isEmpty()) {
            emulator = AndroidEmulatorBuilder.for64Bit()
                    .setProcessName(config.packageName)
                    .setRootDir(new File(config.projectRoot, "unidbg-rootfs"))
                    .build();
        } else {
            emulator = new ConfigurableAndroidARM64Emulator(config.packageName,
                    new File(config.projectRoot, "unidbg-rootfs"),
                    config.nativeConnectRefusedEndpoints,
                    config.nativeLocalSocketResponses);
        }
        Memory memory = emulator.getMemory();
        // AndroidResolver supplies Android system libraries to the emulated process. API 23 is enough for libsigner.so.
        memory.setLibraryResolver(new AndroidResolver(23));
        if (!config.systemProperties.isEmpty()) {
            SystemPropertyHook propertyHook = new SystemPropertyHook(emulator);
            propertyHook.setPropertyProvider(name -> {
                String value = config.systemProperties.get(name);
                trace("__system_property_get " + name + "=" + (value == null ? "<null>" : value));
                return value;
            });
            memory.addHookListener(propertyHook);
        }
        emulator.getSyscallHandler().setVerbose(TRACE);
        emulator.getSyscallHandler().addIOResolver((emu, pathname, oflags) -> {
            byte[] nativeFile = config.nativeFiles.get(pathname);
            if (nativeFile != null) {
                return com.github.unidbg.file.FileResult.success(
                        new ByteArrayFileIO(oflags, pathname, nativeFile.clone()));
            }
            if (config.nativeMissingPaths.contains(pathname)) {
                return com.github.unidbg.file.FileResult.failed(2);
            }
            if (config.nativeUrandomBytes != null
                    && ("/dev/urandom".equals(pathname) || "/dev/random".equals(pathname))) {
                byte[] pattern = config.nativeUrandomBytes.clone();
                return com.github.unidbg.file.FileResult.success(new RandomFileIO(emu, pathname) {
                    @Override
                    protected void randBytes(byte[] bytes) {
                        for (int i = 0; i < bytes.length; i++) bytes[i] = pattern[i % pattern.length];
                    }
                });
            }
            // libsigner.so probes /proc/self/fd. In this host-side harness the fd table is not Android-like;
            // returning ENOENT here matches the safe failure path and avoids a null signature.
            if ("/proc/self/fd".equals(pathname) || pathname.startsWith("/proc/self/fd/")) {
                return com.github.unidbg.file.FileResult.failed(2);
            }
            return null;
        });

        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(TRACE);

        // libsigner.so references __android_log_print but does not declare DT_NEEDED for liblog.
        memory.dlopen("liblog.so", true);

        installPreloadWriteTrace();

        File so = new File(config.projectRoot, "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so");
        DalvikModule dm = vm.loadLibrary(so, false);
        Module module = dm.getModule();
        installNativeRuntimeHooks(memory);
        installNativeOutputWriteTrace(module);
        installNativeSourceWordTrace(module);
        installNativeVectorWriteTrace(module);
        installNativeVectorStoreWatch(module);
        installNativeVectorReadTrace(module);
        installNativeContextWordWatch(module);
        installNativeEnvironmentDispatcherTrace(module);
        installResultLayoutTrace(module);
        installNativeWatchCheckpoints(module);
        installNativeCryptoWordTrace(module);
        installNativeAccessorTransitionTrace(module);
        installNativeVmStackTrace(module);
        installNativeVmNodeWatch(module);
        installNativeVmStackSnapshot(module);
        installNativeBufferTrace(module);
        System.out.printf("loaded %s base=0x%x size=0x%x%n", module.name, module.base, module.size);

        DvmClass cls = vm.resolveClass("com/adjust/sdk/sig/NativeLibHelper");
        helper = cls.newObject(null);
    }

    private void installNativeRuntimeHooks(Memory memory) {
        if (config.nativeProcessId == null
                && config.nativeTimeSeconds == null
                && config.nativeGettimeofdaySeconds == null
                && config.nativeClockGettimeSeconds == null) return;

        Module libc = memory.findModule("libc.so");
        if (libc == null) throw new IllegalStateException("libc.so is not loaded");
        HookZz hook = HookZz.getInstance(emulator);

        // Unidbg's bundled API-23 libc does not reproduce modern Bionic's
        // rand()/srand() sequence. Android Bionic delegates these calls to
        // random()/srandom(); matching that sequence is required for an exact
        // device signature when libsigner seeds its nonce generator with time().
        hook.replace(libc.findSymbolByName("srand"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                     long originFunction) {
                long seed = context.getIntArg(0) & 0xffffffffL;
                bionicRandom.seed(seed);
                String dumpDirectory = System.getenv("ADJUST_MEMORY_DUMP_BEFORE_SRAND");
                if (dumpDirectory != null && !dumpDirectory.isEmpty()) {
                    dumpMemory(emu, new File(dumpDirectory));
                }
                trace("srand seed=" + seed);
                traceWatchMemory(emu, "after-srand");
                return HookStatus.LR(emu, 0);
            }
        });
        hook.replace(libc.findSymbolByName("rand"), new ReplaceCallback() {
            @Override
            public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                     long originFunction) {
                int value = bionicRandom.next();
                trace("rand value=" + value);
                traceWatchMemory(emu, "before-rand-return");
                return HookStatus.LR(emu, value);
            }
        });
        for (String name : new String[]{"getuid", "geteuid", "getgid", "getegid"}) {
            if (libc.findSymbolByName(name) == null) continue;
            hook.replace(libc.findSymbolByName(name), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    trace(name + " value=" + config.appUid);
                    return HookStatus.LR(emu, config.appUid);
                }
            });
        }
        if (libc.findSymbolByName("timer_create") != null) {
            hook.replace(libc.findSymbolByName("timer_create"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    UnidbgPointer timerId = context.getPointerArg(2);
                    if (timerId != null) timerId.setLong(0, 1L);
                    return HookStatus.LR(emu, 0);
                }
            });
        }
        if (libc.findSymbolByName("timer_settime") != null) {
            hook.replace(libc.findSymbolByName("timer_settime"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    return HookStatus.LR(emu, 0);
                }
            });
        }

        if (config.nativeProcessId != null) {
            hook.replace(libc.findSymbolByName("getpid"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    return HookStatus.LR(emu, config.nativeProcessId);
                }
            });
        }
        if (config.nativeTimeSeconds != null) {
            hook.replace(libc.findSymbolByName("time"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    UnidbgPointer out = context.getPointerArg(0);
                    if (out != null) out.setLong(0, config.nativeTimeSeconds);
                    return HookStatus.LR(emu, config.nativeTimeSeconds);
                }
            });
        }
        if (config.nativeGettimeofdaySeconds != null) {
            hook.replace(libc.findSymbolByName("gettimeofday"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    UnidbgPointer out = context.getPointerArg(0);
                    if (out != null) {
                        out.setLong(0, config.nativeGettimeofdaySeconds);
                        out.setLong(8, config.nativeGettimeofdayMicroseconds);
                    }
                    return HookStatus.LR(emu, 0);
                }
            });
        }
        if (config.nativeClockGettimeSeconds != null) {
            hook.replace(libc.findSymbolByName("clock_gettime"), new ReplaceCallback() {
                @Override
                public HookStatus onCall(com.github.unidbg.Emulator<?> emu, HookContext context,
                                         long originFunction) {
                    UnidbgPointer out = context.getPointerArg(1);
                    if (out != null) {
                        out.setLong(0, config.nativeClockGettimeSeconds);
                        out.setLong(8, config.nativeClockGettimeNanoseconds);
                    }
                    return HookStatus.LR(emu, 0);
                }
            });
        }
    }

    private void installNativeOutputWriteTrace(Module module) {
        if (OUTPUT_WRITE_TRACE_ADDRESS == null || OUTPUT_WRITE_TRACE_ADDRESS.isEmpty()) return;
        long start = Long.decode(OUTPUT_WRITE_TRACE_ADDRESS);
        long size = OUTPUT_WRITE_TRACE_SIZE == null || OUTPUT_WRITE_TRACE_SIZE.isEmpty()
                ? 176L : Long.decode(OUTPUT_WRITE_TRACE_SIZE);
        emulator.traceWrite(start, start + size, (emu, address, writeSize, value) -> {
            Arm64RegisterContext context = emu.getContext();
            System.err.printf("[qbdi-host] output-write pc=%s lr=%s address=0x%x size=%d value=0x%x%n",
                    context.getPCPointer(), context.getLRPointer(), address, writeSize, value);
            // This is the final ciphertext word copied by 0x10ee98. Filter on the
            // native caller as the same heap address is also reused by libc and
            // unrelated signer vectors during a signing call.
            if (context.getPCPointer().peer == module.base + 0x138400
                    && context.getLR() == module.base + 0x10ee9c) {
                UnidbgPointer slot = context.getXPointer(26);
                System.err.printf("[qbdi-host] final-word-context x0=%s x1=%s x19=%s x20=%s "
                                + "x21=%s x22=%s x23=%s x24=%s x25=%s x26=%s x27=%s x28=%s%n",
                        context.getXPointer(0), context.getXPointer(1), context.getXPointer(19),
                        context.getXPointer(20), context.getXPointer(21), context.getXPointer(22),
                        context.getXPointer(23), context.getXPointer(24), context.getXPointer(25), slot,
                        context.getXPointer(27), context.getXPointer(28));
                UnidbgPointer source = context.getXPointer(1);
                System.err.printf("[qbdi-host] final-word-source-x1 bytes=%s%n",
                        bytesToHex(source.getByteArray(0, 64)));
            }
            return false;
        });
    }

    private void installPreloadWriteTrace() {
        if (PRELOAD_WRITE_TRACE_ADDRESS == null || PRELOAD_WRITE_TRACE_ADDRESS.isEmpty()) return;
        long start = Long.decode(PRELOAD_WRITE_TRACE_ADDRESS);
        long size = PRELOAD_WRITE_TRACE_SIZE == null || PRELOAD_WRITE_TRACE_SIZE.isEmpty()
                ? 0x1200L : Long.decode(PRELOAD_WRITE_TRACE_SIZE);
        emulator.traceWrite(start, start + size, (emu, address, writeSize, value) -> {
            Arm64RegisterContext context = emu.getContext();
            System.err.printf("[qbdi-host] preload-write pc=%s lr=%s address=0x%x size=%d value=0x%x%n",
                    context.getPCPointer(), context.getLRPointer(), address, writeSize, value);
            return false;
        });
    }

    private void installNativeSourceWordTrace(Module module) {
        if (!SOURCE_WORD_TRACE) return;
        long readerCall = module.base + 0x10ee84;
        long readerReturn = module.base + 0x10ee88;
        emulator.traceCode(readerCall, readerReturn + 4, (emu, address, instruction) -> {
            Arm64RegisterContext context = emu.getContext();
            if (address == readerCall) {
                UnidbgPointer source = context.getXPointer(0);
                int index = context.getIntArg(1);
                System.err.printf("[qbdi-host] source-reader source=%s index=%d%n", source, index);
                if (index != 0) return;
                System.err.printf("[qbdi-host] source-word-struct bytes=%s%n",
                        bytesToHex(source.getByteArray(0, 64)));
                UnidbgPointer data = source.getPointer(8);
                UnidbgPointer offsets = source.getPointer(24);
                int selectedOffset = offsets.getInt(4);
                System.err.printf("[qbdi-host] source-word-data data=%s first64=%s offsets=%s first16=%s%n",
                        data, bytesToHex(data.getByteArray(0, 64)),
                        offsets, bytesToHex(offsets.getByteArray(0, 16)));
                System.err.printf("[qbdi-host] source-word-selected offset=%d rawWord=0x%x%n",
                        selectedOffset, data.getInt(selectedOffset * 4L));
            } else if (address == readerReturn) {
                System.err.printf("[qbdi-host] source-reader-result word=0x%x%n", context.getIntArg(0));
            }
        });
    }

    private void installNativeVectorWriteTrace(Module module) {
        boolean vectorTrace = VECTOR_WRITE_TRACE_ADDRESS != null && !VECTOR_WRITE_TRACE_ADDRESS.isEmpty();
        boolean watchTrace = WATCH_MEMORY_ADDRESS != null && !WATCH_MEMORY_ADDRESS.isEmpty();
        if (!shouldInstallNativeVectorWriteTrace(vectorTrace, watchTrace)) return;
        long vector = vectorTrace ? Long.decode(VECTOR_WRITE_TRACE_ADDRESS) : 0L;
        long writer = module.base + 0x138318;
        int[] lastWatchWord = {Integer.MIN_VALUE};
        long[] previousCaller = {0L};
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != writer) return;
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer destination = context.getXPointer(1);
                if (vectorTrace && destination != null && destination.peer == vector) {
                    System.err.printf("[qbdi-host] vector-write caller=%s vector=%s index=%d word=0x%x%n",
                            context.getLRPointer(), destination, context.getIntArg(2), context.getIntArg(3));
                }
                Integer watched = readWatchedMemory(emulator);
                if (watched != null && watched != lastWatchWord[0]) {
                    System.err.printf("[qbdi-host] writer-watch-change previous-caller=0x%x caller=%s "
                                    + "destination=%s index=%d value=0x%x watched=0x%x%n",
                            previousCaller[0], context.getLRPointer(), destination,
                            context.getIntArg(2), context.getIntArg(3), watched);
                    lastWatchWord[0] = watched;
                }
                previousCaller[0] = context.getLR();
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, writer, writer + 4, null);
    }

    static boolean shouldInstallNativeVectorWriteTrace(boolean vectorTrace, boolean watchTrace) {
        return vectorTrace || watchTrace;
    }

    private void installNativeVectorStoreWatch(Module module) {
        if (!shouldInstallVectorStoreWatch(VECTOR_STORE_WATCH_ADDRESS, VECTOR_STORE_WATCH_RAW_RANGE)) return;
        Long watchedAddress = parseOptionalHex(VECTOR_STORE_WATCH_ADDRESS);
        long[] watchedRawRange = parseModuleRelativeRange(VECTOR_STORE_WATCH_RAW_RANGE);
        long store = module.base + 0x1384dc;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != store) return;
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer data = context.getXPointer(23);
                if (data == null) return;
                long rawIndex = Integer.toUnsignedLong(context.getXInt(25));
                long slot = data.peer + rawIndex * 4L;
                boolean addressMatch = watchedAddress != null && slot == watchedAddress;
                boolean rangeMatch = watchedRawRange != null
                        && rawIndex >= watchedRawRange[0] && rawIndex <= watchedRawRange[1];
                if (!addressMatch && !rangeMatch) return;
                int previous = data.getInt(rawIndex * 4L);
                System.err.printf("[qbdi-host] vector-store-watch caller=libsigner.so+0x%x vector=%s "
                                + "data=%s raw-index=%d slot=0x%x previous=0x%x value=0x%x%n",
                        context.getLR() - module.base, context.getXPointer(21), data, rawIndex, slot,
                        previous, context.getXInt(8));
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, store, store + 4, null);
    }

    static boolean shouldInstallVectorStoreWatch(String address) {
        return shouldInstallVectorStoreWatch(address, null);
    }

    static boolean shouldInstallVectorStoreWatch(String address, String rawRange) {
        return (address != null && !address.isEmpty()) || (rawRange != null && !rawRange.isEmpty());
    }

    private void installNativeVectorReadTrace(Module module) {
        if (!shouldInstallVectorReadTrace(VECTOR_READ_TRACE_CALLER_RANGE)) return;
        long[] range = parseModuleRelativeRange(VECTOR_READ_TRACE_CALLER_RANGE);
        long reader = module.base + 0x138744;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != reader) return;
                Arm64RegisterContext context = emulator.getContext();
                long callerOffset = context.getLR() - module.base;
                if (callerOffset < range[0] || callerOffset > range[1]) return;
                UnidbgPointer vector = context.getXPointer(0);
                long logicalIndex = Integer.toUnsignedLong(context.getIntArg(1));
                int offsetCount = vector.getInt(0x14);
                UnidbgPointer offsets = vector.getPointer(0x18);
                long baseRawIndex = Integer.toUnsignedLong(offsets.getInt((offsetCount - 1L) * 4L));
                long rawIndex = (baseRawIndex + logicalIndex) & 0xffffffffL;
                long count = Integer.toUnsignedLong(vector.getInt(0));
                UnidbgPointer data = vector.getPointer(8);
                int value = rawIndex < count ? data.getInt(rawIndex * 4L) : 0;
                System.err.printf("[qbdi-host] vector-read-trace caller=libsigner.so+0x%x "
                                + "vector=%s logical-index=%d raw-index=%d value=0x%x%n",
                        callerOffset, vector, logicalIndex, rawIndex, value);
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, reader, reader + 4, null);
    }

    static boolean shouldInstallVectorReadTrace(String callerRange) {
        return parseModuleRelativeRange(callerRange) != null;
    }

    private void installNativeContextWordWatch(Module module) {
        if (!shouldInstallNativeContextWordWatch(NATIVE_CONTEXT_WORD_WATCH_OFFSET)) return;
        long offset = Long.decode(NATIVE_CONTEXT_WORD_WATCH_OFFSET);
        long nativeContextConsumer = module.base + 0x11da64;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != nativeContextConsumer) return;
                Arm64RegisterContext registers = emulator.getContext();
                UnidbgPointer context = registers.getXPointer(2);
                long watchedAddress = context.peer + offset;
                System.err.printf("[qbdi-host] native-context-watch context=%s offset=0x%x "
                                + "address=0x%x value=0x%x%n",
                        context, offset, watchedAddress, context.getInt(offset));
                System.err.printf("[qbdi-host] native-context-codewords stage=consumer bytes=%s%n",
                        bytesToHex(context.getByteArray(0x50, 0x80)));
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, nativeContextConsumer, nativeContextConsumer + 4, null);

        long compareEntry = module.base + 0x134dd8;
        long compareReturn = module.base + 0x134f3c;
        long transformEntry = module.base + 0x13531c;
        long correctionEntry = module.base + 0x13548c;
        UnidbgPointer[] comparedState = new UnidbgPointer[1];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Arm64RegisterContext registers = emulator.getContext();
                if (address == compareReturn) {
                    UnidbgPointer state = comparedState[0];
                    System.err.printf("[qbdi-host] native-context-compare-result index=%d value=0x%x%n",
                            Integer.toUnsignedLong(registers.getIntArg(0)),
                            state == null ? 0 : state.getInt(offset - 0x20L));
                    return;
                }
                if (address != compareEntry && address != transformEntry && address != correctionEntry) return;
                UnidbgPointer state = registers.getXPointer(0);
                if (address == compareEntry) comparedState[0] = state;
                String operation = address == compareEntry ? "compare"
                        : address == transformEntry ? "transform" : "correction";
                System.err.printf("[qbdi-host] native-context-%s caller=libsigner.so+0x%x "
                                + "state=%s w1=0x%x w2=0x%x value=0x%x%n",
                        operation, registers.getLR() - module.base, state,
                        registers.getIntArg(1), registers.getIntArg(2), state.getInt(offset - 0x20L));
                if (address == correctionEntry) {
                    System.err.printf("[qbdi-host] native-context-basis bytes=%s%n",
                            bytesToHex(state.getByteArray(0x10, 0x20)));
                    System.err.printf("[qbdi-host] native-context-codewords stage=before-correction code=0x%x "
                                    + "bytes=%s%n",
                            registers.getIntArg(1), bytesToHex(state.getByteArray(0x30, 0x80)));
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, compareEntry, correctionEntry + 4, null);
    }

    static boolean shouldInstallNativeContextWordWatch(String offset) {
        return offset != null && !offset.isEmpty();
    }

    private void installNativeEnvironmentDispatcherTrace(Module module) {
        boolean traceEnabled = shouldInstallNativeEnvironmentDispatcherTrace(NATIVE_ENVIRONMENT_DISPATCHER_TRACE);
        boolean explicitHelperResultOverride = shouldOverrideNativeEnvironmentHelper(
                NATIVE_ENVIRONMENT_HELPER_RESULT_OVERRIDE);
        Long helperResultOverride = explicitHelperResultOverride
                ? Long.decode(NATIVE_ENVIRONMENT_HELPER_RESULT_OVERRIDE)
                : config.nativeSignerCodeTrampolineDetected ? 1L : null;
        if (!traceEnabled && helperResultOverride == null) return;
        long start = module.base + 0x143e8;
        long end = module.base + 0x14e0c;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long offset = address - module.base;
                if (offset == 0x14d48 && helperResultOverride != null) {
                    backend.reg_write(unicorn.Arm64Const.UC_ARM64_REG_X0, helperResultOverride);
                    if (traceEnabled || explicitHelperResultOverride) {
                        System.err.printf("[qbdi-host] native-env-helper override-result=0x%x%n",
                                helperResultOverride);
                    }
                }
                if (!traceEnabled) return;
                Arm64RegisterContext registers = emulator.getContext();
                if (offset == 0x143e8) {
                    System.err.printf("[qbdi-host] native-env-dispatch stage=entry caller=0x%x context=%s%n",
                            registers.getLR() - module.base, registers.getXPointer(0));
                } else if (offset == 0x144dc) {
                    System.err.printf("[qbdi-host] native-env-dispatch stage=state state=0x%x w0=0x%x%n",
                            registers.getXLong(9), registers.getIntArg(0));
                } else if (isNativeEnvironmentDispatcherCall(offset)) {
                    System.err.printf("[qbdi-host] native-env-dispatch stage=call pc=0x%x target=%s "
                                    + "x0=%s w1=0x%x%n",
                            offset, nativeEnvironmentDispatcherCallTarget(offset),
                            registers.getXPointer(0), registers.getIntArg(1));
                } else if (isNativeEnvironmentDispatcherReturn(offset)) {
                    System.err.printf("[qbdi-host] native-env-dispatch stage=return pc=0x%x w0=0x%x%n",
                            offset, registers.getIntArg(0));
                } else if (offset == 0x14e08) {
                    System.err.println("[qbdi-host] native-env-dispatch stage=exit");
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this default-off probe for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, start, end, null);

        if (!traceEnabled) return;
        long helperStart = module.base + 0x13063c;
        long helperEnd = module.base + 0x1309c8;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long offset = address - module.base;
                if (!isNativeEnvironmentHelperCheckpoint(offset)) return;
                Arm64RegisterContext registers = emulator.getContext();
                String result = "";
                if (offset == 0x1309b8) {
                    result = String.format(" result-slot=0x%x", registers.getStackPointer().getInt(0x14));
                }
                System.err.printf("[qbdi-host] native-env-helper pc=0x%x x0=%s x8=0x%x "
                                + "x19=0x%x x20=0x%x x21=0x%x x24=0x%x x25=0x%x x26=0x%x%s%n",
                        offset, registers.getXPointer(0), registers.getXLong(8),
                        registers.getXLong(19), registers.getXLong(20), registers.getXLong(21),
                        registers.getXLong(24), registers.getXLong(25), registers.getXLong(26), result);
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this default-off probe for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, helperStart, helperEnd, null);
    }

    static boolean shouldInstallNativeEnvironmentDispatcherTrace(boolean enabled) {
        return enabled;
    }

    static boolean shouldOverrideNativeEnvironmentHelper(String value) {
        return value != null && !value.isEmpty();
    }

    private static boolean isNativeEnvironmentDispatcherCall(long offset) {
        switch ((int) offset) {
            case 0x14914:
            case 0x1494c:
            case 0x14978:
            case 0x149a4:
            case 0x14a04:
            case 0x14a24:
            case 0x14a8c:
            case 0x14b14:
            case 0x14b54:
            case 0x14b8c:
            case 0x14be0:
            case 0x14c1c:
            case 0x14cc8:
            case 0x14ce8:
            case 0x14d44:
            case 0x14d9c:
                return true;
            default:
                return false;
        }
    }

    private static boolean isNativeEnvironmentDispatcherReturn(long offset) {
        return isNativeEnvironmentDispatcherCall(offset - 4);
    }

    private static String nativeEnvironmentDispatcherCallTarget(long offset) {
        switch ((int) offset) {
            case 0x14914:
            case 0x14b54:
                return "0x139800";
            case 0x1494c:
            case 0x149a4:
            case 0x14a24:
            case 0x14c1c:
            case 0x14ce8:
                return "correction-0x13548c";
            case 0x14978:
                return "correction-wrapper-code-0x3a@0x14e78";
            case 0x14a04:
                return "correction-wrapper-code-0x36@0x14e44";
            case 0x14a8c:
                return "correction-wrapper-code-0x35@0x14e10";
            case 0x14b14:
                return "0x1309cc";
            case 0x14b8c:
                return "0x1311f0";
            case 0x14be0:
                return "0xdb410";
            case 0x14cc8:
                return "correction-wrapper-code-0x3a@0x14eac";
            case 0x14d44:
                return "0x13063c";
            case 0x14d9c:
                return "0xd78b8";
            default:
                return "unknown";
        }
    }

    private static boolean isNativeEnvironmentHelperCheckpoint(long offset) {
        switch ((int) offset) {
            case 0x13063c:
            case 0x13082c:
            case 0x130844:
            case 0x130850:
            case 0x130854:
            case 0x130860:
            case 0x130870:
            case 0x130884:
            case 0x1308a4:
            case 0x1308a8:
            case 0x130934:
            case 0x13095c:
            case 0x130960:
            case 0x1309b8:
                return true;
            default:
                return false;
        }
    }

    private void installNativeVmNodeWatch(Module module) {
        if (!shouldInstallVmNodeWatch(VM_NODE_WATCH_ADDRESS)) return;
        long watchedAddress = Long.decode(VM_NODE_WATCH_ADDRESS);
        // 0x138b34 is immediately after the protected VM push helper stores w19 into its calloc node.
        long materializedNode = module.base + 0x138b34;
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != materializedNode) return;
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer node = context.getXPointer(0);
                if (node == null || node.peer != watchedAddress) return;
                // x30 is clobbered by the helper's calloc call; the original VM call site is its saved x30.
                UnidbgPointer stackFrame = context.getStackPointer();
                UnidbgPointer caller = stackFrame == null ? null : stackFrame.getPointer(8);
                long callerAddress = caller == null ? context.getLR() : caller.peer;
                System.err.printf("[qbdi-host] vm-node-watch caller=libsigner.so+0x%x node=%s "
                                + "stack=%s value=0x%x%n",
                        callerAddress - module.base, node, context.getXPointer(20), node.getInt(0));
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, materializedNode, materializedNode + 4, null);
    }

    static boolean shouldInstallVmNodeWatch(String address) {
        return address != null && !address.isEmpty();
    }

    private void installNativeVmStackSnapshot(Module module) {
        if (!shouldInstallVmStackSnapshot(VM_STACK_SNAPSHOT_PC)) return;
        long offset = Long.decode(VM_STACK_SNAPSHOT_PC);
        long pc = module.base + offset;
        Long topFilter = parseOptionalHex(VM_STACK_SNAPSHOT_TOP_VALUE);
        boolean[] seen = new boolean[1];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != pc || seen[0]) return;
                Arm64RegisterContext context = emulator.getContext();
                UnidbgPointer stack = context.getXPointer(1);
                if (stack == null) return;
                int count = stack.getInt(0);
                UnidbgPointer node = stack.getPointer(8);
                if (node == null) return;
                if (topFilter != null && Integer.toUnsignedLong(node.getInt(0)) != topFilter) return;
                seen[0] = true;
                StringBuilder nodes = new StringBuilder();
                for (int i = 0; i < count && i < 64 && node != null; i++) {
                    if (i > 0) nodes.append(',');
                    nodes.append(node).append(':').append(String.format("0x%x", node.getInt(0)));
                    node = node.getPointer(8);
                }
                System.err.printf("[qbdi-host] vm-stack-snapshot pc=libsigner.so+0x%x count=%d nodes=%s%n",
                        offset, count, nodes);
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, pc, pc + 4, null);
    }

    static boolean shouldInstallVmStackSnapshot(String pc) {
        return pc != null && !pc.isEmpty();
    }

    private void installNativeWatchCheckpoints(Module module) {
        if (WATCH_MEMORY_ADDRESS == null || WATCH_MEMORY_ADDRESS.isEmpty()) return;
        Long callerOffset = parseOptionalHex(WATCH_MEMORY_CHECKPOINT_LR);
        boolean constrainCaller = callerOffset != null;
        long expectedCaller = constrainCaller ? module.base + callerOffset : 0L;
        for (long offset : parseWatchMemoryCheckpoints(WATCH_MEMORY_CHECKPOINTS)) {
            long checkpoint = module.base + offset;
            boolean[] seen = new boolean[1];
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    if (address != checkpoint || seen[0]) return;
                    Arm64RegisterContext context = emulator.getContext();
                    if (constrainCaller && context.getLR() != expectedCaller) return;
                    seen[0] = true;
                    Integer watched = readWatchedMemory(emulator);
                    System.err.printf("[qbdi-host] watch-memory-checkpoint pc=libsigner.so+0x%x "
                                    + "address=0x%x word=%s lr=%s%n",
                            offset, Long.decode(WATCH_MEMORY_ADDRESS),
                            watched == null ? "<unmapped>" : String.format("0x%x", watched),
                            context.getLRPointer());
                    if (shouldDumpWatchCheckpointRegisters(WATCH_MEMORY_CHECKPOINT_REGISTERS)) {
                        System.err.printf("[qbdi-host] watch-memory-checkpoint-registers x0=%s x1=%s "
                                        + "w2=0x%x w3=0x%x w8=0x%x x21=%s x23=%s w25=0x%x%n",
                                context.getXPointer(0), context.getXPointer(1), context.getIntArg(2),
                                context.getIntArg(3), context.getXInt(8), context.getXPointer(21),
                                context.getXPointer(23), context.getXInt(25));
                    }
                }

                @Override
                public void onAttach(UnHook unHook) {
                    // The emulator owns this opt-in hook for its entire short-lived lifecycle.
                }

                @Override
                public void detach() {
                    // Nothing to detach before the emulator closes.
                }
            }, checkpoint, checkpoint + 4, null);
        }
    }

    static List<Long> parseWatchMemoryCheckpoints(String encoded) {
        List<Long> values = new ArrayList<>();
        if (encoded == null || encoded.trim().isEmpty()) return values;
        for (String value : encoded.split(",")) {
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) values.add(Long.decode(trimmed));
        }
        return values;
    }

    static Long parseOptionalHex(String value) {
        return value == null || value.trim().isEmpty() ? null : Long.decode(value.trim());
    }

    static boolean shouldDumpWatchCheckpointRegisters(boolean enabled) {
        return enabled;
    }

    private void installNativeVmStackTrace(Module module) {
        long[] range = parseModuleRelativeRange(VM_STACK_TRACE_CALLER_RANGE);
        if (range == null) return;
        long start = module.base + range[0];
        long end = module.base + range[1];
        installVmTraceHook(module, module.base + 0x138a70, start, end, "push");
        installVmTraceHook(module, module.base + 0x138b74, start, end, "pop");
        installVmTraceHook(module, module.base + 0x138c8c, start, end, "stack-op");
        installVmTraceHook(module, module.base + 0x138e58, start, end, "stack-op-zero");
        installVmTraceHook(module, module.base + 0x138e60, start, end, "stack-op-bound");
        installVmTraceHook(module, module.base + 0x138744, start, end, "vector-read");
    }

    private void installVmTraceHook(Module module, long pc, long callerStart, long callerEnd, String operation) {
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address != pc) return;
                Arm64RegisterContext context = emulator.getContext();
                long caller = context.getLR();
                if (caller < callerStart || caller > callerEnd) return;
                long callerOffset = caller - module.base;
                UnidbgPointer operand = context.getXPointer(1);
                if ("push".equals(operation)) {
                    System.err.printf("[qbdi-host] vm-push caller=0x%x operand=%s count=%d value=0x%x%n",
                            callerOffset, operand, operand.getInt(0), context.getIntArg(2));
                } else if ("pop".equals(operation)) {
                    UnidbgPointer node = operand.getPointer(8);
                    System.err.printf("[qbdi-host] vm-pop caller=0x%x operand=%s count=%d node=%s value=0x%x%n",
                            callerOffset, operand, operand.getInt(0), node, node.getInt(0));
                } else {
                    System.err.printf("[qbdi-host] vm-%s caller=0x%x x0=%s x1=%s w2=0x%x%n",
                            operation, callerOffset, context.getXPointer(0), operand, context.getIntArg(2));
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, pc, pc + 4, null);
    }

    static long[] parseModuleRelativeRange(String value) {
        if (value == null || value.trim().isEmpty()) return null;
        String[] values = value.trim().split(":", -1);
        if (values.length != 2 || values[0].trim().isEmpty() || values[1].trim().isEmpty()) {
            throw new IllegalArgumentException("range must be start:end");
        }
        long start = Long.decode(values[0].trim());
        long end = Long.decode(values[1].trim());
        if (start > end) throw new IllegalArgumentException("range start must not exceed end");
        return new long[]{start, end};
    }

    private void installNativeCryptoWordTrace(Module module) {
        if (!shouldInstallCryptoWordTrace(CRYPTO_WORD_TRACE)) return;
        long getterCall = module.base + 0x10ecb8;
        long getterReturn = module.base + 0x10ecbc;
        boolean[] ownerDumped = new boolean[1];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Arm64RegisterContext context = emulator.getContext();
                if (address == getterCall) {
                    UnidbgPointer owner = context.getXPointer(20);
                    UnidbgPointer operand = context.getXPointer(1);
                    UnidbgPointer node = operand.getPointer(8);
                    System.err.printf("[qbdi-host] crypto-word-input state=%s owner=%s operand=%s count=%d "
                                    + "node=%s word=0x%x next=%s%n",
                            context.getXPointer(0), owner, operand, operand.getInt(0), node,
                            node.getInt(0), node.getPointer(8));
                    if (!ownerDumped[0]) {
                        ownerDumped[0] = true;
                        System.err.printf("[qbdi-host] crypto-word-owner bytes=%s%n",
                                bytesToHex(owner.getByteArray(0, 64)));
                    }
                } else if (address == getterReturn) {
                    System.err.printf("[qbdi-host] crypto-word-result word=0x%x%n", context.getIntArg(0));
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this opt-in hook for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, getterCall, getterReturn + 4, null);
    }

    static boolean shouldInstallCryptoWordTrace(boolean enabled) {
        return enabled;
    }

    static boolean shouldTraceJniCrypto(boolean enabled) {
        return enabled;
    }

    private void installResultLayoutTrace(Module module) {
        if (!shouldInstallResultLayoutTrace(RESULT_LAYOUT_TRACE)) return;
        long start = module.base + 0x11d798;
        long end = module.base + 0x11e984;
        UnidbgPointer[] resultBuffer = new UnidbgPointer[1];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long offset = address - module.base;
                if (!isResultLayoutCheckpoint(offset)) return;
                Arm64RegisterContext registers = emulator.getContext();
                System.err.printf("[qbdi-host] result-layout pc=0x%x x0=%s x1=%s x2=%s "
                                + "x3=%s x4=%s w3=0x%x w4=0x%x fp=%s%n",
                        offset, registers.getXPointer(0), registers.getXPointer(1),
                        registers.getXPointer(2), registers.getXPointer(3), registers.getXPointer(4),
                        registers.getXInt(3), registers.getXInt(4), registers.getFpPointer());
                if (offset == 0x11e08c) {
                    resultBuffer[0] = registers.getXPointer(0);
                }
                if (resultBuffer[0] != null && offset >= 0x11e08c) {
                    byte[] bytes = resultBuffer[0].getByteArray(0, 176);
                    System.err.printf("[qbdi-host] result-layout-state pc=0x%x prefix=%s cipher0=%s tag=%s%n",
                            offset,
                            bytesToHex(java.util.Arrays.copyOfRange(bytes, 0, 16)),
                            bytesToHex(java.util.Arrays.copyOfRange(bytes, 16, 32)),
                            bytesToHex(java.util.Arrays.copyOfRange(bytes, 144, 176)));
                }
                if (offset == 0x11e928) {
                    UnidbgPointer fp = registers.getFpPointer();
                    System.err.printf("[qbdi-host] result-layout components fp-0x20=%s fp-0x28=%s%n",
                            fp.getPointer(-0x20), fp.getPointer(-0x28));
                } else if (offset == 0x11e178) {
                    UnidbgPointer buffer = registers.getXPointer(4);
                    int length = registers.getXInt(3);
                    if (buffer != null && length > 0 && length <= 4096) {
                        System.err.printf("[qbdi-host] result-layout final length=%d bytes=%s%n",
                                length, bytesToHex(buffer.getByteArray(0, length)));
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this default-off probe for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, start, end, null);
    }

    static boolean shouldInstallResultLayoutTrace(boolean enabled) {
        return enabled;
    }

    private static boolean isResultLayoutCheckpoint(long offset) {
        switch ((int) offset) {
            case 0x11d798:
            case 0x11d980:
            case 0x11d984:
            case 0x11da18:
            case 0x11da1c:
            case 0x11e08c:
            case 0x11e0e4:
            case 0x11e178:
            case 0x11e2c4:
            case 0x11e41c:
            case 0x11e600:
            case 0x11e668:
            case 0x11e6c0:
            case 0x11e710:
            case 0x11e76c:
            case 0x11e7f4:
            case 0x11e84c:
            case 0x11e924:
            case 0x11e928:
            case 0x11e980:
            case 0x11e984:
                return true;
            default:
                return false;
        }
    }

    private void installNativeAccessorTransitionTrace(Module module) {
        if (!shouldInstallAccessorTransitionTrace(ACCESSOR_TRANSITION_TRACE, WATCH_MEMORY_ADDRESS)) return;
        long accessorEntry = module.base + 0x138b74;
        long accessorReturn = module.base + 0x138c88;
        Integer[] beforeWord = new Integer[1];
        String[] beforeState = new String[1];
        long[] caller = new long[1];
        boolean[] inAccessor = new boolean[1];
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                Arm64RegisterContext context = emulator.getContext();
                if (address == accessorEntry) {
                    beforeWord[0] = readWatchedMemory(emulator);
                    beforeState[0] = accessorState(context);
                    caller[0] = context.getLR();
                    inAccessor[0] = true;
                } else if (address == accessorReturn && inAccessor[0]) {
                    Integer afterWord = readWatchedMemory(emulator);
                    if (beforeWord[0] != null && afterWord != null && !beforeWord[0].equals(afterWord)) {
                        System.err.printf("[qbdi-host] accessor-watch-transition caller=0x%x address=0x%x "
                                        + "before=0x%x after=0x%x before={%s} after={%s} result=0x%x%n",
                                caller[0] - module.base,
                                Long.decode(WATCH_MEMORY_ADDRESS), beforeWord[0], afterWord,
                                beforeState[0], accessorState(context), context.getIntArg(0));
                    }
                    inAccessor[0] = false;
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
                // The emulator owns this default-off probe for its entire short-lived lifecycle.
            }

            @Override
            public void detach() {
                // Nothing to detach before the emulator closes.
            }
        }, accessorEntry, accessorReturn + 4, null);
    }

    static boolean shouldInstallAccessorTransitionTrace(boolean enabled, String watchAddress) {
        return enabled && watchAddress != null && !watchAddress.isEmpty();
    }

    private static String accessorState(Arm64RegisterContext context) {
        return String.format("x0=%s x1=%s x19=%s x20=%s x21=%s x26=%s lr=%s",
                context.getXPointer(0), context.getXPointer(1), context.getXPointer(19),
                context.getXPointer(20), context.getXPointer(21), context.getXPointer(26),
                context.getLRPointer());
    }

    private void installNativeBufferTrace(Module module) {
        if (!BUFFER_TRACE) return;
        final UnidbgPointer[] plaintext = new UnidbgPointer[1];
        final int[] plaintextLength = new int[1];
        emulator.attach().addBreakPoint(module.base + 0x139e50, (emu, address) -> {
            if (emu.getContext().getLR() == module.base + 0x11d9e0) {
                plaintextLength[0] = emu.getContext().getIntArg(0) * emu.getContext().getIntArg(1);
            }
            return true;
        });
        emulator.attach().addBreakPoint(module.base + 0x11d9e0, (emu, address) -> {
            plaintext[0] = emu.getContext().getPointerArg(0);
            System.err.printf("[qbdi-host] plaintext-allocation pointer=%s length=%d%n",
                    plaintext[0], plaintextLength[0]);
            return true;
        });
        emulator.attach().addBreakPoint(module.base + 0x139de0, (emu, address) -> {
            UnidbgPointer pointer = emu.getContext().getPointerArg(0);
            if (plaintext[0] != null && plaintext[0].equals(pointer)) {
                byte[] bytes = pointer.getByteArray(0, plaintextLength[0]);
                System.err.printf("[qbdi-host] plaintext-before-free bytes=%s%n", bytesToHex(bytes));
            }
            return true;
        });
        emulator.attach().addBreakPoint(module.base + 0x95680, (emu, address) -> {
            int length = emu.getContext().getIntArg(4);
            UnidbgPointer buffer = emu.getContext().getPointerArg(5);
            byte[] bytes = buffer == null || length <= 0
                    ? new byte[0] : buffer.getByteArray(0, Math.min(length, 4096));
            System.err.printf("[qbdi-host] set-byte-array-region caller=libsigner.so+0x%x "
                            + "length=%d pointer=%s bytes=%s%n",
                    emu.getContext().getLR() - module.base, length, buffer, bytesToHex(bytes));
            System.err.printf("[qbdi-host] environment-flags bytes=%s%n",
                    bytesToHex(UnidbgPointer.pointer(emu, module.base + 0x146840).getByteArray(0, 64)));
            String dumpDirectory = System.getenv("ADJUST_MEMORY_DUMP");
            if (dumpDirectory != null && !dumpDirectory.isEmpty()) dumpMemory(emu, new File(dumpDirectory));
            return true;
        });
    }

    private static void dumpMemory(com.github.unidbg.Emulator<?> emu, File directory) {
        try {
            Files.createDirectories(directory.toPath());
            StringBuilder manifest = new StringBuilder();
            for (MemoryMap map : emu.getMemory().getMemoryMap()) {
                if ((map.prot & 1) == 0 || map.size <= 0 || map.size > 16 * 1024 * 1024L) continue;
                byte[] bytes = UnidbgPointer.pointer(emu, map.base).getByteArray(0, (int) map.size);
                String name = String.format("%016x-%08x.bin", map.base, map.size);
                Files.write(new File(directory, name).toPath(), bytes);
                manifest.append(String.format("0x%x 0x%x %d %s%n", map.base, map.size, map.prot, name));
            }
            Files.writeString(new File(directory, "manifest.txt").toPath(), manifest.toString());
        } catch (Exception exception) {
            throw new IllegalStateException("failed to dump emulator memory", exception);
        }
    }

    private static void traceWatchMemory(com.github.unidbg.Emulator<?> emu, String phase) {
        Integer word = readWatchedMemory(emu);
        if (word == null) return;
        Arm64RegisterContext context = emu.getContext();
        System.err.printf("[qbdi-host] watch-memory phase=%s address=0x%x word=0x%x lr=%s%n",
                phase, Long.decode(WATCH_MEMORY_ADDRESS), word, context.getLRPointer());
    }

    private static Integer readWatchedMemory(com.github.unidbg.Emulator<?> emu) {
        if (WATCH_MEMORY_ADDRESS == null || WATCH_MEMORY_ADDRESS.isEmpty()) return null;
        try {
            UnidbgPointer pointer = UnidbgPointer.pointer(emu, Long.decode(WATCH_MEMORY_ADDRESS));
            return pointer.getInt(0);
        } catch (RuntimeException exception) {
            return null;
        }
    }

    public void onResume() {
        helper.callJniMethod(emulator, "nOnResume()V");
    }

    public byte[] signNative(Map<String, String> params, byte[] input) {
        return signNative(params, input, config.androidApi);
    }

    public byte[] signNative(Map<String, String> params, byte[] input, int androidApi) {
        return signNative(new Context(config.packageName), params, input, androidApi);
    }

    public byte[] signNative(Context context, Map<String, String> params, byte[] input, int androidApi) {
        DvmObject<?> dvmContext = newContext(context);
        DvmObject<?> map = ProxyDvmObject.createObject(vm, params);
        ByteArray data = new ByteArray(vm, input);
        ByteArray result = helper.callJniMethodObject(emulator,
                "nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B",
                dvmContext, map, data, androidApi);
        return result == null ? null : result.getValue();
    }

    private DvmObject<?> newContext(Context context) {
        return vm.resolveClass("android/content/Context").newObject(context);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        DvmObject<?> out = handleObjectMethod(vm, dvmObject, signature, reader(vaList));
        if (out != null
                || signature.endsWith("->get(Ljava/lang/Object;)Ljava/lang/Object;")
                || signature.endsWith("->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")
                || signature.endsWith("->remove(Ljava/lang/Object;)Ljava/lang/Object;")) return out;
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        try {
            return handleIntMethod(dvmObject, signature);
        } catch (UnsupportedOperationException ignored) {
            return super.callIntMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        try {
            return handleBooleanMethod(dvmObject, signature, reader(vaList));
        } catch (UnsupportedOperationException ignored) {
            return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if (config.jniFloats.containsKey(signature)) return config.jniFloats.get(signature);
        return super.callFloatMethodV(vm, dvmObject, signature, vaList);
    }

    private static VarArgReader reader(com.github.unidbg.linux.android.dvm.VarArg varArg) {
        return new VarArgReader() {
            @Override public <T extends DvmObject<?>> T getObjectArg(int index) { return varArg.getObjectArg(index); }
            @Override public int getIntArg(int index) { return varArg.getIntArg(index); }
        };
    }

    private static VarArgReader reader(VaList vaList) {
        return new VarArgReader() {
            @Override public <T extends DvmObject<?>> T getObjectArg(int index) { return vaList.getObjectArg(index); }
            @Override public int getIntArg(int index) { return vaList.getIntArg(index); }
        };
    }

    private DvmObject<?> handleObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArgReader args) {
        Object value = dvmObject == null ? null : dvmObject.getValue();
        trace("JNI object " + signature + " this=" + value);
        String className = dvmObject == null ? "" : dvmObject.getObjectType().getClassName();
        DvmObject<?> configured = configuredObject(vm, signature);
        if (configured != null) return configured;
        if (signature.endsWith("->getPackageName()Ljava/lang/String;")) {
            return new StringObject(vm, config.packageName);
        }
        if (signature.endsWith("->getContentResolver()Landroid/content/ContentResolver;") && className.equals("android/content/Context")) {
            return vm.resolveClass("android/content/ContentResolver").newObject("content-resolver");
        }
        if (signature.endsWith("->getPackageManager()Landroid/content/pm/PackageManager;") && className.equals("android/content/Context")) {
            return vm.resolveClass("android/content/pm/PackageManager").newObject("package-manager");
        }
        if (signature.endsWith("->getApplicationInfo()Landroid/content/pm/ApplicationInfo;") && className.equals("android/content/Context")) {
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(config.packageName);
        }
        if (signature.endsWith("->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;") && className.equals("android/content/pm/PackageManager")) {
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(config.packageName);
        }
        if (signature.endsWith("->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;") && className.equals("android/content/pm/PackageManager")) {
            return vm.resolveClass("android/content/pm/PackageInfo").newObject(config.packageName);
        }
        if (className.equals("android/content/pm/SigningInfo")) {
            if (signature.endsWith("->getApkContentsSigners()[Landroid/content/pm/Signature;") || signature.endsWith("->getSigningCertificateHistory()[Landroid/content/pm/Signature;")) {
                DvmObject<?> sig = vm.resolveClass("android/content/pm/Signature").newObject(config.certBytes.clone());
                return new ArrayObject(sig);
            }
        }
        if (className.equals("java/security/KeyStore")) {
            if (signature.endsWith("->getKey(Ljava/lang/String;[C)Ljava/security/Key;")) {
                return ProxyDvmObject.createObject(vm, new SecretKeySpec(config.keyBytes, "HmacSHA256"));
            }
            if (signature.endsWith("->getEntry(Ljava/lang/String;Ljava/security/KeyStore$ProtectionParameter;)Ljava/security/KeyStore$Entry;")) {
                return vm.resolveClass("java/security/KeyStore$Entry").newObject("key-entry");
            }
        }
        if (signature.endsWith("->getSystemService(Ljava/lang/String;)Ljava/lang/Object;")) {
            String service = String.valueOf(args.getObjectArg(0).getValue());
            String serviceClass = config.serviceClasses.getOrDefault(service, "java/lang/Object");
            return vm.resolveClass(serviceClass).newObject("service:" + service);
        }
        if (signature.endsWith("->getDefaultSensor(I)Landroid/hardware/Sensor;")) {
            int type = args.getIntArg(0);
            DeviceProfile.Sensor selected = config.sensors.get(0);
            for (DeviceProfile.Sensor sensor : config.sensors) {
                if (sensor.getType() == type) {
                    selected = sensor;
                    break;
                }
            }
            return vm.resolveClass("android/hardware/Sensor").newObject(selected);
        }
        if (signature.endsWith("->getSensorList(I)Ljava/util/List;")) {
            int type = args.getIntArg(0);
            List<DvmObject<?>> sensors = new ArrayList<>();
            for (DeviceProfile.Sensor sensor : config.sensors) {
                if (type == -1 || sensor.getType() == type) {
                    sensors.add(vm.resolveClass("android/hardware/Sensor").newObject(sensor));
                }
            }
            return ProxyDvmObject.createObject(vm, sensors);
        }
        if (signature.endsWith("->getDisplayMetrics()Landroid/util/DisplayMetrics;") && className.equals("android/content/res/Resources")) {
            return vm.resolveClass("android/util/DisplayMetrics").newObject("display-metrics");
        }
        if (signature.endsWith("->getName()Ljava/lang/String;") && className.equals("java/lang/Thread")) {
            return new StringObject(vm, "main");
        }
        if (signature.endsWith("->getStackTrace()[Ljava/lang/StackTraceElement;") && className.equals("java/lang/Thread")) {
            DvmObject<?> e1 = vm.resolveClass("java/lang/StackTraceElement").newObject("com.adjust.sdk.sig.NativeLibHelper.nSign");
            DvmObject<?> e2 = vm.resolveClass("java/lang/StackTraceElement").newObject("com.adjust.sdk.sig.Signer.sign");
            return new ArrayObject(e1, e2);
        }
        if (signature.endsWith("->getName()Ljava/lang/String;") && className.equals("android/hardware/Sensor")) {
            return new StringObject(vm, sensorValue(value).getName());
        }
        if (signature.endsWith("->getVendor()Ljava/lang/String;") && className.equals("android/hardware/Sensor")) {
            return new StringObject(vm, sensorValue(value).getVendor());
        }
        if (className.equals("java/util/Locale")) {
            java.util.Locale locale = (java.util.Locale) value;
            if (signature.endsWith("->getLanguage()Ljava/lang/String;")) return new StringObject(vm, locale.getLanguage());
            if (signature.endsWith("->getCountry()Ljava/lang/String;")) return new StringObject(vm, locale.getCountry());
        }
        if (className.equals("java/util/TimeZone") && signature.endsWith("->getID()Ljava/lang/String;")) {
            return new StringObject(vm, ((java.util.TimeZone) value).getID());
        }
        if (signature.endsWith("->toString()Ljava/lang/String;")) {
            return new StringObject(vm, String.valueOf(value));
        }
        if (className.equals("java/lang/StackTraceElement")) {
            String frame = String.valueOf(value);
            if (signature.endsWith("->getClassName()Ljava/lang/String;")) return new StringObject(vm, frame.substring(0, frame.lastIndexOf('.')));
            if (signature.endsWith("->getMethodName()Ljava/lang/String;")) return new StringObject(vm, frame.substring(frame.lastIndexOf('.') + 1));
            if (signature.endsWith("->getFileName()Ljava/lang/String;")) return new StringObject(vm, "SourceFile");
        }
        if (signature.endsWith("->get(Ljava/lang/Object;)Ljava/lang/Object;")) {
            Object keyObj = args.getObjectArg(0).getValue();
            Object got = ((Map<?, ?>) value).get(String.valueOf(keyObj));
            return got == null ? null : ProxyDvmObject.createObject(vm, got);
        }
        if (signature.endsWith("->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")) {
            Object keyObj = args.getObjectArg(0).getValue();
            Object valObj = args.getObjectArg(1).getValue();
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) value;
            Object old = map.put(String.valueOf(keyObj), valObj == null ? null : String.valueOf(valObj));
            return old == null ? null : ProxyDvmObject.createObject(vm, old);
        }
        if (signature.endsWith("->remove(Ljava/lang/Object;)Ljava/lang/Object;")) {
            Object keyObj = args.getObjectArg(0).getValue();
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) value;
            Object old = map.remove(String.valueOf(keyObj));
            return old == null ? null : ProxyDvmObject.createObject(vm, old);
        }
        if (signature.endsWith("->get(I)Ljava/lang/Object;")) {
            int index = args.getIntArg(0);
            Object got = ((List<?>) value).get(index);
            return got instanceof DvmObject ? (DvmObject<?>) got : ProxyDvmObject.createObject(vm, got);
        }
        if (signature.endsWith("->toByteArray()[B") && className.equals("android/content/pm/Signature")) {
            return new ByteArray(vm, config.certBytes.clone());
        }
        if (signature.endsWith("->toCharsString()Ljava/lang/String;") && className.equals("android/content/pm/Signature")) {
            return new StringObject(vm, bytesToHex(config.certBytes));
        }
        if (signature.endsWith("->digest([B)[B") && value instanceof MessageDigest) {
            byte[] in = ((ByteArray) args.getObjectArg(0)).getValue();
            MessageDigest digest = (MessageDigest) value;
            byte[] out = digest.digest(in);
            traceJniCrypto("digest algorithm=" + digest.getAlgorithm()
                    + " input=" + bytesToHex(in) + " output=" + bytesToHex(out));
            return new ByteArray(vm, out);
        }
        if (signature.endsWith("->digest()[B") && value instanceof MessageDigest) {
            MessageDigest digest = (MessageDigest) value;
            byte[] out = digest.digest();
            traceJniCrypto("digest algorithm=" + digest.getAlgorithm()
                    + " input=<updated> output=" + bytesToHex(out));
            return new ByteArray(vm, out);
        }
        if (signature.endsWith("->getBytes()[B") && value instanceof String) {
            return new ByteArray(vm, ((String) value).getBytes(StandardCharsets.UTF_8));
        }
        if (signature.endsWith("->getBytes(Ljava/nio/charset/Charset;)[B") && value instanceof String) {
            return new ByteArray(vm, ((String) value).getBytes(StandardCharsets.UTF_8));
        }
        if (signature.endsWith("->doFinal()[B") && value instanceof Mac) {
            Mac mac = (Mac) value;
            byte[] out = mac.doFinal();
            traceJniCrypto("mac-final algorithm=" + mac.getAlgorithm()
                    + " input=<updated> output=" + bytesToHex(out));
            return new ByteArray(vm, out);
        }
        if (signature.endsWith("->doFinal([B)[B") && value instanceof Mac) {
            Mac mac = (Mac) value;
            byte[] in = ((ByteArray) args.getObjectArg(0)).getValue();
            byte[] out = mac.doFinal(in);
            traceJniCrypto("mac-final algorithm=" + mac.getAlgorithm()
                    + " input=" + bytesToHex(in) + " output=" + bytesToHex(out));
            return new ByteArray(vm, out);
        }
        return null;
    }

    private int handleIntMethod(DvmObject<?> dvmObject, String signature) {
        Object value = dvmObject == null ? null : dvmObject.getValue();
        trace("JNI int " + signature + " this=" + value);
        String className = dvmObject == null ? "" : dvmObject.getObjectType().getClassName();
        if (config.jniInts.containsKey(signature)) return config.jniInts.get(signature);
        if (signature.endsWith("->size()I")) {
            if (value instanceof Map) return ((Map<?, ?>) value).size();
            if (value instanceof List) return ((List<?>) value).size();
        }
        if (signature.endsWith("->length()I")) {
            return String.valueOf(value).length();
        }
        if (signature.endsWith("->hashCode()I")) {
            return value == null ? 0 : value.hashCode();
        }
        if (signature.endsWith("->getType()I") && className.equals("android/hardware/Sensor")) {
            return sensorValue(value).getType();
        }
        if (signature.endsWith("->getVersion()I") && className.equals("android/hardware/Sensor")) {
            return sensorValue(value).getVersion();
        }
        if (signature.endsWith("->getLineNumber()I") && className.equals("java/lang/StackTraceElement")) {
            return 1;
        }
        throw new UnsupportedOperationException(signature);
    }

    private boolean handleBooleanMethod(DvmObject<?> dvmObject, String signature, VarArgReader args) {
        Object value = dvmObject == null ? null : dvmObject.getValue();
        trace("JNI boolean " + signature + " this=" + value);
        String className = dvmObject == null ? "" : dvmObject.getObjectType().getClassName();
        if (config.jniBooleans.containsKey(signature)) return config.jniBooleans.get(signature);
        if (signature.endsWith("->containsKey(Ljava/lang/Object;)Z")) {
            Object keyObj = args.getObjectArg(0).getValue();
            return ((Map<?, ?>) value).containsKey(String.valueOf(keyObj));
        }
        if (signature.endsWith("->isEmpty()Z")) {
            return ((Map<?, ?>) value).isEmpty();
        }
        if (className.equals("android/content/pm/SigningInfo") && signature.endsWith("->hasMultipleSigners()Z")) {
            return false;
        }
        if (className.equals("java/security/KeyStore") && signature.endsWith("->containsAlias(Ljava/lang/String;)Z")) {
            return true;
        }
        throw new UnsupportedOperationException(signature);
    }

    private DvmObject<?> configuredObject(BaseVM vm, String signature) {
        if (config.jniStrings.containsKey(signature)) {
            return new StringObject(vm, config.jniStrings.get(signature));
        }
        if (config.jniBytes.containsKey(signature)) {
            return new ByteArray(vm, config.jniBytes.get(signature).clone());
        }
        return null;
    }

    private DeviceProfile.Sensor sensorValue(Object value) {
        return value instanceof DeviceProfile.Sensor
                ? (DeviceProfile.Sensor) value
                : config.sensors.get(0);
    }

    private interface VarArgReader {
        <T extends DvmObject<?>> T getObjectArg(int index);
        int getIntArg(int index);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        trace("JNI static object " + signature);
        DvmObject<?> configured = handleConfiguredStaticObject(vm, signature, reader(varArg));
        if (configured != null) return configured;
        if ("java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;".equals(signature)) {
            try {
                String algorithm = String.valueOf(varArg.getObjectArg(0).getValue());
                return ProxyDvmObject.createObject(vm, MessageDigest.getInstance(algorithm));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        if ("android/content/res/Resources->getSystem()Landroid/content/res/Resources;".equals(signature)) {
            return vm.resolveClass("android/content/res/Resources").newObject("system-resources");
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject("main-thread");
        }
        if ("java/security/KeyStore->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;".equals(signature)) {
            return vm.resolveClass("java/security/KeyStore").newObject("android-keystore");
        }
        if ("javax/crypto/Mac->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;".equals(signature)) {
            try {
                String algorithm = String.valueOf(varArg.getObjectArg(0).getValue());
                return ProxyDvmObject.createObject(vm, Mac.getInstance(algorithm));
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        trace("JNI static objectV " + signature);
        DvmObject<?> configured = handleConfiguredStaticObject(vm, signature, reader(vaList));
        if (configured != null) return configured;
        if ("java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;".equals(signature)) {
            try {
                String algorithm = String.valueOf(vaList.getObjectArg(0).getValue());
                return ProxyDvmObject.createObject(vm, MessageDigest.getInstance(algorithm));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        if ("android/content/res/Resources->getSystem()Landroid/content/res/Resources;".equals(signature)) {
            return vm.resolveClass("android/content/res/Resources").newObject("system-resources");
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject("main-thread");
        }
        if ("java/security/KeyStore->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;".equals(signature)) {
            return vm.resolveClass("java/security/KeyStore").newObject("android-keystore");
        }
        if ("javax/crypto/Mac->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;".equals(signature)) {
            try {
                String algorithm = String.valueOf(vaList.getObjectArg(0).getValue());
                return ProxyDvmObject.createObject(vm, Mac.getInstance(algorithm));
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    private DvmObject<?> handleConfiguredStaticObject(BaseVM vm, String signature, VarArgReader args) {
        DvmObject<?> configured = configuredObject(vm, signature);
        if (configured != null) return configured;
        if (signature.startsWith("android/provider/Settings$Secure->getString")) {
            String key = String.valueOf(args.getObjectArg(1).getValue());
            String value = config.secureSettings.get(key);
            return value == null ? null : new StringObject(vm, value);
        }
        if (signature.startsWith("android/provider/Settings$System->getString")) {
            String key = String.valueOf(args.getObjectArg(1).getValue());
            String value = config.systemSettings.get(key);
            return value == null ? null : new StringObject(vm, value);
        }
        if ("java/util/Locale->getDefault()Ljava/util/Locale;".equals(signature) && config.locale != null) {
            return vm.resolveClass("java/util/Locale").newObject(java.util.Locale.forLanguageTag(config.locale));
        }
        if ("java/util/TimeZone->getDefault()Ljava/util/TimeZone;".equals(signature) && config.timeZone != null) {
            return vm.resolveClass("java/util/TimeZone").newObject(java.util.TimeZone.getTimeZone(config.timeZone));
        }
        return null;
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        Object value = dvmObject == null ? null : dvmObject.getValue();
        trace("JNI void " + signature + " this=" + value);
        if (signature.endsWith("->update([B)V") && value instanceof MessageDigest) {
            ((MessageDigest) value).update(((ByteArray) varArg.getObjectArg(0)).getValue());
            return;
        }
        if (signature.endsWith("->reset()V") && value instanceof MessageDigest) {
            ((MessageDigest) value).reset();
            return;
        }
        if (dvmObject != null && dvmObject.getObjectType().getClassName().equals("java/security/KeyStore") && (signature.endsWith("->load(Ljava/security/KeyStore$LoadStoreParameter;)V") || signature.endsWith("->deleteEntry(Ljava/lang/String;)V"))) {
            return;
        }
        if (value instanceof Mac && signature.endsWith("->init(Ljava/security/Key;)V")) {
            try {
                java.security.Key key = (java.security.Key) varArg.getObjectArg(0).getValue();
                ((Mac) value).init(key);
                traceJniCrypto("mac-init algorithm=" + ((Mac) value).getAlgorithm()
                        + " key=" + bytesToHex(key.getEncoded()));
                return;
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
        if (value instanceof Mac && signature.endsWith("->update([B)V")) {
            byte[] in = ((ByteArray) varArg.getObjectArg(0)).getValue();
            ((Mac) value).update(in);
            traceJniCrypto("mac-update algorithm=" + ((Mac) value).getAlgorithm()
                    + " input=" + bytesToHex(in));
            return;
        }
        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        Object value = dvmObject == null ? null : dvmObject.getValue();
        trace("JNI voidV " + signature + " this=" + value);
        if (signature.endsWith("->update([B)V") && value instanceof MessageDigest) {
            ((MessageDigest) value).update(((ByteArray) vaList.getObjectArg(0)).getValue());
            return;
        }
        if (signature.endsWith("->reset()V") && value instanceof MessageDigest) {
            ((MessageDigest) value).reset();
            return;
        }
        if (dvmObject != null && dvmObject.getObjectType().getClassName().equals("java/security/KeyStore") && (signature.endsWith("->load(Ljava/security/KeyStore$LoadStoreParameter;)V") || signature.endsWith("->deleteEntry(Ljava/lang/String;)V"))) {
            return;
        }
        if (value instanceof Mac && signature.endsWith("->init(Ljava/security/Key;)V")) {
            try {
                java.security.Key key = (java.security.Key) vaList.getObjectArg(0).getValue();
                ((Mac) value).init(key);
                traceJniCrypto("mac-init algorithm=" + ((Mac) value).getAlgorithm()
                        + " key=" + bytesToHex(key.getEncoded()));
                return;
            } catch (Exception e) { throw new IllegalStateException(e); }
        }
        if (value instanceof Mac && signature.endsWith("->update([B)V")) {
            byte[] in = ((ByteArray) vaList.getObjectArg(0)).getValue();
            ((Mac) value).update(in);
            traceJniCrypto("mac-update algorithm=" + ((Mac) value).getAlgorithm()
                    + " input=" + bytesToHex(in));
            return;
        }
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        trace("JNI getObjectField " + signature + " this=" + (dvmObject == null ? null : dvmObject.getValue()));
        DvmObject<?> configured = configuredObject(vm, signature);
        if (configured != null) return configured;
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature)) {
            DvmObject<?> sig = vm.resolveClass("android/content/pm/Signature").newObject(config.certBytes.clone());
            return new ArrayObject(sig);
        }
        if ("android/content/pm/PackageInfo->applicationInfo:Landroid/content/pm/ApplicationInfo;".equals(signature)) {
            return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(config.packageName);
        }
        if ("android/content/pm/PackageInfo->signingInfo:Landroid/content/pm/SigningInfo;".equals(signature)) {
            return vm.resolveClass("android/content/pm/SigningInfo").newObject("signing-info");
        }
        if ("android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;".equals(signature)) return new StringObject(vm, config.sourceDir);
        if ("android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;".equals(signature)) return new StringObject(vm, config.publicSourceDir);
        if ("android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;".equals(signature)) return new StringObject(vm, config.dataDir);
        if ("android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;".equals(signature)) return new StringObject(vm, config.nativeLibraryDir);
        if ("android/content/pm/ApplicationInfo->packageName:Ljava/lang/String;".equals(signature)) return new StringObject(vm, config.packageName);
        return super.getObjectField(vm, dvmObject, signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        trace("JNI getIntField " + signature + " this=" + (dvmObject == null ? null : dvmObject.getValue()));
        if (config.jniInts.containsKey(signature)) return config.jniInts.get(signature);
        if ("android/util/DisplayMetrics->widthPixels:I".equals(signature)) return config.displayWidth;
        if ("android/util/DisplayMetrics->heightPixels:I".equals(signature)) return config.displayHeight;
        if ("android/util/DisplayMetrics->densityDpi:I".equals(signature)) return config.densityDpi;
        if ("android/content/pm/ApplicationInfo->flags:I".equals(signature)) return 0;
        if ("android/content/pm/ApplicationInfo->uid:I".equals(signature)) return config.appUid;
        if ("android/content/pm/ApplicationInfo->targetSdkVersion:I".equals(signature)) return config.targetSdk;
        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public float getFloatField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        trace("JNI getFloatField " + signature + " this=" + (dvmObject == null ? null : dvmObject.getValue()));
        if (config.jniFloats.containsKey(signature)) return config.jniFloats.get(signature);
        if ("android/util/DisplayMetrics->density:F".equals(signature)) return config.density;
        if ("android/util/DisplayMetrics->scaledDensity:F".equals(signature)) return config.scaledDensity;
        if ("android/util/DisplayMetrics->xdpi:F".equals(signature)) return config.xdpi;
        if ("android/util/DisplayMetrics->ydpi:F".equals(signature)) return config.ydpi;
        return super.getFloatField(vm, dvmObject, signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        trace("JNI getBooleanField " + signature);
        if (config.jniBooleans.containsKey(signature)) return config.jniBooleans.get(signature);
        return super.getBooleanField(vm, dvmObject, signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        trace("JNI getLongField " + signature);
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.getLongField(vm, dvmObject, signature);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        trace("JNI getStaticObjectField " + signature);
        DvmObject<?> configured = configuredObject(vm, signature);
        if (configured != null) return configured;
        String buildValue = config.buildFields.get(buildFieldKey(signature));
        if (buildValue != null) return new StringObject(vm, buildValue);
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        trace("JNI getStaticIntField " + signature);
        if (config.jniInts.containsKey(signature)) return config.jniInts.get(signature);
        if ("android/os/Build$VERSION->SDK_INT:I".equals(signature)) return config.androidApi;
        String buildValue = config.buildFields.get(buildFieldKey(signature));
        if (buildValue != null) return Integer.parseInt(buildValue);
        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public boolean getStaticBooleanField(BaseVM vm, DvmClass dvmClass, String signature) {
        trace("JNI getStaticBooleanField " + signature);
        if (config.jniBooleans.containsKey(signature)) return config.jniBooleans.get(signature);
        return super.getStaticBooleanField(vm, dvmClass, signature);
    }

    @Override
    public long getStaticLongField(BaseVM vm, DvmClass dvmClass, String signature) {
        trace("JNI getStaticLongField " + signature);
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.getStaticLongField(vm, dvmClass, signature);
    }

    private static String buildFieldKey(String signature) {
        String prefix;
        if (signature.startsWith("android/os/Build$VERSION->")) {
            prefix = "VERSION.";
        } else if (signature.startsWith("android/os/Build->")) {
            prefix = "";
        } else {
            return signature;
        }
        int arrow = signature.indexOf("->") + 2;
        int colon = signature.indexOf(':', arrow);
        return prefix + signature.substring(arrow, colon < 0 ? signature.length() : colon);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        DvmObject<?> out = handleObjectMethod(vm, dvmObject, signature, reader(varArg));
        if (out != null
                || signature.endsWith("->get(Ljava/lang/Object;)Ljava/lang/Object;")
                || signature.endsWith("->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;")
                || signature.endsWith("->remove(Ljava/lang/Object;)Ljava/lang/Object;")) return out;
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        try {
            return handleIntMethod(dvmObject, signature);
        } catch (UnsupportedOperationException ignored) {
            return super.callIntMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        try {
            return handleBooleanMethod(dvmObject, signature, reader(varArg));
        } catch (UnsupportedOperationException ignored) {
            return super.callBooleanMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.callLongMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public double callDoubleMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniDoubles.containsKey(signature)) return config.jniDoubles.get(signature);
        return super.callDoubleMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniInts.containsKey(signature)) return config.jniInts.get(signature);
        return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (config.jniInts.containsKey(signature)) return config.jniInts.get(signature);
        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniBooleans.containsKey(signature)) return config.jniBooleans.get(signature);
        return super.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (config.jniBooleans.containsKey(signature)) return config.jniBooleans.get(signature);
        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.callStaticLongMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (config.jniLongs.containsKey(signature)) return config.jniLongs.get(signature);
        return super.callStaticLongMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public float callStaticFloatMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniFloats.containsKey(signature)) return config.jniFloats.get(signature);
        return super.callStaticFloatMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public double callStaticDoubleMethod(BaseVM vm, DvmClass dvmClass, String signature, com.github.unidbg.linux.android.dvm.VarArg varArg) {
        if (config.jniDoubles.containsKey(signature)) return config.jniDoubles.get(signature);
        return super.callStaticDoubleMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public void close() throws Exception {
        emulator.close();
    }

    public static void main(String[] args) throws Exception {
        File projectRoot = new File(".").getCanonicalFile();
        String mode = "both";
        String paramsJson = null;
        File paramsFile = null;
        String activityKind = System.getenv().getOrDefault("ADJUST_ACTIVITY_KIND", "session");
        String clientSdk = System.getenv().getOrDefault("ADJUST_CLIENT_SDK", "android4.38.5");
        for (String arg : args) {
            if (arg.startsWith("--mode=")) {
                mode = arg.substring("--mode=".length()).toLowerCase(Locale.ROOT);
            } else if (arg.startsWith("--params-json=")) {
                paramsJson = arg.substring("--params-json=".length());
            } else if (arg.startsWith("--params-file=")) {
                paramsFile = new File(arg.substring("--params-file=".length())).getCanonicalFile();
            } else if (arg.startsWith("--activity-kind=")) {
                activityKind = arg.substring("--activity-kind=".length());
            } else if (arg.startsWith("--client-sdk=")) {
                clientSdk = arg.substring("--client-sdk=".length());
            } else if (!arg.startsWith("--")) {
                projectRoot = new File(arg).getCanonicalFile();
            }
        }

        boolean runNative = "both".equals(mode) || "native".equals(mode);
        boolean runV4 = "both".equals(mode) || "v4".equals(mode) || "aar".equals(mode)
                || "sdk".equals(mode) || "java".equals(mode) || "equiv".equals(mode) || "equivalent".equals(mode);
        boolean runV5 = "both".equals(mode) || "v5".equals(mode);
        if (!runNative && !runV4 && !runV5) {
            throw new IllegalArgumentException("unknown --mode=" + mode + " (use both/native/v4/v5)");
        }

        Config config = Config.from(projectRoot);
        System.out.println("Signer.getVersion OK version=" + Signer.getVersion());
        System.out.println("config package=" + config.packageName + " androidApi=" + config.androidApi + " appPath=" + config.appPathInAndroid);

        if (runNative) {
            try (AdjustSignatureRunner runner = new AdjustSignatureRunner(config)) {
                System.out.println("calling nOnResume...");
                runner.onResume();
                System.out.println("nOnResume OK");

                Map<String, String> nativeParams = paramsForRun(paramsJson, paramsFile, true, activityKind, clientSdk);
                byte[] input = hmacSha256(config.keyBytes, nativeParams.toString().getBytes(StandardCharsets.UTF_8));
                System.out.println("calling nSign native-direct...");
                byte[] sig = runner.signNative(new Context(config.packageName), nativeParams, input, config.androidApi);
                System.out.println("nSign OK len=" + (sig == null ? -1 : sig.length));
                if (sig == null) throw new IllegalStateException("nSign returned null");
                System.out.println(bytesToHex(sig));
                System.out.println("NATIVE_SIGNATURE_HEX=" + bytesToHex(sig));
                System.out.println("NATIVE_PARAMS=" + nativeParams);
            }
        }

        if (runV4) {
            Map<String, String> v4Params = paramsForRun(paramsJson, paramsFile, false, activityKind, clientSdk);
            System.out.println("calling self-implemented Signer.sign(Context,Map,String,String) -> NativeLibHelper.nSign -> Unidbg...");
            SignResult result = SignerDirectRunner.signV4(projectRoot, v4Params, activityKind, clientSdk);
            System.out.println("Signer.sign v4 OK raw_len=" + result.rawSignature.length);
            System.out.println("SIGNER_V4_RAW_SIGNATURE_HEX=" + bytesToHex(result.rawSignature));
            System.out.println("SIGNER_V4_SIGNATURE_BASE64=" + result.signatureBase64);
            System.out.println("SIGNER_V4_PARAMS=" + result.params);
        }

        if (runV5) {
            Map<String, String> v5Params = paramsForRun(paramsJson, paramsFile, false, activityKind, clientSdk);
            Map<String, String> request = new LinkedHashMap<>();
            request.put("activity_kind", activityKind);
            request.put("client_sdk", clientSdk);
            request.put("a", "not-b");
            request.put("network_payload", "sample-network-payload");
            request.put("endpoint", "/session");
            Map<String, String> output = new LinkedHashMap<>();
            System.out.println("calling self-implemented Signer.sign(Context,Map,Map,Map) -> NativeLibHelper.nSign -> Unidbg...");
            SignerDirectRunner.signV5(projectRoot, v5Params, request, output);
            System.out.println("Signer.sign v5 OK");
            System.out.println("SIGNER_V5_AUTHORIZATION=" + output.get("authorization"));
            System.out.println("SIGNER_V5_OUTPUT=" + output);
        }
    }

    private static Map<String, String> paramsForRun(String paramsJson, File paramsFile,
                                                    boolean includeJavaTempKeys,
                                                    String activityKind, String clientSdk) throws Exception {
        Map<String, String> params;
        if (paramsFile != null) {
            params = parseParams(Files.readString(paramsFile.toPath()));
        } else if (paramsJson != null && !paramsJson.isEmpty()) {
            params = parseParams(paramsJson);
        } else {
            params = sampleParams();
        }
        if (includeJavaTempKeys) {
            params.put("activity_kind", activityKind);
            params.put("client_sdk", clientSdk);
        }
        return params;
    }

    private static Map<String, String> parseParams(String json) {
        JSONObject object = JSON.parseObject(json, Feature.OrderedField);
        Map<String, String> params = new LinkedHashMap<>();
        for (String key : object.keySet()) {
            Object value = object.get(key);
            if (value != null) params.put(key, String.valueOf(value));
        }
        return params;
    }

    private static Map<String, String> sampleParams() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-09T23:59:00.000+0800");
        params.put("gps_adid", "00000000-0000-0000-0000-000000000000");
        params.put("device_type", "phone");
        params.put("os_name", "android");
        params.put("os_version", "14");
        return params;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static void trace(String line) {
        if (TRACE) System.out.println(line);
    }

    private static void traceJniCrypto(String line) {
        if (shouldTraceJniCrypto(JNI_CRYPTO_TRACE)) {
            System.err.println("[qbdi-host] jni-crypto " + line);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    private static void prepareBaseApk(Config config) {
        File source = config.baseApk == null
                ? new File(config.projectRoot, "adjust-android-signature-3.67.0.aar")
                : config.baseApk;
        if (!source.isFile()) throw new IllegalArgumentException("base APK does not exist: " + source);
        File target = new File(config.projectRoot,
                "unidbg-rootfs" + config.sourceDir);
        try {
            Files.createDirectories(target.getParentFile().toPath());
            if (!source.getCanonicalFile().equals(target.getCanonicalFile())) {
                Files.copy(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (Exception exception) {
            throw new IllegalStateException("failed to prepare emulated base.apk", exception);
        }
    }

    public static final class SignResult {
        public final byte[] rawSignature;
        public final String signatureBase64;
        public final Map<String, String> params;

        SignResult(byte[] rawSignature, String signatureBase64, Map<String, String> params) {
            this.rawSignature = rawSignature;
            this.signatureBase64 = signatureBase64;
            this.params = params;
        }
    }

    private static final class Config {
        final File projectRoot;
        final String packageName;
        final int androidApi;
        final File baseApk;
        final byte[] certBytes;
        final byte[] keyBytes;
        final String appPathInAndroid;
        final String sourceDir;
        final String publicSourceDir;
        final String dataDir;
        final String nativeLibraryDir;
        final List<DeviceProfile.Sensor> sensors;
        final int displayWidth;
        final int displayHeight;
        final int densityDpi;
        final float density;
        final float scaledDensity;
        final float xdpi;
        final float ydpi;
        final int appUid;
        final int targetSdk;
        final Map<String, String> buildFields;
        final Map<String, String> systemProperties;
        final Map<String, String> secureSettings;
        final Map<String, String> systemSettings;
        final Map<String, String> serviceClasses;
        final String locale;
        final String timeZone;
        final Integer nativeProcessId;
        final Long nativeTimeSeconds;
        final Long nativeGettimeofdaySeconds;
        final Long nativeGettimeofdayMicroseconds;
        final Long nativeClockGettimeSeconds;
        final Long nativeClockGettimeNanoseconds;
        final byte[] nativeUrandomBytes;
        final boolean nativeSignerCodeTrampolineDetected;
        final java.util.Set<String> nativeConnectRefusedEndpoints;
        final Map<String, byte[]> nativeLocalSocketResponses;
        final Map<String, byte[]> nativeFiles;
        final java.util.Set<String> nativeMissingPaths;
        final Map<String, String> jniStrings;
        final Map<String, Integer> jniInts;
        final Map<String, Long> jniLongs;
        final Map<String, Float> jniFloats;
        final Map<String, Double> jniDoubles;
        final Map<String, Boolean> jniBooleans;
        final Map<String, byte[]> jniBytes;

        private Config(File projectRoot, DeviceProfile profile) {
            this.projectRoot = projectRoot;
            this.packageName = profile.getPackageName();
            this.androidApi = profile.getAndroidApi();
            this.baseApk = profile.getBaseApk();
            this.certBytes = profile.getCertificateDer();
            this.keyBytes = profile.getSigningKey();
            this.sourceDir = profile.getSourceDir();
            this.publicSourceDir = profile.getPublicSourceDir();
            this.dataDir = profile.getDataDir();
            this.nativeLibraryDir = profile.getNativeLibraryDir();
            this.appPathInAndroid = sourceDir;
            this.sensors = profile.getSensors();
            this.displayWidth = profile.getDisplayWidth();
            this.displayHeight = profile.getDisplayHeight();
            this.densityDpi = profile.getDensityDpi();
            this.density = profile.getDensity();
            this.scaledDensity = profile.getScaledDensity();
            this.xdpi = profile.getXdpi();
            this.ydpi = profile.getYdpi();
            this.appUid = profile.getAppUid();
            this.targetSdk = profile.getTargetSdk();
            this.buildFields = profile.getBuildFields();
            this.systemProperties = profile.getSystemProperties();
            this.secureSettings = profile.getSecureSettings();
            this.systemSettings = profile.getSystemSettings();
            this.serviceClasses = profile.getServiceClasses();
            this.locale = profile.getLocale();
            this.timeZone = profile.getTimeZone();
            this.nativeProcessId = profile.getNativeProcessId();
            this.nativeTimeSeconds = profile.getNativeTimeSeconds();
            this.nativeGettimeofdaySeconds = profile.getNativeGettimeofdaySeconds();
            this.nativeGettimeofdayMicroseconds = profile.getNativeGettimeofdayMicroseconds();
            this.nativeClockGettimeSeconds = profile.getNativeClockGettimeSeconds();
            this.nativeClockGettimeNanoseconds = profile.getNativeClockGettimeNanoseconds();
            this.nativeUrandomBytes = profile.getNativeUrandomBytes();
            this.nativeSignerCodeTrampolineDetected = profile.isNativeSignerCodeTrampolineDetected();
            this.nativeConnectRefusedEndpoints = profile.getNativeConnectRefusedEndpoints();
            this.nativeLocalSocketResponses = profile.getNativeLocalSocketResponses();
            this.nativeFiles = profile.getNativeFiles();
            this.nativeMissingPaths = profile.getNativeMissingPaths();
            this.jniStrings = profile.getJniStrings();
            this.jniInts = profile.getJniInts();
            this.jniLongs = profile.getJniLongs();
            this.jniFloats = profile.getJniFloats();
            this.jniDoubles = profile.getJniDoubles();
            this.jniBooleans = profile.getJniBooleans();
            this.jniBytes = profile.getJniBytes();
        }

        static Config from(File projectRoot) {
            return from(projectRoot, DeviceProfile.fromEnvironment());
        }

        static Config from(File projectRoot, DeviceProfile profile) {
            if (projectRoot == null) throw new NullPointerException("projectRoot");
            if (profile == null) throw new NullPointerException("profile");
            return new Config(projectRoot, profile);
        }
    }
}
