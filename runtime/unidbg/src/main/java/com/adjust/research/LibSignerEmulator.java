package com.adjust.research;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.file.LocalAndroidUdpSocket;
import com.github.unidbg.linux.file.Stdin;
import com.github.unidbg.memory.SvcMemory;
import com.sun.jna.Pointer;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LibSignerEmulator implements AutoCloseable {

    public static final String N_SIGN_DESCRIPTOR =
            "nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B";
    public static final String N_ON_RESUME_DESCRIPTOR = "nOnResume()V";

    private final SignerConfig config;
    private final AndroidEmulator emulator;
    private final VM vm;
    private final AndroidRuntimeJni jni;
    private final Module module;
    private final DvmObject<?> nativeLibHelper;
    private final Path extractedLibrary;

    public LibSignerEmulator(SignerConfig config) throws IOException {
        this.config = config;
        this.emulator = new SafeAndroidARM64Emulator(
                config.packageName(), null, Collections.singletonList(new Unicorn2Factory(true)));
        this.emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        this.vm = emulator.createDalvikVM();
        this.jni = new AndroidRuntimeJni(
                config.packageName(), config.certificateBytes(), config.hmacKey());
        this.vm.setJni(jni);
        this.vm.setVerbose(config.verbose());

        this.extractedLibrary = extractLibrary();
        DalvikModule dalvikModule = vm.loadLibrary(extractedLibrary.toFile(), false);
        this.module = dalvikModule.getModule();
        installPathAwareStdin();
        requireExport("Java_com_adjust_sdk_sig_NativeLibHelper_nSign");
        requireExport("Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume");

        DvmClass nativeClass = vm.resolveClass("com/adjust/sdk/sig/NativeLibHelper");
        this.nativeLibHelper = nativeClass.newObject(null);
    }

    public Module module() {
        return module;
    }

    public TraceRecorder trace(Path output, long maxEvents) throws IOException {
        return TraceRecorder.attach(emulator, module, output, maxEvents);
    }

    public byte[] sign(SignerRequest request) {
        return signDetailed(request).signature();
    }

    public SignerResult signDetailed(SignerRequest request) {
        LinkedHashMap<String, String> parameters = request.parametersForNative();
        byte[] hmac = config.hmacOverride();
        if (hmac == null) {
            hmac = HmacInputBuilder.hmacSha256(parameters, config.hmacKey());
        }

        DvmObject<?> context = jni.wrapContext(vm);
        DvmObject<?> parameterMap = jni.wrapParameters(vm, parameters);
        ByteArray hmacArray = new ByteArray(vm, hmac);
        DvmObject<?> result = nativeLibHelper.callJniMethodObject(
                emulator,
                N_SIGN_DESCRIPTOR,
                context,
                parameterMap,
                hmacArray,
                config.sdkLevel());

        if (result == null) {
            throw new IllegalStateException("native nSign returned null");
        }
        if (!(result instanceof ByteArray)) {
            throw new IllegalStateException(
                    "nSign returned " + result.getObjectType().getName() + " instead of byte[]");
        }
        byte[] signature = ((ByteArray) result).getValue();
        if (signature == null || signature.length == 0) {
            throw new IllegalStateException("native nSign returned an empty byte array");
        }
        return new SignerResult(signature, parameters);
    }

    public void onResume() {
        nativeLibHelper.callJniMethod(emulator, N_ON_RESUME_DESCRIPTOR);
    }

    @Override
    public void close() throws IOException {
        try {
            emulator.close();
        } finally {
            Files.deleteIfExists(extractedLibrary);
        }
    }

    private Path extractLibrary() throws IOException {
        Path output = Files.createTempFile("adjust-signature-3.62.0-arm64-", ".so");
        try (InputStream input = LibSignerEmulator.class.getResourceAsStream(
                "/arm64-v8a/libsigner.so")) {
            if (input == null) {
                throw new IOException("missing resource /arm64-v8a/libsigner.so");
            }
            Files.copy(input, output, StandardCopyOption.REPLACE_EXISTING);
        }
        output.toFile().setReadable(true);
        output.toFile().setExecutable(true);
        return output;
    }

    private void requireExport(String name) {
        if (module.findSymbolByName(name) == null) {
            throw new IllegalStateException("missing required export " + name);
        }
    }

    @SuppressWarnings("unchecked")
    private void installPathAwareStdin() {
        UnixSyscallHandler<AndroidFileIO> handler =
                (UnixSyscallHandler<AndroidFileIO>) emulator.getSyscallHandler();
        handler.closeFileIO(0);
        int fd = handler.addFileIO(new PathAwareStdin());
        if (fd != 0) {
            throw new IllegalStateException("failed to restore stdin at fd 0, got fd " + fd);
        }
    }

    /**
     * unidbg 0.9.8's stock Stdin inherits a getPath() implementation that deliberately throws.
     * libsigner resolves /proc/self/fd/0 during environment checks, so expose the real fd target.
     */
    private static final class PathAwareStdin extends Stdin {
        private PathAwareStdin() {
            super(0);
        }

        @Override
        public String getPath() {
            return "/dev/stdin";
        }
    }

    private static final class SafeAndroidARM64Emulator extends AndroidARM64Emulator {
        private SafeAndroidARM64Emulator(
                String processName, File rootDir, Collection<BackendFactory> backendFactories) {
            super(processName, rootDir, backendFactories);
        }

        @Override
        protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
            return new PathAwareARM64SyscallHandler(svcMemory);
        }
    }

    private static final class PathAwareARM64SyscallHandler extends ARM64SyscallHandler {
        private static final Pattern PROC_FD = Pattern.compile(
                "^/proc/(?:self|[0-9]+)/fd/([0-9]+)$");

        private PathAwareARM64SyscallHandler(SvcMemory svcMemory) {
            super(svcMemory);
        }

        @Override
        protected int readlink(
                Emulator<?> emulator, String path, Pointer buffer, int bufferSize) {
            Matcher matcher = PROC_FD.matcher(path);
            if (matcher.matches()) {
                int fd = Integer.parseInt(matcher.group(1));
                AndroidFileIO file = fdMap.get(fd);
                if (file instanceof LocalAndroidUdpSocket) {
                    String target = "/dev/socket/logdw";
                    if (target.length() + 1 > bufferSize) {
                        throw new IllegalStateException("readlink buffer too small for " + target);
                    }
                    buffer.setString(0, target);
                    return target.length() + 1;
                }
            }
            return super.readlink(emulator, path, buffer, bufferSize);
        }
    }
}
