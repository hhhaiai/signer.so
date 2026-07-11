package local;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.StatStructure;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.file.LocalSocketIO;
import com.github.unidbg.linux.file.TcpSocket;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

import java.io.File;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Android ARM64 emulator whose syscall layer can model a known native TCP refusal
 * without letting the host network participate in the decision.
 */
final class ConfigurableAndroidARM64Emulator extends AndroidARM64Emulator {
    private static final ThreadLocal<Set<String>> PENDING_CONNECT_REFUSED_ENDPOINTS = new ThreadLocal<>();
    private static final ThreadLocal<Map<String, byte[]>> PENDING_LOCAL_SOCKET_RESPONSES = new ThreadLocal<>();
    private static final boolean TRACE = Boolean.getBoolean("adjust.runner.trace")
            || "1".equals(System.getenv("ADJUST_TRACE"));
    private static final boolean SYSCALL_READ_TRACE = "1".equals(System.getenv("ADJUST_SYSCALL_READ_TRACE"));

    ConfigurableAndroidARM64Emulator(String processName, File rootDir,
                                     Set<String> connectRefusedEndpoints,
                                     Map<String, byte[]> localSocketResponses) {
        super(processName, rootDir, configure(connectRefusedEndpoints, localSocketResponses));
        PENDING_CONNECT_REFUSED_ENDPOINTS.remove();
        PENDING_LOCAL_SOCKET_RESPONSES.remove();
    }

    private static Collection<BackendFactory> configure(Set<String> connectRefusedEndpoints,
                                                        Map<String, byte[]> localSocketResponses) {
        PENDING_CONNECT_REFUSED_ENDPOINTS.set(Collections.unmodifiableSet(
                new LinkedHashSet<>(connectRefusedEndpoints)));
        Map<String, byte[]> responses = new LinkedHashMap<>();
        localSocketResponses.forEach((path, bytes) -> responses.put(path, bytes.clone()));
        PENDING_LOCAL_SOCKET_RESPONSES.set(Collections.unmodifiableMap(responses));
        return Collections.emptyList();
    }

    @Override
    protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
        Set<String> endpoints = PENDING_CONNECT_REFUSED_ENDPOINTS.get();
        if (endpoints == null) throw new IllegalStateException("missing connect refusal configuration");
        Map<String, byte[]> localSocketResponses = PENDING_LOCAL_SOCKET_RESPONSES.get();
        if (localSocketResponses == null) throw new IllegalStateException("missing local socket configuration");
        return new ConfigurableARM64SyscallHandler(svcMemory, endpoints, localSocketResponses);
    }

    private static final class ConfigurableARM64SyscallHandler extends ARM64SyscallHandler {
        private static final int SYS_SOCKET = 198;
        private static final int SYS_READ = 63;
        private final Set<String> connectRefusedEndpoints;
        private final Map<String, byte[]> localSocketResponses;

        ConfigurableARM64SyscallHandler(SvcMemory svcMemory, Set<String> connectRefusedEndpoints,
                                        Map<String, byte[]> localSocketResponses) {
            super(svcMemory);
            this.connectRefusedEndpoints = connectRefusedEndpoints;
            this.localSocketResponses = localSocketResponses;
        }

        @Override
        @SuppressWarnings("unchecked")
        public void hook(Backend backend, int intno, int swi, Object user) {
            if (intno == ARMEmulator.EXCP_SWI && swi == 0) {
                Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user;
                int syscall = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
                if (SYSCALL_READ_TRACE && syscall == SYS_READ) {
                    int fd = emulator.getContext().getIntArg(0);
                    Pointer buffer = emulator.getContext().getPointerArg(1);
                    int requested = emulator.getContext().getIntArg(2);
                    String file = String.valueOf(getFileIO(fd));
                    super.hook(backend, intno, swi, user);
                    long result = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    System.err.printf("[qbdi-host] syscall-read fd=%d file=%s buffer=%s requested=%d result=%d%n",
                            fd, file, buffer, requested, result);
                    return;
                }
                if (syscall == SYS_SOCKET) {
                    int domain = emulator.getContext().getIntArg(0);
                    int type = emulator.getContext().getIntArg(1);
                    super.hook(backend, intno, swi, user);
                    int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
                    if (domain == 2 && (type & 0xf) == 1 && fd >= 0) { // AF_INET / SOCK_STREAM
                        fdMap.put(fd, new RefusedEndpointTcpSocket(emulator, connectRefusedEndpoints));
                    } else if (domain == 1 && fd >= 0 && !localSocketResponses.isEmpty()) { // AF_UNIX
                        fdMap.put(fd, new ProfiledLocalSocket(emulator, localSocketResponses));
                    }
                    return;
                }
            }
            super.hook(backend, intno, swi, user);
        }

        private static final class RefusedEndpointTcpSocket extends TcpSocket {
            private final Emulator<?> emulator;
            private final Set<String> refusedEndpoints;
            private boolean refused;

            RefusedEndpointTcpSocket(Emulator<?> emulator, Set<String> refusedEndpoints) {
                super(emulator);
                this.emulator = emulator;
                this.refusedEndpoints = refusedEndpoints;
            }

            @Override
            public int connect(Pointer address, int length) {
                String endpoint = ipv4Endpoint(address, length);
                if (endpoint != null && refusedEndpoints.contains(endpoint)) {
                    refused = true;
                    emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
                    if (TRACE) System.err.println("[qbdi-host] native connect forced ECONNREFUSED " + endpoint);
                    return -1;
                }
                return super.connect(address, length);
            }

            @Override
            public int write(byte[] data) {
                if (refused) {
                    emulator.getMemory().setErrno(UnixEmulator.ECONNREFUSED);
                    return -1;
                }
                return super.write(data);
            }
        }

        private static final class ProfiledLocalSocket extends LocalSocketIO {
            private final Map<String, byte[]> responses;

            ProfiledLocalSocket(Emulator<?> emulator, Map<String, byte[]> responses) {
                super(emulator, 23);
                this.responses = responses;
            }

            @Override
            protected SocketHandler resolveHandler(String path) {
                byte[] configured = responses.get(path);
                if (configured == null) return super.resolveHandler(path);
                return new SocketHandler() {
                    @Override
                    public byte[] handle(byte[] request) {
                        if (TRACE || SYSCALL_READ_TRACE) {
                            System.err.printf("[qbdi-host] native local socket response path=%s bytes=%d%n",
                                    path, configured.length);
                        }
                        return configured.clone();
                    }

                    @Override
                    public int fstat(StatStructure stat) {
                        return 0;
                    }
                };
            }
        }

        private static String ipv4Endpoint(Pointer address, int length) {
            if (address == null || length < 8) return null;
            byte[] sockaddr = address.getByteArray(0, 8);
            int family = (sockaddr[0] & 0xff) | ((sockaddr[1] & 0xff) << 8);
            if (family != 2) return null; // AF_INET
            int port = ((sockaddr[2] & 0xff) << 8) | (sockaddr[3] & 0xff);
            return (sockaddr[4] & 0xff) + "." + (sockaddr[5] & 0xff) + "."
                    + (sockaddr[6] & 0xff) + "." + (sockaddr[7] & 0xff) + ":" + port;
        }
    }
}
