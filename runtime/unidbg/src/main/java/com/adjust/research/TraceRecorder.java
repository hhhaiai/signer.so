package com.adjust.research;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public final class TraceRecorder implements CodeHook, AutoCloseable {

    public static final String SCHEMA = "libsigner.trace/v1";
    private static final long N_SIGN_RELATIVE_START = 0x0a95acL;
    private static final long N_SIGN_SIZE = 3476L;

    private final Module module;
    private final BufferedWriter writer;
    private final long maxEvents;
    private long sequence;
    private UnHook unHook;
    private boolean detached;

    private TraceRecorder(Module module, Path output, long maxEvents) throws IOException {
        this.module = Objects.requireNonNull(module, "module");
        if (maxEvents <= 0) {
            throw new IllegalArgumentException("maxEvents must be positive");
        }
        this.maxEvents = maxEvents;
        Path absolute = Objects.requireNonNull(output, "output").toAbsolutePath();
        ensureParent(absolute);
        this.writer = Files.newBufferedWriter(
                absolute, StandardCharsets.UTF_8);
    }

    public static TraceRecorder attach(
            AndroidEmulator emulator, Module module, Path output, long maxEvents) throws IOException {
        TraceRecorder recorder = new TraceRecorder(module, output, maxEvents);
        long begin = module.base + N_SIGN_RELATIVE_START;
        long end = begin + N_SIGN_SIZE;
        if (begin < module.base || end > module.base + module.size) {
            recorder.close();
            throw new IllegalArgumentException("nSign trace range is outside the loaded module");
        }
        emulator.getBackend().hook_add_new(
                recorder, begin, end, null);
        return recorder;
    }

    @Override
    public synchronized void hook(Backend backend, long address, int size, Object user) {
        if (detached || address < module.base || address >= module.base + module.size) {
            return;
        }
        if (sequence >= maxEvents) {
            return;
        }
        try {
            writer.write(jsonLine(module.base, module.size, address, size,
                    Thread.currentThread().getId(), sequence++));
            writer.newLine();
            if (sequence >= maxEvents) {
                writer.flush();
            }
        } catch (IOException e) {
            detach();
            throw new UncheckedIOException("failed to write instruction trace", e);
        }
    }

    @Override
    public synchronized void onAttach(UnHook unHook) {
        this.unHook = unHook;
    }

    @Override
    public synchronized void detach() {
        if (!detached) {
            detached = true;
            if (unHook != null) {
                unHook.unhook();
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        detach();
        writer.close();
    }

    static String jsonLine(
            long moduleBase,
            long moduleSize,
            long pc,
            int instructionSize,
            long threadId,
            long sequence) {
        if (pc < moduleBase || pc >= moduleBase + moduleSize) {
            throw new IllegalArgumentException("pc is outside module range");
        }
        if (instructionSize <= 0) {
            throw new IllegalArgumentException("instructionSize must be positive");
        }
        return "{"
                + "\"schema\":\"" + SCHEMA + "\","
                + "\"backend\":\"unidbg\","
                + "\"event\":\"instruction\","
                + "\"module\":\"libsigner.so\","
                + "\"module_base\":\"" + hex(moduleBase) + "\","
                + "\"module_size\":\"" + hex(moduleSize) + "\","
                + "\"pc\":\"" + hex(pc) + "\","
                + "\"relative_pc\":\"" + hex(pc - moduleBase) + "\","
                + "\"instruction_size\":" + instructionSize + ","
                + "\"thread_id\":" + threadId + ","
                + "\"sequence\":" + sequence
                + "}";
    }

    private static String hex(long value) {
        return "0x" + Long.toUnsignedString(value, 16);
    }

    static void ensureParent(Path output) throws IOException {
        Path parent = output.getParent();
        if (parent != null && !Files.isDirectory(parent)) {
            Files.createDirectories(parent);
        }
    }
}
