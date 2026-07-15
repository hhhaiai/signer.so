package local;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class VirtualBoxDmiFileProbeNativeIntegrationTest {
    @Test
    void originalSoBuildsTwoVirtualBoxDmiSubstringRecords()
            throws Exception {
        File root = findProjectRoot();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger recordCount = new AtomicInteger(-1);
        AtomicInteger countBefore = new AtomicInteger(-1);
        AtomicInteger countAfter = new AtomicInteger(-1);
        AtomicLong outputPointer = new AtomicLong();
        AtomicLong forwardedOutput = new AtomicLong();
        List<String> paths = new ArrayList<>();
        List<String> markers = new ArrayList<>();
        List<Integer> kinds = new ArrayList<>();
        List<Long> descriptorCounts = new ArrayList<>();

        try (AdjustSignatureRunner runner =
                new AdjustSignatureRunner(root, profile)) {
            AndroidEmulator emulator = emulator(runner);
            Module module = emulator.getMemory().findModule("libsigner.so");
            assertNotNull(module);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    long offset = address - module.base;
                    Arm64RegisterContext registers = emulator.getContext();
                    if (offset == 0x24860) {
                        entries.incrementAndGet();
                        outputPointer.set(registers.getXLong(0));
                        countBefore.set(registers.getXPointer(0).getShort(0)
                                & 0xffff);
                    } else if (offset == 0x25024) {
                        UnidbgPointer records = registers.getXPointer(0);
                        recordCount.set(registers.getIntArg(1));
                        forwardedOutput.set(registers.getXLong(2));
                        for (int index = 0; index < 2; index++) {
                            UnidbgPointer record = UnidbgPointer.pointer(
                                    emulator, records.peer + index * 0x100L);
                            paths.add(record.getPointer(0).getString(0));
                            markers.add(record.getPointer(8).getString(0));
                            kinds.add(record.getInt(0xa8));
                            descriptorCounts.add(record.getLong(0xf8));
                        }
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x24860, module.base + 0x25068, null);

            runner.onResume();
            MemoryBlock outputBlock = emulator.getMemory().malloc(2, true);
            try {
                UnidbgPointer output = outputBlock.getPointer();
                output.setShort(0, (short) 0);
                Module.emulateFunction(
                        emulator, module.base + 0x24860, output);
                countAfter.set(output.getShort(0) & 0xffff);
            } finally {
                outputBlock.free();
            }
        }

        assertEquals(1, entries.get());
        assertNotEquals(0, outputPointer.get());
        assertEquals(outputPointer.get(), forwardedOutput.get());
        assertEquals(0, countBefore.get());
        assertEquals(2, recordCount.get());
        assertEquals(List.of(
                "/sys/devices/virtual/dmi/id/product_name",
                "/sys/devices/virtual/dmi/id/sys_vendor"), paths);
        assertEquals(List.of("VirtualBox", "innotek"), markers);
        assertEquals(List.of(3, 3), kinds);
        assertEquals(List.of(1L, 1L), descriptorCounts);
        assertEquals(0, countAfter.get());
        System.out.printf(
                "24860 entries=%d count=%d->%d records=%d paths=%s "
                        + "markers=%s kinds=%s descriptorCounts=%s%n",
                entries.get(), countBefore.get(), countAfter.get(),
                recordCount.get(), paths, markers, kinds, descriptorCounts);
    }

    private static AndroidEmulator emulator(AdjustSignatureRunner runner)
            throws Exception {
        Field field = AdjustSignatureRunner.class.getDeclaredField("emulator");
        field.setAccessible(true);
        return (AndroidEmulator) field.get(runner);
    }

    private static File findProjectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        for (int depth = 0; depth < 5 && current != null; depth++) {
            if (new File(current,
                    "adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so")
                    .isFile()) {
                return current;
            }
            current = current.getParentFile();
        }
        throw new IllegalStateException("project root not found");
    }
}
