package local;

import android.content.Context;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.pointer.UnidbgPointer;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EmulatorSocketPathProbeNativeIntegrationTest {
    @Test
    void originalSoChecksTwoQemuAndTwoGenymotionSocketPaths()
            throws Exception {
        File root = findProjectRoot();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger countBefore = new AtomicInteger(-1);
        AtomicInteger countAfterQemu = new AtomicInteger(-1);
        AtomicInteger countAfterAll = new AtomicInteger(-1);
        AtomicInteger firstGroupCount = new AtomicInteger(-1);
        AtomicInteger secondGroupCount = new AtomicInteger(-1);
        AtomicLong outputPointer = new AtomicLong();
        AtomicLong firstTable = new AtomicLong();
        AtomicLong secondTable = new AtomicLong();
        List<String> paths = new ArrayList<>();

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
                    if (offset == 0x1f058) {
                        entries.incrementAndGet();
                        outputPointer.set(registers.getXLong(0));
                        countBefore.set(registers.getXPointer(0).getShort(0)
                                & 0xffff);
                    } else if (offset == 0x1f928) {
                        firstTable.set(registers.getXLong(0));
                        firstGroupCount.set(registers.getIntArg(1));
                        assertEquals(outputPointer.get(),
                                registers.getXLong(2));
                        UnidbgPointer table = registers.getXPointer(0);
                        for (int index = 0; index < 4; index++) {
                            long pathPointer = table.getLong(index * 8L);
                            paths.add(UnidbgPointer.pointer(
                                    emulator, pathPointer).getString(0));
                        }
                    } else if (offset == 0x1f92c) {
                        countAfterQemu.set(UnidbgPointer.pointer(
                                emulator, outputPointer.get()).getShort(0)
                                & 0xffff);
                    } else if (offset == 0x1f958) {
                        secondTable.set(registers.getXLong(0));
                        secondGroupCount.set(registers.getIntArg(1));
                        assertEquals(outputPointer.get(),
                                registers.getXLong(2));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x1f058, module.base + 0x1f95c, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    countAfterAll.set(UnidbgPointer.pointer(
                            emulator, outputPointer.get()).getShort(0)
                            & 0xffff);
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xfaac, module.base + 0xfab0, null);

            runner.onResume();
            Map<String, String> params = params();
            byte[] input = hmacSha256(profile.getSigningKey(),
                    params.toString().getBytes(StandardCharsets.UTF_8));
            assertNotNull(runner.signNative(new Context(profile.getPackageName()),
                    params, input, profile.getAndroidApi()));
        }

        assertEquals(1, entries.get());
        assertNotEquals(0, outputPointer.get());
        assertEquals(0, countBefore.get());
        assertEquals(2, firstGroupCount.get());
        assertEquals(2, secondGroupCount.get());
        assertEquals(firstTable.get() + 16, secondTable.get());
        assertEquals(List.of(
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/dev/socket/genyd",
                "/dev/socket/baseband_genyd"), paths);
        assertTrue(countAfterQemu.get() >= countBefore.get());
        assertTrue(countAfterAll.get() >= countAfterQemu.get());
        assertTrue(countAfterAll.get() <= 4);
        System.out.printf(
                "1f058 entries=%d count=%d->%d->%d groups=[%d,%d] "
                        + "paths=%s%n",
                entries.get(), countBefore.get(), countAfterQemu.get(),
                countAfterAll.get(), firstGroupCount.get(),
                secondGroupCount.get(), paths);
    }

    private static Map<String, String> params() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-15T05:00:00.000+0800");
        params.put("gps_adid", "00000000-0000-0000-0000-000000000000");
        params.put("device_type", "phone");
        params.put("os_name", "android");
        params.put("os_version", "14");
        params.put("activity_kind", "session");
        params.put("client_sdk", "android4.38.5");
        return params;
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
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
