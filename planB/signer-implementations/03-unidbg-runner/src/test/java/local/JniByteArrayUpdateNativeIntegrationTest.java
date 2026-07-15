package local;

import android.content.Context;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JniByteArrayUpdateNativeIntegrationTest {
    @Test
    void originalSoForwardsObjectAndByteArrayToUpdateVoidMethod()
            throws Exception {
        File root = findProjectRoot();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger deletes = new AtomicInteger();
        AtomicLong entryObject = new AtomicLong();
        AtomicLong entryByteArray = new AtomicLong();
        AtomicLong callObject = new AtomicLong();
        AtomicLong callMethod = new AtomicLong();
        AtomicLong callByteArray = new AtomicLong();
        AtomicLong deletedClass = new AtomicLong();
        AtomicInteger statusBefore = new AtomicInteger(-1);
        AtomicInteger statusAfter = new AtomicInteger(-1);
        AtomicInteger callException = new AtomicInteger(-1);
        AtomicReference<String> methodName = new AtomicReference<>();
        AtomicReference<String> methodSignature = new AtomicReference<>();

        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root, profile)) {
            AndroidEmulator emulator = emulator(runner);
            Module module = emulator.getMemory().findModule("libsigner.so");
            assertNotNull(module);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    long offset = address - module.base;
                    Arm64RegisterContext registers = emulator.getContext();
                    if (offset == 0xb081c) {
                        entries.incrementAndGet();
                        statusBefore.set(registers.getXPointer(0).getInt(0));
                        entryObject.set(registers.getXLong(2));
                        entryByteArray.set(registers.getXLong(3));
                    } else if (offset == 0xb0e34) {
                        methodName.set(registers.getXPointer(2).getString(0));
                        methodSignature.set(registers.getXPointer(3).getString(0));
                    } else if (offset == 0xb0ea4) {
                        callObject.set(registers.getXLong(1));
                        callMethod.set(registers.getXLong(2));
                        callByteArray.set(registers.getXLong(3));
                    } else if (offset == 0xb0eb0) {
                        callException.set(registers.getIntArg(0) & 1);
                    } else if (offset == 0xb0d04) {
                        deletes.incrementAndGet();
                        deletedClass.set(registers.getXLong(1));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xb081c, module.base + 0xb0f38, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    statusAfter.set((int) registers.getXLong(8));
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x1ee2c, module.base + 0x1ee30, null);

            runner.onResume();
            Map<String, String> params = params();
            byte[] input = hmacSha256(profile.getSigningKey(),
                    params.toString().getBytes(StandardCharsets.UTF_8));
            assertNotNull(runner.signNative(new Context(profile.getPackageName()),
                    params, input, profile.getAndroidApi()));
        }

        assertEquals(1, entries.get());
        assertEquals(0, statusBefore.get());
        assertEquals(0, statusAfter.get());
        assertEquals("update", methodName.get());
        assertEquals("([B)V", methodSignature.get());
        assertNotEquals(0, entryObject.get());
        assertNotEquals(0, entryByteArray.get());
        assertEquals(entryObject.get(), callObject.get());
        assertNotEquals(0, callMethod.get());
        assertEquals(entryByteArray.get(), callByteArray.get());
        assertEquals(0, callException.get());
        assertEquals(1, deletes.get());
        assertNotEquals(0, deletedClass.get());
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
