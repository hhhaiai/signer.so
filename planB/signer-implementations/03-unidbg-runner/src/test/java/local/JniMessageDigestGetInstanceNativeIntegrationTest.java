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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JniMessageDigestGetInstanceNativeIntegrationTest {
    @Test
    void originalSoCreatesSha1MessageDigestAndCleansTemporaryRefs()
            throws Exception {
        File root = findProjectRoot();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger statusBefore = new AtomicInteger(-1);
        AtomicInteger statusAfter = new AtomicInteger(-1);
        AtomicReference<String> entryAlgorithm = new AtomicReference<>();
        AtomicReference<String> className = new AtomicReference<>();
        AtomicReference<String> methodName = new AtomicReference<>();
        AtomicReference<String> methodSignature = new AtomicReference<>();
        AtomicReference<String> newStringValue = new AtomicReference<>();
        AtomicLong outputSlot = new AtomicLong();
        AtomicLong foundClass = new AtomicLong();
        AtomicLong methodClass = new AtomicLong();
        AtomicLong methodId = new AtomicLong();
        AtomicLong newString = new AtomicLong();
        AtomicLong callClass = new AtomicLong();
        AtomicLong callMethod = new AtomicLong();
        AtomicLong callString = new AtomicLong();
        AtomicLong outputObject = new AtomicLong();
        List<Integer> exceptions = new ArrayList<>();
        List<Long> deletedReferences = new ArrayList<>();

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
                    if (offset == 0xaf438) {
                        entries.incrementAndGet();
                        statusBefore.set(registers.getXPointer(0).getInt(0));
                        entryAlgorithm.set(registers.getXPointer(2).getString(0));
                        outputSlot.set(registers.getXLong(3));
                    } else if (offset == 0xb02c8) {
                        className.set(registers.getXPointer(1).getString(0));
                    } else if (offset == 0xb02cc) {
                        foundClass.set(registers.getXLong(0));
                    } else if (offset == 0xb02e8
                            || offset == 0xafeB8
                            || offset == 0xb0188
                            || offset == 0xb046c) {
                        exceptions.add(registers.getIntArg(0) & 1);
                    } else if (offset == 0xafe98) {
                        methodClass.set(registers.getXLong(1));
                        methodName.set(registers.getXPointer(2).getString(0));
                        methodSignature.set(
                                registers.getXPointer(3).getString(0));
                    } else if (offset == 0xafe9c) {
                        methodId.set(registers.getXLong(0));
                    } else if (offset == 0xb0168) {
                        newStringValue.set(registers.getXPointer(1).getString(0));
                    } else if (offset == 0xb016c) {
                        newString.set(registers.getXLong(0));
                    } else if (offset == 0xb0448) {
                        callClass.set(registers.getXLong(1));
                        callMethod.set(registers.getXLong(2));
                        callString.set(registers.getXLong(3));
                    } else if (offset == 0xb0024 || offset == 0xafb3c) {
                        deletedReferences.add(registers.getXLong(1));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xaf438, module.base + 0xb081c, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    statusAfter.set(registers.getXPointer(23).getInt(0));
                    outputObject.set(registers.getFpPointer()
                            .share(-0x28).getLong(0));
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x1ec18, module.base + 0x1ec1c, null);

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
        assertEquals("SHA1", entryAlgorithm.get());
        assertEquals("java/security/MessageDigest", className.get());
        assertEquals("getInstance", methodName.get());
        assertEquals("(Ljava/lang/String;)Ljava/security/MessageDigest;",
                methodSignature.get());
        assertEquals("SHA1", newStringValue.get());
        assertNotEquals(0, outputSlot.get());
        assertNotEquals(0, foundClass.get());
        assertEquals(foundClass.get(), methodClass.get());
        assertNotEquals(0, methodId.get());
        assertNotEquals(0, newString.get());
        assertEquals(foundClass.get(), callClass.get());
        assertEquals(methodId.get(), callMethod.get());
        assertEquals(newString.get(), callString.get());
        assertNotEquals(0, outputObject.get());
        assertEquals(List.of(0, 0, 0, 0), exceptions);
        assertEquals(List.of(foundClass.get(), newString.get()),
                deletedReferences);
        System.out.printf(
                "af438 entries=%d status=%d->%d algorithm=%s "
                        + "class=%s method=%s signature=%s output=%x "
                        + "exceptions=%s cleanup=class,string%n",
                entries.get(), statusBefore.get(), statusAfter.get(),
                entryAlgorithm.get(), className.get(), methodName.get(),
                methodSignature.get(), outputObject.get(), exceptions);
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
