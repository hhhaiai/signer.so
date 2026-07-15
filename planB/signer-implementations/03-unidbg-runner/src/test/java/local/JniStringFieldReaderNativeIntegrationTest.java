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

class JniStringFieldReaderNativeIntegrationTest {
    @Test
    void originalSoReadsPublicSourceDirStringFieldAndCleansClassRef()
            throws Exception {
        File root = findProjectRoot();
        String publicSourceDir =
                "/data/app/~~audit/com.adjust.test-audit/base-public.apk";
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .applicationPaths(
                        "/data/app/~~audit/com.adjust.test-audit/base.apk",
                        publicSourceDir,
                        "/data/user/0/com.adjust.test",
                        "/data/app/~~audit/com.adjust.test-audit/lib/arm64")
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger statusBefore = new AtomicInteger(-1);
        AtomicInteger statusAfter = new AtomicInteger(-1);
        AtomicReference<String> entryFieldName = new AtomicReference<>();
        AtomicReference<String> lookupFieldName = new AtomicReference<>();
        AtomicReference<String> lookupSignature = new AtomicReference<>();
        AtomicLong entryObject = new AtomicLong();
        AtomicLong outputSlot = new AtomicLong();
        AtomicLong objectClass = new AtomicLong();
        AtomicLong lookupClass = new AtomicLong();
        AtomicLong fieldId = new AtomicLong();
        AtomicLong fieldObject = new AtomicLong();
        AtomicLong fieldLookupId = new AtomicLong();
        AtomicLong outputObject = new AtomicLong();
        AtomicLong forwardedString = new AtomicLong();
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
                    if (offset == 0xb2978) {
                        entries.incrementAndGet();
                        statusBefore.set(registers.getXPointer(0).getInt(0));
                        entryObject.set(registers.getXLong(2));
                        entryFieldName.set(
                                registers.getXPointer(3).getString(0));
                        outputSlot.set(registers.getXLong(4));
                    } else if (offset == 0xb3144) {
                        objectClass.set(registers.getXLong(0));
                    } else if (offset == 0xb3150
                            || offset == 0xb2dd0
                            || offset == 0xb2cfc) {
                        exceptions.add(registers.getIntArg(0) & 1);
                    } else if (offset == 0xb2dc0) {
                        lookupClass.set(registers.getXLong(1));
                        lookupFieldName.set(
                                registers.getXPointer(2).getString(0));
                        lookupSignature.set(
                                registers.getXPointer(3).getString(0));
                    } else if (offset == 0xb2dc4) {
                        fieldId.set(registers.getXLong(0));
                    } else if (offset == 0xb2ce8) {
                        fieldObject.set(registers.getXLong(1));
                        fieldLookupId.set(registers.getXLong(2));
                    } else if (offset == 0xb2cec) {
                        outputObject.set(registers.getXLong(0));
                    } else if (offset == 0xb3044) {
                        deletedReferences.add(registers.getXLong(1));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xb2978, module.base + 0xb3230, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    statusAfter.set(registers.getXPointer(22).getInt(0));
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x181c4, module.base + 0x181c4, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    forwardedString.set(registers.getXLong(2));
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x18468, module.base + 0x18468, null);

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
        assertEquals("publicSourceDir", entryFieldName.get());
        assertEquals(entryFieldName.get(), lookupFieldName.get());
        assertEquals("Ljava/lang/String;", lookupSignature.get());
        assertNotEquals(0, entryObject.get());
        assertNotEquals(0, outputSlot.get());
        assertNotEquals(0, objectClass.get());
        assertEquals(objectClass.get(), lookupClass.get());
        assertNotEquals(0, fieldId.get());
        assertEquals(entryObject.get(), fieldObject.get());
        assertEquals(fieldId.get(), fieldLookupId.get());
        assertNotEquals(0, outputObject.get());
        assertEquals(outputObject.get(), forwardedString.get());
        assertEquals(List.of(0, 0, 0), exceptions);
        assertEquals(List.of(objectClass.get()), deletedReferences);
        System.out.printf(
                "b2978 entries=%d status=%d->%d field=%s "
                        + "signature=%s output=%x forwarded=%x "
                        + "exceptions=%s cleanup=class path=%s%n",
                entries.get(), statusBefore.get(), statusAfter.get(),
                lookupFieldName.get(), lookupSignature.get(),
                outputObject.get(), forwardedString.get(), exceptions,
                publicSourceDir);
    }

    private static Map<String, String> params() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-15T16:00:00.000+0800");
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
