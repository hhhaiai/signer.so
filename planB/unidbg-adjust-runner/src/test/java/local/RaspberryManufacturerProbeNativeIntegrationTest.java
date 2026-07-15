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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RaspberryManufacturerProbeNativeIntegrationTest {
    @Test
    void nonRaspberryPropertiesReturnFalseWithoutCorrection28() throws Exception {
        Observation observation = observe("Google", "Google");
        assertEquals(1, observation.entries);
        assertEquals(0, observation.result);
        assertEquals(0, observation.correction28Calls);
    }

    @Test
    void mixedCaseRaspberryManufacturerReturnsTrueAndAppliesCorrection28()
            throws Exception {
        Observation observation = observe("RaSpBeRrY Pi Foundation", "Google");
        assertEquals(1, observation.entries);
        assertEquals(1, observation.result);
        assertEquals(1, observation.correction28Calls);
    }

    private static Observation observe(String manufacturer, String vendorManufacturer)
            throws Exception {
        File root = findProjectRoot();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.adjust.test")
                .androidApi(35)
                .systemProperty("ro.product.manufacturer", manufacturer)
                .systemProperty("ro.product.vendor.manufacturer", vendorManufacturer)
                .systemProperty("ro.build.version.sdk", "35")
                .nativeTimeSeconds(1_760_000_000L)
                .build();
        AtomicInteger entries = new AtomicInteger();
        AtomicInteger result = new AtomicInteger(-1);
        AtomicInteger correction28Calls = new AtomicInteger();
        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root, profile)) {
            AndroidEmulator emulator = emulator(runner);
            Module module = emulator.getMemory().findModule("libsigner.so");
            assertNotNull(module);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    long offset = address - module.base;
                    Arm64RegisterContext registers = emulator.getContext();
                    if (offset == 0x2c618) entries.incrementAndGet();
                    if (offset == 0x2cc64) result.set(registers.getIntArg(0) & 1);
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x2c618, module.base + 0x2cc68, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    if (address - module.base == 0xf988
                            && registers.getIntArg(1) == 0x28) {
                        correction28Calls.incrementAndGet();
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xf988, module.base + 0xf98c, null);

            runner.onResume();
            Map<String, String> params = params();
            byte[] input = hmacSha256(profile.getSigningKey(),
                    params.toString().getBytes(StandardCharsets.UTF_8));
            assertNotNull(runner.signNative(new Context(profile.getPackageName()),
                    params, input, profile.getAndroidApi()));
        }
        return new Observation(entries.get(), result.get(), correction28Calls.get());
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

    private static final class Observation {
        final int entries;
        final int result;
        final int correction28Calls;

        Observation(int entries, int result, int correction28Calls) {
            this.entries = entries;
            this.result = result;
            this.correction28Calls = correction28Calls;
        }
    }
}
