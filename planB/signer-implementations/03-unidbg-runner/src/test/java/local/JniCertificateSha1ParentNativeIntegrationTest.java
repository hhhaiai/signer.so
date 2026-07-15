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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JniCertificateSha1ParentNativeIntegrationTest {
    @Test
    void originalSoPublishesTwentyByteCertificateSha1AndCleansParentRefs()
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
        AtomicInteger statusAfterSelector = new AtomicInteger(-1);
        AtomicInteger statusAfter = new AtomicInteger(-1);
        AtomicInteger api = new AtomicInteger(-1);
        AtomicInteger arrayIndex = new AtomicInteger(-1);
        AtomicInteger digestLength = new AtomicInteger(-1);
        AtomicLong statusPointer = new AtomicLong();
        AtomicLong environment = new AtomicLong();
        AtomicLong context = new AtomicLong();
        AtomicLong outputPointer = new AtomicLong();
        AtomicLong signatureArray = new AtomicLong();
        AtomicLong arrayArgument = new AtomicLong();
        AtomicLong signature = new AtomicLong();
        AtomicLong certificateBytes = new AtomicLong();
        AtomicLong messageDigest = new AtomicLong();
        AtomicLong digestBytes = new AtomicLong();
        AtomicLong digestElements = new AtomicLong();
        AtomicLong releaseArray = new AtomicLong();
        AtomicLong releaseElements = new AtomicLong();
        AtomicReference<String> outputHex = new AtomicReference<>();
        List<Long> deletedReferences = new ArrayList<>();
        List<String> ownershipEvents = new ArrayList<>();

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
                    if (offset == 0x1e578) {
                        entries.incrementAndGet();
                        statusPointer.set(registers.getXLong(0));
                        statusBefore.set(registers.getXPointer(0).getInt(0));
                        environment.set(registers.getXLong(1));
                        context.set(registers.getXLong(2));
                        api.set(registers.getIntArg(3));
                        outputPointer.set(registers.getXLong(4));
                    } else if (offset == 0x1e5f0) {
                        statusAfterSelector.set(UnidbgPointer.pointer(
                                emulator, statusPointer.get()).getInt(0));
                        signatureArray.set(registers.getFpPointer()
                                .share(-0x18).getLong(0));
                    } else if (offset == 0x1ef1c) {
                        arrayArgument.set(registers.getXLong(1));
                        arrayIndex.set(registers.getIntArg(2));
                    } else if (offset == 0x1ef20) {
                        signature.set(registers.getXLong(0));
                    } else if (offset == 0x1eec8) {
                        certificateBytes.set(registers.getFpPointer()
                                .share(-0x20).getLong(0));
                    } else if (offset == 0x1ec18) {
                        messageDigest.set(registers.getFpPointer()
                                .share(-0x28).getLong(0));
                    } else if (offset == 0x1ede4) {
                        digestBytes.set(registers.getFpPointer()
                                .share(-0x30).getLong(0));
                    } else if (offset == 0x1efc8) {
                        digestElements.set(registers.getFpPointer()
                                .share(-0x38).getLong(0));
                        digestLength.set(registers.getFpPointer()
                                .share(-0x3c).getInt(0));
                    } else if (offset == 0x1ee84) {
                        ownershipEvents.add("copy20");
                        outputHex.set(hex(UnidbgPointer.pointer(
                                emulator, outputPointer.get())
                                .getByteArray(0, 20)));
                    } else if (offset == 0x1ec8c) {
                        ownershipEvents.add("release-elements");
                        releaseArray.set(registers.getXLong(1));
                        releaseElements.set(registers.getXLong(2));
                    } else if (offset == 0x1eb04
                            || offset == 0x1ecd0
                            || offset == 0x1ee98
                            || offset == 0x1f008) {
                        ownershipEvents.add("delete-" + Long.toHexString(offset));
                        deletedReferences.add(registers.getXLong(1));
                    } else if (offset == 0x1f020) {
                        statusAfter.set(UnidbgPointer.pointer(
                                emulator, statusPointer.get()).getInt(0));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x1e578, module.base + 0x1f058, null);

            runner.onResume();
            Map<String, String> params = params();
            byte[] input = hmacSha256(profile.getSigningKey(),
                    params.toString().getBytes(StandardCharsets.UTF_8));
            assertNotNull(runner.signNative(new Context(profile.getPackageName()),
                    params, input, profile.getAndroidApi()));
        }

        assertEquals(1, entries.get());
        assertEquals(0, statusBefore.get());
        assertEquals(0, statusAfterSelector.get());
        assertEquals(0, statusAfter.get());
        assertEquals(35, api.get());
        assertNotEquals(0, environment.get());
        assertNotEquals(0, context.get());
        assertNotEquals(0, outputPointer.get());
        assertNotEquals(0, signatureArray.get());
        assertEquals(signatureArray.get(), arrayArgument.get());
        assertEquals(0, arrayIndex.get());
        assertNotEquals(0, signature.get());
        assertNotEquals(0, certificateBytes.get());
        assertNotEquals(0, messageDigest.get());
        assertNotEquals(0, digestBytes.get());
        assertNotEquals(0, digestElements.get());
        assertEquals(20, digestLength.get());
        assertEquals(digestBytes.get(), releaseArray.get());
        assertEquals(digestElements.get(), releaseElements.get());
        assertNotNull(outputHex.get());
        assertEquals("c0cfa6f8ecb636b7d03915227b2ce6517c514ef6",
                outputHex.get());
        assertFalse(deletedReferences.contains(signature.get()));
        assertEquals(List.of(messageDigest.get(), certificateBytes.get(),
                        digestBytes.get(), signatureArray.get()),
                deletedReferences);
        assertEquals(List.of("copy20", "release-elements",
                        "delete-1eb04", "delete-1ee98",
                        "delete-1ecd0", "delete-1f008"),
                ownershipEvents);
        System.out.printf(
                "1e578 status=%d->%d api=%d signatureArray=%x "
                        + "signature=%x certificateBytes=%x digest=%x "
                        + "digestBytes=%x elements=%x length=%d sha1=%s "
                        + "deletes=%s events=%s%n",
                statusBefore.get(), statusAfter.get(), api.get(),
                signatureArray.get(), signature.get(), certificateBytes.get(),
                messageDigest.get(), digestBytes.get(), digestElements.get(),
                digestLength.get(), outputHex.get(), deletedReferences,
                ownershipEvents);
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

    private static String hex(byte[] bytes) {
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            output.append(String.format("%02x", value & 0xff));
        }
        return output.toString();
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
