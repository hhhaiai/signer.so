package local;

import android.content.Context;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import local.android.AndroidKeyStoreProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JniCipherInitNativeIntegrationTest {
    @Test
    void originalSoInitializesLegacyDecryptCipherWithCallerKey()
            throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root,
                "device-reference/references/pixel8-api36");
        JSONObject job = importedLegacyJob(fixture);
        DeviceProfile profile = SignerOneClick.parseProfile(
                job.getJSONObject("device"), fixture);
        AndroidKeyStoreProvider.install(profile.getSigningKey(),
                profile.getLegacyRsaPrivateKeyPkcs8(),
                profile.getLegacyRsaPublicKeyX509());
        Context context = new Context(profile.getPackageName());
        for (Map.Entry<String, Map<String, String>> file
                : profile.getSharedPreferences().entrySet()) {
            for (Map.Entry<String, String> entry : file.getValue().entrySet()) {
                context.putSharedPreference(
                        file.getKey(), entry.getKey(), entry.getValue());
            }
        }

        AtomicInteger entries = new AtomicInteger();
        AtomicInteger deletes = new AtomicInteger();
        AtomicLong entryCipher = new AtomicLong();
        AtomicLong entryKey = new AtomicLong();
        AtomicLong callCipher = new AtomicLong();
        AtomicLong callMethod = new AtomicLong();
        AtomicLong callKey = new AtomicLong();
        AtomicLong deletedClass = new AtomicLong();
        AtomicInteger entryMode = new AtomicInteger(Integer.MIN_VALUE);
        AtomicInteger callMode = new AtomicInteger(Integer.MIN_VALUE);
        AtomicInteger statusBefore = new AtomicInteger(-1);
        AtomicInteger statusAfter = new AtomicInteger(-1);
        AtomicInteger callException = new AtomicInteger(-1);
        AtomicReference<String> methodName = new AtomicReference<>();
        AtomicReference<String> methodSignature = new AtomicReference<>();

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
                    if (offset == 0x96ea8) {
                        entries.incrementAndGet();
                        statusBefore.set(registers.getXPointer(0).getInt(0));
                        entryCipher.set(registers.getXLong(2));
                        entryMode.set(registers.getIntArg(3));
                        entryKey.set(registers.getXLong(4));
                    } else if (offset == 0x97428) {
                        methodName.set(registers.getXPointer(2).getString(0));
                        methodSignature.set(
                                registers.getXPointer(3).getString(0));
                    } else if (offset == 0x975a4) {
                        callCipher.set(registers.getXLong(1));
                        callMethod.set(registers.getXLong(2));
                        callMode.set(registers.getIntArg(3));
                        callKey.set(registers.getXLong(4));
                    } else if (offset == 0x975b0) {
                        callException.set(registers.getIntArg(0) & 1);
                    } else if (offset == 0x97564) {
                        deletes.incrementAndGet();
                        deletedClass.set(registers.getXLong(1));
                    }
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0x96ea8, module.base + 0x975f0, null);
            emulator.getBackend().hook_add_new(new CodeHook() {
                @Override
                public void hook(
                        Backend backend, long address, int size, Object user) {
                    Arm64RegisterContext registers = emulator.getContext();
                    statusAfter.set(registers.getXPointer(22).getInt(0));
                }

                @Override public void onAttach(UnHook unHook) {}
                @Override public void detach() {}
            }, module.base + 0xcb1e4, module.base + 0xcb1e8, null);

            runner.onResume();
            assertNotNull(runner.signNative(
                    context, legacyParams(), new byte[32], 18));
        }

        assertEquals(1, entries.get());
        assertEquals(0, statusBefore.get());
        assertEquals(0, statusAfter.get());
        assertEquals("init", methodName.get());
        assertEquals("(ILjava/security/Key;)V", methodSignature.get());
        assertEquals(Cipher.DECRYPT_MODE, entryMode.get());
        assertEquals(Cipher.DECRYPT_MODE, callMode.get());
        assertNotEquals(0, entryCipher.get());
        assertNotEquals(0, entryKey.get());
        assertEquals(entryCipher.get(), callCipher.get());
        assertNotEquals(0, callMethod.get());
        assertEquals(entryKey.get(), callKey.get());
        assertEquals(0, callException.get());
        assertEquals(1, deletes.get());
        assertNotEquals(0, deletedClass.get());
        System.out.printf(
                "96ea8 entries=%d status=%d->%d method=%s signature=%s "
                        + "mode=%d/%d cipherForward=%s keyForward=%s "
                        + "exception=%d deletes=%d%n",
                entries.get(), statusBefore.get(), statusAfter.get(),
                methodName.get(), methodSignature.get(), entryMode.get(),
                callMode.get(), entryCipher.get() == callCipher.get(),
                entryKey.get() == callKey.get(), callException.get(),
                deletes.get());
    }

    private static JSONObject importedLegacyJob(File fixture)
            throws Exception {
        JSONObject job = JSON.parseObject(Files.readString(
                new File(fixture, "signer-job.json").toPath()),
                Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 18);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        byte[] secret = DeviceProfile.hexToBytes(
                "00112233445566778899aabbccddeeff");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        JSONObject legacyKeyStore = new JSONObject(true);
        legacyKeyStore.put(
                "privateKeyPkcs8Hex", hex(pair.getPrivate().getEncoded()));
        legacyKeyStore.put(
                "publicKeyX509Hex", hex(pair.getPublic().getEncoded()));
        device.put("legacyKeyStore", legacyKeyStore);
        JSONObject preferences = new JSONObject(true);
        JSONObject adjustKeys = new JSONObject(true);
        adjustKeys.put("encrypted_key",
                Base64.getEncoder().encodeToString(cipher.doFinal(secret)));
        preferences.put("adjust_keys", adjustKeys);
        device.put("sharedPreferences", preferences);
        return job;
    }

    private static Map<String, String> legacyParams() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("a", "b");
        params.put("environment", "production");
        params.put("activity_kind", "session");
        params.put("client_sdk", "android4.38.5");
        return params;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
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
                    "adjust-android-signature-3.67.0/jni/arm64-v8a/"
                            + "libsigner.so").isFile()) {
                return current;
            }
            current = current.getParentFile();
        }
        throw new IllegalStateException("project root not found");
    }
}
