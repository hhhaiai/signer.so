package local;

import android.content.Context;
import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.d;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import local.android.AndroidKeyStoreProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LegacyAndroidApiNativeIntegrationTest {
    @AfterEach
    void tearDown() throws Exception {
        NativeLibHelper.closeBridge();
        NativeLibHelper.clearConfiguration();
        d.a = false;
    }

    @Test
    void api18RsaWrappedKeyPathMatchesOriginalSoOracle() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        job.getJSONObject("device").put("androidApi", 18);

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11e41c9a76d043c6ecb8e95630c0667b93"
                        + "03c5fd31ac192e854bb30f9f4d07b176954014b5000f425e1dbba4ccca277defc9"
                        + "30b47cc34f8120028d0891ce4d4c0031226885d95c64aa948e5ed521b18d14955"
                        + "ce2ed3ccde07296f6c72910d1233ca839e9eb6de02d0b487296a5bbd72ce56e73"
                        + "e24879dc972faae2531e6e58f350fcf5c30753ea9ee72236b14f5fbf75041163b"
                        + "346c3fa3deb8a5b4101b44f1a14",
                actual.getString("rawSignatureHex"));
        assertEquals("adj8", actual.getJSONObject("metadata").getString("algorithm"));
        assertEquals(176, actual.getString("rawSignatureHex").length() / 2);
    }

    @Test
    void api18ImportsPersistedRsaPairAndWrappedSecretFromProfile() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = importedLegacyJob(fixture);

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));
        job.getJSONObject("device").getJSONObject("runtime").put("backend", "recovered");
        JSONObject recovered = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11e41c9a76d043c6ecb8e95630c0667b93"
                        + "03c5fd31ac192e854bb30f9f4d07b176954014b5000f425e1dbba4ccca277defc9"
                        + "30b47cc34f8120028d0891ce4d4c0031226885d95c64aa948e5ed521b18d14955"
                        + "ce2ed3ccde07296f6c72910d1233ca839e9eb6de02d0b487296a5bbd72ce56e73"
                        + "e24879dc972faae2531e6e58f350fcf5c30753ea9ee72236b14f5fbf75041163b"
                        + "346c3fa3deb8a5b4101b44f1a14",
                actual.getString("rawSignatureHex"));
        assertEquals(actual.getString("rawSignatureHex"), recovered.getString("rawSignatureHex"));
    }

    @Test
    void api18RecoveredBackendDerivesInvalidJavaHmacCorrection07() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = importedLegacyJob(fixture);
        DeviceProfile profile = SignerOneClick.parseProfile(job.getJSONObject("device"), fixture);
        AndroidKeyStoreProvider.install(profile.getSigningKey(),
                profile.getLegacyRsaPrivateKeyPkcs8(), profile.getLegacyRsaPublicKeyX509());
        Context context = new Context(profile.getPackageName());
        for (Map.Entry<String, Map<String, String>> file : profile.getSharedPreferences().entrySet()) {
            for (Map.Entry<String, String> entry : file.getValue().entrySet()) {
                context.putSharedPreference(file.getKey(), entry.getKey(), entry.getValue());
            }
        }

        byte[] original;
        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root, profile)) {
            runner.onResume();
            original = runner.signNative(context, legacyParams(), new byte[32], 18);
        }

        Class<?> type = Class.forName("com.adjust.sdk.sig.RecoveredNativeBackend");
        java.lang.reflect.Constructor<?> constructor = type.getDeclaredConstructor(File.class, DeviceProfile.class);
        constructor.setAccessible(true);
        Object backend = constructor.newInstance(root, profile);
        java.lang.reflect.Method onResume = type.getDeclaredMethod("onResume");
        onResume.setAccessible(true);
        onResume.invoke(backend);
        java.lang.reflect.Method sign = type.getDeclaredMethod(
                "sign", Context.class, Object.class, byte[].class, int.class);
        sign.setAccessible(true);
        byte[] recovered = (byte[]) sign.invoke(backend, context, legacyParams(), new byte[32], 18);

        assertEquals("3b273362218b186a73e7349775b93f1137ca9fced8fcea894f6aecedf01c00238"
                        + "99e64fa01a02858940e7ee97549b9cf4c37a53c5f0f1febcf3c422ade40858063"
                        + "112e0bd439f05f560716c827a89d77f616008e5fffa1fa86fcb018a95beaa0b3e"
                        + "7151743735dd140df9d58c83dc54389dd45d5d502ed1d166d3f54e2a91e9d72f"
                        + "459b783a370e51db2fce5994556d1eed8d37174fb65ec98c89efc725dad17d15f"
                        + "338018e58efc7e42021e2738ef12", hex(original));
        assertEquals(hex(original), hex(recovered));
    }

    private static JSONObject importedLegacyJob(File fixture) throws Exception {
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 18);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        byte[] secret = DeviceProfile.hexToBytes("00112233445566778899aabbccddeeff");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        JSONObject legacyKeyStore = new JSONObject(true);
        legacyKeyStore.put("privateKeyPkcs8Hex", hex(pair.getPrivate().getEncoded()));
        legacyKeyStore.put("publicKeyX509Hex", hex(pair.getPublic().getEncoded()));
        device.put("legacyKeyStore", legacyKeyStore);
        JSONObject preferences = new JSONObject(true);
        JSONObject adjustKeys = new JSONObject(true);
        adjustKeys.put("encrypted_key", Base64.getEncoder().encodeToString(cipher.doFinal(secret)));
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
        for (byte item : value) result.append(String.format("%02x", item & 0xff));
        return result.toString();
    }

    private static File findProjectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "native-reimplementation/recovered_primitives.cpp").isFile()) return current;
        File parent = current.getParentFile();
        if (parent != null && new File(parent, "native-reimplementation/recovered_primitives.cpp").isFile()) {
            return parent;
        }
        throw new IllegalStateException("project root not found from " + current);
    }
}
