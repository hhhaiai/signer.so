package local;

import android.content.Context;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import local.android.AndroidKeyStoreProvider;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class ProbeLegacyCorrection07 {
    public static void main(String[] args) throws Exception {
        File root = new File(args[0]).getCanonicalFile();
        boolean valid = "valid".equals(args[1]);
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 18);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        byte[] secret = DeviceProfile.hexToBytes("00112233445566778899aabbccddeeff");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
        JSONObject legacy = new JSONObject(true);
        legacy.put("privateKeyPkcs8Hex", hex(pair.getPrivate().getEncoded()));
        legacy.put("publicKeyX509Hex", hex(pair.getPublic().getEncoded()));
        device.put("legacyKeyStore", legacy);
        JSONObject preferences = new JSONObject(true);
        JSONObject adjustKeys = new JSONObject(true);
        adjustKeys.put("encrypted_key", Base64.getEncoder().encodeToString(cipher.doFinal(secret)));
        preferences.put("adjust_keys", adjustKeys);
        device.put("sharedPreferences", preferences);
        DeviceProfile profile = SignerOneClick.parseProfile(device, fixture);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("a", "b");
        params.put("environment", "production");
        params.put("activity_kind", "session");
        params.put("client_sdk", "android4.38.5");
        byte[] input = new byte[32];
        if (valid) {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "AES"));
            input = mac.doFinal(params.toString().getBytes(StandardCharsets.UTF_8));
        }
        AndroidKeyStoreProvider.install(profile.getSigningKey(),
                profile.getLegacyRsaPrivateKeyPkcs8(), profile.getLegacyRsaPublicKeyX509());
        Context context = new Context(profile.getPackageName());
        for (Map.Entry<String, Map<String, String>> file : profile.getSharedPreferences().entrySet()) {
            for (Map.Entry<String, String> entry : file.getValue().entrySet()) {
                context.putSharedPreference(file.getKey(), entry.getKey(), entry.getValue());
            }
        }
        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root, profile)) {
            runner.onResume();
            byte[] result = runner.signNative(context, params, input, 18);
            System.out.println("MODE=" + args[1]);
            System.out.println("INPUT_HEX=" + hex(input));
            System.out.println("SIGNATURE_HEX=" + hex(result));
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format("%02x", value & 0xff));
        return result.toString();
    }
}
