package local;

import android.content.Context;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import java.io.File;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class ProbeCorrection07 {
    public static void main(String[] args) throws Exception {
        File root = new File(args[0]).getCanonicalFile();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        String contextPackage = args[1];
        int api = Integer.parseInt(args[2]);
        String mode = args.length > 3 ? args[3] : "minimal";
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", api);
        if (api < 23) {
            JSONObject legacy = new JSONObject(true);
            legacy.put("privateKeyPkcs8File", new File(root,
                    ".omx/legacy07/private.pkcs8.der").getCanonicalPath());
            legacy.put("publicKeyX509File", new File(root,
                    ".omx/legacy07/public.x509.der").getCanonicalPath());
            device.put("legacyKeyStore", legacy);
            JSONObject preferences = new JSONObject(true);
            JSONObject adjustKeys = new JSONObject(true);
            adjustKeys.put("encrypted_key", Files.readString(
                    new File(root, ".omx/legacy07/encrypted.b64").toPath()).trim());
            preferences.put("adjust_keys", adjustKeys);
            device.put("sharedPreferences", preferences);
        }
        DeviceProfile profile = SignerOneClick.parseProfile(device, fixture);
        byte[] input = new byte[32];
        Arrays.fill(input, (byte) 0x11);
        Map<String, String> params = new LinkedHashMap<>();
        if (mode.endsWith("full")) {
            JSONObject source = job.getJSONObject("sign").getJSONObject("parameters");
            for (String key : source.keySet()) params.put(key, source.getString(key));
        } else {
            params.put("a", "b");
            params.put("environment", "production");
        }
        params.put("activity_kind", "session");
        params.put("client_sdk", "android4.38.5");
        if (mode.startsWith("valid-")) {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] hmacKey = api >= 23 ? profile.getSigningKey()
                    : Files.readAllBytes(new File(root, ".omx/legacy07/secret.bin").toPath());
            mac.init(new SecretKeySpec(hmacKey, api >= 23 ? "HmacSHA256" : "AES"));
            input = mac.doFinal(params.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root, profile)) {
            runner.onResume();
            byte[] result = runner.signNative(new Context(contextPackage), params, input, api);
            System.out.printf("profilePackage=%s contextPackage=%s api=%d mode=%s params=%d resultLength=%d%n",
                    profile.getPackageName(), contextPackage, api, mode, params.size(),
                    result == null ? -1 : result.length);
            System.out.println("INPUT_HEX=" + hex(input));
            System.out.println("SIGNATURE_HEX=" + hex(result));
        }
    }

    private static String hex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
        return out.toString();
    }
}
