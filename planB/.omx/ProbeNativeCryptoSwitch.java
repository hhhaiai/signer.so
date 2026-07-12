package local;

import android.content.Context;
import java.io.File;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public final class ProbeNativeCryptoSwitch {
    public static void main(String[] args) throws Exception {
        File root = new File(args[0]).getCanonicalFile();
        int api = Integer.parseInt(args[1]);
        int inputLength = Integer.parseInt(args[2]);
        int inputByte = Integer.decode(args[3]);
        byte[] input = new byte[inputLength];
        Arrays.fill(input, (byte) inputByte);

        Map<String, String> params = new LinkedHashMap<>();
        params.put("a", "b");
        params.put("environment", "production");
        params.put("activity_kind", "session");
        params.put("client_sdk", "android4.38.5");

        try (AdjustSignatureRunner runner = new AdjustSignatureRunner(root)) {
            runner.onResume();
            byte[] result = runner.signNative(new Context("com.example.qbdi.reference"), params, input, api);
            System.out.printf("api=%d inputLength=%d inputByte=0x%02x resultLength=%d sha256=%s algorithm=%s%n",
                    api, inputLength, inputByte & 0xff, result == null ? -1 : result.length,
                    result == null ? "null" : hex(MessageDigest.getInstance("SHA-256").digest(result)),
                    params.get("algorithm"));
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) out.append(String.format("%02x", value & 0xff));
        return out.toString();
    }
}
