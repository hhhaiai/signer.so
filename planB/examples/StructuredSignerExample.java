import local.DeviceProfile;
import local.SignerEngine;
import local.SignerRequest;
import local.SignerResult;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

public final class StructuredSignerExample {
    private StructuredSignerExample() {}

    public static void main(String[] args) throws Exception {
        File projectRoot = new File(args.length == 0 ? "." : args[0]).getCanonicalFile();
        DeviceProfile profile = DeviceProfile.fromEnvironment();

        Map<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "abc123");
        parameters.put("created_at", "2026-07-10T00:00:00.000+0800");
        parameters.put("gps_adid", "11111111-1111-1111-1111-111111111111");
        parameters.put("device_type", "phone");
        parameters.put("os_name", "android");
        parameters.put("os_version", String.valueOf(profile.getAndroidApi()));

        SignerResult result = SignerEngine.signOnce(projectRoot, profile,
                SignerRequest.v4(parameters, "session", "android4.38.5"));

        System.out.println("STRUCTURED_SIGNER_SIGNED=" + result.isSigned());
        System.out.println("STRUCTURED_SIGNER_RAW_LENGTH=" + result.getRawSignature().length);
        System.out.println("STRUCTURED_SIGNER_SIGNATURE_BASE64=" + result.getSignatureBase64());
        System.out.println("STRUCTURED_SIGNER_HEADERS_ID=" + result.getHeadersId());
        System.out.println("STRUCTURED_SIGNER_ADJ_SIGNING_ID=" + result.getAdjustSigningId());
        System.out.println("STRUCTURED_SIGNER_ALGORITHM=" + result.getAlgorithm());
        System.out.println("STRUCTURED_SIGNER_NATIVE_VERSION=" + result.getNativeVersion());
        System.out.println("STRUCTURED_SIGNER_OUTPUT=" + result.getOutput());
    }
}
