package local;

import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.d;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerEngineNativeIntegrationTest {
    private File copiedApk;

    @AfterEach
    void tearDown() throws Exception {
        NativeLibHelper.closeBridge();
        NativeLibHelper.clearConfiguration();
        d.a = false;
        if (copiedApk != null) {
            Files.deleteIfExists(copiedApk.toPath());
            Files.deleteIfExists(copiedApk.getParentFile().toPath());
        }
    }

    @Test
    void structuredDeviceProfileRunsRealNativeV4AndV5() throws Exception {
        File root = findProjectRoot();
        File baseApk = new File(root, "adjust-android-signature-3.67.0.aar");
        String packageName = "com.example.structured.device";
        DeviceProfile profile = DeviceProfile.builder()
                .packageName(packageName)
                .androidApi(35)
                .baseApk(baseApk)
                .certificateDer("structured-device-certificate".getBytes(StandardCharsets.UTF_8))
                .signingKey("structured-device-hmac-key".getBytes(StandardCharsets.UTF_8))
                .sensor("LSM6DSO", "STMicroelectronics", 1, 3)
                .display(1440, 3120, 560, 3.5f, 3.5f, 560.0f, 560.0f)
                .appUid(10234)
                .targetSdk(35)
                .nativeProcessId(4242)
                .nativeTimeSeconds(1_760_000_000L)
                .nativeGettimeofday(1_760_000_000L, 123_000L)
                .nativeClockGettime(1_760_000_000L, 123_000_000L)
                .nativeConnectRefusedEndpoint("127.0.0.1:27042")
                .build();

        SignerResult v4;
        SignerResult v4Repeat;
        SignerResult v5;
        try (SignerEngine engine = new SignerEngine(root, profile)) {
            v4 = engine.sign(SignerRequest.v4(params("00"), "session", "android4.38.5"));
            v4Repeat = engine.sign(SignerRequest.v4(params("00"), "session", "android4.38.5"));

            Map<String, String> request = new LinkedHashMap<>();
            request.put("activity_kind", "event");
            request.put("client_sdk", "android5.0.0");
            request.put("a", "not-b");
            request.put("network_payload", "payload");
            request.put("endpoint", "/event");
            v5 = engine.sign(SignerRequest.v5(params("01"), request));
        }

        assertSigned(v4);
        assertSigned(v4Repeat);
        assertArrayEquals(v4.getRawSignature(), v4Repeat.getRawSignature());
        assertSigned(v5);
        assertNotNull(v5.getAuthorization());
        assertEquals("payload", v5.getOutput().get("network_payload"));
        assertEquals("/event", v5.getOutput().get("endpoint"));

        copiedApk = new File(root, "unidbg-rootfs/data/app/" + packageName + "/base.apk");
        assertTrue(copiedApk.isFile());
        assertEquals(Files.size(baseApk.toPath()), Files.size(copiedApk.toPath()));
    }

    private static void assertSigned(SignerResult result) {
        assertTrue(result.isSigned());
        assertNotNull(result.getRawSignature());
        assertTrue(result.getRawSignature().length > 0);
        assertNotNull(result.getSignatureBase64());
        assertNotNull(result.getHeadersId());
        assertNotNull(result.getAdjustSigningId());
        assertNotNull(result.getAlgorithm());
        assertNotNull(result.getNativeVersion());
        assertFalse(result.getMetadata().isEmpty());
    }

    private static Map<String, String> params(String second) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-10T00:00:" + second + ".000+0800");
        params.put("gps_adid", "11111111-1111-1111-1111-111111111111");
        params.put("device_type", "phone");
        params.put("os_name", "android");
        params.put("os_version", "15");
        return params;
    }

    private static File findProjectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "adjust-android-signature-3.67.0").isDirectory()) return current;
        File parent = current.getParentFile();
        if (parent != null && new File(parent, "adjust-android-signature-3.67.0").isDirectory()) return parent;
        throw new IllegalStateException("project root not found from " + current);
    }
}
