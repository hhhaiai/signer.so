package local;

import android.content.Context;
import android.os.Build;
import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.d;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerEngineTest {
    private static final byte[] KEY = "profile-hmac-key".getBytes(StandardCharsets.UTF_8);
    private static final byte[] NATIVE_RESULT = new byte[]{1, 2, 3, 4};

    @BeforeEach
    void setUp() {
        Build.VERSION.SDK_INT = 35;
        d.a = false;
    }

    @AfterEach
    void tearDown() throws Exception {
        Method clear = NativeLibHelper.class.getDeclaredMethod("clearBackendForTesting");
        clear.setAccessible(true);
        clear.invoke(null);
        d.a = false;
    }

    @Test
    void deviceProfileDefensivelyCopiesSensitiveBytes() {
        byte[] certificate = new byte[]{10, 11, 12};
        byte[] key = new byte[]{20, 21, 22};

        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.example.real")
                .androidApi(34)
                .certificateDer(certificate)
                .signingKey(key)
                .sensor("LSM6DSO", "STMicroelectronics", 1, 3)
                .display(1440, 3120, 560, 3.5f, 3.5f, 560.0f, 560.0f)
                .appUid(10234)
                .targetSdk(34)
                .build();

        certificate[0] = 99;
        key[0] = 99;

        assertEquals("com.example.real", profile.getPackageName());
        assertEquals(34, profile.getAndroidApi());
        assertArrayEquals(new byte[]{10, 11, 12}, profile.getCertificateDer());
        assertArrayEquals(new byte[]{20, 21, 22}, profile.getSigningKey());
        assertNotSame(profile.getCertificateDer(), profile.getCertificateDer());
        assertNotSame(profile.getSigningKey(), profile.getSigningKey());
        assertEquals("LSM6DSO", profile.getSensorName());
        assertEquals(1440, profile.getDisplayWidth());
        assertEquals(10234, profile.getAppUid());
        assertEquals(34, profile.getTargetSdk());
    }

    @Test
    void engineAutomaticallyResumesOnceAndReturnsStructuredV4Results() throws Exception {
        Capture capture = installCapture();
        DeviceProfile profile = DeviceProfile.builder()
                .packageName("com.example.real")
                .androidApi(35)
                .signingKey(KEY)
                .build();

        SignerResult first;
        SignerResult second;
        try (SignerEngine engine = new SignerEngine(projectRoot(), profile)) {
            first = engine.sign(SignerRequest.v4(params("00"), "session", "android4.38.5"));
            second = engine.sign(SignerRequest.v4(params("01"), "event", "android4.38.5"));
        }

        assertEquals(1, capture.resumeCalls);
        assertEquals(2, capture.signCalls);
        assertEquals("com.example.real", capture.context.getPackageName());
        assertEquals(35, capture.androidApi);
        assertArrayEquals(hmac(KEY, capture.paramsAtNative.toString().getBytes(StandardCharsets.UTF_8)), capture.input);
        assertTrue(first.isSigned());
        assertArrayEquals(NATIVE_RESULT, first.getRawSignature());
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), first.getSignatureBase64());
        assertEquals("9", first.getHeadersId());
        assertEquals("1400000", first.getAdjustSigningId());
        assertEquals("adj8", first.getAlgorithm());
        assertEquals("3.67.0", first.getNativeVersion());
        assertEquals(first.getSignatureBase64(), first.getOutput().get("signature"));
        assertFalse(first.getOutput().containsKey("activity_kind"));
        assertFalse(first.getOutput().containsKey("client_sdk"));
        assertTrue(second.isSigned());
    }

    @Test
    void engineReturnsV5AuthorizationAndDecodedSignature() throws Exception {
        Capture capture = installCapture();
        DeviceProfile profile = DeviceProfile.builder().signingKey(KEY).build();
        Map<String, String> request = new LinkedHashMap<>();
        request.put("activity_kind", "session");
        request.put("client_sdk", "android5.0.0");
        request.put("a", "not-b");
        request.put("network_payload", "payload");
        request.put("endpoint", "/session");

        SignerResult result = SignerEngine.signOnce(
                projectRoot(), profile, SignerRequest.v5(params("02"), request));

        assertEquals(1, capture.resumeCalls);
        assertEquals(1, capture.signCalls);
        assertTrue(result.isSigned());
        assertArrayEquals(NATIVE_RESULT, result.getRawSignature());
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), result.getSignatureBase64());
        assertEquals("9", result.getHeadersId());
        assertEquals("1400000", result.getAdjustSigningId());
        assertEquals("adj8", result.getAlgorithm());
        assertEquals("3.67.0", result.getNativeVersion());
        assertEquals("payload", result.getOutput().get("network_payload"));
        assertEquals("/session", result.getOutput().get("endpoint"));
        assertEquals(result.getAuthorization(), result.getOutput().get("authorization"));
    }

    private static Capture installCapture() throws Exception {
        Class<?> backendType = Class.forName("com.adjust.sdk.sig.NativeLibHelper$NativeBackend");
        Capture capture = new Capture();
        Object backend = Proxy.newProxyInstance(backendType.getClassLoader(), new Class<?>[]{backendType}, capture);
        Method install = NativeLibHelper.class.getDeclaredMethod("setBackendForTesting", backendType);
        install.setAccessible(true);
        install.invoke(null, backend);
        return capture;
    }

    private static Map<String, String> params(String second) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-10T00:00:" + second + ".000+0800");
        params.put("gps_adid", "11111111-1111-1111-1111-111111111111");
        return params;
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static File projectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "adjust-android-signature-3.67.0").isDirectory()) return current;
        return current.getParentFile();
    }

    private static final class Capture implements InvocationHandler {
        int resumeCalls;
        int signCalls;
        Context context;
        Map<String, String> paramsAtNative;
        byte[] input;
        int androidApi;

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            switch (method.getName()) {
                case "onResume":
                    resumeCalls++;
                    return null;
                case "sign":
                    signCalls++;
                    context = (Context) args[0];
                    @SuppressWarnings("unchecked")
                    Map<String, String> params = (Map<String, String>) args[1];
                    paramsAtNative = new LinkedHashMap<>(params);
                    input = ((byte[]) args[2]).clone();
                    androidApi = (Integer) args[3];
                    params.put("headers_id", "9");
                    params.put("adj_signing_id", "1400000");
                    params.put("native_version", "3.67.0");
                    params.put("algorithm", "adj8");
                    return NATIVE_RESULT.clone();
                case "close":
                    return null;
                case "toString":
                    return "CaptureBackend";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    throw new AssertionError("unexpected backend method: " + method);
            }
        }
    }
}
