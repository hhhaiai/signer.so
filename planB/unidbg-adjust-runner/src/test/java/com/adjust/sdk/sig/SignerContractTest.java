package com.adjust.sdk.sig;

import android.content.Context;
import android.os.Build;
import local.android.AndroidKeyStoreProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerContractTest {
    private static final byte[] NATIVE_RESULT = new byte[]{1, 2, 3, 4};

    @BeforeEach
    void setUp() {
        Build.VERSION.SDK_INT = 35;
        AndroidKeyStoreProvider.installFromEnv();
        d.a = false;
    }

    @AfterEach
    void tearDown() throws Exception {
        try {
            Method clear = NativeLibHelper.class.getDeclaredMethod("clearBackendForTesting");
            clear.setAccessible(true);
            clear.invoke(null);
        } catch (NoSuchMethodException ignored) {
            // Expected while the production bridge has not been implemented yet.
        }
        d.a = false;
    }

    @Test
    void signerIsImplementedByThisProject() {
        String location = String.valueOf(Signer.class.getProtectionDomain().getCodeSource().getLocation());
        assertTrue(location.contains("/target/classes/"), location);
        assertEquals("3.67.0", Signer.getVersion());
    }

    @Test
    void v4CallsOnResumeThenSignsWithParsedJavaArguments() throws Exception {
        Capture capture = installCapture();
        Context context = new Context("com.example.app");
        Map<String, String> params = sampleParams();
        Map<String, String> expectedAtNative = new LinkedHashMap<>(params);
        expectedAtNative.put("activity_kind", "session");
        expectedAtNative.put("client_sdk", "android4.38.5");

        Signer signer = new Signer();
        signer.onResume();
        signer.sign(context, params, "session", "android4.38.5");

        assertEquals(1, capture.resumeCalls);
        assertEquals(1, capture.signCalls);
        assertSame(context, capture.context);
        assertEquals(expectedAtNative, capture.paramsAtNative);
        assertArrayEquals(hmac(expectedAtNative.toString().getBytes(StandardCharsets.UTF_8)), capture.input);
        assertEquals(35, capture.androidApi);
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), params.get("signature"));
        assertEquals("9", params.get("headers_id"));
        assertEquals("1400000", params.get("adj_signing_id"));
        assertEquals("3.67.0", params.get("native_version"));
        assertEquals("adj8", params.get("algorithm"));
        assertFalse(params.containsKey("activity_kind"));
        assertFalse(params.containsKey("client_sdk"));
    }

    @Test
    void v5BuildsAuthorizationAndCopiesOnlyDocumentedMaps() throws Exception {
        Capture capture = installCapture();
        Context context = new Context("com.example.app");
        Map<String, String> params = sampleParams();
        Map<String, String> request = new LinkedHashMap<>();
        request.put("activity_kind", "session");
        request.put("client_sdk", "android5.0.0");
        request.put("a", "not-b");
        request.put("network_payload", "payload");
        request.put("endpoint", "/session");
        request.put("ignored", "value");
        Map<String, String> output = new LinkedHashMap<>();

        Signer signer = new Signer();
        signer.onResume();
        signer.sign(context, params, request, output);

        assertEquals(1, capture.signCalls);
        assertEquals("Signaturesignature=\"AQIDBA==\",adj_signing_id=\"1400000\",algorithm=\"adj8\",headers_id=\"9\",native_version=\"3.67.0\"",
                output.get("authorization"));
        for (Map.Entry<String, String> entry : params.entrySet()) {
            assertEquals(entry.getValue(), output.get(entry.getKey()));
        }
        assertEquals("payload", output.get("network_payload"));
        assertEquals("/session", output.get("endpoint"));
        assertFalse(output.containsKey("ignored"));
        assertFalse(output.containsKey("activity_kind"));
        assertFalse(output.containsKey("client_sdk"));
        assertFalse(params.containsKey("signature"));
    }

    @Test
    void v5ModeBOnlyCopiesInputMapsWithoutCallingNative() throws Exception {
        Capture capture = installCapture();
        Map<String, String> params = sampleParams();
        Map<String, String> request = new LinkedHashMap<>();
        request.put("a", "b");
        request.put("network_payload", "payload");
        request.put("endpoint", "/session");
        Map<String, String> output = new LinkedHashMap<>();

        new Signer().sign(new Context("com.example.app"), params, request, output);

        assertEquals(0, capture.signCalls);
        assertFalse(output.containsKey("authorization"));
        for (Map.Entry<String, String> entry : params.entrySet()) {
            assertEquals(entry.getValue(), output.get(entry.getKey()));
        }
        assertEquals("payload", output.get("network_payload"));
        assertEquals("/session", output.get("endpoint"));
    }

    @Test
    void api22RsaWrappedKeyPathStillReachesNativeSign() throws Exception {
        Build.VERSION.SDK_INT = 22;
        Capture capture = installCapture();
        Map<String, String> params = sampleParams();

        Signer signer = new Signer();
        signer.onResume();
        signer.sign(new Context("com.example.legacy"), params, "session", "android4.38.5");

        assertEquals(1, capture.signCalls);
        assertEquals(32, capture.input.length);
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), params.get("signature"));
    }

    @Test
    void api35RegeneratesDeletedHmacAlias() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry("key2");
        Capture capture = installCapture();
        Map<String, String> params = sampleParams();

        new Signer().sign(new Context("com.example.modern"), params, "session", "android4.38.5");

        assertEquals(1, capture.signCalls);
        assertEquals(32, capture.input.length);
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), params.get("signature"));
    }

    @Test
    void apiBelow18LocksSignerAndNeverCallsNative() throws Exception {
        Build.VERSION.SDK_INT = 17;
        Capture capture = installCapture();
        Map<String, String> params = sampleParams();
        Signer signer = new Signer();

        assertThrows(b.class, () -> signer.sign(new Context("com.example.old"), params,
                "session", "android4.38.5"));

        assertTrue(d.a);
        assertEquals(0, capture.signCalls);
        assertFalse(params.containsKey("activity_kind"));
        assertFalse(params.containsKey("client_sdk"));
        signer.onResume();
        assertEquals(0, capture.resumeCalls);
    }

    private static Map<String, String> sampleParams() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", "2026-07-09T23:59:00.000+0800");
        params.put("gps_adid", "00000000-0000-0000-0000-000000000000");
        return params;
    }

    private static byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(configuredKey(), "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] configuredKey() {
        String hex = System.getenv("ADJUST_KEY_HEX");
        if (hex != null && !hex.isEmpty()) {
            String clean = hex.replaceAll("[^0-9a-fA-F]", "");
            byte[] out = new byte[clean.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }
        String text = System.getenv("ADJUST_KEY");
        return (text == null ? "local-adjust-keystore-key" : text).getBytes(StandardCharsets.UTF_8);
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
