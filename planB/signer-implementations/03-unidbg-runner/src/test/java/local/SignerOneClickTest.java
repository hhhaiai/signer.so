package local;

import android.content.Context;
import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.d;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerOneClickTest {
    private static final byte[] NATIVE_RESULT = new byte[]{5, 6, 7, 8};

    @AfterEach
    void tearDown() throws Exception {
        Method clear = NativeLibHelper.class.getDeclaredMethod("clearBackendForTesting");
        clear.setAccessible(true);
        clear.invoke(null);
        d.a = false;
    }

    @Test
    void oneJsonProducesStructuredV4SignerJson() throws Exception {
        Capture capture = installCapture();
        String json = "{"
                + "\"device\":{"
                + "\"packageName\":\"com.example.oneclick\","
                + "\"androidApi\":35,"
                + "\"certificateText\":\"one-click-cert\","
                + "\"signingKeyText\":\"one-click-key\","
                + "\"build\":{\"MODEL\":\"Pixel 9 Pro\",\"VERSION.RELEASE\":\"15\"},"
                + "\"systemProperties\":{\"ro.product.model\":\"Pixel 9 Pro\"},"
                + "\"settings\":{\"secure\":{\"android_id\":\"abc123\"}},"
                + "\"sharedPreferences\":{\"adjust_keys\":{\"encrypted_key\":\"seed\"}},"
                + "\"locale\":\"zh-CN\",\"timezone\":\"Asia/Shanghai\","
                + "\"sensors\":[{\"name\":\"LSM6DSO\",\"vendor\":\"ST\",\"type\":1,\"version\":3}],"
                + "\"jni\":{\"strings\":{\"android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;\":\"imei\"}}"
                + "},"
                + "\"sign\":{\"version\":\"v4\",\"activityKind\":\"session\",\"clientSdk\":\"android4.38.5\","
                + "\"parameters\":{\"environment\":\"sandbox\",\"app_token\":\"abc123\",\"created_at\":\"2026-07-10T00:00:00.000+0800\"}}"
                + "}";

        String resultJson = SignerOneClick.run(projectRoot(), json, projectRoot());
        JSONObject result = JSON.parseObject(resultJson);

        assertTrue(result.getBooleanValue("signed"));
        assertEquals("V4", result.getString("version"));
        assertEquals(Base64.getEncoder().encodeToString(NATIVE_RESULT), result.getString("signatureBase64"));
        assertEquals("3.67.0", result.getJSONObject("metadata").getString("native_version"));
        assertEquals("com.example.oneclick", capture.context.getPackageName());
        assertEquals("seed", capture.context.getSharedPreferences("adjust_keys", Context.MODE_PRIVATE)
                .getString("encrypted_key", null));
        assertEquals(35, capture.androidApi);
        assertEquals(1, capture.resumeCalls);
        assertEquals(1, capture.signCalls);
    }

    @Test
    void oneJsonSupportsV5RequestMap() throws Exception {
        installCapture();
        String json = "{\"device\":{\"signingKeyText\":\"key\"},"
                + "\"sign\":{\"version\":\"v5\","
                + "\"parameters\":{\"environment\":\"sandbox\",\"app_token\":\"abc123\"},"
                + "\"request\":{\"activity_kind\":\"session\",\"client_sdk\":\"android5.0.0\",\"a\":\"not-b\",\"endpoint\":\"/session\"}}}";

        JSONObject result = JSON.parseObject(SignerOneClick.run(projectRoot(), json, projectRoot()));

        assertEquals("V5", result.getString("version"));
        assertTrue(result.getBooleanValue("signed"));
        assertTrue(result.getString("authorization").startsWith("Signaturesignature=\""));
        assertEquals("/session", result.getJSONObject("output").getString("endpoint"));
    }

    @Test
    void parsesNativeRuntimeAndRejectsMismatchedExpectedResult() throws Exception {
        installCapture();
        String json = "{"
                + "\"device\":{\"signingKeyText\":\"key\",\"runtime\":{"
                + "\"processId\":4242,\"timeSeconds\":1760000000,"
                + "\"gettimeofday\":{\"seconds\":1760000001,\"microseconds\":123456},"
                + "\"clockGettime\":{\"seconds\":1760000002,\"nanoseconds\":987654321},"
                + "\"urandomHex\":\"0001020304050607\","
                + "\"backend\":\"recovered\",\"correction05Enabled\":false,"
                + "\"correctionCodes\":[\"2b\",\"0x36\",37],"
                + "\"signerCodeTrampolineDetected\":true,"
                + "\"network\":{\"connectRefusedEndpoints\":[\"127.0.0.1:27042\"],"
                + "\"localSocketResponses\":{\"/dev/socket/fwmarkd\":{\"hex\":\"00000000\"}}}}},"
                + "\"sign\":{\"version\":\"v4\",\"activityKind\":\"session\","
                + "\"clientSdk\":\"android4.38.5\",\"parameters\":{"
                + "\"environment\":\"sandbox\",\"app_token\":\"abc123\"}}}"
                ;

        JSONObject root = JSON.parseObject(json);
        DeviceProfile profile = SignerOneClick.parseProfile(root.getJSONObject("device"), projectRoot());
        assertEquals(4242, profile.getNativeProcessId());
        assertEquals(1_760_000_000L, profile.getNativeTimeSeconds());
        assertEquals(1_760_000_001L, profile.getNativeGettimeofdaySeconds());
        assertEquals(123_456L, profile.getNativeGettimeofdayMicroseconds());
        assertEquals(1_760_000_002L, profile.getNativeClockGettimeSeconds());
        assertEquals(987_654_321L, profile.getNativeClockGettimeNanoseconds());
        assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5, 6, 7}, profile.getNativeUrandomBytes());
        assertEquals("recovered", profile.getNativeBackend());
        assertEquals(false, profile.getNativeCorrection05Enabled());
        assertEquals(java.util.List.of(0x2b, 0x36, 37), profile.getNativeCorrectionCodes());
        assertTrue(profile.isNativeSignerCodeTrampolineDetected());
        assertEquals(Set.of("127.0.0.1:27042"), profile.getNativeConnectRefusedEndpoints());
        assertArrayEquals(new byte[]{0, 0, 0, 0},
                profile.getNativeLocalSocketResponses().get("/dev/socket/fwmarkd"));

        JSONObject expected = JSON.parseObject(SignerOneClick.run(projectRoot(), json, projectRoot()));
        root.put("expectedResult", expected);
        assertEquals(expected, JSON.parseObject(SignerOneClick.run(
                projectRoot(), root.toJSONString(), projectRoot())));

        expected.put("rawSignatureHex", "00");
        IllegalStateException mismatch = assertThrows(IllegalStateException.class, () ->
                SignerOneClick.run(projectRoot(), root.toJSONString(), projectRoot()));
        assertTrue(mismatch.getMessage().contains("expectedResult mismatch"));
        assertTrue(mismatch.getMessage().contains("rawSignatureHex"));

        Path expectedFile = Files.createTempFile("signer-expected-", ".json");
        try {
            expected.put("rawSignatureHex", "05060708");
            Files.writeString(expectedFile, expected.toJSONString());
            root.remove("expectedResult");
            root.put("expectedResultFile", expectedFile.toString());
            assertEquals(expected, JSON.parseObject(SignerOneClick.run(
                    projectRoot(), root.toJSONString(), projectRoot())));

            expected.put("rawSignatureHex", "00");
            Files.writeString(expectedFile, expected.toJSONString());
            assertThrows(IllegalStateException.class, () ->
                    SignerOneClick.run(projectRoot(), root.toJSONString(), projectRoot()));
        } finally {
            Files.deleteIfExists(expectedFile);
        }
    }

    @Test
    void parsesNativeFilesystemFilesAndMissingPaths() throws Exception {
        Path cpuInfo = Files.createTempFile("signer-cpuinfo-", ".txt");
        try {
            Files.writeString(cpuInfo, "processor\\t: 0\\n");
            String json = "{\"signingKeyText\":\"key\",\"filesystem\":{"
                    + "\"files\":{"
                    + "\"/proc/cpuinfo\":{\"file\":\"" + cpuInfo + "\"},"
                    + "\"/proc/self/cmdline\":{\"text\":\"com.example.app\\u0000\"},"
                    + "\"/proc/random\":{\"hex\":\"00010203\"}},"
                    + "\"missing\":[\"/proc/version\"]}}";

            DeviceProfile profile = SignerOneClick.parseProfile(JSON.parseObject(json), projectRoot());

            assertArrayEquals("processor\\t: 0\\n".getBytes(StandardCharsets.UTF_8),
                    profile.getNativeFiles().get("/proc/cpuinfo"));
            assertArrayEquals("com.example.app\0".getBytes(StandardCharsets.UTF_8),
                    profile.getNativeFiles().get("/proc/self/cmdline"));
            assertArrayEquals(new byte[]{0, 1, 2, 3}, profile.getNativeFiles().get("/proc/random"));
            assertTrue(profile.getNativeMissingPaths().contains("/proc/version"));
        } finally {
            Files.deleteIfExists(cpuInfo);
        }
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

    private static File projectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "adjust-android-signature-3.67.0").isDirectory()) return current;
        return current.getParentFile();
    }

    private static final class Capture implements InvocationHandler {
        int resumeCalls;
        int signCalls;
        Context context;
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
                    androidApi = (Integer) args[3];
                    @SuppressWarnings("unchecked")
                    Map<String, String> params = (Map<String, String>) args[1];
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
