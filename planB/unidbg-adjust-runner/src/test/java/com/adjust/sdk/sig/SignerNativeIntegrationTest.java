package com.adjust.sdk.sig;

import android.content.Context;
import android.os.Build;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SignerNativeIntegrationTest {
    @Test
    void oneOnResumeSupportsRepeatedRealNativeSignCalls() throws Exception {
        File root = findProjectRoot();
        String packageName = System.getenv().getOrDefault("ADJUST_PACKAGE", "com.adjust.test");
        File baseApk = new File(root, "unidbg-rootfs/data/app/" + packageName + "/base.apk");
        Files.createDirectories(baseApk.getParentFile().toPath());
        Files.copy(new File(root, "adjust-android-signature-3.67.0.aar").toPath(), baseApk.toPath(),
                StandardCopyOption.REPLACE_EXISTING);

        Build.VERSION.SDK_INT = 35;
        d.a = false;
        NativeLibHelper.configure(root);
        try {
            Signer signer = new Signer();
            signer.onResume();

            Map<String, String> first = params("2026-07-10T00:00:00.000+0800");
            signer.sign(new Context(packageName), first, "session", "android4.38.5");
            assertSigned(first);

            Map<String, String> second = params("2026-07-10T00:00:01.000+0800");
            signer.sign(new Context(packageName), second, "event", "android4.38.5");
            assertSigned(second);
        } finally {
            NativeLibHelper.closeBridge();
            d.a = false;
        }
    }

    private static void assertSigned(Map<String, String> params) {
        assertNotNull(params.get("signature"));
        assertNotNull(params.get("adj_signing_id"));
        assertNotNull(params.get("headers_id"));
        assertNotNull(params.get("algorithm"));
        assertNotNull(params.get("native_version"));
        assertFalse(params.containsKey("activity_kind"));
        assertFalse(params.containsKey("client_sdk"));
    }

    private static Map<String, String> params(String createdAt) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("environment", "sandbox");
        params.put("app_token", "abc123");
        params.put("created_at", createdAt);
        params.put("gps_adid", "00000000-0000-0000-0000-000000000000");
        params.put("device_type", "phone");
        params.put("os_name", "android");
        params.put("os_version", "14");
        return params;
    }

    private static File findProjectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "adjust-android-signature-3.67.0").isDirectory()) {
            return current;
        }
        File parent = current.getParentFile();
        if (parent != null && new File(parent, "adjust-android-signature-3.67.0").isDirectory()) {
            return parent;
        }
        throw new IllegalStateException("project root not found from " + current);
    }
}
