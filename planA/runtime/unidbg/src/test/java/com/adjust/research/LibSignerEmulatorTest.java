package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LibSignerEmulatorTest {

    private static final byte[] FIXED_HMAC_KEY = fromHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    @Test
    void loadsExactModuleAndFindsBothStaticJniExports() throws Exception {
        try (LibSignerEmulator signer = new LibSignerEmulator(config())) {
            assertNotNull(signer.module().findSymbolByName(
                    "Java_com_adjust_sdk_sig_NativeLibHelper_nSign"));
            assertNotNull(signer.module().findSymbolByName(
                    "Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume"));
        }
    }

    @Test
    void returnsNonEmptyNativeSignatureForDeterministicFixture() throws Exception {
        LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "test_token");
        parameters.put("event_token", "event_123");

        SignerRequest request = new SignerRequest(parameters, "event", "android5.4.1");
        try (LibSignerEmulator signer = new LibSignerEmulator(config())) {
            Path tracePath = Files.createTempFile("libsigner-unidbg-", ".jsonl");
            byte[] signature;
            try (TraceRecorder ignored = signer.trace(tracePath, 16)) {
                signature = signer.sign(request);
            }
            assertNotNull(signature);
            assertTrue(signature.length > 0, "native nSign must return a non-empty byte array");
            List<String> trace = Files.readAllLines(tracePath);
            assertFalse(trace.isEmpty());
            assertTrue(trace.size() <= 16, "trace must honor maxEvents");
            assertTrue(trace.stream().allMatch(line ->
                    line.contains("\"schema\":\"libsigner.trace/v1\"")
                            && line.contains("\"backend\":\"unidbg\"")
                            && line.contains("\"event\":\"instruction\"")
                            && line.contains("\"module\":\"libsigner.so\"")));
            assertTrue(trace.stream().anyMatch(
                    line -> line.contains("\"relative_pc\":\"0xa95ac\"")));
            Files.deleteIfExists(tracePath);
        }
    }

    @Test
    void signsThroughSdk30SigningInfoPathWithoutDeviceDependencies() throws Exception {
        LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "test_token");
        parameters.put("event_token", "event_123");

        SignerRequest request = new SignerRequest(parameters, "event", "android5.4.1");
        try (LibSignerEmulator signer = new LibSignerEmulator(config(30))) {
            SignerResult result = signer.signDetailed(request);
            assertEquals(304, result.signature().length);
            assertEquals("3.62.0", result.nativeMetadata().get("native_version"));
            assertEquals("adj7", result.nativeMetadata().get("algorithm"));
        }
    }

    private static SignerConfig config() {
        return config(23);
    }

    private static SignerConfig config(int sdkLevel) {
        return new SignerConfig(
                "com.adjust.fixture", sdkLevel, FIXED_HMAC_KEY, null, false);
    }

    private static byte[] fromHex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
