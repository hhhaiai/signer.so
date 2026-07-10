package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerCliTest {

    @Test
    void parsesHexAndFormatsUppercase() {
        byte[] value = SignerCli.parseHex("0x00a1FF", "fixture");
        assertArrayEquals(new byte[]{0, (byte) 0xa1, (byte) 0xff}, value);
        assertEquals("00A1FF", SignerCli.toUpperHex(value));
    }

    @Test
    void rejectsMalformedHexWithoutStartingNativeRuntime() {
        ByteArrayOutputStream error = new ByteArrayOutputStream();
        int exitCode = SignerCli.run(
                new String[]{"--param", "environment=sandbox", "--hmac-key-hex", "xyz"},
                new PrintStream(new ByteArrayOutputStream()),
                new PrintStream(error));
        assertEquals(64, exitCode);
        assertTrue(error.toString(StandardCharsets.UTF_8).contains("hex"));
    }

    @Test
    void parsesFlatRequestJsonInFileOrder() throws Exception {
        Path request = Files.createTempFile("libsigner-request-", ".json");
        Files.writeString(request,
                "{\"environment\":\"sandbox\",\"app_token\":\"t\","
                        + "\"activity_kind\":\"event\",\"client_sdk\":\"android5.4.1\"}");
        SignerCli.Options options = SignerCli.Options.parse(
                new String[]{"--request-json", request.toString(), "--output", "base64"});
        assertEquals("{environment=sandbox, app_token=t}", options.parameters().toString());
        assertEquals(SignerCli.OutputMode.BASE64, options.outputMode());
        Files.deleteIfExists(request);
    }

    @Test
    void signsWithExplicitFixtureKeyAndHexOutput() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exitCode = SignerCli.run(
                new String[]{
                        "--param", "environment=sandbox",
                        "--param", "app_token=test_token",
                        "--param", "event_token=event_123",
                        "--hmac-key-hex",
                        "000102030405060708090a0b0c0d0e0f"
                                + "101112131415161718191a1b1c1d1e1f",
                        "--output", "hex"
                },
                new PrintStream(output),
                new PrintStream(error));

        String text = output.toString(StandardCharsets.UTF_8);
        assertEquals(0, exitCode, error.toString(StandardCharsets.UTF_8));
        assertTrue(text.contains("signature_length=304"));
        assertTrue(text.matches("(?s).*signature_hex=[0-9A-F]{608}.*"));
        assertFalse(text.contains("signature_base64="));
    }

    @Test
    void signsWithCallerProvidedHmacAndBase64Output() {
        LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "test_token");
        parameters.put("event_token", "event_123");
        parameters.put("activity_kind", "event");
        parameters.put("client_sdk", "android5.4.1");
        byte[] key = SignerCli.parseHex(
                "000102030405060708090a0b0c0d0e0f"
                        + "101112131415161718191a1b1c1d1e1f",
                "fixture key");
        String hmac = SignerCli.toUpperHex(HmacInputBuilder.hmacSha256(parameters, key));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exitCode = SignerCli.run(
                new String[]{
                        "--param", "environment=sandbox",
                        "--param", "app_token=test_token",
                        "--param", "event_token=event_123",
                        "--hmac-hex", hmac,
                        "--output", "base64"
                },
                new PrintStream(output),
                new PrintStream(error));

        String text = output.toString(StandardCharsets.UTF_8);
        assertEquals(0, exitCode, error.toString(StandardCharsets.UTF_8));
        assertTrue(text.contains("signature_length=304"));
        assertTrue(text.matches("(?s).*signature_base64=[A-Za-z0-9+/]+={0,2}.*"));
        assertFalse(text.contains("signature_hex="));
        assertTrue(error.toString(StandardCharsets.UTF_8).contains("built-in fixture key2"));
    }
}
