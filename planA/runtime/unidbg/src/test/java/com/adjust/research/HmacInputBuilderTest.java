package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HmacInputBuilderTest {

    @Test
    void reproducesJavaMapToStringAndHmacSha256Boundary() {
        LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "test_token");
        parameters.put("activity_kind", "event");
        parameters.put("client_sdk", "android5.4.1");

        byte[] key = fromHex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        assertEquals(
                "{environment=sandbox, app_token=test_token, activity_kind=event, client_sdk=android5.4.1}",
                new String(HmacInputBuilder.mapBytes(parameters), StandardCharsets.UTF_8));
        assertEquals(
                "b710d0656c6315c6665ac48caca852ff1ad8c21f9bd527a3f961e1a349486f1a",
                toHex(HmacInputBuilder.hmacSha256(parameters, key)));
    }

    private static byte[] fromHex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", value & 0xff));
        }
        return out.toString();
    }
}
