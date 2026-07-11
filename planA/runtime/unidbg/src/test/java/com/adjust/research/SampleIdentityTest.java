package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SampleIdentityTest {

    @Test
    void embedsExactAdjustSignature362Arm64Sample() throws Exception {
        try (InputStream input = getClass().getResourceAsStream("/arm64-v8a/libsigner.so")) {
            assertNotNull(input, "arm64-v8a/libsigner.so must be packaged as a resource");
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.readAllBytes());
            assertEquals(
                    "fb279ea3d929928055c8cb90e3a3c213939869a51ffafe6d587a072c530c5736",
                    toHex(digest));
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            out.append(String.format("%02x", value & 0xff));
        }
        return out.toString();
    }
}
