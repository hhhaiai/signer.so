package com.adjust.research;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Objects;

public final class HmacInputBuilder {

    private HmacInputBuilder() {
    }

    public static byte[] mapBytes(Map<String, String> parameters) {
        Objects.requireNonNull(parameters, "parameters");
        return parameters.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static byte[] hmacSha256(Map<String, String> parameters, byte[] key) {
        Objects.requireNonNull(key, "key");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(mapBytes(parameters));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is unavailable", e);
        }
    }
}
