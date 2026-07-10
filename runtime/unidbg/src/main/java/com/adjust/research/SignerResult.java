package com.adjust.research;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SignerResult {

    private final byte[] signature;
    private final LinkedHashMap<String, String> effectiveParameters;

    SignerResult(byte[] signature, LinkedHashMap<String, String> effectiveParameters) {
        this.signature = Arrays.copyOf(signature, signature.length);
        this.effectiveParameters = new LinkedHashMap<>(effectiveParameters);
    }

    public byte[] signature() {
        return Arrays.copyOf(signature, signature.length);
    }

    public Map<String, String> effectiveParameters() {
        return Collections.unmodifiableMap(effectiveParameters);
    }

    public Map<String, String> nativeMetadata() {
        LinkedHashMap<String, String> metadata = new LinkedHashMap<>();
        for (String key : new String[]{"headers_id", "adj_signing_id", "native_version", "algorithm"}) {
            if (effectiveParameters.containsKey(key)) {
                metadata.put(key, effectiveParameters.get(key));
            }
        }
        return Collections.unmodifiableMap(metadata);
    }
}

