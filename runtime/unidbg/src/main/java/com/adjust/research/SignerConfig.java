package com.adjust.research;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

public final class SignerConfig {

    public static final String DEFAULT_PACKAGE_NAME = "com.adjust.fixture";
    public static final int DEFAULT_SDK_LEVEL = 23;

    private final String packageName;
    private final int sdkLevel;
    private final byte[] hmacKey;
    private final byte[] hmacOverride;
    private final byte[] certificateBytes;
    private final boolean verbose;

    public SignerConfig(String packageName, int sdkLevel, byte[] hmacKey, byte[] hmacOverride, boolean verbose) {
        this(packageName, sdkLevel, hmacKey, hmacOverride,
                "adjust-signature-fixture-certificate".getBytes(StandardCharsets.UTF_8), verbose);
    }

    public SignerConfig(
            String packageName,
            int sdkLevel,
            byte[] hmacKey,
            byte[] hmacOverride,
            byte[] certificateBytes,
            boolean verbose) {
        this.packageName = Objects.requireNonNull(packageName, "packageName");
        if (sdkLevel < 23) {
            throw new IllegalArgumentException(
                    "sdkLevel must be at least 23 for this local harness; "
                            + "Adjust Signature 3.62.0 SDK 18-22 requires the legacy "
                            + "SharedPreferences/RSA AndroidKeyStore bridge");
        }
        if (hmacKey == null && hmacOverride == null) {
            throw new IllegalArgumentException("either hmacKey or hmacOverride is required");
        }
        this.sdkLevel = sdkLevel;
        this.hmacKey = cloneOrNull(hmacKey);
        this.hmacOverride = cloneOrNull(hmacOverride);
        this.certificateBytes = Arrays.copyOf(
                Objects.requireNonNull(certificateBytes, "certificateBytes"), certificateBytes.length);
        this.verbose = verbose;
    }

    public String packageName() {
        return packageName;
    }

    public int sdkLevel() {
        return sdkLevel;
    }

    public byte[] hmacKey() {
        return cloneOrNull(hmacKey);
    }

    public byte[] hmacOverride() {
        return cloneOrNull(hmacOverride);
    }

    public byte[] certificateBytes() {
        return Arrays.copyOf(certificateBytes, certificateBytes.length);
    }

    public boolean verbose() {
        return verbose;
    }

    @Override
    public String toString() {
        return "SignerConfig{" +
                "packageName='" + packageName + '\'' +
                ", sdkLevel=" + sdkLevel +
                ", hmacKeyLength=" + (hmacKey == null ? 0 : hmacKey.length) +
                ", hmacOverrideLength=" + (hmacOverride == null ? 0 : hmacOverride.length) +
                ", certificateLength=" + certificateBytes.length +
                ", verbose=" + verbose +
                '}';
    }

    private static byte[] cloneOrNull(byte[] value) {
        return value == null ? null : Arrays.copyOf(value, value.length);
    }
}
