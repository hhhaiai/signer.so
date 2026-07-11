package com.adjust.research;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignerConfigTest {

    @Test
    void rejectsLegacySdkWithoutSharedPreferencesAndRsaKeyStoreBridge() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> new SignerConfig(
                        "com.adjust.fixture", 22, new byte[32], null, false));

        assertTrue(error.getMessage().contains("23"));
    }
}
