package android.security.keystore;

import java.security.spec.AlgorithmParameterSpec;

public final class KeyGenParameterSpec implements AlgorithmParameterSpec {
    private final String alias;
    private final int purposes;

    private KeyGenParameterSpec(String alias, int purposes) {
        this.alias = alias;
        this.purposes = purposes;
    }

    public String getKeystoreAlias() { return alias; }
    public int getPurposes() { return purposes; }

    public static final class Builder {
        private final String alias;
        private final int purposes;

        public Builder(String alias, int purposes) {
            this.alias = alias;
            this.purposes = purposes;
        }

        public KeyGenParameterSpec build() {
            return new KeyGenParameterSpec(alias, purposes);
        }
    }
}
