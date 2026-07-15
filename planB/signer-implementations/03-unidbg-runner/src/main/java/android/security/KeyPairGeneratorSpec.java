package android.security;

import android.content.Context;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

public final class KeyPairGeneratorSpec implements AlgorithmParameterSpec {
    public static final class Builder {
        public Builder(Context context) {}
        public Builder setAlias(String alias) { return this; }
        public Builder setSubject(X500Principal subject) { return this; }
        public Builder setSerialNumber(BigInteger serialNumber) { return this; }
        public Builder setStartDate(Date startDate) { return this; }
        public Builder setEndDate(Date endDate) { return this; }
        public Builder setKeySize(int keySize) { return this; }
        public KeyPairGeneratorSpec build() { return new KeyPairGeneratorSpec(); }
    }
}
