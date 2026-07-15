package android.content.pm;

public class SigningInfo {
    private final Signature signature;

    public SigningInfo(Signature signature) {
        this.signature = signature;
    }

    public boolean hasMultipleSigners() {
        return false;
    }

    public Signature[] getApkContentsSigners() {
        return new Signature[]{signature};
    }

    public Signature[] getSigningCertificateHistory() {
        return new Signature[]{signature};
    }
}
