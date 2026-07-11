package local;

import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SignerResult {
    private static final Pattern AUTH_FIELD = Pattern.compile(
            "(signature|adj_signing_id|algorithm|headers_id|native_version)=\\\"([^\\\"]*)\\\"");

    private final SignerRequest.Version version;
    private final byte[] rawSignature;
    private final String signatureBase64;
    private final String authorization;
    private final Map<String, String> output;
    private final Map<String, String> metadata;

    private SignerResult(SignerRequest.Version version, Map<String, String> output, String authorization) {
        this.version = version;
        this.output = Collections.unmodifiableMap(new LinkedHashMap<>(output));
        this.authorization = authorization;
        Map<String, String> values = new LinkedHashMap<>();
        if (authorization != null) {
            Matcher matcher = AUTH_FIELD.matcher(authorization);
            while (matcher.find()) values.put(matcher.group(1), matcher.group(2));
        }
        for (String key : new String[]{"signature", "adj_signing_id", "algorithm", "headers_id", "native_version"}) {
            if (output.containsKey(key)) values.put(key, output.get(key));
        }
        metadata = Collections.unmodifiableMap(values);
        signatureBase64 = values.get("signature");
        rawSignature = signatureBase64 == null || signatureBase64.isEmpty()
                ? null : Base64.getDecoder().decode(signatureBase64);
    }

    static SignerResult v4(Map<String, String> output) {
        return new SignerResult(SignerRequest.Version.V4, output, null);
    }

    static SignerResult v5(Map<String, String> output) {
        return new SignerResult(SignerRequest.Version.V5, output, output.get("authorization"));
    }

    public SignerRequest.Version getVersion() { return version; }
    public boolean isSigned() { return rawSignature != null; }
    public byte[] getRawSignature() { return rawSignature == null ? null : rawSignature.clone(); }
    public String getSignatureBase64() { return signatureBase64; }
    public String getAuthorization() { return authorization; }
    public Map<String, String> getOutput() { return output; }
    public Map<String, String> getMetadata() { return metadata; }
    public String getHeadersId() { return metadata.get("headers_id"); }
    public String getAdjustSigningId() { return metadata.get("adj_signing_id"); }
    public String getAlgorithm() { return metadata.get("algorithm"); }
    public String getNativeVersion() { return metadata.get("native_version"); }
}
