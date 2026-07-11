package local;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SignerRequest {
    public enum Version { V4, V5 }

    private final Version version;
    private final Map<String, String> parameters;
    private final String activityKind;
    private final String clientSdk;
    private final Map<String, String> request;

    private SignerRequest(Version version, Map<String, String> parameters,
                          String activityKind, String clientSdk, Map<String, String> request) {
        this.version = version;
        this.parameters = immutableCopy(parameters, "parameters");
        this.activityKind = activityKind;
        this.clientSdk = clientSdk;
        this.request = request == null ? Collections.emptyMap() : immutableCopy(request, "request");
    }

    public static SignerRequest v4(Map<String, String> parameters, String activityKind, String clientSdk) {
        if (activityKind == null || activityKind.isEmpty()) throw new IllegalArgumentException("activityKind must not be empty");
        if (clientSdk == null || clientSdk.isEmpty()) throw new IllegalArgumentException("clientSdk must not be empty");
        return new SignerRequest(Version.V4, parameters, activityKind, clientSdk, null);
    }

    public static SignerRequest v5(Map<String, String> parameters, Map<String, String> request) {
        return new SignerRequest(Version.V5, parameters, null, null, request);
    }

    public Version getVersion() { return version; }
    public Map<String, String> getParameters() { return parameters; }
    public String getActivityKind() { return activityKind; }
    public String getClientSdk() { return clientSdk; }
    public Map<String, String> getRequest() { return request; }

    Map<String, String> copyParameters() { return new LinkedHashMap<>(parameters); }
    Map<String, String> copyRequest() { return new LinkedHashMap<>(request); }

    private static Map<String, String> immutableCopy(Map<String, String> source, String name) {
        Objects.requireNonNull(source, name);
        if (source.isEmpty()) throw new IllegalArgumentException(name + " must not be empty");
        return Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }
}
