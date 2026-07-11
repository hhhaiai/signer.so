package com.adjust.research;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SignerRequest {

    private final LinkedHashMap<String, String> parameters;
    private final String activityKind;
    private final String clientSdk;

    public SignerRequest(Map<String, String> parameters, String activityKind, String clientSdk) {
        this.parameters = new LinkedHashMap<>(Objects.requireNonNull(parameters, "parameters"));
        this.activityKind = Objects.requireNonNull(activityKind, "activityKind");
        this.clientSdk = Objects.requireNonNull(clientSdk, "clientSdk");
    }

    public LinkedHashMap<String, String> parametersForNative() {
        LinkedHashMap<String, String> result = new LinkedHashMap<>(parameters);
        result.put("activity_kind", activityKind);
        result.put("client_sdk", clientSdk);
        return result;
    }
}
