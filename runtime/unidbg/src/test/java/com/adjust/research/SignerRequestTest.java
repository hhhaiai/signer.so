package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SignerRequestTest {

    @Test
    void injectsSdkFieldsUsingJavaLinkedHashMapSemantics() {
        LinkedHashMap<String, String> input = new LinkedHashMap<>();
        input.put("environment", "sandbox");
        input.put("app_token", "token");

        SignerRequest request = new SignerRequest(input, "event", "android5.4.1");

        assertEquals(
                "{environment=sandbox, app_token=token, activity_kind=event, client_sdk=android5.4.1}",
                request.parametersForNative().toString());
        assertEquals("{environment=sandbox, app_token=token}", input.toString(),
                "request must not mutate caller-owned maps");
    }
}
