package com.adjust.sdk.sig;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;

public class Signer {
    public boolean a = false;
    public d b;
    public a c;
    public c d;

    public static String getVersion() {
        return "3.67.0";
    }

    public synchronized void onResume() {
        a();
        b.getClass();
        if (!com.adjust.sdk.sig.d.a) {
            ((NativeLibHelper) c).a();
        }
    }

    public synchronized void sign(Context context, Map<String, String> params,
                                  String activityKind, String clientSdk) {
        a();
        b.getClass();
        com.adjust.sdk.sig.d.a(context, d, c, params, activityKind, clientSdk);
    }

    public synchronized void sign(Context context, Map<String, String> params,
                                  Map<String, String> request, Map<String, String> output) {
        a();
        b.getClass();
        if (params == null || params.isEmpty() || request == null || output == null) {
            Log.e("SignerInstance", "sign: One or more parameters are null");
            return;
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
        boolean sandbox = "sandbox".equals(params.get("environment"));
        if (sandbox) {
            Log.v("SignerInstance", "SDKv5 Signing all the parameters begin: " + dateFormat.format(new Date(System.currentTimeMillis())));
        }

        HashMap<String, String> signingParams = new HashMap<>();
        com.adjust.sdk.sig.d.a(params.keySet(), params, signingParams);
        String activityKind = request.get("activity_kind");
        String clientSdk = request.get("client_sdk");
        if (!"b".equals(request.get("a"))) {
            com.adjust.sdk.sig.d.a(context, d, c, signingParams, activityKind, clientSdk);
            if (!hasSignatureFields(signingParams)) {
                Log.e("SignerInstance", "sign: Signature generation failed. Exiting...");
                return;
            }
            output.put("authorization", authorization(signingParams));
        }

        com.adjust.sdk.sig.d.a(params.keySet(), params, output);
        com.adjust.sdk.sig.d.a(new HashSet<>(Arrays.asList("network_payload", "endpoint")), request, output);
        if (sandbox) {
            Log.v("SignerInstance", "SDKv5 Signing all the parameters end  : " + dateFormat.format(new Date(System.currentTimeMillis())));
        }
    }

    public final synchronized void a() {
        if (a) {
            return;
        }
        b = new d();
        d = new c(Build.VERSION.SDK_INT);
        c = new NativeLibHelper();
        a = true;
    }

    private static boolean hasSignatureFields(Map<String, String> params) {
        return params.containsKey("signature")
                && params.containsKey("adj_signing_id")
                && params.containsKey("headers_id")
                && params.containsKey("algorithm")
                && params.containsKey("native_version");
    }

    private static String authorization(Map<String, String> params) {
        return "Signature"
                + "signature=\"" + params.get("signature") + "\""
                + ",adj_signing_id=\"" + params.get("adj_signing_id") + "\""
                + ",algorithm=\"" + params.get("algorithm") + "\""
                + ",headers_id=\"" + params.get("headers_id") + "\""
                + ",native_version=\"" + params.get("native_version") + "\"";
    }
}
