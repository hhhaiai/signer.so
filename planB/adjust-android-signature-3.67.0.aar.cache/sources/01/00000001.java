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

/* loaded from: adjust-android-signature-3.67.0.aar:classes.jar:com/adjust/sdk/sig/Signer.class */
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
        d dVar = this.b;
        a aVar = this.c;
        dVar.getClass();
        if (d.a) {
            return;
        }
        ((NativeLibHelper) aVar).a();
    }

    public synchronized void sign(Context context, Map<String, String> map, String str, String str2) {
        a();
        d dVar = this.b;
        c cVar = this.d;
        a aVar = this.c;
        dVar.getClass();
        d.a(context, cVar, aVar, map, str, str2);
    }

    public final synchronized void a() {
        if (this.a) {
            return;
        }
        this.b = new d();
        this.d = new c(Build.VERSION.SDK_INT);
        this.c = new NativeLibHelper();
        this.a = true;
    }

    public synchronized void sign(Context context, Map<String, String> map, Map<String, String> map2, Map<String, String> map3) {
        a();
        d dVar = this.b;
        c cVar = this.d;
        a aVar = this.c;
        dVar.getClass();
        if (map == null || map.isEmpty() || map2 == null || map3 == null) {
            Log.e("SignerInstance", "sign: One or more parameters are null");
            return;
        }
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
        boolean equals = "sandbox".equals(map.get("environment"));
        if (equals) {
            Log.v("SignerInstance", "SDKv5 Signing all the parameters begin: " + simpleDateFormat.format(new Date(System.currentTimeMillis())));
        }
        HashMap hashMap = new HashMap();
        d.a(map.keySet(), map, hashMap);
        String str = map2.get("activity_kind");
        String str2 = map2.get("client_sdk");
        if (!"b".equals(map2.get("a"))) {
            d.a(context, cVar, aVar, hashMap, str, str2);
            if (!hashMap.containsKey("signature") || !hashMap.containsKey("adj_signing_id") || !hashMap.containsKey("headers_id") || !hashMap.containsKey("algorithm") || !hashMap.containsKey("native_version")) {
                Log.e("SignerInstance", "sign: Signature generation failed. Exiting...");
                return;
            }
            String str3 = (String) hashMap.get("native_version");
            StringBuilder sb = new StringBuilder("signature=\"");
            sb.append((String) hashMap.get("signature"));
            sb.append("\"");
            String sb2 = sb.toString();
            StringBuilder sb3 = new StringBuilder("adj_signing_id=\"");
            sb3.append((String) hashMap.get("adj_signing_id"));
            sb3.append("\"");
            String sb4 = sb3.toString();
            StringBuilder sb5 = new StringBuilder("headers_id=\"");
            sb5.append((String) hashMap.get("headers_id"));
            sb5.append("\"");
            String sb6 = sb5.toString();
            StringBuilder sb7 = new StringBuilder("algorithm=\"");
            sb7.append((String) hashMap.get("algorithm"));
            sb7.append("\"");
            String sb8 = sb7.toString();
            StringBuilder sb9 = new StringBuilder("native_version=\"");
            sb9.append(str3);
            sb9.append("\"");
            String sb10 = sb9.toString();
            StringBuilder sb11 = new StringBuilder("Signature ");
            sb11.append(sb2);
            sb11.append(",");
            sb11.append(sb4);
            sb11.append(",");
            sb11.append(sb8);
            sb11.append(",");
            sb11.append(sb6);
            sb11.append(",");
            sb11.append(sb10);
            map3.put("authorization", sb11.toString());
        }
        d.a(map.keySet(), map, map3);
        d.a(new HashSet(Arrays.asList("network_payload", "endpoint")), map2, map3);
        if (!equals) {
            return;
        }
        Log.v("SignerInstance", "SDKv5 Signing all the parameters end  : " + simpleDateFormat.format(new Date(System.currentTimeMillis())));
    }
}