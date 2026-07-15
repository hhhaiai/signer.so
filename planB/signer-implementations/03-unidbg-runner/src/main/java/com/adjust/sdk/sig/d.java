package com.adjust.sdk.sig;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class d {
    public static boolean a = false;

    public static void a(Context context, c keyManager, a nativeHelper, Map<String, String> params,
                         String activityKind, String clientSdk) {
        if (a) {
            Log.e("SignerInstance", "sign: library received error. It has locked down");
            return;
        }
        if (params == null || params.isEmpty() || activityKind == null || clientSdk == null) {
            Log.e("SignerInstance", "sign: One or more parameters are null");
            return;
        }

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
        boolean sandbox = "sandbox".equals(params.get("environment"));
        if (sandbox) {
            Log.v("SignerInstance", "Signing all the parameters begin: " + dateFormat.format(new Date(System.currentTimeMillis())));
        }

        params.put("activity_kind", activityKind);
        params.put("client_sdk", clientSdk);
        int attempts = 2;
        byte[] hmac = null;
        while (attempts > 0) {
            try {
                keyManager.a(context);
                hmac = keyManager.a(context, params.toString().getBytes(StandardCharsets.UTF_8));
                break;
            } catch (b unsupportedApi) {
                Log.e("SignerInstance", "sign: Api is less than JellyBean-4-18");
                a = true;
                removeTemporaryKeys(params);
                throw unsupportedApi;
            } catch (InvalidKeyException | UnrecoverableKeyException retriable) {
                Log.e("SignerInstance", "sign: Received a retriable exception: " + retriable.getMessage(), retriable);
                Log.e("SignerInstance", "sign: Attempting retry #" + attempts);
                attempts--;
                resetKey(context);
            } catch (Exception exception) {
                Log.e("SignerInstance", "sign: Received an Exception: " + exception.getMessage(), exception);
                removeTemporaryKeys(params);
                d.<RuntimeException>sneakyThrow(exception);
                return;
            }
        }

        if (attempts == 0) {
            a = true;
            removeTemporaryKeys(params);
            return;
        }

        if (sandbox) {
            Log.v("SignerInstance", "Calling native begin: " + dateFormat.format(new Date(System.currentTimeMillis())));
        }
        byte[] signature = ((NativeLibHelper) nativeHelper).a(context, params, hmac, keyManager.a);
        if (sandbox) {
            Log.v("SignerInstance", "Calling native end  : " + dateFormat.format(new Date(System.currentTimeMillis())));
        }
        if (signature == null) {
            Log.e("SignerInstance", "sign: Returned an null signature. Exiting...");
            removeTemporaryKeys(params);
            return;
        }

        params.put("signature", Base64.encodeToString(signature, Base64.NO_WRAP));
        removeTemporaryKeys(params);
        if (sandbox) {
            Log.v("SignerInstance", "Signing all the parameters end  : " + dateFormat.format(new Date(System.currentTimeMillis())));
        }
    }

    public static void a(Set<String> keys, Map<String, String> source, Map<String, String> destination) {
        for (String key : keys) {
            if (source.containsKey(key)) {
                destination.put(key, source.get(key));
            }
        }
    }

    private static void removeTemporaryKeys(Map<String, String> params) {
        params.remove("activity_kind");
        params.remove("client_sdk");
    }

    private static void resetKey(Context context) {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry("key2");
            context.getSharedPreferences("adjust_keys", Context.MODE_PRIVATE)
                    .edit().remove("encrypted_key").apply();
        } catch (Exception exception) {
            d.<RuntimeException>sneakyThrow(exception);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneakyThrow(Throwable throwable) throws T {
        throw (T) throwable;
    }
}
