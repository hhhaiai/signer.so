package com.adjust.sdk.sig;

import android.content.Context;
import android.util.Log;

/* loaded from: adjust-android-signature-3.67.0.aar:classes.jar:com/adjust/sdk/sig/NativeLibHelper.class */
class NativeLibHelper implements a {
    private native byte[] nSign(Context context, Object obj, byte[] bArr, int i);

    private native void nOnResume();

    static {
        try {
            System.loadLibrary("signer");
        } catch (UnsatisfiedLinkError e) {
            Log.e("NativeLibHelper", "Signer Library could not be loaded: " + e.getMessage());
        }
    }

    public final void a() {
        nOnResume();
    }

    public final byte[] a(Context context, Object obj, byte[] bArr, int i) {
        return nSign(context, obj, bArr, i);
    }
}