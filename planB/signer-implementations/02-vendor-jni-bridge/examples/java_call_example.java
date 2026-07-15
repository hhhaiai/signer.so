package com.adjust.sdk.sig;

import android.content.Context;

// Documentation example: native code must first call
// libsigner_compat_install_vendor() with an absolute local official-SO path.
public final class NativeLibHelper {
    static {
        System.loadLibrary("signer_compat");
    }

    public native void nOnResume();

    public native byte[] nSign(
            Context context,
            Object parameterObject,
            byte[] input,
            int androidApi);
}
