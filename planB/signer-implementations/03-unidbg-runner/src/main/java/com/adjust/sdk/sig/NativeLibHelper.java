package com.adjust.sdk.sig;

import android.content.Context;
import local.AdjustSignatureRunner;
import local.DeviceProfile;
import local.android.AndroidKeyStoreProvider;
import java.io.File;

public class NativeLibHelper implements a {
    private static File projectRoot;
    private static DeviceProfile deviceProfile;
    private static AdjustSignatureRunner runner;
    private static RecoveredNativeBackend recoveredBackend;
    private static NativeBackend backendForTesting;

    interface NativeBackend {
        void onResume();
        byte[] sign(Context context, Object params, byte[] input, int androidApi);
        void close() throws Exception;
    }

    public NativeLibHelper() {
        DeviceProfile configured = configuredProfile();
        if (configured == null) {
            AndroidKeyStoreProvider.installFromEnv();
        } else {
            AndroidKeyStoreProvider.install(configured.getSigningKey(),
                    configured.getLegacyRsaPrivateKeyPkcs8(),
                    configured.getLegacyRsaPublicKeyX509());
        }
    }

    public static synchronized void configure(File root) {
        projectRoot = root;
        deviceProfile = null;
    }

    public static synchronized void configure(File root, DeviceProfile profile) {
        projectRoot = root;
        deviceProfile = profile;
    }

    private static synchronized AdjustSignatureRunner runner() {
        if (runner == null) {
            File root = projectRoot;
            if (root == null) {
                String configured = System.getProperty("adjust.project.root");
                root = new File(configured == null || configured.isEmpty() ? "." : configured);
            }
            DeviceProfile profile = deviceProfile;
            runner = profile == null
                    ? new AdjustSignatureRunner(root)
                    : new AdjustSignatureRunner(root, profile);
        }
        return runner;
    }

    private static synchronized DeviceProfile configuredProfile() {
        return deviceProfile;
    }

    private static synchronized RecoveredNativeBackend recoveredBackend() {
        if (recoveredBackend == null) {
            File root = projectRoot;
            if (root == null) {
                String configured = System.getProperty("adjust.project.root");
                root = new File(configured == null || configured.isEmpty() ? "." : configured);
            }
            if (deviceProfile == null) {
                throw new IllegalStateException("recovered backend requires a configured DeviceProfile");
            }
            recoveredBackend = new RecoveredNativeBackend(root, deviceProfile);
        }
        return recoveredBackend;
    }

    public static synchronized void closeBridge() throws Exception {
        if (runner != null) {
            runner.close();
            runner = null;
        }
        if (recoveredBackend != null) {
            recoveredBackend.close();
            recoveredBackend = null;
        }
    }

    public static synchronized void clearConfiguration() {
        projectRoot = null;
        deviceProfile = null;
    }

    static synchronized void setBackendForTesting(NativeBackend backend) throws Exception {
        closeBridge();
        backendForTesting = backend;
    }

    static synchronized void clearBackendForTesting() throws Exception {
        if (backendForTesting != null) {
            backendForTesting.close();
            backendForTesting = null;
        }
        closeBridge();
        clearConfiguration();
    }

    private void nOnResume() {
        NativeBackend backend = backendForTesting;
        if (backend != null) {
            backend.onResume();
            return;
        }
        DeviceProfile profile = configuredProfile();
        if (profile != null && "recovered".equals(profile.getNativeBackend())) {
            recoveredBackend().onResume();
            return;
        }
        runner().onResume();
    }

    private byte[] nSign(Context context, Object obj, byte[] input, int androidApi) {
        NativeBackend backend = backendForTesting;
        if (backend != null) {
            return backend.sign(context, obj, input, androidApi);
        }
        DeviceProfile profile = configuredProfile();
        if (profile != null && "recovered".equals(profile.getNativeBackend())) {
            return recoveredBackend().sign(context, obj, input, androidApi);
        }
        if (!(obj instanceof java.util.Map)) {
            throw new IllegalArgumentException("nSign obj must be a Map, got " + (obj == null ? "null" : obj.getClass()));
        }
        @SuppressWarnings("unchecked")
        java.util.Map<String, String> params = (java.util.Map<String, String>) obj;
        return runner().signNative(context, params, input, androidApi);
    }

    public final void a() {
        nOnResume();
    }

    public final byte[] a(Context context, Object obj, byte[] input, int androidApi) {
        return nSign(context, obj, input, androidApi);
    }
}
