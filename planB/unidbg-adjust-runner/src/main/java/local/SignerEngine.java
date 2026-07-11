package local;

import android.content.Context;
import android.os.Build;
import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.Signer;
import com.adjust.sdk.sig.d;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class SignerEngine implements AutoCloseable {
    private static final Object BRIDGE_LOCK = new Object();
    private static SignerEngine activeEngine;

    private final DeviceProfile profile;
    private final Context context;
    private final Signer signer;
    private boolean closed;

    public SignerEngine(File projectRoot, DeviceProfile profile) throws Exception {
        Objects.requireNonNull(projectRoot, "projectRoot");
        this.profile = Objects.requireNonNull(profile, "profile");
        synchronized (BRIDGE_LOCK) {
            if (activeEngine != null && !activeEngine.closed) {
                throw new IllegalStateException("only one SignerEngine can be active in a JVM");
            }
            NativeLibHelper.closeBridge();
            Build.VERSION.SDK_INT = profile.getAndroidApi();
            d.a = false;
            NativeLibHelper.configure(projectRoot.getCanonicalFile(), profile);
            context = new Context(profile.getPackageName());
            signer = new Signer();
            try {
                signer.onResume();
                activeEngine = this;
            } catch (Throwable throwable) {
                NativeLibHelper.closeBridge();
                NativeLibHelper.clearConfiguration();
                throw throwable;
            }
        }
    }

    public SignerResult sign(SignerRequest request) {
        Objects.requireNonNull(request, "request");
        synchronized (BRIDGE_LOCK) {
            ensureActive();
            Map<String, String> parameters = request.copyParameters();
            if (request.getVersion() == SignerRequest.Version.V4) {
                signer.sign(context, parameters, request.getActivityKind(), request.getClientSdk());
                if (!parameters.containsKey("signature")) {
                    throw new IllegalStateException("Signer v4 did not produce a signature: " + parameters);
                }
                return SignerResult.v4(parameters);
            }

            Map<String, String> nativeRequest = request.copyRequest();
            Map<String, String> output = new LinkedHashMap<>();
            signer.sign(context, parameters, nativeRequest, output);
            if (!"b".equals(nativeRequest.get("a")) && !output.containsKey("authorization")) {
                throw new IllegalStateException("Signer v5 did not produce authorization: " + output);
            }
            return SignerResult.v5(output);
        }
    }

    public static SignerResult signOnce(File projectRoot, DeviceProfile profile, SignerRequest request) throws Exception {
        try (SignerEngine engine = new SignerEngine(projectRoot, profile)) {
            return engine.sign(request);
        }
    }

    public DeviceProfile getProfile() {
        return profile;
    }

    @Override
    public void close() throws Exception {
        synchronized (BRIDGE_LOCK) {
            if (closed) return;
            if (activeEngine == this) {
                NativeLibHelper.closeBridge();
                NativeLibHelper.clearConfiguration();
                activeEngine = null;
            }
            closed = true;
        }
    }

    private void ensureActive() {
        if (closed) throw new IllegalStateException("SignerEngine is closed");
        if (activeEngine != this) throw new IllegalStateException("SignerEngine is not active");
    }
}
