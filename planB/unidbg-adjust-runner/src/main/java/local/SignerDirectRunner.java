package local;

import android.content.Context;
import android.os.Build;
import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.Signer;
import local.android.AndroidKeyStoreProvider;

import java.io.File;
import java.util.Base64;
import java.util.Map;

public final class SignerDirectRunner {
    private SignerDirectRunner() {}

    public static AdjustSignatureRunner.SignResult signV4(File projectRoot, Map<String, String> params,
                                                          String activityKind, String clientSdk) throws Exception {
        configure(projectRoot);
        try {
            Signer signer = new Signer();
            signer.onResume();
            System.out.println("Signer.onResume OK");
            signer.sign(new Context(System.getenv().getOrDefault("ADJUST_PACKAGE", "com.adjust.test")),
                    params, activityKind, clientSdk);
            String signature = params.get("signature");
            if (signature == null || signature.isEmpty()) {
                throw new IllegalStateException("Signer.sign v4 did not write signature: " + params);
            }
            byte[] raw = Base64.getDecoder().decode(signature);
            return new AdjustSignatureRunner.SignResult(raw, signature, params);
        } finally {
            NativeLibHelper.closeBridge();
        }
    }

    public static Map<String, String> signV5(File projectRoot, Map<String, String> params,
                                             Map<String, String> request, Map<String, String> output) throws Exception {
        configure(projectRoot);
        try {
            Signer signer = new Signer();
            signer.onResume();
            System.out.println("Signer.onResume OK");
            signer.sign(new Context(System.getenv().getOrDefault("ADJUST_PACKAGE", "com.adjust.test")),
                    params, request, output);
            if (!"b".equals(request.get("a")) && !output.containsKey("authorization")) {
                throw new IllegalStateException("Signer.sign v5 did not write authorization: " + output);
            }
            return output;
        } finally {
            NativeLibHelper.closeBridge();
        }
    }

    private static void configure(File projectRoot) throws Exception {
        System.setProperty("adjust.project.root", projectRoot.getCanonicalPath());
        Build.VERSION.SDK_INT = Integer.parseInt(System.getenv().getOrDefault("ADJUST_ANDROID_API", "35"));
        AndroidKeyStoreProvider.installFromEnv();
        NativeLibHelper.configure(projectRoot);
    }
}
