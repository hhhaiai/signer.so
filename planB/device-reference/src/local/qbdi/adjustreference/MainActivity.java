package local.qbdi.adjustreference;

import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.util.Base64;
import android.util.DisplayMetrics;
import android.util.Log;
import android.widget.TextView;

import com.adjust.sdk.sig.Signer;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class MainActivity extends Activity {
    private static final String TAG = "SignerReference";
    private static final String KEY_ALIAS = "key2";
    private static final byte[] SIGNING_KEY =
            "local-adjust-keystore-key".getBytes(StandardCharsets.UTF_8);

    private TextView outputView;
    private boolean started;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        outputView = new TextView(this);
        outputView.setText("Waiting for onResume -> sign...");
        outputView.setTextIsSelectable(true);
        outputView.setPadding(24, 24, 24, 24);
        setContentView(outputView);
        System.loadLibrary("reference_runtime");
        System.loadLibrary("signer");
        try {
            Thread.sleep(200L);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (started) return;
        started = true;
        runReference();
    }

    private void runReference() {
        try {
            installSigningKey();
            LinkedHashMap<String, String> parameters = sampleParameters();
            String hmacInput = hmacInput(parameters, "session", "android4.38.5");

            Signer signer = new Signer();
            signer.onResume();
            signer.sign(this, parameters, "session", "android4.38.5");

            JSONObject result = resultJson(parameters);
            JSONObject observation = collectObservation(hmacInput);
            writeJson("reference-result.json", result);
            writeJson("device-observation.json", observation);

            String rendered = result.toString();
            outputView.setText(rendered);
            Log.i(TAG, "SIGNER_RESULT_JSON=" + rendered);
            Log.i(TAG, "REFERENCE_READY files=" + getFilesDir());
        } catch (Throwable throwable) {
            Log.e(TAG, "reference failed", throwable);
            outputView.setText(Log.getStackTraceString(throwable));
            try {
                JSONObject error = new JSONObject();
                error.put("error", throwable.toString());
                error.put("stackTrace", Log.getStackTraceString(throwable));
                writeJson("reference-error.json", error);
            } catch (Throwable ignored) {
                // The original failure is already in logcat.
            }
        }
    }

    private void installSigningKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
        KeyProtection protection = new KeyProtection.Builder(
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build();
        keyStore.setEntry(KEY_ALIAS,
                new KeyStore.SecretKeyEntry(new SecretKeySpec(SIGNING_KEY, "HmacSHA256")),
                protection);

        Mac probe = Mac.getInstance("HmacSHA256");
        probe.init(keyStore.getKey(KEY_ALIAS, null));
        probe.doFinal("key-import-probe".getBytes(StandardCharsets.UTF_8));
    }

    private static LinkedHashMap<String, String> sampleParameters() {
        LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        parameters.put("environment", "sandbox");
        parameters.put("app_token", "abc123");
        parameters.put("created_at", "2026-07-10T00:00:00.000+0800");
        parameters.put("gps_adid", "11111111-1111-1111-1111-111111111111");
        parameters.put("android_id", "0123456789abcdef");
        parameters.put("device_type", "phone");
        parameters.put("device_name", "Pixel 9 Pro");
        parameters.put("os_name", "android");
        parameters.put("os_version", "15");
        parameters.put("language", "zh");
        parameters.put("country", "CN");
        return parameters;
    }

    private static String hmacInput(LinkedHashMap<String, String> parameters,
                                    String activityKind, String clientSdk) {
        LinkedHashMap<String, String> copy = new LinkedHashMap<>(parameters);
        copy.put("activity_kind", activityKind);
        copy.put("client_sdk", clientSdk);
        return copy.toString();
    }

    private static JSONObject resultJson(LinkedHashMap<String, String> parameters) throws Exception {
        String signatureBase64 = parameters.get("signature");
        if (signatureBase64 == null || signatureBase64.isEmpty()) {
            throw new IllegalStateException("Signer.sign did not produce signature: " + parameters);
        }
        byte[] raw = Base64.decode(signatureBase64, Base64.NO_WRAP);
        JSONObject result = new JSONObject();
        result.put("signed", true);
        result.put("version", "V4");
        result.put("rawSignatureHex", hex(raw));
        result.put("signatureBase64", signatureBase64);

        JSONObject metadata = new JSONObject();
        for (String key : new String[]{"signature", "adj_signing_id", "algorithm", "headers_id", "native_version"}) {
            metadata.put(key, parameters.get(key));
        }
        result.put("metadata", metadata);

        JSONObject output = new JSONObject();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            output.put(entry.getKey(), entry.getValue());
        }
        result.put("output", output);
        return result;
    }

    private JSONObject collectObservation(String hmacInput) throws Exception {
        JSONObject root = new JSONObject();
        root.put("signerVersion", Signer.getVersion());
        root.put("packageName", getPackageName());
        root.put("androidApi", Build.VERSION.SDK_INT);
        root.put("hmacInput", hmacInput);
        root.put("hmacHex", hmac(SIGNING_KEY, hmacInput.getBytes(StandardCharsets.UTF_8)));

        PackageManager packageManager = getPackageManager();
        ApplicationInfo applicationInfo = packageManager.getApplicationInfo(getPackageName(), 0);
        root.put("appUid", applicationInfo.uid);
        root.put("targetSdk", applicationInfo.targetSdkVersion);
        root.put("sourceDir", applicationInfo.sourceDir);
        root.put("publicSourceDir", applicationInfo.publicSourceDir);
        root.put("dataDir", applicationInfo.dataDir);
        root.put("nativeLibraryDir", applicationInfo.nativeLibraryDir);

        PackageInfo packageInfo = packageManager.getPackageInfo(
                getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
        Signature[] signatures = packageInfo.signingInfo.hasMultipleSigners()
                ? packageInfo.signingInfo.getApkContentsSigners()
                : packageInfo.signingInfo.getSigningCertificateHistory();
        root.put("certificateHex", hex(signatures[0].toByteArray()));

        DisplayMetrics metrics = getResources().getSystem().getDisplayMetrics();
        JSONObject display = new JSONObject();
        display.put("width", metrics.widthPixels);
        display.put("height", metrics.heightPixels);
        display.put("densityDpi", metrics.densityDpi);
        display.put("density", metrics.density);
        display.put("scaledDensity", metrics.scaledDensity);
        display.put("xdpi", metrics.xdpi);
        display.put("ydpi", metrics.ydpi);
        root.put("display", display);

        SensorManager sensorManager = (SensorManager) getSystemService(Context.SENSOR_SERVICE);
        List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
        JSONArray sensorArray = new JSONArray();
        for (Sensor sensor : sensors) {
            JSONObject value = new JSONObject();
            value.put("name", sensor.getName());
            value.put("vendor", sensor.getVendor());
            value.put("type", sensor.getType());
            value.put("version", sensor.getVersion());
            sensorArray.put(value);
        }
        root.put("sensors", sensorArray);

        JSONObject build = new JSONObject();
        build.put("BRAND", Build.BRAND);
        build.put("MANUFACTURER", Build.MANUFACTURER);
        build.put("MODEL", Build.MODEL);
        build.put("DEVICE", Build.DEVICE);
        build.put("PRODUCT", Build.PRODUCT);
        build.put("HARDWARE", Build.HARDWARE);
        build.put("FINGERPRINT", Build.FINGERPRINT);
        build.put("VERSION.RELEASE", Build.VERSION.RELEASE);
        build.put("VERSION.SECURITY_PATCH", Build.VERSION.SECURITY_PATCH);
        root.put("build", build);

        JSONObject properties = new JSONObject();
        properties.put("ro.arch", getProperty("ro.arch"));
        properties.put("ro.product.model", getProperty("ro.product.model"));
        properties.put("ro.product.manufacturer", getProperty("ro.product.manufacturer"));
        properties.put("ro.build.version.release", getProperty("ro.build.version.release"));
        root.put("systemProperties", properties);

        JSONObject secure = new JSONObject();
        secure.put("android_id", Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID));
        JSONObject system = new JSONObject();
        system.put("time_12_24", Settings.System.getString(getContentResolver(), Settings.System.TIME_12_24));
        JSONObject settings = new JSONObject();
        settings.put("secure", secure);
        settings.put("system", system);
        root.put("settings", settings);

        root.put("locale", Locale.getDefault().toLanguageTag());
        root.put("timezone", TimeZone.getDefault().getID());

        JSONObject runtime = new JSONObject();
        runtime.put("processId", 4242);
        runtime.put("timeSeconds", 1760000000L);
        JSONObject tv = new JSONObject();
        tv.put("seconds", 1760000000L);
        tv.put("microseconds", 123000L);
        runtime.put("gettimeofday", tv);
        JSONObject ts = new JSONObject();
        ts.put("seconds", 1760000000L);
        ts.put("nanoseconds", 123000000L);
        runtime.put("clockGettime", ts);
        root.put("runtime", runtime);
        return root;
    }

    private void writeJson(String name, JSONObject json) throws Exception {
        File target = new File(getFilesDir(), name);
        try (FileOutputStream output = new FileOutputStream(target)) {
            output.write(json.toString().getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String getProperty(String key) {
        Process process = null;
        try {
            process = new ProcessBuilder("/system/bin/getprop", key).redirectErrorStream(true).start();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line = reader.readLine();
                process.waitFor();
                return line == null ? "" : line.trim();
            }
        } catch (Exception exception) {
            return "";
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static String hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return hex(mac.doFinal(data));
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) value.append(String.format(Locale.US, "%02x", b & 0xff));
        return value.toString();
    }
}
