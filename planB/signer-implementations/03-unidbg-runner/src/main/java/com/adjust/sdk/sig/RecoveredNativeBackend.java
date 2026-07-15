package com.adjust.sdk.sig;

import android.content.Context;
import local.DeviceProfile;
import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkV2Signer;
import net.dongliu.apk.parser.bean.CertificateMeta;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class RecoveredNativeBackend implements NativeLibHelper.NativeBackend {
    private static final List<String> PLAINTEXT_FIELDS = Arrays.asList(
            "ad_impressions_count", "ad_revenue_network", "ad_revenue_placement",
            "ad_revenue_unit", "adgroup", "android_id", "android_uuid", "api_level",
            "app_secret", "app_token", "app_version", "app_version_short", "att_status",
            "bundle_id", "callback_params", "campaign", "click_time", "click_time_server",
            "country", "created_at", "creative", "currency", "deduplication_id",
            "default_tracker", "details", "device_known", "device_name", "device_type",
            "environment", "event_callback_id", "event_count", "event_token",
            "external_device_id", "fb_anon_id", "fb_id", "ff_app_set_id_disabled",
            "ff_att_disabled", "ff_idfv_disabled", "ff_odm_enabled", "fire_adid",
            "fire_tracking_enabled", "found_location", "google_play_instant", "gps_adid",
            "gps_adid_src", "granular_third_party_sharing_options", "hardware_name", "idfa",
            "idfv", "initiated_by", "initiating_package_name", "install_begin_time",
            "install_begin_time_server", "install_version", "installed_at", "last_skan_update",
            "mcc", "measurement", "mnc", "needs_cost", "odm_info", "order_id",
            "originating_package_name", "os_build", "os_name", "os_version", "package_name",
            "params", "partner_params", "partner_sharing_settings", "payload",
            "primary_dedupe_token", "purchase_time", "push_token", "referrer", "referrer_api",
            "reftag", "revenue", "sales_region", "secondary_dedupe_token", "secret_id", "seq",
            "session_count", "session_length", "sharing", "skadn_registered_at", "source",
            "started_at", "store_app_id_from_client", "store_name_from_client",
            "store_name_from_system", "subsession_count", "time_spent", "tracker",
            "tracking_enabled", "updated_at", "activity_kind", "client_sdk",
            "headers_id", "native_version");

    private final File projectRoot;
    private final DeviceProfile profile;
    private boolean resumed;

    RecoveredNativeBackend(File projectRoot, DeviceProfile profile) {
        this.projectRoot = projectRoot;
        this.profile = profile;
    }

    @Override
    public void onResume() {
        resumed = true;
    }

    @Override
    public byte[] sign(Context context, Object value, byte[] javaHmac, int androidApi) {
        if (!resumed) throw new IllegalStateException("recovered backend requires onResume before sign");
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("recovered sign params must be a Map");
        }
        @SuppressWarnings("unchecked")
        Map<String, String> params = (Map<String, String>) value;
        boolean javaHmacMismatch = javaHmacMismatch(params, javaHmac, androidApi);

        params.put("headers_id", "9");
        params.put("adj_signing_id", "1400000");
        params.put("native_version", "3.67.0");
        params.put("algorithm", "adj8");

        try {
            File executable = ensureExecutable();
            Long configuredTimeSeconds = profile.getNativeTimeSeconds();
            if (configuredTimeSeconds == null) {
                throw new IllegalStateException(
                        "recovered backend requires explicit runtime.timeSeconds");
            }
            byte[] urandom = profile.getNativeUrandomBytes();
            if (urandom == null || urandom.length < 4) {
                throw new IllegalStateException(
                        "recovered backend requires at least 4 explicit runtime.urandomHex bytes");
            }
            List<String> command = new ArrayList<>();
            command.add(executable.getCanonicalPath());
            command.add("--time-seconds=" + configuredTimeSeconds);
            command.add("--certificate-sha1=" + hex(MessageDigest.getInstance("SHA-1")
                    .digest(profile.getCertificateDer())));
            command.add("--native-plaintext-hex=" + hex(nativePlaintext(params)));
            command.add("--urandom-hex=" + hex(urandom));
            // The payload field-6 state remains 1 when correction 0x05 is disabled in the original SO;
            // correction05Enabled controls only the timing-guard correction, not this payload byte.
            command.add("--state=true");
            command.add("--correction-codes=" + correctionCodes(javaHmacMismatch));

            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            String output = readAll(process.getInputStream());
            int exit = process.waitFor();
            if (exit != 0) throw new IllegalStateException("recovered signer failed (" + exit + "): " + output);
            for (String line : output.split("\\R")) {
                if (line.startsWith("SIGNATURE_HEX=")) {
                    return decodeHex(line.substring("SIGNATURE_HEX=".length()));
                }
            }
            throw new IllegalStateException("recovered signer returned no SIGNATURE_HEX: " + output);
        } catch (RuntimeException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("recovered signer execution failed", exception);
        }
    }

    private byte[] nativePlaintext(Map<String, String> params) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (String field : PLAINTEXT_FIELDS) {
            String text;
            if ("secret_id".equals(field)) text = "1400000";
            else if ("headers_id".equals(field)) text = "9";
            else if ("native_version".equals(field)) text = "3.67.0";
            else text = params.get(field);
            if (text != null) output.writeBytes(text.getBytes(StandardCharsets.UTF_8));
        }
        return output.toByteArray();
    }

    private boolean javaHmacMismatch(Map<String, String> params, byte[] javaHmac, int androidApi) {
        if (androidApi < 18 || javaHmac == null) return false;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            byte[] key = androidApi >= 23 ? profile.getSigningKey() : legacyJavaHmacKey();
            if (key == null) return false;
            mac.init(new SecretKeySpec(key, androidApi >= 23 ? "HmacSHA256" : "AES"));
            byte[] expected = mac.doFinal(params.toString().getBytes(StandardCharsets.UTF_8));
            return !MessageDigest.isEqual(expected, javaHmac);
        } catch (Exception exception) {
            throw new IllegalStateException("failed to verify Java HMAC for native correction 0x07", exception);
        }
    }

    private byte[] legacyJavaHmacKey() throws Exception {
        byte[] privateKey = profile.getLegacyRsaPrivateKeyPkcs8();
        Map<String, String> adjustKeys = profile.getSharedPreferences().get("adjust_keys");
        String encryptedKey = adjustKeys == null ? null : adjustKeys.get("encrypted_key");
        if (privateKey == null || privateKey.length == 0
                || encryptedKey == null || encryptedKey.isEmpty()) return null;
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
        return cipher.doFinal(Base64.getMimeDecoder().decode(encryptedKey));
    }

    private String correctionCodes(boolean javaHmacMismatch) {
        List<Integer> configured = profile.getNativeCorrectionCodes();
        if (configured.isEmpty()) {
            StringBuilder defaults = new StringBuilder("2b");
            if (javaHmacMismatch) defaults.append(",07");
            appendProcessNameCorrection(defaults);
            byte[] procMaps = profile.getNativeFiles().get("/proc/self/maps");
            boolean procMapsMissing = profile.getNativeMissingPaths().contains("/proc/self/maps");
            boolean sparseFilesystemProfile = nativeFilesystemProfileUnspecified();
            if (procMapsMissing || (procMaps == null && sparseFilesystemProfile)) {
                defaults.append(",37");
            } else if (procMaps != null) {
                String mappedBaseApk = firstMappedBaseApk(procMaps, profile.getPackageName());
                if (mappedBaseApk == null) defaults.append(",37");
                else if (!mappedBaseApk.equals(profile.getPublicSourceDir())) defaults.append(",29");
            }
            if (sparseFilesystemProfile || publicSourceDirMissing()) defaults.append(",38");
            if (apkCertificateMismatch()) defaults.append(",2a");
            if (!nativeFileAvailable("/system/lib64/libart.so")
                    && !nativeFileAvailable("/system/lib64/ld-android.so")) {
                defaults.append(",2f");
            }
            if (nativeAtoi(profile.getSystemProperties()
                    .getOrDefault("ro.build.version.sdk", "23")) != profile.getAndroidApi()) {
                defaults.append(",3c");
            }
            if (procMapsMissing) defaults.append(",35");
            defaults.append(",36");
            if (profile.isNativeSignerCodeTrampolineDetected()) defaults.append(",25");
            if (profile.getNativeCorrection05Enabled() == null
                    || profile.getNativeCorrection05Enabled()) defaults.append(",05");
            return defaults.toString();
        }
        StringBuilder value = new StringBuilder();
        for (Integer code : configured) {
            if (value.length() > 0) value.append(',');
            value.append(Integer.toHexString(code));
        }
        return value.toString();
    }

    private boolean nativeFilesystemProfileUnspecified() {
        return profile.getNativeFiles().isEmpty() && profile.getNativeMissingPaths().isEmpty();
    }

    private boolean nativeFileAvailable(String path) {
        return profile.getNativeFiles().containsKey(path)
                && !profile.getNativeMissingPaths().contains(path);
    }

    private static int nativeAtoi(String value) {
        int index = 0;
        while (index < value.length() && Character.isWhitespace(value.charAt(index))) index++;
        int sign = 1;
        if (index < value.length() && (value.charAt(index) == '+' || value.charAt(index) == '-')) {
            if (value.charAt(index++) == '-') sign = -1;
        }
        int result = 0;
        while (index < value.length()) {
            char digit = value.charAt(index++);
            if (digit < '0' || digit > '9') break;
            result = result * 10 + digit - '0';
        }
        return sign * result;
    }

    private void appendProcessNameCorrection(StringBuilder corrections) {
        String path = "/proc/self/cmdline";
        if (profile.getNativeMissingPaths().contains(path)) {
            corrections.append(",34");
            return;
        }
        byte[] bytes = profile.getNativeFiles().get(path);
        if (bytes == null) {
            if (nativeFilesystemProfileUnspecified()) corrections.append(",34");
            return;
        }
        int length = 0;
        while (length < bytes.length && bytes[length] != 0) length++;
        if (length == 0) {
            corrections.append(",34");
            return;
        }
        String processName = new String(bytes, 0, length, StandardCharsets.UTF_8);
        if (!processName.equals(profile.getPackageName())) corrections.append(",9");
    }

    private boolean publicSourceDirMissing() {
        String publicSourceDir = profile.getPublicSourceDir();
        if (profile.getNativeFiles().containsKey(publicSourceDir)) return false;
        if (profile.getNativeMissingPaths().contains(publicSourceDir)) return true;
        return !publicSourceDir.equals(profile.getSourceDir());
    }

    private static String firstMappedBaseApk(byte[] procMaps, String packageName) {
        String[] lines = new String(procMaps, StandardCharsets.UTF_8).split("\\R");
        for (String line : lines) {
            if (!line.contains(packageName) || !line.contains("/base.apk")) continue;
            int pathStart = line.indexOf('/');
            if (pathStart < 0) continue;
            String path = line.substring(pathStart).trim();
            int deleted = path.indexOf(" (deleted)");
            return deleted < 0 ? path : path.substring(0, deleted);
        }
        return null;
    }

    private boolean apkCertificateMismatch() {
        File apk = profile.getBaseApk();
        if (apk == null || !apk.isFile()) return false;
        try (ApkFile apkFile = new ApkFile(apk)) {
            List<byte[]> certificates = new ArrayList<>();
            try {
                for (CertificateMeta certificate : apkFile.getCertificateMetaList()) {
                    certificates.add(certificate.getData());
                }
            } catch (RuntimeException ignored) {
                // A v2-only APK has no META-INF certificate entry.
            }
            if (certificates.isEmpty()) {
                for (ApkV2Signer signer : apkFile.getApkV2Singers()) {
                    for (CertificateMeta certificate : signer.getCertificateMetas()) {
                        certificates.add(certificate.getData());
                    }
                }
            }
            if (certificates.isEmpty()) {
                certificates.addAll(ApkSigningBlockCertificates.readV3Certificates(apk));
            }
            if (certificates.isEmpty()) return false;
            byte[] packageCertificate = profile.getCertificateDer();
            for (byte[] certificate : certificates) {
                if (Arrays.equals(packageCertificate, certificate)) return false;
            }
            return true;
        } catch (Exception ignored) {
            // APKs without a readable signer remain configurable through runtime.correctionCodes.
            return false;
        }
    }

    private synchronized File ensureExecutable() throws Exception {
        File directory = new File(projectRoot, "native-reimplementation");
        File source = new File(directory, "recovered_primitives.cpp");
        File build = new File(directory, "build");
        File executable = new File(build, "recovered-primitives");
        if (!source.isFile()) throw new IllegalStateException("recovered source not found: " + source);
        if (executable.isFile() && executable.lastModified() >= source.lastModified()) return executable;
        Files.createDirectories(build.toPath());
        String compiler = System.getenv().getOrDefault("CXX", "c++");
        Process compile = new ProcessBuilder(compiler, "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
                source.getCanonicalPath(), "-o", executable.getCanonicalPath())
                .redirectErrorStream(true).start();
        String output = readAll(compile.getInputStream());
        int exit = compile.waitFor();
        if (exit != 0) throw new IllegalStateException("failed to build recovered signer (" + exit + "): " + output);
        return executable;
    }

    private static String readAll(InputStream input) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
        return output.toString(StandardCharsets.UTF_8.name());
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte current : bytes) value.append(String.format("%02x", current & 0xff));
        return value.toString();
    }

    private static byte[] decodeHex(String value) {
        if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd recovered signature hex length");
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    @Override
    public void close() {
        resumed = false;
    }
}
