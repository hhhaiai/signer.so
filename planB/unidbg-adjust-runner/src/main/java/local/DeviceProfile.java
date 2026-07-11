package local;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class DeviceProfile {
    private final String packageName;
    private final int androidApi;
    private final File baseApk;
    private final byte[] certificateDer;
    private final byte[] signingKey;
    private final List<Sensor> sensors;
    private final int displayWidth;
    private final int displayHeight;
    private final int densityDpi;
    private final float density;
    private final float scaledDensity;
    private final float xdpi;
    private final float ydpi;
    private final int appUid;
    private final int targetSdk;
    private final String sourceDir;
    private final String publicSourceDir;
    private final String dataDir;
    private final String nativeLibraryDir;
    private final Map<String, String> buildFields;
    private final Map<String, String> systemProperties;
    private final Map<String, String> secureSettings;
    private final Map<String, String> systemSettings;
    private final Map<String, String> serviceClasses;
    private final String locale;
    private final String timeZone;
    private final Integer nativeProcessId;
    private final Long nativeTimeSeconds;
    private final Long nativeGettimeofdaySeconds;
    private final Long nativeGettimeofdayMicroseconds;
    private final Long nativeClockGettimeSeconds;
    private final Long nativeClockGettimeNanoseconds;
    private final byte[] nativeUrandomBytes;
    private final boolean nativeSignerCodeTrampolineDetected;
    private final Set<String> nativeConnectRefusedEndpoints;
    private final Map<String, byte[]> nativeLocalSocketResponses;
    private final Map<String, byte[]> nativeFiles;
    private final Set<String> nativeMissingPaths;
    private final Map<String, String> jniStrings;
    private final Map<String, Integer> jniInts;
    private final Map<String, Long> jniLongs;
    private final Map<String, Float> jniFloats;
    private final Map<String, Double> jniDoubles;
    private final Map<String, Boolean> jniBooleans;
    private final Map<String, byte[]> jniBytes;

    private DeviceProfile(Builder builder) {
        packageName = requireText(builder.packageName, "packageName");
        if (builder.androidApi < 1) throw new IllegalArgumentException("androidApi must be positive");
        if (builder.certificateDer.length == 0) throw new IllegalArgumentException("certificateDer must not be empty");
        if (builder.signingKey.length == 0) throw new IllegalArgumentException("signingKey must not be empty");
        if (builder.sensors.isEmpty()) throw new IllegalArgumentException("at least one sensor is required");
        if (builder.displayWidth < 1 || builder.displayHeight < 1 || builder.densityDpi < 1) {
            throw new IllegalArgumentException("display dimensions and densityDpi must be positive");
        }
        if (builder.density <= 0 || builder.scaledDensity <= 0 || builder.xdpi <= 0 || builder.ydpi <= 0) {
            throw new IllegalArgumentException("display density values must be positive");
        }
        if (builder.appUid < 0) throw new IllegalArgumentException("appUid must not be negative");
        if (builder.targetSdk < 1) throw new IllegalArgumentException("targetSdk must be positive");
        if (builder.nativeProcessId != null && builder.nativeProcessId < 1) {
            throw new IllegalArgumentException("runtime.processId must be positive");
        }
        if (builder.nativeGettimeofdayMicroseconds != null
                && (builder.nativeGettimeofdayMicroseconds < 0 || builder.nativeGettimeofdayMicroseconds > 999_999)) {
            throw new IllegalArgumentException("runtime.gettimeofday.microseconds must be between 0 and 999999");
        }
        if (builder.nativeClockGettimeNanoseconds != null
                && (builder.nativeClockGettimeNanoseconds < 0 || builder.nativeClockGettimeNanoseconds > 999_999_999)) {
            throw new IllegalArgumentException("runtime.clockGettime.nanoseconds must be between 0 and 999999999");
        }
        if (builder.nativeUrandomBytes != null && builder.nativeUrandomBytes.length == 0) {
            throw new IllegalArgumentException("runtime.urandomHex must not be empty");
        }

        androidApi = builder.androidApi;
        baseApk = builder.baseApk;
        certificateDer = builder.certificateDer.clone();
        signingKey = builder.signingKey.clone();
        sensors = Collections.unmodifiableList(new ArrayList<>(builder.sensors));
        displayWidth = builder.displayWidth;
        displayHeight = builder.displayHeight;
        densityDpi = builder.densityDpi;
        density = builder.density;
        scaledDensity = builder.scaledDensity;
        xdpi = builder.xdpi;
        ydpi = builder.ydpi;
        appUid = builder.appUid;
        targetSdk = builder.targetSdk;
        sourceDir = builder.sourceDir == null ? "/data/app/" + packageName + "/base.apk" : requireText(builder.sourceDir, "sourceDir");
        publicSourceDir = builder.publicSourceDir == null ? sourceDir : requireText(builder.publicSourceDir, "publicSourceDir");
        dataDir = builder.dataDir == null ? "/data/data/" + packageName : requireText(builder.dataDir, "dataDir");
        nativeLibraryDir = builder.nativeLibraryDir == null
                ? "/data/app/" + packageName + "/lib/arm64"
                : requireText(builder.nativeLibraryDir, "nativeLibraryDir");
        buildFields = immutableCopy(builder.buildFields);
        systemProperties = immutableCopy(builder.systemProperties);
        secureSettings = immutableCopy(builder.secureSettings);
        systemSettings = immutableCopy(builder.systemSettings);
        serviceClasses = immutableCopy(builder.serviceClasses);
        locale = builder.locale;
        timeZone = builder.timeZone;
        nativeProcessId = builder.nativeProcessId;
        nativeTimeSeconds = builder.nativeTimeSeconds;
        nativeGettimeofdaySeconds = builder.nativeGettimeofdaySeconds;
        nativeGettimeofdayMicroseconds = builder.nativeGettimeofdayMicroseconds;
        nativeClockGettimeSeconds = builder.nativeClockGettimeSeconds;
        nativeClockGettimeNanoseconds = builder.nativeClockGettimeNanoseconds;
        nativeUrandomBytes = builder.nativeUrandomBytes == null ? null : builder.nativeUrandomBytes.clone();
        nativeSignerCodeTrampolineDetected = builder.nativeSignerCodeTrampolineDetected;
        nativeConnectRefusedEndpoints = Collections.unmodifiableSet(
                new LinkedHashSet<>(builder.nativeConnectRefusedEndpoints));
        nativeLocalSocketResponses = immutableBytes(builder.nativeLocalSocketResponses);
        nativeFiles = immutableBytes(builder.nativeFiles);
        nativeMissingPaths = Collections.unmodifiableSet(new LinkedHashSet<>(builder.nativeMissingPaths));
        jniStrings = immutableCopy(builder.jniStrings);
        jniInts = immutableCopy(builder.jniInts);
        jniLongs = immutableCopy(builder.jniLongs);
        jniFloats = immutableCopy(builder.jniFloats);
        jniDoubles = immutableCopy(builder.jniDoubles);
        jniBooleans = immutableCopy(builder.jniBooleans);
        jniBytes = immutableBytes(builder.jniBytes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static DeviceProfile fromEnvironment() {
        int androidApi = envInt("ADJUST_ANDROID_API", 35);
        Builder builder = builder()
                .packageName(env("ADJUST_PACKAGE", "com.adjust.test"))
                .androidApi(androidApi)
                .certificateDer(envBytes("ADJUST_CERT_HEX", "ADJUST_CERT_TEXT", "local-adjust-debug-certificate"))
                .signingKey(envBytes("ADJUST_KEY_HEX", "ADJUST_KEY", "local-adjust-keystore-key"))
                .sensor(env("ADJUST_SENSOR_NAME", "BMI160 accelerometer"),
                        env("ADJUST_SENSOR_VENDOR", "Bosch"),
                        envInt("ADJUST_SENSOR_TYPE", 1),
                        envInt("ADJUST_SENSOR_VERSION", 1))
                .display(envInt("ADJUST_DISPLAY_WIDTH", 1080),
                        envInt("ADJUST_DISPLAY_HEIGHT", 2400),
                        envInt("ADJUST_DISPLAY_DENSITY_DPI", 420),
                        envFloat("ADJUST_DISPLAY_DENSITY", 2.75f),
                        envFloat("ADJUST_DISPLAY_SCALED_DENSITY", envFloat("ADJUST_DISPLAY_DENSITY", 2.75f)),
                        envFloat("ADJUST_DISPLAY_XDPI", 420.0f),
                        envFloat("ADJUST_DISPLAY_YDPI", 420.0f))
                .appUid(envInt("ADJUST_APP_UID", 10000))
                .targetSdk(envInt("ADJUST_TARGET_SDK", androidApi));
        String baseApk = System.getenv("ADJUST_BASE_APK");
        if (baseApk != null && !baseApk.isEmpty()) builder.baseApk(new File(baseApk));
        Integer nativeProcessId = envOptionalInt("ADJUST_NATIVE_PROCESS_ID");
        Long nativeTimeSeconds = envOptionalLong("ADJUST_NATIVE_TIME_SECONDS");
        Long nativeGettimeofdaySeconds = envOptionalLong("ADJUST_NATIVE_GETTIMEOFDAY_SECONDS");
        Long nativeGettimeofdayMicroseconds = envOptionalLong("ADJUST_NATIVE_GETTIMEOFDAY_MICROSECONDS");
        Long nativeClockGettimeSeconds = envOptionalLong("ADJUST_NATIVE_CLOCK_GETTIME_SECONDS");
        Long nativeClockGettimeNanoseconds = envOptionalLong("ADJUST_NATIVE_CLOCK_GETTIME_NANOSECONDS");
        String nativeUrandomHex = System.getenv("ADJUST_NATIVE_URANDOM_HEX");
        if (nativeProcessId != null) builder.nativeProcessId(nativeProcessId);
        if (nativeTimeSeconds != null) builder.nativeTimeSeconds(nativeTimeSeconds);
        if (nativeGettimeofdaySeconds != null || nativeGettimeofdayMicroseconds != null) {
            if (nativeGettimeofdaySeconds == null || nativeGettimeofdayMicroseconds == null) {
                throw new IllegalArgumentException("both ADJUST_NATIVE_GETTIMEOFDAY_SECONDS and "
                        + "ADJUST_NATIVE_GETTIMEOFDAY_MICROSECONDS are required");
            }
            builder.nativeGettimeofday(nativeGettimeofdaySeconds, nativeGettimeofdayMicroseconds);
        }
        if (nativeClockGettimeSeconds != null || nativeClockGettimeNanoseconds != null) {
            if (nativeClockGettimeSeconds == null || nativeClockGettimeNanoseconds == null) {
                throw new IllegalArgumentException("both ADJUST_NATIVE_CLOCK_GETTIME_SECONDS and "
                        + "ADJUST_NATIVE_CLOCK_GETTIME_NANOSECONDS are required");
            }
            builder.nativeClockGettime(nativeClockGettimeSeconds, nativeClockGettimeNanoseconds);
        }
        if (nativeUrandomHex != null && !nativeUrandomHex.isEmpty()) builder.nativeUrandomHex(nativeUrandomHex);
        return builder.build();
    }

    public String getPackageName() { return packageName; }
    public int getAndroidApi() { return androidApi; }
    public File getBaseApk() { return baseApk; }
    public byte[] getCertificateDer() { return certificateDer.clone(); }
    public byte[] getSigningKey() { return signingKey.clone(); }
    public List<Sensor> getSensors() { return sensors; }
    public String getSensorName() { return sensors.get(0).getName(); }
    public String getSensorVendor() { return sensors.get(0).getVendor(); }
    public int getSensorType() { return sensors.get(0).getType(); }
    public int getSensorVersion() { return sensors.get(0).getVersion(); }
    public int getDisplayWidth() { return displayWidth; }
    public int getDisplayHeight() { return displayHeight; }
    public int getDensityDpi() { return densityDpi; }
    public float getDensity() { return density; }
    public float getScaledDensity() { return scaledDensity; }
    public float getXdpi() { return xdpi; }
    public float getYdpi() { return ydpi; }
    public int getAppUid() { return appUid; }
    public int getTargetSdk() { return targetSdk; }
    public String getSourceDir() { return sourceDir; }
    public String getPublicSourceDir() { return publicSourceDir; }
    public String getDataDir() { return dataDir; }
    public String getNativeLibraryDir() { return nativeLibraryDir; }
    public Map<String, String> getBuildFields() { return buildFields; }
    public Map<String, String> getSystemProperties() { return systemProperties; }
    public Map<String, String> getSecureSettings() { return secureSettings; }
    public Map<String, String> getSystemSettings() { return systemSettings; }
    public Map<String, String> getServiceClasses() { return serviceClasses; }
    public String getLocale() { return locale; }
    public String getTimeZone() { return timeZone; }
    public Integer getNativeProcessId() { return nativeProcessId; }
    public Long getNativeTimeSeconds() { return nativeTimeSeconds; }
    public Long getNativeGettimeofdaySeconds() { return nativeGettimeofdaySeconds; }
    public Long getNativeGettimeofdayMicroseconds() { return nativeGettimeofdayMicroseconds; }
    public Long getNativeClockGettimeSeconds() { return nativeClockGettimeSeconds; }
    public Long getNativeClockGettimeNanoseconds() { return nativeClockGettimeNanoseconds; }
    public byte[] getNativeUrandomBytes() { return nativeUrandomBytes == null ? null : nativeUrandomBytes.clone(); }
    public boolean isNativeSignerCodeTrampolineDetected() { return nativeSignerCodeTrampolineDetected; }
    public Set<String> getNativeConnectRefusedEndpoints() { return nativeConnectRefusedEndpoints; }
    public Map<String, byte[]> getNativeLocalSocketResponses() { return mutableBytesCopy(nativeLocalSocketResponses); }
    public Map<String, byte[]> getNativeFiles() { return mutableBytesCopy(nativeFiles); }
    public Set<String> getNativeMissingPaths() { return nativeMissingPaths; }
    public Map<String, String> getJniStrings() { return jniStrings; }
    public Map<String, Integer> getJniInts() { return jniInts; }
    public Map<String, Long> getJniLongs() { return jniLongs; }
    public Map<String, Float> getJniFloats() { return jniFloats; }
    public Map<String, Double> getJniDoubles() { return jniDoubles; }
    public Map<String, Boolean> getJniBooleans() { return jniBooleans; }
    public Map<String, byte[]> getJniBytes() { return mutableBytesCopy(jniBytes); }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.trim().isEmpty()) throw new IllegalArgumentException(name + " must not be blank");
        return value;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static int envInt(String name, int fallback) {
        return Integer.parseInt(env(name, String.valueOf(fallback)));
    }

    private static float envFloat(String name, float fallback) {
        return Float.parseFloat(env(name, String.valueOf(fallback)));
    }

    private static Integer envOptionalInt(String name) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? null : Integer.valueOf(value);
    }

    private static Long envOptionalLong(String name) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? null : Long.valueOf(value);
    }

    private static byte[] envBytes(String hexName, String textName, String fallback) {
        String hex = System.getenv(hexName);
        if (hex != null && !hex.isEmpty()) return hexToBytes(hex);
        return env(textName, fallback).getBytes(StandardCharsets.UTF_8);
    }

    static byte[] hexToBytes(String value) {
        String clean = value.replaceAll("[^0-9a-fA-F]", "");
        if ((clean.length() & 1) != 0) throw new IllegalArgumentException("hex value has odd length");
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }

    private static <T> Map<String, T> immutableCopy(Map<String, T> source) {
        return Collections.unmodifiableMap(new LinkedHashMap<>(source));
    }

    private static Map<String, byte[]> immutableBytes(Map<String, byte[]> source) {
        return Collections.unmodifiableMap(mutableBytesCopy(source));
    }

    private static Map<String, byte[]> mutableBytesCopy(Map<String, byte[]> source) {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> entry : source.entrySet()) {
            copy.put(entry.getKey(), entry.getValue().clone());
        }
        return copy;
    }

    public static final class Sensor {
        private final String name;
        private final String vendor;
        private final int type;
        private final int version;

        public Sensor(String name, String vendor, int type, int version) {
            this.name = requireText(name, "sensor.name");
            this.vendor = requireText(vendor, "sensor.vendor");
            this.type = type;
            this.version = version;
        }

        public String getName() { return name; }
        public String getVendor() { return vendor; }
        public int getType() { return type; }
        public int getVersion() { return version; }
    }

    public static final class Builder {
        private String packageName = "com.adjust.test";
        private int androidApi = 35;
        private File baseApk;
        private byte[] certificateDer = "local-adjust-debug-certificate".getBytes(StandardCharsets.UTF_8);
        private byte[] signingKey = "local-adjust-keystore-key".getBytes(StandardCharsets.UTF_8);
        private final List<Sensor> sensors = new ArrayList<>();
        private boolean customSensors;
        private int displayWidth = 1080;
        private int displayHeight = 2400;
        private int densityDpi = 420;
        private float density = 2.75f;
        private float scaledDensity = 2.75f;
        private float xdpi = 420.0f;
        private float ydpi = 420.0f;
        private int appUid = 10000;
        private int targetSdk = 35;
        private boolean targetSdkExplicit;
        private String sourceDir;
        private String publicSourceDir;
        private String dataDir;
        private String nativeLibraryDir;
        private final Map<String, String> buildFields = new LinkedHashMap<>();
        private final Map<String, String> systemProperties = new LinkedHashMap<>();
        private final Map<String, String> secureSettings = new LinkedHashMap<>();
        private final Map<String, String> systemSettings = new LinkedHashMap<>();
        private final Map<String, String> serviceClasses = new LinkedHashMap<>();
        private String locale;
        private String timeZone;
        private Integer nativeProcessId;
        private Long nativeTimeSeconds;
        private Long nativeGettimeofdaySeconds;
        private Long nativeGettimeofdayMicroseconds;
        private Long nativeClockGettimeSeconds;
        private Long nativeClockGettimeNanoseconds;
        private byte[] nativeUrandomBytes;
        private boolean nativeSignerCodeTrampolineDetected;
        private final Set<String> nativeConnectRefusedEndpoints = new LinkedHashSet<>();
        private final Map<String, byte[]> nativeLocalSocketResponses = new LinkedHashMap<>();
        private final Map<String, byte[]> nativeFiles = new LinkedHashMap<>();
        private final Set<String> nativeMissingPaths = new LinkedHashSet<>();
        private final Map<String, String> jniStrings = new LinkedHashMap<>();
        private final Map<String, Integer> jniInts = new LinkedHashMap<>();
        private final Map<String, Long> jniLongs = new LinkedHashMap<>();
        private final Map<String, Float> jniFloats = new LinkedHashMap<>();
        private final Map<String, Double> jniDoubles = new LinkedHashMap<>();
        private final Map<String, Boolean> jniBooleans = new LinkedHashMap<>();
        private final Map<String, byte[]> jniBytes = new LinkedHashMap<>();

        private Builder() {
            sensors.add(new Sensor("BMI160 accelerometer", "Bosch", 1, 1));
            serviceClasses.put("sensor", "android/hardware/SensorManager");
            serviceClasses.put("phone", "android/telephony/TelephonyManager");
            serviceClasses.put("connectivity", "android/net/ConnectivityManager");
            serviceClasses.put("wifi", "android/net/wifi/WifiManager");
            serviceClasses.put("window", "android/view/WindowManager");
        }

        public Builder packageName(String value) { packageName = value; return this; }
        public Builder androidApi(int value) {
            androidApi = value;
            if (!targetSdkExplicit) targetSdk = value;
            return this;
        }
        public Builder baseApk(File value) { baseApk = value; return this; }
        public Builder certificateDer(byte[] value) { certificateDer = Objects.requireNonNull(value, "certificateDer").clone(); return this; }
        public Builder certificateHex(String value) { return certificateDer(hexToBytes(Objects.requireNonNull(value, "certificateHex"))); }
        public Builder signingKey(byte[] value) { signingKey = Objects.requireNonNull(value, "signingKey").clone(); return this; }
        public Builder signingKeyHex(String value) { return signingKey(hexToBytes(Objects.requireNonNull(value, "signingKeyHex"))); }
        public Builder sensor(String name, String vendor, int type, int version) {
            sensors.clear();
            sensors.add(new Sensor(name, vendor, type, version));
            customSensors = true;
            return this;
        }
        public Builder addSensor(String name, String vendor, int type, int version) {
            if (!customSensors) {
                sensors.clear();
                customSensors = true;
            }
            sensors.add(new Sensor(name, vendor, type, version));
            return this;
        }
        public Builder display(int width, int height, int dpi, float densityValue,
                               float scaledDensityValue, float xdpiValue, float ydpiValue) {
            displayWidth = width;
            displayHeight = height;
            densityDpi = dpi;
            density = densityValue;
            scaledDensity = scaledDensityValue;
            xdpi = xdpiValue;
            ydpi = ydpiValue;
            return this;
        }
        public Builder appUid(int value) { appUid = value; return this; }
        public Builder targetSdk(int value) { targetSdk = value; targetSdkExplicit = true; return this; }
        public Builder applicationPaths(String source, String publicSource, String data, String nativeLibrary) {
            sourceDir = source;
            publicSourceDir = publicSource;
            dataDir = data;
            nativeLibraryDir = nativeLibrary;
            return this;
        }
        public Builder buildField(String name, String value) { buildFields.put(name, value); return this; }
        public Builder buildFields(Map<String, String> values) { buildFields.putAll(values); return this; }
        public Builder systemProperty(String name, String value) { systemProperties.put(name, value); return this; }
        public Builder systemProperties(Map<String, String> values) { systemProperties.putAll(values); return this; }
        public Builder secureSetting(String name, String value) { secureSettings.put(name, value); return this; }
        public Builder secureSettings(Map<String, String> values) { secureSettings.putAll(values); return this; }
        public Builder systemSetting(String name, String value) { systemSettings.put(name, value); return this; }
        public Builder systemSettings(Map<String, String> values) { systemSettings.putAll(values); return this; }
        public Builder serviceClass(String name, String className) { serviceClasses.put(name, className); return this; }
        public Builder serviceClasses(Map<String, String> values) { serviceClasses.putAll(values); return this; }
        public Builder locale(String value) { locale = value; return this; }
        public Builder timeZone(String value) { timeZone = value; return this; }
        public Builder nativeProcessId(int value) { nativeProcessId = value; return this; }
        public Builder nativeTimeSeconds(long value) { nativeTimeSeconds = value; return this; }
        public Builder nativeGettimeofday(long seconds, long microseconds) {
            nativeGettimeofdaySeconds = seconds;
            nativeGettimeofdayMicroseconds = microseconds;
            return this;
        }
        public Builder nativeClockGettime(long seconds, long nanoseconds) {
            nativeClockGettimeSeconds = seconds;
            nativeClockGettimeNanoseconds = nanoseconds;
            return this;
        }
        public Builder nativeUrandom(byte[] value) {
            nativeUrandomBytes = Objects.requireNonNull(value, "nativeUrandom").clone();
            return this;
        }
        public Builder nativeUrandomHex(String value) {
            return nativeUrandom(hexToBytes(Objects.requireNonNull(value, "nativeUrandomHex")));
        }
        public Builder nativeSignerCodeTrampolineDetected(boolean value) {
            nativeSignerCodeTrampolineDetected = value;
            return this;
        }
        public Builder nativeConnectRefusedEndpoint(String value) {
            nativeConnectRefusedEndpoints.add(requireText(value, "nativeConnectRefusedEndpoint"));
            return this;
        }
        public Builder nativeLocalSocketResponse(String path, byte[] value) {
            nativeLocalSocketResponses.put(requireText(path, "nativeLocalSocketResponse.path"),
                    Objects.requireNonNull(value, "nativeLocalSocketResponse.value").clone());
            return this;
        }
        public Builder nativeFile(String path, byte[] value) {
            nativeFiles.put(requireText(path, "nativeFile.path"),
                    Objects.requireNonNull(value, "nativeFile.value").clone());
            nativeMissingPaths.remove(path);
            return this;
        }
        public Builder nativeMissingPath(String path) {
            String checked = requireText(path, "nativeMissingPath");
            nativeFiles.remove(checked);
            nativeMissingPaths.add(checked);
            return this;
        }
        public Builder jniString(String signature, String value) { jniStrings.put(signature, value); return this; }
        public Builder jniStrings(Map<String, String> values) { jniStrings.putAll(values); return this; }
        public Builder jniInt(String signature, int value) { jniInts.put(signature, value); return this; }
        public Builder jniInts(Map<String, Integer> values) { jniInts.putAll(values); return this; }
        public Builder jniLong(String signature, long value) { jniLongs.put(signature, value); return this; }
        public Builder jniLongs(Map<String, Long> values) { jniLongs.putAll(values); return this; }
        public Builder jniFloat(String signature, float value) { jniFloats.put(signature, value); return this; }
        public Builder jniFloats(Map<String, Float> values) { jniFloats.putAll(values); return this; }
        public Builder jniDouble(String signature, double value) { jniDoubles.put(signature, value); return this; }
        public Builder jniDoubles(Map<String, Double> values) { jniDoubles.putAll(values); return this; }
        public Builder jniBoolean(String signature, boolean value) { jniBooleans.put(signature, value); return this; }
        public Builder jniBooleans(Map<String, Boolean> values) { jniBooleans.putAll(values); return this; }
        public Builder jniBytes(String signature, byte[] value) { jniBytes.put(signature, value.clone()); return this; }
        public Builder jniBytesHex(String signature, String value) { return jniBytes(signature, hexToBytes(value)); }
        public DeviceProfile build() { return new DeviceProfile(this); }
    }
}
