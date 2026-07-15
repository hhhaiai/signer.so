package local;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class SignerOneClick {
    private SignerOneClick() {}

    public static String run(File projectRoot, File inputFile) throws Exception {
        File input = inputFile.getCanonicalFile();
        return run(projectRoot, Files.readString(input.toPath()), input.getParentFile());
    }

    public static String run(File projectRoot, String json, File baseDirectory) throws Exception {
        JSONObject root = JSON.parseObject(json, Feature.OrderedField);
        if (root == null) throw new IllegalArgumentException("input JSON is empty");
        DeviceProfile profile = parseProfile(root.getJSONObject("device"), baseDirectory);
        SignerRequest request = parseRequest(root.getJSONObject("sign"));
        SignerResult result = SignerEngine.signOnce(projectRoot, profile, request);
        JSONObject actual = resultJson(result);
        JSONObject expected = root.getJSONObject("expectedResult");
        if (expected != null && root.containsKey("expectedResultFile")) {
            throw new IllegalArgumentException("use only one of expectedResult or expectedResultFile");
        }
        if (expected == null && root.containsKey("expectedResultFile")) {
            File expectedFile = resolve(baseDirectory, root.getString("expectedResultFile"));
            expected = JSON.parseObject(Files.readString(expectedFile.toPath()), Feature.OrderedField);
            if (expected == null) throw new IllegalArgumentException("expectedResultFile is empty: " + expectedFile);
        }
        if (expected != null) assertExpectedResult(expected, actual);
        return actual.toJSONString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("usage: SignerOneClick <input.json> [project-root]");
        }
        File input = new File(args[0]).getCanonicalFile();
        File projectRoot = new File(args.length == 2 ? args[1] : ".").getCanonicalFile();
        System.out.println("SIGNER_RESULT_JSON=" + run(projectRoot, input));
    }

    static DeviceProfile parseProfile(JSONObject device, File baseDirectory) throws Exception {
        JSONObject value = device == null ? new JSONObject(true) : device;
        DeviceProfile.Builder builder = DeviceProfile.builder();
        if (value.containsKey("packageName")) builder.packageName(value.getString("packageName"));
        if (value.containsKey("androidApi")) builder.androidApi(value.getIntValue("androidApi"));
        if (value.containsKey("baseApk")) builder.baseApk(resolve(baseDirectory, value.getString("baseApk")));
        applyBytes(value, "certificate", baseDirectory, builder::certificateDer);
        applyBytes(value, "signingKey", baseDirectory, builder::signingKey);
        JSONObject legacyKeyStore = value.getJSONObject("legacyKeyStore");
        if (legacyKeyStore != null) {
            applyBytes(legacyKeyStore, "privateKeyPkcs8", baseDirectory,
                    builder::legacyRsaPrivateKeyPkcs8);
            applyBytes(legacyKeyStore, "publicKeyX509", baseDirectory,
                    builder::legacyRsaPublicKeyX509);
        }
        if (value.containsKey("appUid")) builder.appUid(value.getIntValue("appUid"));
        if (value.containsKey("targetSdk")) builder.targetSdk(value.getIntValue("targetSdk"));
        JSONObject applicationInfo = value.getJSONObject("applicationInfo");
        if (applicationInfo != null) {
            String packageName = value.getString("packageName");
            if (packageName == null) packageName = "com.adjust.test";
            String sourceDir = applicationInfo.getString("sourceDir");
            if (sourceDir == null) sourceDir = "/data/app/" + packageName + "/base.apk";
            String publicSourceDir = applicationInfo.getString("publicSourceDir");
            if (publicSourceDir == null) publicSourceDir = sourceDir;
            String dataDir = applicationInfo.getString("dataDir");
            if (dataDir == null) dataDir = "/data/data/" + packageName;
            String nativeLibraryDir = applicationInfo.getString("nativeLibraryDir");
            if (nativeLibraryDir == null) nativeLibraryDir = "/data/app/" + packageName + "/lib/arm64";
            builder.applicationPaths(sourceDir, publicSourceDir, dataDir, nativeLibraryDir);
        }

        JSONObject display = value.getJSONObject("display");
        if (display != null) {
            float density = floatValue(display, "density", 2.75f);
            builder.display(intValue(display, "width", 1080),
                    intValue(display, "height", 2400),
                    intValue(display, "densityDpi", 420),
                    density,
                    floatValue(display, "scaledDensity", density),
                    floatValue(display, "xdpi", 420.0f),
                    floatValue(display, "ydpi", 420.0f));
        }

        JSONArray sensors = value.getJSONArray("sensors");
        if (sensors != null && !sensors.isEmpty()) {
            for (int i = 0; i < sensors.size(); i++) {
                JSONObject sensor = sensors.getJSONObject(i);
                String name = sensor.getString("name");
                String vendor = sensor.getString("vendor");
                int type = sensor.getIntValue("type");
                int version = sensor.getIntValue("version");
                if (i == 0) builder.sensor(name, vendor, type, version);
                else builder.addSensor(name, vendor, type, version);
            }
        }

        builder.buildFields(stringMap(value.getJSONObject("build")));
        builder.systemProperties(stringMap(value.getJSONObject("systemProperties")));
        JSONObject settings = value.getJSONObject("settings");
        if (settings != null) {
            builder.secureSettings(stringMap(settings.getJSONObject("secure")));
            builder.systemSettings(stringMap(settings.getJSONObject("system")));
        }
        JSONObject sharedPreferences = value.getJSONObject("sharedPreferences");
        if (sharedPreferences != null) {
            for (String name : sharedPreferences.keySet()) {
                JSONObject entries = sharedPreferences.getJSONObject(name);
                if (entries == null) {
                    throw new IllegalArgumentException("sharedPreferences entry must be an object: " + name);
                }
                builder.sharedPreferences(name, stringMap(entries));
            }
        }
        builder.serviceClasses(stringMap(value.getJSONObject("services")));
        if (value.containsKey("locale")) builder.locale(value.getString("locale"));
        if (value.containsKey("timezone")) builder.timeZone(value.getString("timezone"));

        JSONObject runtime = value.getJSONObject("runtime");
        if (runtime != null) {
            if (runtime.containsKey("backend")) builder.nativeBackend(runtime.getString("backend"));
            if (runtime.containsKey("processId")) builder.nativeProcessId(runtime.getIntValue("processId"));
            if (runtime.containsKey("timeSeconds")) builder.nativeTimeSeconds(runtime.getLongValue("timeSeconds"));
            JSONObject gettimeofday = runtime.getJSONObject("gettimeofday");
            if (gettimeofday != null) {
                builder.nativeGettimeofday(gettimeofday.getLongValue("seconds"),
                        gettimeofday.getLongValue("microseconds"));
            }
            JSONObject clockGettime = runtime.getJSONObject("clockGettime");
            if (clockGettime != null) {
                builder.nativeClockGettime(clockGettime.getLongValue("seconds"),
                        clockGettime.getLongValue("nanoseconds"));
            }
            if (runtime.containsKey("urandomHex")) builder.nativeUrandomHex(runtime.getString("urandomHex"));
            if (runtime.containsKey("signerCodeTrampolineDetected")) {
                builder.nativeSignerCodeTrampolineDetected(
                        runtime.getBooleanValue("signerCodeTrampolineDetected"));
            }
            if (runtime.containsKey("correction05Enabled")) {
                builder.nativeCorrection05Enabled(runtime.getBooleanValue("correction05Enabled"));
            }
            JSONArray correctionCodes = runtime.getJSONArray("correctionCodes");
            if (correctionCodes != null) {
                for (int i = 0; i < correctionCodes.size(); i++) {
                    Object correction = correctionCodes.get(i);
                    if (correction instanceof Number) {
                        builder.nativeCorrectionCode(((Number) correction).intValue());
                    } else {
                        String text = String.valueOf(correction).trim();
                        if (text.startsWith("0x") || text.startsWith("0X")) text = text.substring(2);
                        builder.nativeCorrectionCode(Integer.parseInt(text, 16));
                    }
                }
            }
            JSONObject network = runtime.getJSONObject("network");
            if (network != null) {
                JSONArray connectRefused = network.getJSONArray("connectRefusedEndpoints");
                if (connectRefused != null) {
                    for (int i = 0; i < connectRefused.size(); i++) {
                        builder.nativeConnectRefusedEndpoint(connectRefused.getString(i));
                    }
                }
                JSONObject localSocketResponses = network.getJSONObject("localSocketResponses");
                if (localSocketResponses != null) {
                    for (String path : localSocketResponses.keySet()) {
                        JSONObject source = localSocketResponses.getJSONObject(path);
                        if (source == null) {
                            throw new IllegalArgumentException(
                                    "runtime.network.localSocketResponses entry must be an object: " + path);
                        }
                        int choices = (source.containsKey("file") ? 1 : 0)
                                + (source.containsKey("text") ? 1 : 0)
                                + (source.containsKey("hex") ? 1 : 0);
                        if (choices != 1) {
                            throw new IllegalArgumentException(
                                    "runtime.network.localSocketResponses entry needs exactly one of file/text/hex: "
                                            + path);
                        }
                        byte[] bytes;
                        if (source.containsKey("file")) {
                            bytes = Files.readAllBytes(resolve(baseDirectory, source.getString("file")).toPath());
                        } else if (source.containsKey("hex")) {
                            bytes = DeviceProfile.hexToBytes(source.getString("hex"));
                        } else {
                            bytes = source.getString("text").getBytes(StandardCharsets.UTF_8);
                        }
                        builder.nativeLocalSocketResponse(path, bytes);
                    }
                }
            }
        }

        JSONObject filesystem = value.getJSONObject("filesystem");
        if (filesystem != null) {
            JSONObject files = filesystem.getJSONObject("files");
            if (files != null) {
                for (String path : files.keySet()) {
                    JSONObject source = files.getJSONObject(path);
                    if (source == null) throw new IllegalArgumentException("filesystem.files entry must be an object: " + path);
                    int choices = (source.containsKey("file") ? 1 : 0)
                            + (source.containsKey("text") ? 1 : 0)
                            + (source.containsKey("hex") ? 1 : 0);
                    if (choices != 1) {
                        throw new IllegalArgumentException("filesystem.files entry needs exactly one of file/text/hex: " + path);
                    }
                    byte[] bytes;
                    if (source.containsKey("file")) {
                        bytes = Files.readAllBytes(resolve(baseDirectory, source.getString("file")).toPath());
                    } else if (source.containsKey("hex")) {
                        bytes = DeviceProfile.hexToBytes(source.getString("hex"));
                    } else {
                        bytes = source.getString("text").getBytes(StandardCharsets.UTF_8);
                    }
                    builder.nativeFile(path, bytes);
                }
            }
            JSONArray missing = filesystem.getJSONArray("missing");
            if (missing != null) {
                for (int i = 0; i < missing.size(); i++) builder.nativeMissingPath(missing.getString(i));
            }
        }

        JSONObject jni = value.getJSONObject("jni");
        if (jni != null) {
            builder.jniStrings(stringMap(jni.getJSONObject("strings")));
            JSONObject ints = jni.getJSONObject("ints");
            if (ints != null) for (String key : ints.keySet()) builder.jniInt(key, ints.getIntValue(key));
            JSONObject longs = jni.getJSONObject("longs");
            if (longs != null) for (String key : longs.keySet()) builder.jniLong(key, longs.getLongValue(key));
            JSONObject floats = jni.getJSONObject("floats");
            if (floats != null) for (String key : floats.keySet()) builder.jniFloat(key, floats.getFloatValue(key));
            JSONObject doubles = jni.getJSONObject("doubles");
            if (doubles != null) for (String key : doubles.keySet()) builder.jniDouble(key, doubles.getDoubleValue(key));
            JSONObject booleans = jni.getJSONObject("booleans");
            if (booleans != null) for (String key : booleans.keySet()) builder.jniBoolean(key, booleans.getBooleanValue(key));
            JSONObject bytesHex = jni.getJSONObject("bytesHex");
            if (bytesHex != null) for (String key : bytesHex.keySet()) builder.jniBytesHex(key, bytesHex.getString(key));
        }
        return builder.build();
    }

    private static SignerRequest parseRequest(JSONObject sign) {
        if (sign == null) throw new IllegalArgumentException("missing sign object");
        Map<String, String> parameters = stringMap(sign.getJSONObject("parameters"));
        String version = sign.getString("version");
        if (version == null || "v4".equalsIgnoreCase(version)) {
            return SignerRequest.v4(parameters,
                    sign.getString("activityKind"), sign.getString("clientSdk"));
        }
        if ("v5".equalsIgnoreCase(version)) {
            return SignerRequest.v5(parameters, stringMap(sign.getJSONObject("request")));
        }
        throw new IllegalArgumentException("unknown sign.version: " + version);
    }

    private static JSONObject resultJson(SignerResult result) {
        JSONObject json = new JSONObject(true);
        json.put("signed", result.isSigned());
        json.put("version", result.getVersion().name());
        byte[] raw = result.getRawSignature();
        if (raw != null) json.put("rawSignatureHex", bytesToHex(raw));
        if (result.getSignatureBase64() != null) json.put("signatureBase64", result.getSignatureBase64());
        if (result.getAuthorization() != null) json.put("authorization", result.getAuthorization());
        json.put("metadata", new JSONObject(new LinkedHashMap<>(result.getMetadata())));
        json.put("output", new JSONObject(new LinkedHashMap<>(result.getOutput())));
        return json;
    }

    private static void assertExpectedResult(JSONObject expected, JSONObject actual) {
        String mismatch = firstMismatch("expectedResult", expected, actual);
        if (mismatch != null) throw new IllegalStateException("expectedResult mismatch at " + mismatch);
    }

    private static String firstMismatch(String path, Object expected, Object actual) {
        if (expected instanceof Map && actual instanceof Map) {
            Map<?, ?> expectedMap = (Map<?, ?>) expected;
            Map<?, ?> actualMap = (Map<?, ?>) actual;
            if (!expectedMap.keySet().equals(actualMap.keySet())) {
                return path + " keys expected=" + expectedMap.keySet() + " actual=" + actualMap.keySet();
            }
            for (Object key : expectedMap.keySet()) {
                String mismatch = firstMismatch(path + "." + key, expectedMap.get(key), actualMap.get(key));
                if (mismatch != null) return mismatch;
            }
            return null;
        }
        if (expected instanceof List && actual instanceof List) {
            List<?> expectedList = (List<?>) expected;
            List<?> actualList = (List<?>) actual;
            if (expectedList.size() != actualList.size()) {
                return path + " size expected=" + expectedList.size() + " actual=" + actualList.size();
            }
            for (int i = 0; i < expectedList.size(); i++) {
                String mismatch = firstMismatch(path + "[" + i + "]", expectedList.get(i), actualList.get(i));
                if (mismatch != null) return mismatch;
            }
            return null;
        }
        return Objects.equals(expected, actual)
                ? null : path + " expected=" + expected + " actual=" + actual;
    }

    private interface BytesConsumer {
        void accept(byte[] value);
    }

    private static void applyBytes(JSONObject source, String prefix, File baseDirectory,
                                   BytesConsumer consumer) throws Exception {
        String fileKey = prefix + "File";
        String hexKey = prefix + "Hex";
        String textKey = prefix + "Text";
        if (source.containsKey(fileKey)) {
            consumer.accept(Files.readAllBytes(resolve(baseDirectory, source.getString(fileKey)).toPath()));
        } else if (source.containsKey(hexKey)) {
            consumer.accept(DeviceProfile.hexToBytes(source.getString(hexKey)));
        } else if (source.containsKey(textKey)) {
            consumer.accept(source.getString(textKey).getBytes(StandardCharsets.UTF_8));
        }
    }

    private static File resolve(File baseDirectory, String path) throws Exception {
        File file = new File(path);
        if (!file.isAbsolute() && baseDirectory != null) file = new File(baseDirectory, path);
        return file.getCanonicalFile();
    }

    private static Map<String, String> stringMap(JSONObject object) {
        Map<String, String> values = new LinkedHashMap<>();
        if (object == null) return values;
        for (String key : object.keySet()) {
            Object value = object.get(key);
            if (value != null) values.put(key, String.valueOf(value));
        }
        return values;
    }

    private static int intValue(JSONObject object, String key, int fallback) {
        return object.containsKey(key) ? object.getIntValue(key) : fallback;
    }

    private static float floatValue(JSONObject object, String key, float fallback) {
        return object.containsKey(key) ? object.getFloatValue(key) : fallback;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) value.append(String.format("%02x", b & 0xff));
        return value.toString();
    }
}
