package local;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class DeviceProfileFlexibleTest {
    @Test
    void acceptsFriendlyAndroidFieldsAndGenericJniOverrides() {
        Map<String, String> build = new LinkedHashMap<>();
        build.put("MODEL", "Pixel 9 Pro");
        build.put("VERSION.RELEASE", "15");

        DeviceProfile profile = DeviceProfile.builder()
                .sensor("LSM6DSO", "STMicroelectronics", 1, 3)
                .addSensor("AK09918", "Asahi Kasei", 2, 1)
                .buildFields(build)
                .systemProperty("ro.product.model", "Pixel 9 Pro")
                .secureSetting("android_id", "0123456789abcdef")
                .systemSetting("time_12_24", "24")
                .serviceClass("phone", "android/telephony/TelephonyManager")
                .locale("zh-CN")
                .timeZone("Asia/Shanghai")
                .nativeProcessId(4242)
                .nativeTimeSeconds(1_760_000_000L)
                .nativeGettimeofday(1_760_000_001L, 123_456L)
                .nativeClockGettime(1_760_000_002L, 987_654_321L)
                .nativeUrandom(new byte[]{0, 1, 2, 3, 4, 5, 6, 7})
                .nativeLocalSocketResponse("/dev/socket/fwmarkd", new byte[]{0, 0, 0, 0})
                .nativeFile("/proc/cpuinfo", "processor\\t: 0\\n".getBytes())
                .nativeMissingPath("/proc/version")
                .applicationPaths("/data/app/random/base.apk", "/data/app/random/base.apk",
                        "/data/user/0/com.adjust.test", "/data/app/random/lib/arm64")
                .jniString("android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;", "imei-value")
                .jniInt("android/net/NetworkInfo->getType()I", 1)
                .jniLong("android/os/SystemClock->elapsedRealtime()J", 123456L)
                .jniFloat("android/view/Display->getRefreshRate()F", 120.0f)
                .jniDouble("android/location/Location->getLatitude()D", 31.2304d)
                .jniBoolean("android/net/NetworkInfo->isConnected()Z", true)
                .jniBytes("android/provider/Settings$Secure->getBytes()[B", new byte[]{1, 2, 3})
                .build();

        assertEquals(2, profile.getSensors().size());
        assertEquals("AK09918", profile.getSensors().get(1).getName());
        assertEquals("Pixel 9 Pro", profile.getBuildFields().get("MODEL"));
        assertEquals("Pixel 9 Pro", profile.getSystemProperties().get("ro.product.model"));
        assertEquals("0123456789abcdef", profile.getSecureSettings().get("android_id"));
        assertEquals("24", profile.getSystemSettings().get("time_12_24"));
        assertEquals("android/telephony/TelephonyManager", profile.getServiceClasses().get("phone"));
        assertEquals("zh-CN", profile.getLocale());
        assertEquals("Asia/Shanghai", profile.getTimeZone());
        assertEquals(4242, profile.getNativeProcessId());
        assertEquals(1_760_000_000L, profile.getNativeTimeSeconds());
        assertEquals(1_760_000_001L, profile.getNativeGettimeofdaySeconds());
        assertEquals(123_456L, profile.getNativeGettimeofdayMicroseconds());
        assertEquals(1_760_000_002L, profile.getNativeClockGettimeSeconds());
        assertEquals(987_654_321L, profile.getNativeClockGettimeNanoseconds());
        assertArrayEquals(new byte[]{0, 1, 2, 3, 4, 5, 6, 7}, profile.getNativeUrandomBytes());
        assertArrayEquals(new byte[]{0, 0, 0, 0},
                profile.getNativeLocalSocketResponses().get("/dev/socket/fwmarkd"));
        assertArrayEquals("processor\\t: 0\\n".getBytes(), profile.getNativeFiles().get("/proc/cpuinfo"));
        assertEquals(Set.of("/proc/version"), profile.getNativeMissingPaths());
        assertEquals("/data/app/random/base.apk", profile.getSourceDir());
        assertEquals("/data/app/random/base.apk", profile.getPublicSourceDir());
        assertEquals("/data/user/0/com.adjust.test", profile.getDataDir());
        assertEquals("/data/app/random/lib/arm64", profile.getNativeLibraryDir());
        assertEquals("imei-value", profile.getJniStrings().get("android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;"));
        assertEquals(1, profile.getJniInts().get("android/net/NetworkInfo->getType()I"));
        assertEquals(123456L, profile.getJniLongs().get("android/os/SystemClock->elapsedRealtime()J"));
        assertEquals(120.0f, profile.getJniFloats().get("android/view/Display->getRefreshRate()F"));
        assertEquals(31.2304d, profile.getJniDoubles().get("android/location/Location->getLatitude()D"));
        assertEquals(true, profile.getJniBooleans().get("android/net/NetworkInfo->isConnected()Z"));
        assertArrayEquals(new byte[]{1, 2, 3}, profile.getJniBytes().get("android/provider/Settings$Secure->getBytes()[B"));
    }
}
