package android.content;

import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Context {
    public static final int MODE_PRIVATE = 0;

    private final String packageName;
    private final Map<String, SharedPreferences> preferences = new ConcurrentHashMap<>();

    public Context() {
        this(System.getenv().getOrDefault("ADJUST_PACKAGE", "com.adjust.test"));
    }

    public Context(String packageName) {
        this.packageName = packageName;
    }

    public String getPackageName() {
        return packageName;
    }

    public PackageManager getPackageManager() {
        return new PackageManager(packageName);
    }

    public ApplicationInfo getApplicationInfo() {
        ApplicationInfo info = new ApplicationInfo();
        info.packageName = packageName;
        info.sourceDir = "/data/app/" + packageName + "/base.apk";
        info.publicSourceDir = info.sourceDir;
        info.dataDir = "/data/data/" + packageName;
        info.nativeLibraryDir = "/data/app/" + packageName + "/lib/arm64";
        info.targetSdkVersion = android.os.Build.VERSION.SDK_INT;
        return info;
    }

    public Object getSystemService(String name) {
        return null;
    }

    public SharedPreferences getSharedPreferences(String name, int mode) {
        return preferences.computeIfAbsent(name, ignored -> new MemorySharedPreferences());
    }

    public void putSharedPreference(String name, String key, String value) {
        getSharedPreferences(name, MODE_PRIVATE).edit().putString(key, value).apply();
    }

    private static final class MemorySharedPreferences implements SharedPreferences {
        private final Map<String, String> values = new ConcurrentHashMap<>();

        @Override public boolean contains(String key) { return values.containsKey(key); }
        @Override public String getString(String key, String defValue) { return values.getOrDefault(key, defValue); }
        @Override public Editor edit() { return new MemoryEditor(); }

        private final class MemoryEditor implements Editor {
            @Override public Editor putString(String key, String value) { values.put(key, value); return this; }
            @Override public Editor remove(String key) { values.remove(key); return this; }
            @Override public void apply() {}
        }
    }
}
