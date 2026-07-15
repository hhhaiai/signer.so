package android.content.pm;

import java.nio.charset.StandardCharsets;

public class PackageManager {
    private final String packageName;

    public PackageManager(String packageName) {
        this.packageName = packageName;
    }

    public ApplicationInfo getApplicationInfo(String packageName, int flags) {
        ApplicationInfo info = new ApplicationInfo();
        info.packageName = packageName;
        info.sourceDir = "/data/app/" + packageName + "/base.apk";
        info.publicSourceDir = info.sourceDir;
        info.dataDir = "/data/data/" + packageName;
        info.nativeLibraryDir = "/data/app/" + packageName + "/lib/arm64";
        return info;
    }

    public PackageInfo getPackageInfo(String packageName, int flags) {
        PackageInfo info = new PackageInfo();
        info.applicationInfo = getApplicationInfo(packageName, flags);
        Signature sig = new Signature(System.getenv().getOrDefault("ADJUST_CERT_TEXT", "local-adjust-debug-certificate").getBytes(StandardCharsets.UTF_8));
        info.signatures = new Signature[]{sig};
        info.signingInfo = new SigningInfo(sig);
        return info;
    }
}
