package android.content.pm;

public class ApplicationInfo {
    public String sourceDir;
    public String publicSourceDir;
    public String dataDir;
    public String nativeLibraryDir;
    public String packageName;
    public int flags;
    public int uid = 10000;
    public int targetSdkVersion = android.os.Build.VERSION.SDK_INT;
}
