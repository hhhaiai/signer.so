package android.os;

public final class Build {
    private Build() {}

    public static final class VERSION {
        public static int SDK_INT = Integer.parseInt(System.getenv().getOrDefault("ADJUST_ANDROID_API", "35"));
        private VERSION() {}
    }
}
