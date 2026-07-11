package android.util;

public final class Log {
    private Log() {}

    public static int v(String tag, String msg) {
        System.out.println("[main]V/" + tag + ": " + msg);
        return 0;
    }

    public static int e(String tag, String msg) {
        System.err.println("[main]E/" + tag + ": " + msg);
        return 0;
    }

    public static int e(String tag, String msg, Throwable tr) {
        System.err.println("[main]E/" + tag + ": " + msg);
        if (tr != null) tr.printStackTrace(System.err);
        return 0;
    }
}
