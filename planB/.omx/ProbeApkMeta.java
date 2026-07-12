import net.dongliu.apk.parser.ApkFile;
public class ProbeApkMeta { public static void main(String[] a) throws Exception { try(ApkFile f=new ApkFile(a[0])) { System.out.println(f.getApkMeta().getPackageName()); } } }
