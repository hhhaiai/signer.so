import net.dongliu.apk.parser.ApkFile;
public class ProbeManifest { public static void main(String[] a) throws Exception { try(ApkFile f=new ApkFile(a[0])) { System.out.println(f.getManifestXml().substring(0,Math.min(500,f.getManifestXml().length()))); } } }
