import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.*;
public class ProbeApkCert {
  public static void main(String[] args) throws Exception {
    try (ApkFile apk = new ApkFile(args[0])) {
      System.out.println("metas=" + apk.getCertificateMetaList().size());
      for (CertificateMeta m : apk.getCertificateMetaList()) System.out.println("meta bytes="+m.getData().length+" md5="+m.getCertMd5());
      System.out.println("v1=" + apk.getApkSingers().size());
      System.out.println("v2=" + apk.getApkV2Singers().size());
    }
  }
}
