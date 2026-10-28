import com.android.apksig.ApkSigner;
import com.android.apksig.SigningCertificateLineage;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Fixture signer. Usage:
 *   java -cp apksig.jar Sign.java <in.apk> <out.apk> <minSdk> <v1> <v2> <v3> <ks1.p12> [ks2.p12]
 * When two keystores are given, the APK is signed with a rotation lineage ks1 -> ks2.
 */
@SuppressWarnings("deprecation")
public class Sign {
  static Object[] load(String path) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (FileInputStream in = new FileInputStream(path)) { ks.load(in, "fixture".toCharArray()); }
    String alias = ks.aliases().nextElement();
    return new Object[] { (PrivateKey) ks.getKey(alias, "fixture".toCharArray()), (X509Certificate) ks.getCertificate(alias) };
  }

  public static void main(String[] a) throws Exception {
    int minSdk = Integer.parseInt(a[2]);
    boolean v1 = Boolean.parseBoolean(a[3]), v2 = Boolean.parseBoolean(a[4]), v3 = Boolean.parseBoolean(a[5]);
    List<ApkSigner.SignerConfig> signers = new ArrayList<>();
    Object[] k1 = load(a[6]);
    signers.add(new ApkSigner.SignerConfig.Builder("old", (PrivateKey) k1[0], List.of((X509Certificate) k1[1])).build());
    SigningCertificateLineage lineage = null;
    if (a.length > 7) {
      Object[] k2 = load(a[7]);
      signers.add(new ApkSigner.SignerConfig.Builder("new", (PrivateKey) k2[0], List.of((X509Certificate) k2[1])).build());
      lineage = new SigningCertificateLineage.Builder(
          new SigningCertificateLineage.SignerConfig.Builder((PrivateKey) k1[0], (X509Certificate) k1[1]).build(),
          new SigningCertificateLineage.SignerConfig.Builder((PrivateKey) k2[0], (X509Certificate) k2[1]).build()).build();
    }
    ApkSigner.Builder b = new ApkSigner.Builder(signers)
        .setInputApk(new File(a[0])).setOutputApk(new File(a[1]))
        .setMinSdkVersion(minSdk)
        .setV1SigningEnabled(v1).setV2SigningEnabled(v2).setV3SigningEnabled(v3)
        .setV4SigningEnabled(false);
    if (lineage != null) b.setSigningCertificateLineage(lineage);
    b.build().sign();
  }
}
