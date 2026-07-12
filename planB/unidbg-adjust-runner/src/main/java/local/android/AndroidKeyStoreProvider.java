package local.android;

import javax.crypto.SecretKey;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;

public final class AndroidKeyStoreProvider extends Provider {
    private static volatile byte[] keyBytes = "local-adjust-keystore-key".getBytes(StandardCharsets.UTF_8);
    private static volatile SecretKey secretKey = currentKey();
    private static volatile KeyPair rsaKeyPair;
    private static volatile Certificate rsaCertificate;

    public AndroidKeyStoreProvider() {
        super("AndroidKeyStore", 1.0, "Local AndroidKeyStore stub for adjust signature runner");
        put("KeyStore.AndroidKeyStore", LocalKeyStoreSpi.class.getName());
        put("KeyGenerator.HmacSHA256", LocalHmacKeyGeneratorSpi.class.getName());
        put("KeyPairGenerator.RSA", LocalRsaKeyPairGeneratorSpi.class.getName());
    }

    public static void installFromEnv() {
        install(envBytes("ADJUST_KEY_HEX", "ADJUST_KEY", "local-adjust-keystore-key"));
    }

    public static synchronized void install(byte[] configuredKey) {
        install(configuredKey, null, null);
    }

    public static synchronized void install(byte[] configuredKey, byte[] privateKeyPkcs8,
                                            byte[] publicKeyX509) {
        if (configuredKey == null || configuredKey.length == 0) {
            throw new IllegalArgumentException("configuredKey must not be empty");
        }
        if ((privateKeyPkcs8 == null) != (publicKeyX509 == null)) {
            throw new IllegalArgumentException("legacy RSA import requires both private and public keys");
        }
        keyBytes = configuredKey.clone();
        secretKey = currentKey();
        rsaKeyPair = null;
        rsaCertificate = null;
        if (privateKeyPkcs8 != null) {
            try {
                KeyFactory factory = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyPkcs8));
                PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicKeyX509));
                storeRsaKeyPair(new KeyPair(publicKey, privateKey));
            } catch (Exception exception) {
                throw new IllegalArgumentException("invalid legacy RSA key pair", exception);
            }
        }
        if (Security.getProvider("AndroidKeyStore") == null) {
            Security.addProvider(new AndroidKeyStoreProvider());
        }
    }

    private static SecretKey currentKey() {
        return new SecretKeySpec(keyBytes.clone(), "HmacSHA256");
    }

    private static synchronized void storeRsaKeyPair(KeyPair keyPair) {
        rsaKeyPair = keyPair;
        rsaCertificate = new LocalCertificate(keyPair.getPublic());
    }

    private static byte[] envBytes(String hexEnv, String textEnv, String defaultText) {
        String hex = System.getenv(hexEnv);
        if (hex != null && !hex.isEmpty()) return hexToBytes(hex);
        String text = System.getenv(textEnv);
        if (text != null) return text.getBytes(StandardCharsets.UTF_8);
        return defaultText.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hexToBytes(String s) {
        String clean = s.replaceAll("[^0-9a-fA-F]", "");
        if ((clean.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    public static final class LocalKeyStoreSpi extends KeyStoreSpi {
        @Override public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
            return "key2".equals(alias) ? secretKey : null;
        }
        @Override public Certificate[] engineGetCertificateChain(String alias) {
            return "key2".equals(alias) && rsaCertificate != null ? new Certificate[]{rsaCertificate} : null;
        }
        @Override public Certificate engineGetCertificate(String alias) {
            return "key2".equals(alias) ? rsaCertificate : null;
        }
        @Override public Date engineGetCreationDate(String alias) { return new Date(0); }
        @Override public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) throws KeyStoreException {
            if ("key2".equals(alias) && key instanceof SecretKey) secretKey = (SecretKey) key;
        }
        @Override public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {}
        @Override public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {}
        @Override public void engineDeleteEntry(String alias) throws KeyStoreException {
            if ("key2".equals(alias)) {
                secretKey = null;
                rsaKeyPair = null;
                rsaCertificate = null;
            }
        }
        @Override public Enumeration<String> engineAliases() {
            return hasKey() ? Collections.enumeration(Collections.singleton("key2")) : Collections.emptyEnumeration();
        }
        @Override public boolean engineContainsAlias(String alias) { return "key2".equals(alias) && hasKey(); }
        @Override public int engineSize() { return hasKey() ? 1 : 0; }
        @Override public boolean engineIsKeyEntry(String alias) { return "key2".equals(alias) && hasKey(); }
        @Override public boolean engineIsCertificateEntry(String alias) { return false; }
        @Override public String engineGetCertificateAlias(Certificate cert) { return null; }
        @Override public void engineStore(OutputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {}
        @Override public void engineLoad(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {}
        @Override public void engineLoad(KeyStore.LoadStoreParameter param) throws IOException, NoSuchAlgorithmException, CertificateException {}

        @Override
        public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protectionParameter) {
            if (!"key2".equals(alias)) return null;
            if (rsaKeyPair != null && rsaCertificate != null) {
                return new KeyStore.PrivateKeyEntry(rsaKeyPair.getPrivate(), new Certificate[]{rsaCertificate});
            }
            return secretKey == null ? null : new KeyStore.SecretKeyEntry(secretKey);
        }

        private static boolean hasKey() {
            return secretKey != null || rsaKeyPair != null;
        }
    }

    public static final class LocalHmacKeyGeneratorSpi extends KeyGeneratorSpi {
        @Override protected void engineInit(SecureRandom random) {}
        @Override protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {}
        @Override protected void engineInit(int keySize, SecureRandom random) {}

        @Override
        protected SecretKey engineGenerateKey() {
            secretKey = currentKey();
            return secretKey;
        }
    }

    public static final class LocalRsaKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
        private int keySize = 1024;
        private SecureRandom random = new SecureRandom();

        @Override
        public void initialize(int keySize, SecureRandom random) {
            this.keySize = keySize;
            if (random != null) this.random = random;
        }

        @Override
        public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
            this.keySize = 1024;
            if (random != null) this.random = random;
        }

        @Override
        public KeyPair generateKeyPair() {
            try {
                KeyPairGenerator generator = standardRsaGenerator();
                generator.initialize(keySize, random);
                KeyPair keyPair = generator.generateKeyPair();
                storeRsaKeyPair(keyPair);
                return keyPair;
            } catch (Exception exception) {
                throw new ProviderException("failed to generate local AndroidKeyStore RSA key", exception);
            }
        }

        private static KeyPairGenerator standardRsaGenerator() throws NoSuchAlgorithmException {
            for (Provider provider : Security.getProviders("KeyPairGenerator.RSA")) {
                if (!"AndroidKeyStore".equals(provider.getName())) {
                    return KeyPairGenerator.getInstance("RSA", provider);
                }
            }
            throw new NoSuchAlgorithmException("no non-AndroidKeyStore RSA provider");
        }
    }

    private static final class LocalCertificate extends Certificate {
        private final PublicKey publicKey;

        private LocalCertificate(PublicKey publicKey) {
            super("X.509");
            this.publicKey = publicKey;
        }

        @Override public byte[] getEncoded() { return publicKey.getEncoded().clone(); }
        @Override public void verify(PublicKey key) {}
        @Override public void verify(PublicKey key, String sigProvider) {}
        @Override public String toString() { return "LocalCertificate(" + publicKey.getAlgorithm() + ")"; }
        @Override public PublicKey getPublicKey() { return publicKey; }
    }
}
