package com.adjust.sdk.sig;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

public final class c {
    public final int a;

    public c(int androidApi) {
        this.a = androidApi;
    }

    public void a(Context context) throws Exception {
        if (a >= 23) {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (!keyStore.containsAlias("key2")) {
                KeyGenerator generator = KeyGenerator.getInstance("HmacSHA256", "AndroidKeyStore");
                generator.init(new KeyGenParameterSpec.Builder("key2", 4).build());
                generator.generateKey();
            }
            return;
        }

        if (a < 18) {
            throw new b();
        }

        SharedPreferences preferences = context.getSharedPreferences("adjust_keys", Context.MODE_PRIVATE);
        if (preferences.contains("encrypted_key")) {
            return;
        }

        Date start = Calendar.getInstance().getTime();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);
        KeyPairGeneratorSpec.Builder spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias("key2")
                .setSubject(new X500Principal("CN=key2"))
                .setSerialNumber(BigInteger.TEN)
                .setStartDate(start)
                .setEndDate(end.getTime());
        if (a >= 19) {
            spec.setKeySize(1024);
        }

        KeyPairGenerator pairGenerator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        pairGenerator.initialize(spec.build());
        pairGenerator.genKeyPair();

        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("key2", null);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, entry.getCertificate().getPublicKey());
        String encrypted = Base64.encodeToString(cipher.doFinal(key), Base64.DEFAULT);
        preferences.edit().putString("encrypted_key", encrypted).apply();
    }

    public byte[] a(Context context, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        Key key;
        if (a >= 23) {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            key = keyStore.getKey("key2", null);
        } else if (a >= 18) {
            String encrypted = context.getSharedPreferences("adjust_keys", Context.MODE_PRIVATE)
                    .getString("encrypted_key", null);
            if (encrypted == null) {
                throw new RuntimeException("Failed to find encrypted key in SharedPreferences");
            }
            byte[] encryptedBytes = Base64.decode(encrypted, Base64.DEFAULT);
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("key2", null);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, entry.getPrivateKey());
            key = new SecretKeySpec(cipher.doFinal(encryptedBytes), "AES");
        } else {
            throw new RuntimeException("Unsupported version");
        }

        mac.init(key);
        mac.update(data);
        return mac.doFinal();
    }
}
