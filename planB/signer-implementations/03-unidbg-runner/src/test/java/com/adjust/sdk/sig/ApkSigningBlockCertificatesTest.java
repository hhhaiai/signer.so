package com.adjust.sdk.sig;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApkSigningBlockCertificatesTest {
    @TempDir
    Path tempDir;

    @Test
    void extractsCertificateFromV3OnlyApkWithoutAndroidSdkRuntime() throws Exception {
        File root = findProjectRoot();
        File apk = new File(root, ".omx/certificate-experiments/alt-v3-only.apk");

        List<byte[]> certificates = ApkSigningBlockCertificates.readV3Certificates(apk);

        assertEquals(1, certificates.size());
        assertEquals("164a86faf30e412b59223a36ccbe0f6e46e40958",
                hex(MessageDigest.getInstance("SHA-1").digest(certificates.get(0))));
    }

    @Test
    void unsignedArchiveHasNoV3Certificates() throws Exception {
        File root = findProjectRoot();
        assertTrue(ApkSigningBlockCertificates.readV3Certificates(
                new File(root, "adjust-android-signature-3.67.0.aar")).isEmpty());
    }

    @Test
    void recognizesV31BlockIdWithTheSameSignerEncoding() throws Exception {
        File root = findProjectRoot();
        byte[] apk = Files.readAllBytes(
                new File(root, ".omx/certificate-experiments/alt-v3-only.apk").toPath());
        byte[] v3 = {(byte) 0xc0, 0x68, 0x53, (byte) 0xf0};
        byte[] v31 = {0x61, (byte) 0xad, (byte) 0x93, 0x1b};
        int found = replaceOnce(apk, v3, v31);
        assertTrue(found >= 0, "v3 signing block ID not found");
        File patched = tempDir.resolve("v31-block.apk").toFile();
        Files.write(patched.toPath(), apk);

        List<byte[]> certificates = ApkSigningBlockCertificates.readV3Certificates(patched);

        assertEquals(1, certificates.size());
        assertEquals("164a86faf30e412b59223a36ccbe0f6e46e40958",
                hex(MessageDigest.getInstance("SHA-1").digest(certificates.get(0))));
    }

    private static int replaceOnce(byte[] value, byte[] before, byte[] after) {
        for (int offset = 0; offset <= value.length - before.length; offset++) {
            boolean equal = true;
            for (int i = 0; i < before.length; i++) equal &= value[offset + i] == before[i];
            if (!equal) continue;
            System.arraycopy(after, 0, value, offset, after.length);
            return offset;
        }
        return -1;
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) result.append(String.format("%02x", item & 0xff));
        return result.toString();
    }

    private static File findProjectRoot() throws Exception {
        String configured = System.getProperty("signer.projectRoot");
        if (configured != null && !configured.isEmpty()) return new File(configured).getCanonicalFile();
        File current = new File(".").getCanonicalFile();
        while (current != null) {
            if (Files.isRegularFile(
                    current.toPath().resolve(".omx/certificate-experiments/alt-v3-only.apk"))) {
                return current;
            }
            current = current.getParentFile();
        }
        throw new IllegalStateException("project root with certificate experiment not found");
    }
}
