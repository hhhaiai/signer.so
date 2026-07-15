package com.adjust.sdk.sig;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApkManifestReaderTest {
    @Test
    void readsPackageNameFromFrozenReferenceApkWithoutAndroidTools() throws Exception {
        File root = findProjectRoot();
        File apk = new File(root,
                "device-reference/references/pixel8-api36/adjust-reference.apk");
        assertEquals("local.qbdi.adjustreference", ApkManifestReader.packageName(apk));
    }

    private static File findProjectRoot() throws Exception {
        String configured = System.getProperty("signer.projectRoot");
        if (configured != null && !configured.isEmpty()) return new File(configured).getCanonicalFile();
        File current = new File(".").getCanonicalFile();
        while (current != null) {
            if (new File(current, "device-reference").isDirectory()) return current;
            current = current.getParentFile();
        }
        throw new IllegalStateException("project root with device-reference not found");
    }
}
