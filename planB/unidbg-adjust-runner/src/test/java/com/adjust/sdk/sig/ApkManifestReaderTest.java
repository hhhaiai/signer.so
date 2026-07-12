package com.adjust.sdk.sig;

import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ApkManifestReaderTest {
    @Test
    void readsPackageNameFromFrozenReferenceApkWithoutAndroidTools() throws Exception {
        File root = new File(".").getCanonicalFile();
        if (!new File(root, "device-reference").isDirectory()) root = root.getParentFile();
        File apk = new File(root,
                "device-reference/references/pixel8-api36/adjust-reference.apk");
        assertEquals("local.qbdi.adjustreference", ApkManifestReader.packageName(apk));
    }
}
