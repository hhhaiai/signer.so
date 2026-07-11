package com.adjust.research;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class AndroidRuntimeJniTest {

    @Test
    void bridgesContextPackageAndOrderedMapObjects() throws Exception {
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().build()) {
            VM vm = emulator.createDalvikVM();
            AndroidRuntimeJni jni = new AndroidRuntimeJni("com.example.fixture");
            vm.setJni(jni);

            DvmObject<?> context = jni.wrapContext(vm);
            StringObject packageName = (StringObject) jni.callObjectMethodV(
                    (BaseVM) vm,
                    context,
                    "android/content/Context->getPackageName()Ljava/lang/String;",
                    null);
            assertEquals("com.example.fixture", packageName.getValue());

            LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
            parameters.put("environment", "sandbox");
            DvmObject<?> map = jni.wrapParameters(vm, parameters);
            assertEquals("java.util.Map", map.getObjectType().getName());
            assertSame(parameters, map.getValue());
        }
    }

    @Test
    void exposesSdk28SigningInfoFromPackageInfo() throws Exception {
        byte[] certificate = new byte[]{1, 2, 3, 4};
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().build()) {
            VM vm = emulator.createDalvikVM();
            AndroidRuntimeJni jni = new AndroidRuntimeJni(
                    "com.example.fixture", certificate, new byte[32]);
            vm.setJni(jni);

            DvmObject<?> packageInfo = vm.resolveClass("android/content/pm/PackageInfo")
                    .newObject("com.example.fixture");
            DvmObject<?> signingInfo = jni.getObjectField(
                    (BaseVM) vm,
                    packageInfo,
                    "android/content/pm/PackageInfo->signingInfo:Landroid/content/pm/SigningInfo;");

            assertNotNull(signingInfo);
            assertEquals("android.content.pm.SigningInfo", signingInfo.getObjectType().getName());
            assertFalse(jni.callBooleanMethodV(
                    (BaseVM) vm,
                    signingInfo,
                    "android/content/pm/SigningInfo->hasMultipleSigners()Z",
                    null));
            ArrayObject certificateHistory = (ArrayObject) jni.callObjectMethodV(
                    (BaseVM) vm,
                    signingInfo,
                    "android/content/pm/SigningInfo->getSigningCertificateHistory()"
                            + "[Landroid/content/pm/Signature;",
                    null);
            assertEquals(1, certificateHistory.length());
            assertEquals(
                    "android.content.pm.Signature",
                    certificateHistory.getValue()[0].getObjectType().getName());
        }
    }
}
