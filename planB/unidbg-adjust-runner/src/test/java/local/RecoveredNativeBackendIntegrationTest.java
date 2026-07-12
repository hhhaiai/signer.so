package local;

import com.adjust.sdk.sig.NativeLibHelper;
import com.adjust.sdk.sig.d;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RecoveredNativeBackendIntegrationTest {
    @AfterEach
    void tearDown() throws Exception {
        NativeLibHelper.closeBridge();
        NativeLibHelper.clearConfiguration();
        d.a = false;
    }

    @Test
    void recoveredSourceBackendExactlyMatchesFrozenPixelReference() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.getJSONObject("device").getJSONObject("runtime").put("backend", "recovered");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));
        JSONObject expected = JSON.parseObject(
                Files.readString(new File(fixture, "reference-result.json").toPath()), Feature.OrderedField);

        assertEquals(expected, actual);
        assertEquals(176, actual.getString("rawSignatureHex").length() / 2);
    }

    @Test
    void recoveredSourceBackendMatchesOriginalSoWhenOptionalFieldsAreMissing() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        job.getJSONObject("device").getJSONObject("runtime").put("backend", "recovered");
        JSONObject parameters = job.getJSONObject("sign").getJSONObject("parameters");
        parameters.remove("android_id");
        parameters.remove("country");
        parameters.remove("device_name");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f1151da6894512660bd1e9809e7c17c3898"
                        + "a2d0c5508f89e6c3022e6c8f7b442797b9c3cbceec98968732365365690cd6d"
                        + "49eedbeff89e4f3eff80d87a481c39bb27a9862ada32dc4d46a6624d290e3b54"
                        + "d72e3a1ca3e9db49ce02d5dfaad7a29403af49ac600c6b9d5837e3e46db1e7c"
                        + "a529fc511f42616d75a82d8942c2c8256d87fb5cd7d5e532820a2e77ea493fbc"
                        + "caf0f58b5ae9cc76e1d862c7d69992e049",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendMatchesOriginalSoWithCorrection05Disabled() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject runtime = job.getJSONObject("device").getJSONObject("runtime");
        runtime.put("backend", "recovered");
        runtime.put("correction05Enabled", false);

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f1175ea84869289d37a021c609fdba4210c"
                        + "44453a53705c11a25fbfc7dd54fe3e048a436cfe216b02ef7fb09085f2092621"
                        + "9bb70e9ec164cfb658f8dd112f2129a2f8c26923d3d58e4ae09cfcf297047467"
                        + "5b5754bad315280431964a2675d4258c62fb1cc700120b9367afa2e7b3bac5972"
                        + "3fa554d1b257445534c25bd4dc502aa18cadcc5d1c394042973d5024b4010fe0"
                        + "d8e2ed95208ff0a3ebcc9f1de550ad6",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesEmptyProcMapsCorrections() throws Exception {
        JSONObject actual = runWithProcMaps("empty");
        assertEquals("3b273362218b186a73e7349775b93f118b66c81962540c095ad13a9257ff30e6"
                        + "5ecc6645fbe361a009b131f80bf41313c239e586e9f910e178e77fa38bd8546b9"
                        + "54615996c2ecaa93229f254f49ab5f9772085e577577cce2ef7e006520626b8aa"
                        + "8d4ece6a413b55bbf0cea98f891bb4231659ac980af095c74881e6de2aae6c206"
                        + "d5ece678f9f5db5b25f7fdc0d1980b417a7ddfc978f375f41f75102c5e2a9ca"
                        + "8b27b558dfc073c746e01963fa1645",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesMissingProcMapsCorrections() throws Exception {
        JSONObject actual = runWithProcMaps("missing");
        assertEquals("3b273362218b186a73e7349775b93f11bf0e565a4dcc3dbd0f20b938e6a648e7"
                        + "b4d1b1ae646530c0e37b5d6f57c53aa36873c135abf30c8007a7a88b4833337b"
                        + "079162e03a8477dc0dc86dd4fc7d6ee071dcb2008f58d4b9999e8a2358536b39c"
                        + "d862bd9fa119c1c0e720d5986590afc9bf118ecd167a60c39fb0e7b36db0bc3d3"
                        + "8e3cec66022f33acaeb80f27f54ac0b73c52b08756d876e3337b3d6f005b3991"
                        + "671b8df6c7505955cd7dd51c3e37d8",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesNonMatchingProcMapsCorrections() throws Exception {
        JSONObject actual = runWithProcMaps("nonmatching");
        assertEquals("3b273362218b186a73e7349775b93f118b66c81962540c095ad13a9257ff30e6"
                        + "5ecc6645fbe361a009b131f80bf41313c239e586e9f910e178e77fa38bd8546b9"
                        + "54615996c2ecaa93229f254f49ab5f9772085e577577cce2ef7e006520626b8aa"
                        + "8d4ece6a413b55bbf0cea98f891bb4231659ac980af095c74881e6de2aae6c206"
                        + "d5ece678f9f5db5b25f7fdc0d1980b417a7ddfc978f375f41f75102c5e2a9ca"
                        + "8b27b558dfc073c746e01963fa1645",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendRecognizesApplicationSourceDirInProcMaps() throws Exception {
        JSONObject actual = runWithProcMaps("matching");
        assertEquals("3b273362218b186a73e7349775b93f1151da6894512660bd1e9809e7c17c3898"
                        + "a2d0c5508f89e6c3022e6c8f7b442797abef7d1d32d8a04d887d2d1bf24b19b1"
                        + "f9ab2e878f79e9e4403f2fbb71ee5609443039c0ce6fc355892096d63e697e9ca"
                        + "2794cf0628c4403e0d6e9e452c356cbf881e5aebd431e2b583b6d923875d3eb9b"
                        + "3b2de520ab291ca72a1f1cd661d6af510d952d14921db3ae61537b5fccc21e455"
                        + "54bf72a6d107816fbbf28ebd8f6f7",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesApkCertificateMismatchCorrection() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.getJSONObject("runtime").put("backend", "recovered");
        byte[] certificate = Files.readAllBytes(new File(fixture, "reference-certificate.der").toPath());
        certificate[0] ^= 1;
        device.remove("certificateFile");
        device.put("certificateHex", hex(certificate));

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11049d1036eecf9d2b2fc48ef8c6aa6f99"
                        + "8b41dcb1cd09071baa199168954814e660982270cf6d38748c483f8f8c551a6e39"
                        + "b2686eaafcb63dac3536f3c26a7f822e943acd70c9daa840231fb6bc0916db6d02"
                        + "998a6666e1ccb1b703f589b9dbcb2ec2c417378e3a00c8fb4f45f5b6565e81235"
                        + "63489745e4b68882a2fcf7dfe811c65bb6e6426c08b72b83bc06622868d0127f1"
                        + "e3081ca57fd8fff77c530aecf2",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void v3OnlyApkCertificateCorrectionExactlyMatchesOriginalSo() throws Exception {
        String matchingOriginal = runV3OnlyCertificateCase(false, false);
        String matchingRecovered = runV3OnlyCertificateCase(false, true);
        String mismatchOriginal = runV3OnlyCertificateCase(true, false);
        String mismatchRecovered = runV3OnlyCertificateCase(true, true);

        assertEquals("3b273362218b186a73e7349775b93f1151da6894512660bd1e9809e7c17c3898"
                        + "a2d0c5508f89e6c3022e6c8f7b442797abef7d1d32d8a04d887d2d1bf24b19b1"
                        + "f9ab2e878f79e9e4403f2fbb71ee5609443039c0ce6fc355892096d63e697e9ca"
                        + "2794cf0628c4403e0d6e9e452c356cbf881e5aebd431e2b583b6d923875d3eb9b"
                        + "3b2de520ab291ca72a1f1cd661d6af510d952d14921db3ae61537b5fccc21e455"
                        + "54bf72a6d107816fbbf28ebd8f6f7", matchingOriginal);
        assertEquals(matchingOriginal, matchingRecovered);
        assertEquals("3b273362218b186a73e7349775b93f11049d1036eecf9d2b2fc48ef8c6aa6f99"
                        + "91226758ea8b1dcbd6445fa6a0adb539c6f3bdd5a123399057e3ea709bade33a94"
                        + "f84a3edf9cfebabc18d9771a9b62ab0cafb95309a403e1efd2337e1264760cd145"
                        + "86f2f11e23642c3a002f90209fde62f0c1c55c666df3267222d2a3de0a9db04b9"
                        + "675f0ec3ee0842bd3a52627c7b52b549142d4ef827021e6ca17813be125dd7be64"
                        + "4fa66b2f00e1101c23763a071", mismatchOriginal);
        assertEquals(mismatchOriginal, mismatchRecovered);
    }

    private static String runV3OnlyCertificateCase(boolean mismatch, boolean recovered)
            throws Exception {
        NativeLibHelper.closeBridge();
        NativeLibHelper.clearConfiguration();
        d.a = false;
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("baseApk", new File(root,
                ".omx/certificate-experiments/alt-v3-only.apk").getCanonicalPath());
        device.put("certificateFile", (mismatch
                ? new File(root, ".omx/certificate-experiments/alt-valid.der")
                : new File(fixture, "reference-certificate.der")).getCanonicalPath());
        if (recovered) device.getJSONObject("runtime").put("backend", "recovered");
        return JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture))
                .getString("rawSignatureHex");
    }

    @Test
    void recoveredSourceBackendDerivesAndroidApiMismatchCorrection() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 35);
        device.getJSONObject("runtime").put("backend", "recovered");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11e41c9a76d043c6ecb8e95630c0667b93"
                        + "03c5fd31ac192e854bb30f9f4d07b176954014b5000f425e1dbba4ccca277defc9"
                        + "30b47cc34f8120028d0891ce4d4c0031226885d95c64aa948e5ed521b18d14955"
                        + "ce2ed3ccde07296f6c72910d1233ca839e9eb6de02d0b487296a5bbd72ce56e73"
                        + "e24879dc972faae2531e6e58f350fcf5c30753ea9ee72236b14f5fbf75041163b"
                        + "346c3fa3deb8a5b4101b44f1a14",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendMatchesConfiguredApi23OriginalSoCorrectionVector() throws Exception {
        File root = findProjectRoot();
        File examples = new File(root, "examples");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(examples, "signer-job.json").toPath()), Feature.OrderedField);
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 23);
        device.put("targetSdk", 23);
        JSONObject runtime = device.getJSONObject("runtime");
        runtime.put("backend", "recovered");
        runtime.put("urandomHex", "000102030405060708090a0b0c0d0e0f");
        runtime.put("correctionCodes", List.of("2b", "34", "37", "38", "2f", "36", "05"));

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), examples));

        assertEquals("3b273362218b186a73e7349775b93f11f7b1c30b49ae6da84f0f7055c198614e"
                        + "01f2f839b297451f9fe5c03d45039a2b80563b71fb8f0b930500c9b3bda1afae"
                        + "77d6cc2789b455c9a95296c7042a75af42ca91abc28e4784b7b7fb426982b21b"
                        + "7b60a2ff3e1e5d660963261a9c12e535177f00ac0e42888b70581e7e48f2706b"
                        + "f142d8789cfc90643329b5ed36696e5f17264a05f46cdfdbbefa53a84a8d73966"
                        + "9cbd6a585f607363cda4bc18b8b76fa",
                actual.getString("rawSignatureHex"));
        assertEquals(176, actual.getString("rawSignatureHex").length() / 2);
    }

    @Test
    void recoveredSourceBackendDerivesMissingArtRuntimeCorrection2f() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.getJSONObject("runtime").put("backend", "recovered");
        device.getJSONObject("filesystem").getJSONObject("files")
                .remove("/system/lib64/ld-android.so");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11800ca14fada7c06003fb616aa29dba35"
                        + "e963fe8d55cf40e25006ec501f7e1cae7a1b402a7a062fdf410e0074866a9868"
                        + "09ef050d74ec43cdbb8d9d65f39984be6fa492995059f79288d9f51aa8d6cca0"
                        + "b1a3ee9fb6219eca036d763d10e18b42c1f81a32152f0a5ef5d418414beac19a"
                        + "55f12955ae30cfa00063fa0f44b1e88f63c24bf783837e89e50418eefe89c66a"
                        + "cd0b6dc268f8131443003744128e99dc",
                actual.getString("rawSignatureHex"));
        assertEquals(176, actual.getString("rawSignatureHex").length() / 2);
    }

    @Test
    void recoveredSourceBackendDerivesProcessNameMismatchCorrection09() throws Exception {
        JSONObject actual = runWithCmdline("com.example.other\0".getBytes(), false, null);
        assertEquals("3b273362218b186a73e7349775b93f1170bfe197a0b1f1ed7360766164fab6fd"
                        + "7b1a069099eeabb081c32948cc3f1376e177ab8f12289ff33e25275d7c97a826"
                        + "d473e043bb94eb108134fc50be62964e33596c08dc7a0ead0567a031bb304f49d"
                        + "30d1517989be22ed706cc1d0c6077f06b5427448baf16ff01f2b4190d4b67835"
                        + "c1ed13abcb831020241799709817d276cda9f5902ce893089ebc8a793e36fbfe5"
                        + "bd754eef9ca0979691258ef7d9664d",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesMissingCmdlineCorrection34() throws Exception {
        JSONObject actual = runWithCmdline(null, true, null);
        assertEquals("3b273362218b186a73e7349775b93f112f99badc4cc1bdb2c58761f699f62817"
                        + "e386bc0e6a005b894a0212cf212a2dceba35ccdd09c560bce68f1ddd13805a42"
                        + "e2d93bdee03252019cd49ce3d9965e022392aa1a6f5daa396403be2d30273499"
                        + "110efcc388a5f9c2df34b0a13a62f01ead457a3ba2f5101513d40964bb7c52b4"
                        + "dd55a335fb837a8f7ee5e601965eab4cca94f1e847d0ee51d8252146169d4575"
                        + "f15be21272bf9224a3b78bb5d7efb48a",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDoesNotTreatManifestPackageAsCorrection09() throws Exception {
        JSONObject actual = runWithCmdline("local.qbdi.changed\0".getBytes(), false,
                "local.qbdi.changed");
        assertEquals("3b273362218b186a73e7349775b93f11a65b5f46f9d9af4ac2177f2d65ae15e"
                        + "b99b965baf40291ef094df1e47361a06e6a443cd0ad537ae4a2a954e41a9f80c"
                        + "c9511baf51522c622c5cc510b69ce729f9db951d9c7b06984c24e91dbf795fffb"
                        + "7ef96652b0fb473c37444a88051e1e26e235e86faf1029f1b8e9265f5fb997c1f"
                        + "ef20f7fcadaed6b68756137638709fd1497860b8c60414fd2121843646a055c66"
                        + "9abf574712d52c824d9c96c905ce19",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendDerivesPublicSourcePathCorrections() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.getJSONObject("runtime").put("backend", "recovered");
        device.getJSONObject("applicationInfo").put("publicSourceDir", "/tmp/base.apk");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11a38d99edb05bf835c165a660ae00bcd7"
                        + "4f5323213cb548109b658dd238fbe6b11d679071cb90997973a03f0f06392f8b5"
                        + "591fbb8afb187e916c1bc66f66deb7536239fa60b8743133c6c3d3bda8ce3209c"
                        + "fe621d23b2ae72a7e93623ff228f8a9456586383c284d90db14f7496a5748eb83"
                        + "c14175bb2fbab788ccf19b1dda36db2e7b19c58fc635a9c674ca9440d4b70c906"
                        + "e11eae508351391d55d3f9c674ee",
                actual.getString("rawSignatureHex"));
    }

    @Test
    void recoveredSourceBackendMatchesNineCorrectionDynamicPayload() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 35);
        device.put("packageName", "local.qbdi.changed");
        device.getJSONObject("runtime").put("backend", "recovered");
        byte[] certificate = Files.readAllBytes(new File(fixture, "reference-certificate.der").toPath());
        certificate[0] ^= 1;
        device.remove("certificateFile");
        device.put("certificateHex", hex(certificate));
        JSONObject filesystem = device.getJSONObject("filesystem");
        filesystem.getJSONObject("files").remove("/proc/self/maps");
        filesystem.getJSONArray("missing").add("/proc/self/maps");

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f1179481da885a7cac310c774c58ffbfb89"
                        + "d3a1d182c6df2f2922882e512d25c6cb7ed86876f6849e9b071fc729fc32b0e7"
                        + "e95afdc0d901d404a1fdf97f88c969edf01c1466d12c8cee7c934446e3fedf73d"
                        + "083430b7228bc54b540bf837d6efb936eace726faac44574bc338f74c1c930859"
                        + "903d6b242176114096df19a2afd257de5fd434e74d04c592ea0976ee67f0995f2"
                        + "1c466c09d976d3ae4524267ca276cce4e55b7d252e8111ccd41e98389f1ce",
                actual.getString("rawSignatureHex"));
        assertEquals(192, actual.getString("rawSignatureHex").length() / 2);
    }

    @Test
    void recoveredSourceBackendMatchesSeventeenCorrectionOriginalSoOracle() throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject runtime = job.getJSONObject("device").getJSONObject("runtime");
        runtime.put("backend", "recovered");
        runtime.put("correctionCodes", List.of(
                "2b", "36", "25", "05", "01", "02", "03", "04", "05",
                "06", "07", "08", "09", "0a", "0b", "0c", "0d"));

        JSONObject actual = JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));

        assertEquals("3b273362218b186a73e7349775b93f11bb4851ad16acbcbc3f62e2a6a52db497"
                        + "abb81be1392bd9fd14c765a2137a333ff4700b38ed747e686a45dfcaa1f35af9f"
                        + "1d74881fb4f8677d4dfa500c324d6f7852b401f816b8d76f193728b52aaa58818"
                        + "65f80f4969a885f520113d04700b94abee5d98971aacf9b1714053ff3e77d04b9"
                        + "09fc216437e7c867ad76c6900c806ac89f98fd54447ddea86f023245fb78a91c9"
                        + "93cdacdd995c5b52b16c8adae8080687def487a211c7ac86bd116ae9b10a16953"
                        + "6cf557089fc821e4ef1432a820a",
                actual.getString("rawSignatureHex"));
        assertEquals(208, actual.getString("rawSignatureHex").length() / 2);
    }

    private static JSONObject runWithProcMaps(String mode) throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        job.getJSONObject("device").getJSONObject("runtime").put("backend", "recovered");
        JSONObject filesystem = job.getJSONObject("device").getJSONObject("filesystem");
        JSONObject files = filesystem.getJSONObject("files");
        if ("empty".equals(mode)) {
            JSONObject empty = new JSONObject(true);
            empty.put("hex", "");
            files.put("/proc/self/maps", empty);
        } else if ("missing".equals(mode)) {
            files.remove("/proc/self/maps");
            filesystem.getJSONArray("missing").add("/proc/self/maps");
        } else {
            String sourceDir = job.getJSONObject("device").getJSONObject("applicationInfo")
                    .getString("sourceDir");
            JSONObject text = new JSONObject(true);
            text.put("text", "matching".equals(mode)
                    ? "7904e9f000-7904ea0000 r--s 00000000 00:2fe 35059 " + sourceDir + "\n"
                    : "70000000-70001000 r-xp 00000000 00:00 0 /system/lib64/libc.so\n");
            files.put("/proc/self/maps", text);
        }
        return JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));
    }

    private static JSONObject runWithCmdline(byte[] cmdline, boolean missing, String packageName)
            throws Exception {
        File root = findProjectRoot();
        File fixture = new File(root, "device-reference/references/pixel8-api36");
        JSONObject job = JSON.parseObject(
                Files.readString(new File(fixture, "signer-job.json").toPath()), Feature.OrderedField);
        job.remove("expectedResultFile");
        JSONObject device = job.getJSONObject("device");
        device.put("androidApi", 22);
        if (packageName != null) device.put("packageName", packageName);
        device.getJSONObject("runtime").put("backend", "recovered");
        JSONObject filesystem = device.getJSONObject("filesystem");
        JSONObject files = filesystem.getJSONObject("files");
        files.remove("/proc/self/cmdline");
        if (missing) {
            filesystem.getJSONArray("missing").add("/proc/self/cmdline");
        } else {
            JSONObject source = new JSONObject(true);
            source.put("hex", hex(cmdline));
            files.put("/proc/self/cmdline", source);
        }
        return JSON.parseObject(SignerOneClick.run(root, job.toJSONString(), fixture));
    }

    private static File findProjectRoot() throws Exception {
        File current = new File(".").getCanonicalFile();
        if (new File(current, "native-reimplementation/recovered_primitives.cpp").isFile()) return current;
        File parent = current.getParentFile();
        if (parent != null && new File(parent, "native-reimplementation/recovered_primitives.cpp").isFile()) {
            return parent;
        }
        throw new IllegalStateException("project root not found from " + current);
    }

    private static String hex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte current : bytes) value.append(String.format("%02x", current & 0xff));
        return value.toString();
    }
}
