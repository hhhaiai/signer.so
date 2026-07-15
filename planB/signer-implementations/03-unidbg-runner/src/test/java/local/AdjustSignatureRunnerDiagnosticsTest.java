package local;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AdjustSignatureRunnerDiagnosticsTest {
    @Test
    void accessorTransitionTraceRequiresExplicitToggleAndWatchAddress() {
        assertFalse(AdjustSignatureRunner.shouldInstallAccessorTransitionTrace(false, "0x12511750"));
        assertFalse(AdjustSignatureRunner.shouldInstallAccessorTransitionTrace(true, null));
        assertFalse(AdjustSignatureRunner.shouldInstallAccessorTransitionTrace(true, ""));
        assertTrue(AdjustSignatureRunner.shouldInstallAccessorTransitionTrace(true, "0x12511750"));
    }

    @Test
    void nativeVectorTraceRequiresEitherAnExplicitVectorOrAWatchAddress() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeVectorWriteTrace(false, false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeVectorWriteTrace(true, false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeVectorWriteTrace(false, true));
    }

    @Test
    void parsesCommaSeparatedModuleRelativeWatchCheckpoints() {
        assertEquals(List.of(), AdjustSignatureRunner.parseWatchMemoryCheckpoints(null));
        assertEquals(List.of(), AdjustSignatureRunner.parseWatchMemoryCheckpoints("  "));
        assertEquals(List.of(0x10b1a4L, 0x10ecd4L),
                AdjustSignatureRunner.parseWatchMemoryCheckpoints("0x10b1a4, 0x10ecd4"));
    }

    @Test
    void parsesOptionalModuleRelativeCallerFilter() {
        assertNull(AdjustSignatureRunner.parseOptionalHex(null));
        assertNull(AdjustSignatureRunner.parseOptionalHex("  "));
        assertEquals(0x10ecd8L, AdjustSignatureRunner.parseOptionalHex("0x10ecd8"));
    }

    @Test
    void checkpointRegisterDumpRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldDumpWatchCheckpointRegisters(false));
        assertTrue(AdjustSignatureRunner.shouldDumpWatchCheckpointRegisters(true));
    }

    @Test
    void cryptoWordTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallCryptoWordTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallCryptoWordTrace(true));
    }

    @Test
    void jniCryptoTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldTraceJniCrypto(false));
        assertTrue(AdjustSignatureRunner.shouldTraceJniCrypto(true));
    }

    @Test
    void resultLayoutTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallResultLayoutTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallResultLayoutTrace(true));
    }

    @Test
    void tagWordTraceRequiresExplicitToggleAndWatchAddress() {
        assertFalse(AdjustSignatureRunner.shouldInstallTagWordTrace(false, "0x1233e490"));
        assertFalse(AdjustSignatureRunner.shouldInstallTagWordTrace(true, null));
        assertFalse(AdjustSignatureRunner.shouldInstallTagWordTrace(true, ""));
        assertTrue(AdjustSignatureRunner.shouldInstallTagWordTrace(true, "0x1233e490"));
    }

    @Test
    void field4WordTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallField4WordTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallField4WordTrace(true));
    }

    @Test
    void parsesOptionalModuleRelativeVmTraceCallerRange() {
        assertNull(AdjustSignatureRunner.parseModuleRelativeRange(null));
        assertNull(AdjustSignatureRunner.parseModuleRelativeRange("  "));
        assertArrayEquals(new long[]{0x10e920L, 0x10ed90L},
                AdjustSignatureRunner.parseModuleRelativeRange("0x10e920:0x10ed90"));
    }

    @Test
    void vectorStoreWatchRequiresAnExplicitGuestAddress() {
        assertFalse(AdjustSignatureRunner.shouldInstallVectorStoreWatch(null));
        assertFalse(AdjustSignatureRunner.shouldInstallVectorStoreWatch(""));
        assertTrue(AdjustSignatureRunner.shouldInstallVectorStoreWatch("0x12511f58"));
    }

    @Test
    void vectorStoreWatchAlsoAcceptsAnExplicitRawIndexRange() {
        assertFalse(AdjustSignatureRunner.shouldInstallVectorStoreWatch(null, null));
        assertTrue(AdjustSignatureRunner.shouldInstallVectorStoreWatch("0x12511f58", null));
        assertTrue(AdjustSignatureRunner.shouldInstallVectorStoreWatch(null, "0x3d6:0x3e5"));
    }

    @Test
    void vectorReadTraceRequiresAnExplicitCallerRange() {
        assertFalse(AdjustSignatureRunner.shouldInstallVectorReadTrace(null));
        assertFalse(AdjustSignatureRunner.shouldInstallVectorReadTrace(""));
        assertTrue(AdjustSignatureRunner.shouldInstallVectorReadTrace("0x10af70:0x10af80"));
    }

    @Test
    void nativeContextWordWatchRequiresAnExplicitOffset() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeContextWordWatch(null));
        assertFalse(AdjustSignatureRunner.shouldInstallNativeContextWordWatch(""));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeContextWordWatch("0x54"));
    }

    @Test
    void parsesOptionalNativeCorrectionAppendList() {
        assertEquals(List.of(), AdjustSignatureRunner.parseCorrectionCodeList(null));
        assertEquals(List.of(), AdjustSignatureRunner.parseCorrectionCodeList("  "));
        assertEquals(List.of(0x2b, 0x05, 0x0d),
                AdjustSignatureRunner.parseCorrectionCodeList("2b, 0x05, 0D"));
    }

    @Test
    void nativeEnvironmentDispatcherTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeEnvironmentDispatcherTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeEnvironmentDispatcherTrace(true));
    }

    @Test
    void nativeStatProbeTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeStatProbeTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeStatProbeTrace(true));
    }

    @Test
    void nativeStringProbeTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeStringProbeTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeStringProbeTrace(true));
    }

    @Test
    void nativeStateByteTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeStateByteTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeStateByteTrace(true));
    }

    @Test
    void nativeInitializationTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeInitializationTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeInitializationTrace(true));
    }

    @Test
    void nativeMetadataTraceRequiresExplicitToggle() {
        assertFalse(AdjustSignatureRunner.shouldInstallNativeMetadataTrace(false));
        assertTrue(AdjustSignatureRunner.shouldInstallNativeMetadataTrace(true));
    }

    @Test
    void nativeEnvironmentHelperOverrideRequiresExplicitValue() {
        assertFalse(AdjustSignatureRunner.shouldOverrideNativeEnvironmentHelper(null));
        assertFalse(AdjustSignatureRunner.shouldOverrideNativeEnvironmentHelper(""));
        assertTrue(AdjustSignatureRunner.shouldOverrideNativeEnvironmentHelper("1"));
    }

    @Test
    void vmNodeWatchRequiresAnExplicitGuestAddress() {
        assertFalse(AdjustSignatureRunner.shouldInstallVmNodeWatch(null));
        assertFalse(AdjustSignatureRunner.shouldInstallVmNodeWatch(""));
        assertTrue(AdjustSignatureRunner.shouldInstallVmNodeWatch("0x1231f200"));
    }

    @Test
    void vmStackSnapshotRequiresAnExplicitModuleRelativePc() {
        assertFalse(AdjustSignatureRunner.shouldInstallVmStackSnapshot(null));
        assertFalse(AdjustSignatureRunner.shouldInstallVmStackSnapshot(""));
        assertTrue(AdjustSignatureRunner.shouldInstallVmStackSnapshot("0xfe02c"));
    }

}
