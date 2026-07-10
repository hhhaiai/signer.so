package com.adjust.research;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureVmProgramTest {

    private static final long VM_INIT = 0x111a18;
    private static final long VM_PROGRAM = 0x0b6c50;
    private static final long VM_OUTPUT_LENGTH = 0x111904;
    private static final long VM_OUTPUT_COPY = 0x111910;

    @Test
    void fixedNineBlobShapeProducesStableProtectedVmVector() throws Exception {
        Path library = Files.createTempFile("libsigner-vm-vector-", ".so");
        try (InputStream input = getClass().getResourceAsStream("/arm64-v8a/libsigner.so")) {
            if (input == null) {
                throw new IllegalStateException("missing libsigner.so resource");
            }
            Files.copy(input, library, StandardCopyOption.REPLACE_EXISTING);
        }

        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(true))
                .setProcessName("com.adjust.vm.fixture")
                .build()) {
            Memory memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(23));
            Module module = emulator.loadLibrary(library.toFile(), false);
            UnidbgPointer error = memory.malloc(16, true).getPointer();
            error.setMemory(0, 16, (byte) 0);
            UnidbgPointer context = memory.pointer(
                    module.callFunction(emulator, VM_INIT, error).longValue());

            int[] lengths = {8, 40, 8, 512, 4, 4, 32, 4, 32};
            Object[] arguments = new Object[12];
            arguments[0] = error;
            arguments[1] = context;
            arguments[2] = 9;
            for (int index = 0; index < lengths.length; index++) {
                arguments[index + 3] = zeroBlob(memory, lengths[index]);
            }

            module.callFunction(emulator, VM_PROGRAM, arguments);
            assertEquals(0, error.getInt(0));
            int outputLength = module.callFunction(emulator, VM_OUTPUT_LENGTH, context).intValue();
            assertEquals(304, outputLength);
            UnidbgPointer output = memory.malloc(outputLength, true).getPointer();
            module.callFunction(emulator, VM_OUTPUT_COPY, error, context, output);
            assertEquals(0, error.getInt(0));
            byte[] bytes = output.getByteArray(0, outputLength);

            assertEquals(
                    "d43a36f81b41cebd016c03e7e7e075e4df5741f46efc33380eabc2182272f1e2",
                    hex(MessageDigest.getInstance("SHA-256").digest(bytes)));
            assertTrue(hex(bytes).startsWith("59f066a1020fd01a6df980ae48bdcca6"));
        } finally {
            Files.deleteIfExists(library);
        }
    }

    private static UnidbgPointer zeroBlob(Memory memory, int length) {
        UnidbgPointer data = memory.malloc(Math.max(length, 1), true).getPointer();
        data.setMemory(0, Math.max(length, 1), (byte) 0);
        UnidbgPointer blob = memory.malloc(16, true).getPointer();
        blob.setMemory(0, 16, (byte) 0);
        blob.setInt(0, length);
        blob.setPointer(8, data);
        return blob;
    }

    private static String hex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte current : value) {
            output.append(String.format("%02x", current & 0xff));
        }
        return output.toString();
    }
}

