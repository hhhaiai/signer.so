package com.adjust.research;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TraceRecorderTest {

    @Test
    void formatsVersionedModuleRelativeInstructionEvent() {
        String line = TraceRecorder.jsonLine(
                0x40000000L, 0x200000L, 0x400a95acL, 4, 7, 0);

        assertTrue(line.contains("\"schema\":\"libsigner.trace/v1\""));
        assertTrue(line.contains("\"backend\":\"unidbg\""));
        assertTrue(line.contains("\"event\":\"instruction\""));
        assertTrue(line.contains("\"module\":\"libsigner.so\""));
        assertTrue(line.contains("\"module_base\":\"0x40000000\""));
        assertTrue(line.contains("\"pc\":\"0x400a95ac\""));
        assertTrue(line.contains("\"relative_pc\":\"0xa95ac\""));
        assertTrue(line.contains("\"instruction_size\":4"));
        assertTrue(line.contains("\"thread_id\":7"));
        assertTrue(line.contains("\"sequence\":0"));
        long moduleBase = parseHex(stringField(line, "module_base"));
        long pc = parseHex(stringField(line, "pc"));
        long relativePc = parseHex(stringField(line, "relative_pc"));
        assertEquals(pc - moduleBase, relativePc);
    }

    @Test
    void rejectsProgramCountersOutsideModule() {
        assertThrows(IllegalArgumentException.class, () -> TraceRecorder.jsonLine(
                0x40000000L, 0x1000L, 0x3fffffffL, 4, 1, 0));
    }

    @Test
    void acceptsExistingSymlinkDirectoryAsOutputParent() throws Exception {
        TraceRecorder.ensureParent(Path.of("/tmp/libsigner-trace-parent-test.jsonl"));
    }

    private static String stringField(String json, String name) {
        String marker = "\"" + name + "\":\"";
        int start = json.indexOf(marker);
        if (start < 0) {
            throw new AssertionError("missing field " + name + " in " + json);
        }
        start += marker.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }

    private static long parseHex(String value) {
        return Long.parseUnsignedLong(value.substring(2), 16);
    }
}
