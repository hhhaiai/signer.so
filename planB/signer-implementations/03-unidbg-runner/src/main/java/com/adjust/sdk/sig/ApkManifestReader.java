package com.adjust.sdk.sig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class ApkManifestReader {
    private static final int RES_XML_TYPE = 0x0003;
    private static final int RES_STRING_POOL_TYPE = 0x0001;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int UTF8_FLAG = 0x00000100;
    private static final int TYPE_STRING = 0x03;

    private ApkManifestReader() {}

    static String packageName(File apk) throws IOException {
        if (apk.getName().endsWith(".xml")) return packageName(Files.readAllBytes(apk.toPath()));
        try (ZipFile zip = new ZipFile(apk)) {
            ZipEntry manifest = zip.getEntry("AndroidManifest.xml");
            if (manifest == null) throw new IOException("AndroidManifest.xml not found in " + apk);
            try (InputStream input = zip.getInputStream(manifest)) {
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) != -1) output.write(buffer, 0, read);
                return packageName(output.toByteArray());
            }
        }
    }

    static String packageName(byte[] xml) throws IOException {
        require(xml.length >= 8 && u16(xml, 0) == RES_XML_TYPE, "not a binary Android XML file");
        String[] strings = null;
        int offset = u16(xml, 2);
        while (offset + 8 <= xml.length) {
            int type = u16(xml, offset);
            int headerSize = u16(xml, offset + 2);
            int chunkSize = i32(xml, offset + 4);
            require(headerSize >= 8 && chunkSize >= headerSize && offset + chunkSize <= xml.length,
                    "invalid Android XML chunk");
            if (type == RES_STRING_POOL_TYPE) {
                strings = readStringPool(xml, offset);
            } else if (type == RES_XML_START_ELEMENT_TYPE && strings != null) {
                int extension = offset + 16;
                require(extension + 20 <= offset + chunkSize, "truncated start element");
                int elementName = i32(xml, extension + 4);
                if ("manifest".equals(string(strings, elementName))) {
                    int attributeStart = u16(xml, extension + 8);
                    int attributeSize = u16(xml, extension + 10);
                    int attributeCount = u16(xml, extension + 12);
                    int attribute = extension + attributeStart;
                    require(attributeSize >= 20 && attribute + attributeSize * attributeCount <= offset + chunkSize,
                            "invalid manifest attributes");
                    for (int i = 0; i < attributeCount; i++, attribute += attributeSize) {
                        if (!"package".equals(string(strings, i32(xml, attribute + 4)))) continue;
                        int rawValue = i32(xml, attribute + 8);
                        if (rawValue >= 0) return string(strings, rawValue);
                        int valueType = xml[attribute + 15] & 0xff;
                        if (valueType == TYPE_STRING) return string(strings, i32(xml, attribute + 16));
                    }
                }
            }
            offset += chunkSize;
        }
        throw new IOException("manifest package attribute not found");
    }

    private static String[] readStringPool(byte[] data, int chunk) throws IOException {
        int headerSize = u16(data, chunk + 2);
        int stringCount = i32(data, chunk + 8);
        int flags = i32(data, chunk + 16);
        int stringsStart = i32(data, chunk + 20);
        require(stringCount >= 0 && headerSize + (long) stringCount * 4 <= i32(data, chunk + 4),
                "invalid string pool");
        String[] strings = new String[stringCount];
        for (int i = 0; i < stringCount; i++) {
            int stringOffset = i32(data, chunk + headerSize + i * 4);
            int position = chunk + stringsStart + stringOffset;
            require(position >= 0 && position < data.length, "invalid string offset");
            int[] cursor = {position};
            if ((flags & UTF8_FLAG) != 0) {
                readLength8(data, cursor);
                int byteLength = readLength8(data, cursor);
                require(cursor[0] + byteLength <= data.length, "truncated UTF-8 string");
                strings[i] = new String(data, cursor[0], byteLength, StandardCharsets.UTF_8);
            } else {
                int length = readLength16(data, cursor);
                require(cursor[0] + (long) length * 2 <= data.length, "truncated UTF-16 string");
                strings[i] = new String(data, cursor[0], length * 2, StandardCharsets.UTF_16LE);
            }
        }
        return strings;
    }

    private static int readLength8(byte[] data, int[] cursor) throws IOException {
        require(cursor[0] < data.length, "truncated UTF-8 length");
        int first = data[cursor[0]++] & 0xff;
        if ((first & 0x80) == 0) return first;
        require(cursor[0] < data.length, "truncated UTF-8 length");
        return ((first & 0x7f) << 8) | (data[cursor[0]++] & 0xff);
    }

    private static int readLength16(byte[] data, int[] cursor) throws IOException {
        int first = u16(data, cursor[0]);
        cursor[0] += 2;
        if ((first & 0x8000) == 0) return first;
        int second = u16(data, cursor[0]);
        cursor[0] += 2;
        return ((first & 0x7fff) << 16) | second;
    }

    private static String string(String[] strings, int index) throws IOException {
        require(index >= 0 && index < strings.length, "invalid string index");
        return strings[index];
    }

    private static int u16(byte[] data, int offset) throws IOException {
        require(offset >= 0 && offset + 2 <= data.length, "truncated uint16");
        return (data[offset] & 0xff) | ((data[offset + 1] & 0xff) << 8);
    }

    private static int i32(byte[] data, int offset) throws IOException {
        require(offset >= 0 && offset + 4 <= data.length, "truncated int32");
        return (data[offset] & 0xff)
                | ((data[offset + 1] & 0xff) << 8)
                | ((data[offset + 2] & 0xff) << 16)
                | (data[offset + 3] << 24);
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}
