package com.adjust.sdk.sig;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class ApkSigningBlockCertificates {
    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int V3_BLOCK_ID = 0xf05368c0;
    private static final int V31_BLOCK_ID = 0x1b93ad61;
    private static final byte[] APK_SIG_BLOCK_MAGIC = {
            'A', 'P', 'K', ' ', 'S', 'i', 'g', ' ', 'B', 'l', 'o', 'c', 'k', ' ', '4', '2'
    };

    private ApkSigningBlockCertificates() {
    }

    static List<byte[]> readV3Certificates(File apk) throws IOException {
        byte[] bytes = Files.readAllBytes(apk.toPath());
        int eocd = findEocd(bytes);
        if (eocd < 0) return Collections.emptyList();

        long centralDirectoryOffset = uint32(bytes, eocd + 16);
        if (centralDirectoryOffset < 32 || centralDirectoryOffset > bytes.length) {
            return Collections.emptyList();
        }
        int footer = Math.toIntExact(centralDirectoryOffset) - 24;
        if (!matches(bytes, footer + 8, APK_SIG_BLOCK_MAGIC)) return Collections.emptyList();

        long blockSize = uint64(bytes, footer);
        if (blockSize < 24 || blockSize > Integer.MAX_VALUE) return Collections.emptyList();
        long blockStartLong = centralDirectoryOffset - blockSize - 8;
        if (blockStartLong < 0 || blockStartLong > footer) return Collections.emptyList();
        int blockStart = Math.toIntExact(blockStartLong);
        if (uint64(bytes, blockStart) != blockSize) return Collections.emptyList();

        List<byte[]> certificates = new ArrayList<>();
        ByteBuffer pairs = slice(bytes, blockStart + 8, footer);
        while (pairs.hasRemaining()) {
            long pairSize = getUint64(pairs);
            if (pairSize < 4 || pairSize > pairs.remaining()) {
                throw new IOException("invalid APK Signing Block pair length: " + pairSize);
            }
            int pairEnd = pairs.position() + Math.toIntExact(pairSize);
            int id = pairs.getInt();
            if (id == V3_BLOCK_ID || id == V31_BLOCK_ID) {
                parseSigners(slice(pairs, pairs.position(), pairEnd), certificates);
            }
            pairs.position(pairEnd);
        }
        return certificates;
    }

    private static void parseSigners(ByteBuffer value, List<byte[]> certificates) throws IOException {
        ByteBuffer signers = lengthPrefixed(value, "v3 signers");
        while (signers.hasRemaining()) {
            ByteBuffer signer = lengthPrefixed(signers, "v3 signer");
            ByteBuffer signedData = lengthPrefixed(signer, "v3 signed data");
            requireRemaining(signer, 8, "v3 signer SDK range");
            signer.getInt();
            signer.getInt();
            lengthPrefixed(signer, "v3 signatures");
            lengthPrefixed(signer, "v3 public key");
            parseSignedData(signedData, certificates);
        }
    }

    private static void parseSignedData(ByteBuffer signedData, List<byte[]> certificates)
            throws IOException {
        lengthPrefixed(signedData, "v3 digests");
        ByteBuffer encodedCertificates = lengthPrefixed(signedData, "v3 certificates");
        while (encodedCertificates.hasRemaining()) {
            ByteBuffer certificate = lengthPrefixed(encodedCertificates, "v3 certificate");
            byte[] der = new byte[certificate.remaining()];
            certificate.get(der);
            certificates.add(der);
        }
    }

    private static ByteBuffer lengthPrefixed(ByteBuffer source, String name) throws IOException {
        requireRemaining(source, 4, name + " length");
        long length = Integer.toUnsignedLong(source.getInt());
        if (length > source.remaining()) throw new IOException(name + " exceeds containing block");
        int end = source.position() + Math.toIntExact(length);
        ByteBuffer result = slice(source, source.position(), end);
        source.position(end);
        return result;
    }

    private static void requireRemaining(ByteBuffer source, int required, String name)
            throws IOException {
        if (source.remaining() < required) throw new IOException("truncated " + name);
    }

    private static int findEocd(byte[] bytes) {
        int minimum = Math.max(0, bytes.length - 22 - 0xffff);
        for (int offset = bytes.length - 22; offset >= minimum; offset--) {
            if ((int) uint32(bytes, offset) != EOCD_SIGNATURE) continue;
            int commentLength = uint16(bytes, offset + 20);
            if (offset + 22 + commentLength == bytes.length) return offset;
        }
        return -1;
    }

    private static ByteBuffer slice(byte[] bytes, int start, int end) throws IOException {
        if (start < 0 || end < start || end > bytes.length) throw new IOException("invalid APK slice");
        return ByteBuffer.wrap(bytes, start, end - start).slice().order(ByteOrder.LITTLE_ENDIAN);
    }

    private static ByteBuffer slice(ByteBuffer source, int start, int end) throws IOException {
        if (start < 0 || end < start || end > source.limit()) throw new IOException("invalid block slice");
        ByteBuffer copy = source.duplicate().order(ByteOrder.LITTLE_ENDIAN);
        copy.position(start);
        copy.limit(end);
        return copy.slice().order(ByteOrder.LITTLE_ENDIAN);
    }

    private static boolean matches(byte[] source, int offset, byte[] expected) {
        if (offset < 0 || offset + expected.length > source.length) return false;
        for (int i = 0; i < expected.length; i++) {
            if (source[offset + i] != expected[i]) return false;
        }
        return true;
    }

    private static int uint16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xff) | ((bytes[offset + 1] & 0xff) << 8);
    }

    private static long uint32(byte[] bytes, int offset) {
        return Integer.toUnsignedLong(ByteBuffer.wrap(bytes, offset, 4)
                .order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    private static long uint64(byte[] bytes, int offset) {
        return ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
    }

    private static long getUint64(ByteBuffer source) throws IOException {
        requireRemaining(source, 8, "APK Signing Block pair");
        long value = source.getLong();
        if (value < 0) throw new IOException("APK Signing Block length exceeds signed long range");
        return value;
    }
}
