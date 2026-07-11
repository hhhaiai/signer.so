package android.content.pm;

public class Signature {
    private final byte[] bytes;

    public Signature(byte[] bytes) {
        this.bytes = bytes.clone();
    }

    public byte[] toByteArray() {
        return bytes.clone();
    }

    public String toCharsString() {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
}
