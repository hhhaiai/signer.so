package com.adjust.research;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public final class SignerCli {

    private static final String DEFAULT_HMAC_KEY_HEX =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    private SignerCli() {
    }

    public static void main(String[] args) {
        int exitCode = run(args, System.out, System.err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        final Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException | IOException e) {
            err.println("error: " + e.getMessage());
            err.println(usage());
            return 64;
        }
        if (options.help) {
            out.println(usage());
            return 0;
        }
        if (options.parameters.isEmpty()) {
            err.println("error: provide at least one --param or --request-json entry");
            return 64;
        }

        byte[] hmacKey = options.hmacKey == null
                ? parseHex(DEFAULT_HMAC_KEY_HEX, "default fixture HMAC key")
                : options.hmacKey;
        byte[] certificate = options.certificate == null
                ? "adjust-signature-fixture-certificate".getBytes(StandardCharsets.UTF_8)
                : options.certificate;

        SignerConfig config = new SignerConfig(
                options.packageName,
                options.sdk,
                hmacKey,
                options.hmacOverride,
                certificate,
                options.verbose);
        SignerRequest request = new SignerRequest(
                options.parameters, options.activityKind, options.clientSdk);

        try (LibSignerEmulator signer = new LibSignerEmulator(config)) {
            SignerResult result;
            if (options.tracePath != null) {
                try (TraceRecorder ignored = signer.trace(options.tracePath, options.maxTraceEvents)) {
                    result = signer.signDetailed(request);
                }
            } else {
                result = signer.signDetailed(request);
            }
            byte[] signature = result.signature();
            out.println("signature_length=" + signature.length);
            if (options.outputMode != OutputMode.BASE64) {
                out.println("signature_hex=" + toUpperHex(signature));
            }
            if (options.outputMode != OutputMode.HEX) {
                out.println("signature_base64=" + Base64.getEncoder().encodeToString(signature));
            }
            for (Map.Entry<String, String> entry : result.nativeMetadata().entrySet()) {
                out.println("native_" + entry.getKey() + "=" + entry.getValue());
            }
            if (options.tracePath != null) {
                out.println("trace_jsonl=" + options.tracePath.toAbsolutePath());
            }
            if (options.hmacOverride != null && options.hmacKey == null) {
                err.println("warning: --hmac-hex used with the built-in fixture key2; "
                        + "this is flow-equivalent, not device-identical");
            }
            return 0;
        } catch (Exception e) {
            err.println("native signing failed: " + e.getMessage());
            if (options.verbose) {
                e.printStackTrace(err);
            }
            return 70;
        }
    }

    static byte[] parseHex(String value, String label) {
        String normalized = value.startsWith("0x") || value.startsWith("0X")
                ? value.substring(2) : value;
        if (normalized.isEmpty() || (normalized.length() & 1) != 0) {
            throw new IllegalArgumentException(label + " must contain an even number of hex digits");
        }
        byte[] output = new byte[normalized.length() / 2];
        for (int index = 0; index < output.length; index++) {
            int high = Character.digit(normalized.charAt(index * 2), 16);
            int low = Character.digit(normalized.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException(label + " contains a non-hex character");
            }
            output[index] = (byte) ((high << 4) | low);
        }
        return output;
    }

    static String toUpperHex(byte[] value) {
        StringBuilder output = new StringBuilder(value.length * 2);
        for (byte current : value) {
            output.append(String.format(Locale.ROOT, "%02X", current & 0xff));
        }
        return output.toString();
    }

    private static String usage() {
        return String.join(System.lineSeparator(),
                "Usage: run.sh [options]",
                "  --param key=value              add an ordered request parameter (repeatable)",
                "  --request-json PATH            merge a flat JSON object of string parameters",
                "  --activity-kind VALUE          injected activity_kind (default: event)",
                "  --client-sdk VALUE              injected client_sdk (default: android5.4.1)",
                "  --hmac-key-hex HEX              key2 fixture; also computes Java HMAC",
                "  --hmac-hex HEX                  override the third JNI byte[] argument",
                "  --certificate-hex HEX           Android package Signature.toByteArray fixture",
                "  --sdk N                         Android SDK level (default: 23)",
                "  --package NAME                  package identity (default: com.adjust.fixture)",
                "  --output hex|base64|both        output encoding (default: both)",
                "  --trace-jsonl PATH              bounded instruction trace",
                "  --max-trace-events N            trace cap (default: 10000)",
                "  --verbose                       verbose JNI diagnostics",
                "  --help                          show this help");
    }

    enum OutputMode { HEX, BASE64, BOTH }

    static final class Options {
        private final LinkedHashMap<String, String> parameters = new LinkedHashMap<>();
        private String activityKind = "event";
        private String clientSdk = "android5.4.1";
        private String packageName = SignerConfig.DEFAULT_PACKAGE_NAME;
        private int sdk = SignerConfig.DEFAULT_SDK_LEVEL;
        private byte[] hmacKey;
        private byte[] hmacOverride;
        private byte[] certificate;
        private OutputMode outputMode = OutputMode.BOTH;
        private Path tracePath;
        private long maxTraceEvents = 10_000;
        private boolean verbose;
        private boolean help;

        Map<String, String> parameters() {
            return parameters;
        }

        OutputMode outputMode() {
            return outputMode;
        }

        static Options parse(String[] args) throws IOException {
            Options options = new Options();
            for (int index = 0; index < args.length; index++) {
                String argument = args[index];
                switch (argument) {
                    case "--help":
                    case "-h":
                        options.help = true;
                        break;
                    case "--verbose":
                        options.verbose = true;
                        break;
                    case "--param":
                        options.addParameter(requireValue(args, ++index, argument));
                        break;
                    case "--request-json":
                        options.addJson(Path.of(requireValue(args, ++index, argument)));
                        break;
                    case "--activity-kind":
                        options.activityKind = requireValue(args, ++index, argument);
                        break;
                    case "--client-sdk":
                        options.clientSdk = requireValue(args, ++index, argument);
                        break;
                    case "--package":
                        options.packageName = requireValue(args, ++index, argument);
                        break;
                    case "--sdk":
                        options.sdk = parsePositiveInt(requireValue(args, ++index, argument), "sdk");
                        break;
                    case "--hmac-key-hex":
                        options.hmacKey = parseHex(
                                requireValue(args, ++index, argument), "HMAC key");
                        break;
                    case "--hmac-hex":
                        options.hmacOverride = parseHex(
                                requireValue(args, ++index, argument), "HMAC override");
                        break;
                    case "--certificate-hex":
                        options.certificate = parseHex(
                                requireValue(args, ++index, argument), "certificate");
                        break;
                    case "--output":
                        options.outputMode = parseOutputMode(
                                requireValue(args, ++index, argument));
                        break;
                    case "--trace-jsonl":
                        options.tracePath = Path.of(requireValue(args, ++index, argument));
                        break;
                    case "--max-trace-events":
                        options.maxTraceEvents = parsePositiveLong(
                                requireValue(args, ++index, argument), "max trace events");
                        break;
                    default:
                        if (argument.startsWith("--param=")) {
                            options.addParameter(argument.substring("--param=".length()));
                        } else {
                            throw new IllegalArgumentException("unknown option " + argument);
                        }
                }
            }
            return options;
        }

        private void addJson(Path path) throws IOException {
            for (Map.Entry<String, String> entry : FlatJson.parse(
                    Files.readString(path, StandardCharsets.UTF_8)).entrySet()) {
                if ("activity_kind".equals(entry.getKey())) {
                    activityKind = entry.getValue();
                } else if ("client_sdk".equals(entry.getKey())) {
                    clientSdk = entry.getValue();
                } else {
                    parameters.put(entry.getKey(), entry.getValue());
                }
            }
        }

        private void addParameter(String pair) {
            int separator = pair.indexOf('=');
            if (separator <= 0) {
                throw new IllegalArgumentException("--param must be key=value");
            }
            parameters.put(pair.substring(0, separator), pair.substring(separator + 1));
        }

        private static String requireValue(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException(option + " requires a value");
            }
            return args[index];
        }

        private static int parsePositiveInt(String value, String label) {
            long parsed = parsePositiveLong(value, label);
            if (parsed > Integer.MAX_VALUE) {
                throw new IllegalArgumentException(label + " is too large");
            }
            return (int) parsed;
        }

        private static long parsePositiveLong(String value, String label) {
            try {
                long parsed = Long.parseLong(value);
                if (parsed <= 0) {
                    throw new IllegalArgumentException(label + " must be positive");
                }
                return parsed;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(label + " must be an integer", e);
            }
        }

        private static OutputMode parseOutputMode(String value) {
            switch (value.toLowerCase(Locale.ROOT)) {
                case "hex": return OutputMode.HEX;
                case "base64": return OutputMode.BASE64;
                case "both": return OutputMode.BOTH;
                default: throw new IllegalArgumentException("output must be hex, base64, or both");
            }
        }
    }

    private static final class FlatJson {
        private final String input;
        private int offset;

        private FlatJson(String input) {
            this.input = input;
        }

        static LinkedHashMap<String, String> parse(String input) {
            return new FlatJson(input).parseObject();
        }

        private LinkedHashMap<String, String> parseObject() {
            LinkedHashMap<String, String> result = new LinkedHashMap<>();
            whitespace();
            expect('{');
            whitespace();
            if (peek('}')) {
                offset++;
                return result;
            }
            while (true) {
                String key = string();
                whitespace();
                expect(':');
                whitespace();
                String value = string();
                if (result.putIfAbsent(key, value) != null) {
                    throw error("duplicate key " + key);
                }
                whitespace();
                if (peek('}')) {
                    offset++;
                    whitespace();
                    if (offset != input.length()) {
                        throw error("trailing content");
                    }
                    return result;
                }
                expect(',');
                whitespace();
            }
        }

        private String string() {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (offset < input.length()) {
                char current = input.charAt(offset++);
                if (current == '"') {
                    return value.toString();
                }
                if (current != '\\') {
                    value.append(current);
                    continue;
                }
                if (offset >= input.length()) {
                    throw error("unterminated escape");
                }
                char escaped = input.charAt(offset++);
                switch (escaped) {
                    case '"': case '\\': case '/': value.append(escaped); break;
                    case 'b': value.append('\b'); break;
                    case 'f': value.append('\f'); break;
                    case 'n': value.append('\n'); break;
                    case 'r': value.append('\r'); break;
                    case 't': value.append('\t'); break;
                    case 'u':
                        if (offset + 4 > input.length()) {
                            throw error("short unicode escape");
                        }
                        try {
                            value.append((char) Integer.parseInt(
                                    input.substring(offset, offset + 4), 16));
                        } catch (NumberFormatException e) {
                            throw error("invalid unicode escape");
                        }
                        offset += 4;
                        break;
                    default: throw error("invalid escape \\" + escaped);
                }
            }
            throw error("unterminated string");
        }

        private void whitespace() {
            while (offset < input.length() && Character.isWhitespace(input.charAt(offset))) {
                offset++;
            }
        }

        private void expect(char expected) {
            whitespace();
            if (offset >= input.length() || input.charAt(offset) != expected) {
                throw error("expected " + expected);
            }
            offset++;
        }

        private boolean peek(char expected) {
            return offset < input.length() && input.charAt(offset) == expected;
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException("invalid request JSON at offset " + offset + ": " + message);
        }
    }
}
