#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${LIBSIGNER_COMPAT_ALLOW_LEGACY_RECOVERED_AUDIT:-0}" != "1" ]]; then
  echo "refusing legacy recovered-oracle execution by default" >&2
  echo "use the safe compatibility entrypoint: $ROOT/build-compatibility-layer.sh" >&2
  echo "set LIBSIGNER_COMPAT_ALLOW_LEGACY_RECOVERED_AUDIT=1 only for an explicitly authorized legacy audit" >&2
  exit 1
fi

echo "WARNING: executing the historical production-format recovered oracle because LIBSIGNER_COMPAT_ALLOW_LEGACY_RECOVERED_AUDIT=1" >&2
mkdir -p "$ROOT/build"

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
  "$ROOT/recovered_primitives.cpp" \
  -o "$ROOT/build/recovered-primitives"

run_fixture() {
  "$ROOT/build/recovered-primitives" --use-regression-fixture "$@"
}

STRICT_MISSING_STDERR="$(mktemp)"
if "$ROOT/build/recovered-primitives" --time-seconds=0 \
    >/dev/null 2>"$STRICT_MISSING_STDERR"; then
  echo "partial strict input unexpectedly inherited fixture defaults" >&2
  rm -f "$STRICT_MISSING_STDERR"
  exit 1
fi
if ! grep -Fq "strict user-input mode does not synthesize omitted fields" \
    "$STRICT_MISSING_STDERR"; then
  echo "partial strict input did not report omitted fields" >&2
  cat "$STRICT_MISSING_STDERR" >&2
  rm -f "$STRICT_MISSING_STDERR"
  exit 1
fi
rm -f "$STRICT_MISSING_STDERR"
echo "strict CLI rejects omitted runtime fields instead of inventing defaults: PASS"

STRICT_ZERO_OUTPUT="$("$ROOT/build/recovered-primitives" \
  --time-seconds=0 \
  --correction-codes= \
  --urandom-hex=00000000 \
  --certificate-sha1=0000000000000000000000000000000000000000 \
  --native-plaintext-hex= \
  --state=false)"
STRICT_ZERO_SIGNATURE="$(printf '%s\n' "$STRICT_ZERO_OUTPUT" | \
  awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ -z "$STRICT_ZERO_SIGNATURE" ]]; then
  echo "explicit zero/false/empty strict input was treated as missing" >&2
  exit 1
fi
echo "strict CLI distinguishes explicit zero/false/empty values from missing: PASS"

OUTPUT="$(run_fixture --time-seconds=1760000001)"
printf '%s\n' "$OUTPUT"

EXPECTED_TIME_PLUS_ONE="123549ac1e84afbe4c96620b74fe22321ff754e352209fad235c4c83b2d4063e1560946d440193da1451cccc148c32a09bd4e5e6eec3b057551645502d01c0633cc7a4df2c63a8bd74ce36903d3e09f4b0bb3c6cfacede9ed89f40feca71810ed44d8ce4d70d952831879f740e9027e9f24719a8db8913328d32f23c158b8ac4c3b5894f6df16c09a466152bd2179e8c86fd68442db22ba1b8d24612bd10990f72b555a3fbff26a686f009db0d90ed02"
ACTUAL_TIME_PLUS_ONE="$(printf '%s\n' "$OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_TIME_PLUS_ONE" != "$EXPECTED_TIME_PLUS_ONE" ]]; then
  echo "timeSeconds=1760000001 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "timeSeconds=1760000001 original-SO oracle exact 176-byte match: PASS"

EXPECTED_NO_TRAMPOLINE="3b273362218b186a73e7349775b93f11ddd8309a1bb05b2a137aa23a545411eb3c7aebfded81c7e87a8b50f259b91c4bf6f169a7e21d32b350da60daca079a7ccf94a5db5fb20c112b4b5b1d351b57eda7570f49ca5602a0bed7a6a77cb237ca8c16a253c6068a23484b10ded89e698e0754586d50370acf0f86b3b53138be70b85dc058cb9630e1e396fb0fb5ebe2a5c7e7db068304dd6eca12578fa9bac89a21de14487bd8dea98a023f26af2e6976"
NO_TRAMPOLINE_OUTPUT="$(run_fixture --signer-code-trampoline-detected=false)"
ACTUAL_NO_TRAMPOLINE="$(printf '%s\n' "$NO_TRAMPOLINE_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_NO_TRAMPOLINE" != "$EXPECTED_NO_TRAMPOLINE" ]]; then
  echo "signerCodeTrampolineDetected=false SO-oracle vector mismatch" >&2
  exit 1
fi
echo "signerCodeTrampolineDetected=false original-SO oracle exact 176-byte match: PASS"

EXPECTED_NO_CORRECTION_05="3b273362218b186a73e7349775b93f1175ea84869289d37a021c609fdba4210c44453a53705c11a25fbfc7dd54fe3e048a436cfe216b02ef7fb09085f20926219bb70e9ec164cfb658f8dd112f2129a2f8c26923d3d58e4ae09cfcf2970474675b5754bad315280431964a2675d4258c62fb1cc700120b9367afa2e7b3bac59723fa554d1b257445534c25bd4dc502aa18cadcc5d1c394042973d5024b4010fe0d8e2ed95208ff0a3ebcc9f1de550ad6"
NO_CORRECTION_05_OUTPUT="$(run_fixture \
  --correction-codes=2b,36,25 \
  --state=true)"
ACTUAL_NO_CORRECTION_05="$(printf '%s\n' "$NO_CORRECTION_05_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_NO_CORRECTION_05" != "$EXPECTED_NO_CORRECTION_05" ]]; then
  echo "correction05Enabled=false SO-oracle vector mismatch" >&2
  exit 1
fi
echo "correction05Enabled=false original-SO oracle exact 176-byte match: PASS"

EXPECTED_EMPTY_PROC_MAPS="3b273362218b186a73e7349775b93f118b66c81962540c095ad13a9257ff30e65ecc6645fbe361a009b131f80bf41313c239e586e9f910e178e77fa38bd8546b954615996c2ecaa93229f254f49ab5f9772085e577577cce2ef7e006520626b8aa8d4ece6a413b55bbf0cea98f891bb4231659ac980af095c74881e6de2aae6c206d5ece678f9f5db5b25f7fdc0d1980b417a7ddfc978f375f41f75102c5e2a9ca8b27b558dfc073c746e01963fa1645"
EMPTY_PROC_MAPS_OUTPUT="$(run_fixture --correction-codes=2b,37,36,25,05)"
ACTUAL_EMPTY_PROC_MAPS="$(printf '%s\n' "$EMPTY_PROC_MAPS_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_EMPTY_PROC_MAPS" != "$EXPECTED_EMPTY_PROC_MAPS" ]]; then
  echo "empty /proc/self/maps SO-oracle vector mismatch" >&2
  exit 1
fi
echo "empty /proc/self/maps original-SO oracle exact 176-byte match: PASS"

EXPECTED_MISSING_PROC_MAPS="3b273362218b186a73e7349775b93f11bf0e565a4dcc3dbd0f20b938e6a648e7b4d1b1ae646530c0e37b5d6f57c53aa36873c135abf30c8007a7a88b4833337b079162e03a8477dc0dc86dd4fc7d6ee071dcb2008f58d4b9999e8a2358536b39cd862bd9fa119c1c0e720d5986590afc9bf118ecd167a60c39fb0e7b36db0bc3d38e3cec66022f33acaeb80f27f54ac0b73c52b08756d876e3337b3d6f005b3991671b8df6c7505955cd7dd51c3e37d8"
MISSING_PROC_MAPS_OUTPUT="$(run_fixture --correction-codes=2b,37,35,36,25,05)"
ACTUAL_MISSING_PROC_MAPS="$(printf '%s\n' "$MISSING_PROC_MAPS_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_MISSING_PROC_MAPS" != "$EXPECTED_MISSING_PROC_MAPS" ]]; then
  echo "missing /proc/self/maps SO-oracle vector mismatch" >&2
  exit 1
fi
echo "missing /proc/self/maps original-SO oracle exact 176-byte match: PASS"

EXPECTED_MISSING_ART_RUNTIME="3b273362218b186a73e7349775b93f11800ca14fada7c06003fb616aa29dba35e963fe8d55cf40e25006ec501f7e1cae7a1b402a7a062fdf410e0074866a986809ef050d74ec43cdbb8d9d65f39984be6fa492995059f79288d9f51aa8d6cca0b1a3ee9fb6219eca036d763d10e18b42c1f81a32152f0a5ef5d418414beac19a55f12955ae30cfa00063fa0f44b1e88f63c24bf783837e89e50418eefe89c66acd0b6dc268f8131443003744128e99dc"
MISSING_ART_RUNTIME_OUTPUT="$(run_fixture --correction-codes=2b,2f,36,25,05)"
ACTUAL_MISSING_ART_RUNTIME="$(printf '%s\n' "$MISSING_ART_RUNTIME_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_MISSING_ART_RUNTIME" != "$EXPECTED_MISSING_ART_RUNTIME" ]]; then
  echo "missing ART runtime correction 0x2f SO-oracle vector mismatch" >&2
  exit 1
fi
echo "missing both /system/lib64/libart.so and ld-android.so correction 0x2f original-SO exact 176-byte match: PASS"

INVALID_JAVA_HMAC_PLAINTEXT_HEX="70726f64756374696f6e3134303030303073657373696f6e616e64726f6964342e33382e3539332e36372e30"
EXPECTED_INVALID_JAVA_HMAC="3b273362218b186a73e7349775b93f11caae2e12d78b1701c676ed06c809f44408f6bec00e3171165911abed8c93e1eb50a0aa09eb5b55788c55f80cdbee7f26c8db26b88a2dc6ea03294681738ff23caf8782d1cc9fee8e5264e71a441ff9a56aedcf851f3cd57918a12da004290a8de39d0149424cc33b0a92f7cdd9d35f67c2ffc2edb22e879c91b26ab1246c538aabb2c290829dc739dd64e035feafdaefda126c69da1301660b2b1ddbfa8822f5"
INVALID_JAVA_HMAC_OUTPUT="$(run_fixture \
  --native-plaintext-hex="$INVALID_JAVA_HMAC_PLAINTEXT_HEX" \
  --correction-codes=2b,07,36,25,05)"
ACTUAL_INVALID_JAVA_HMAC="$(printf '%s\n' "$INVALID_JAVA_HMAC_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_INVALID_JAVA_HMAC" != "$EXPECTED_INVALID_JAVA_HMAC" ]]; then
  echo "invalid Java HMAC correction 0x07 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "invalid Java HMAC correction 0x07 original-SO exact 176-byte match: PASS"

EXPECTED_LEGACY_INVALID_JAVA_HMAC="3b273362218b186a73e7349775b93f1137ca9fced8fcea894f6aecedf01c0023899e64fa01a02858940e7ee97549b9cf4c37a53c5f0f1febcf3c422ade40858063112e0bd439f05f560716c827a89d77f616008e5fffa1fa86fcb018a95beaa0b3e7151743735dd140df9d58c83dc54389dd45d5d502ed1d166d3f54e2a91e9d72f459b783a370e51db2fce5994556d1eed8d37174fb65ec98c89efc725dad17d15f338018e58efc7e42021e2738ef12"
LEGACY_INVALID_JAVA_HMAC_OUTPUT="$(run_fixture \
  --native-plaintext-hex="$INVALID_JAVA_HMAC_PLAINTEXT_HEX" \
  --correction-codes=2b,07,3c,36,25,05)"
ACTUAL_LEGACY_INVALID_JAVA_HMAC="$(printf '%s\n' "$LEGACY_INVALID_JAVA_HMAC_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_LEGACY_INVALID_JAVA_HMAC" != "$EXPECTED_LEGACY_INVALID_JAVA_HMAC" ]]; then
  echo "legacy API18 invalid Java HMAC correction 0x07 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "legacy API18 invalid Java HMAC corrections 0x07/0x3c original-SO exact 176-byte match: PASS"

ALT_DEVICE_NAME_PLAINTEXT_HEX="30313233343536373839616263646566616263313233434e323032362d30372d31305430303a30303a30302e3030302b30383030506978656c20392050726f205870686f6e6573616e64626f7831313131313131312d313131312d313131312d313131312d313131313131313131313131616e64726f696431353134303030303073657373696f6e616e64726f6964342e33382e3539332e36372e30"
EXPECTED_ALT_DEVICE_NAME="3b273362218b186a73e7349775b93f1151da6894512660bd1e9809e7c17c3898a2d0c5508f89e6c3022e6c8f7b4427977b34105b20ae26c5ac356dfb46f545e838eb55bdcbc07db18a0867d16abf126358d2b09b81780e2f48c0243e867679b43d321d87cf26843ae58957b845c2c48bbcb6185acf4d75cab3f4558b3722e63f6dd0f89f0d2f11de80832d8479ff948b9d3d16b204b523bc966f946187ed69a37c3ce900712bda6cd08ee2f3a8e4389f"
ALT_DEVICE_NAME_OUTPUT="$(run_fixture --native-plaintext-hex="$ALT_DEVICE_NAME_PLAINTEXT_HEX")"
ACTUAL_ALT_DEVICE_NAME="$(printf '%s\n' "$ALT_DEVICE_NAME_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_ALT_DEVICE_NAME" != "$EXPECTED_ALT_DEVICE_NAME" ]]; then
  echo "changed device_name SO-oracle vector mismatch" >&2
  exit 1
fi
echo "changed device_name/nativePlaintext original-SO oracle exact 176-byte match: PASS"

MISSING_FIELDS_PLAINTEXT_HEX="616263313233323032362d30372d31305430303a30303a30302e3030302b3038303070686f6e6573616e64626f7831313131313131312d313131312d313131312d313131312d313131313131313131313131616e64726f696431353134303030303073657373696f6e616e64726f6964342e33382e3539332e36372e30"
EXPECTED_MISSING_FIELDS="3b273362218b186a73e7349775b93f1151da6894512660bd1e9809e7c17c3898a2d0c5508f89e6c3022e6c8f7b442797b9c3cbceec98968732365365690cd6d49eedbeff89e4f3eff80d87a481c39bb27a9862ada32dc4d46a6624d290e3b54d72e3a1ca3e9db49ce02d5dfaad7a29403af49ac600c6b9d5837e3e46db1e7ca529fc511f42616d75a82d8942c2c8256d87fb5cd7d5e532820a2e77ea493fbccaf0f58b5ae9cc76e1d862c7d69992e049"
MISSING_FIELDS_OUTPUT="$(run_fixture --native-plaintext-hex="$MISSING_FIELDS_PLAINTEXT_HEX")"
ACTUAL_MISSING_FIELDS="$(printf '%s\n' "$MISSING_FIELDS_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_MISSING_FIELDS" != "$EXPECTED_MISSING_FIELDS" ]]; then
  echo "missing android_id/country/device_name SO-oracle vector mismatch" >&2
  exit 1
fi
echo "missing android_id/country/device_name original-SO oracle exact 176-byte match: PASS"

EXPECTED_ALT_CERTIFICATE="3b273362218b186a73e7349775b93f11049d1036eecf9d2b2fc48ef8c6aa6f998b41dcb1cd09071baa199168954814e660982270cf6d38748c483f8f8c551a6e39b2686eaafcb63dac3536f3c26a7f822e943acd70c9daa840231fb6bc0916db6d02998a6666e1ccb1b703f589b9dbcb2ec2c417378e3a00c8fb4f45f5b6565e8123563489745e4b68882a2fcf7dfe811c65bb6e6426c08b72b83bc06622868d0127f1e3081ca57fd8fff77c530aecf2"
ALT_CERTIFICATE_OUTPUT="$(run_fixture \
  --certificate-sha1=18eb38693ef45c932340d8e8e23d6dfd3770c54c \
  --correction-codes=2b,2a,36,25,05)"
ACTUAL_ALT_CERTIFICATE="$(printf '%s\n' "$ALT_CERTIFICATE_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_ALT_CERTIFICATE" != "$EXPECTED_ALT_CERTIFICATE" ]]; then
  echo "APK/package certificate mismatch correction 0x2a SO-oracle vector mismatch" >&2
  exit 1
fi
echo "APK/package certificate mismatch correction 0x2a original-SO oracle exact 176-byte match: PASS"

EXPECTED_CMDLINE_MISMATCH="3b273362218b186a73e7349775b93f1170bfe197a0b1f1ed7360766164fab6fd7b1a069099eeabb081c32948cc3f1376e177ab8f12289ff33e25275d7c97a826d473e043bb94eb108134fc50be62964e33596c08dc7a0ead0567a031bb304f49d30d1517989be22ed706cc1d0c6077f06b5427448baf16ff01f2b4190d4b67835c1ed13abcb831020241799709817d276cda9f5902ce893089ebc8a793e36fbfe5bd754eef9ca0979691258ef7d9664d"
CMDLINE_MISMATCH_OUTPUT="$(run_fixture --correction-codes=2b,09,3c,36,25,05)"
ACTUAL_CMDLINE_MISMATCH="$(printf '%s\n' "$CMDLINE_MISMATCH_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_CMDLINE_MISMATCH" != "$EXPECTED_CMDLINE_MISMATCH" ]]; then
  echo "/proc/self/cmdline package mismatch correction 0x09 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "/proc/self/cmdline package mismatch correction 0x09 original-SO exact 176-byte match: PASS"

EXPECTED_MISSING_CMDLINE="3b273362218b186a73e7349775b93f112f99badc4cc1bdb2c58761f699f62817e386bc0e6a005b894a0212cf212a2dceba35ccdd09c560bce68f1ddd13805a42e2d93bdee03252019cd49ce3d9965e022392aa1a6f5daa396403be2d30273499110efcc388a5f9c2df34b0a13a62f01ead457a3ba2f5101513d40964bb7c52b4dd55a335fb837a8f7ee5e601965eab4cca94f1e847d0ee51d8252146169d4575f15be21272bf9224a3b78bb5d7efb48a"
MISSING_CMDLINE_OUTPUT="$(run_fixture --correction-codes=2b,34,3c,36,25,05)"
ACTUAL_MISSING_CMDLINE="$(printf '%s\n' "$MISSING_CMDLINE_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_MISSING_CMDLINE" != "$EXPECTED_MISSING_CMDLINE" ]]; then
  echo "missing/empty /proc/self/cmdline correction 0x34 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "missing/empty /proc/self/cmdline correction 0x34 original-SO exact 176-byte match: PASS"

EXPECTED_NINE_CORRECTIONS="3b273362218b186a73e7349775b93f1179481da885a7cac310c774c58ffbfb89d3a1d182c6df2f2922882e512d25c6cb7ed86876f6849e9b071fc729fc32b0e7e95afdc0d901d404a1fdf97f88c969edf01c1466d12c8cee7c934446e3fedf73d083430b7228bc54b540bf837d6efb936eace726faac44574bc338f74c1c930859903d6b242176114096df19a2afd257de5fd434e74d04c592ea0976ee67f0995f21c466c09d976d3ae4524267ca276cce4e55b7d252e8111ccd41e98389f1ce"
NINE_CORRECTIONS_OUTPUT="$(run_fixture \
  --certificate-sha1=18eb38693ef45c932340d8e8e23d6dfd3770c54c \
  --correction-codes=2b,09,37,2a,3c,35,36,25,05)"
ACTUAL_NINE_CORRECTIONS="$(printf '%s\n' "$NINE_CORRECTIONS_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_NINE_CORRECTIONS" != "$EXPECTED_NINE_CORRECTIONS" ]]; then
  echo "nine-correction dynamic field-0 SO-oracle vector mismatch" >&2
  exit 1
fi
echo "nine corrections -> 16 halfwords -> 129-byte payload -> 192-byte result original-SO exact match: PASS"

EXPECTED_SEVENTEEN_CORRECTIONS="3b273362218b186a73e7349775b93f11bb4851ad16acbcbc3f62e2a6a52db497abb81be1392bd9fd14c765a2137a333ff4700b38ed747e686a45dfcaa1f35af9f1d74881fb4f8677d4dfa500c324d6f7852b401f816b8d76f193728b52aaa5881865f80f4969a885f520113d04700b94abee5d98971aacf9b1714053ff3e77d04b909fc216437e7c867ad76c6900c806ac89f98fd54447ddea86f023245fb78a91c993cdacdd995c5b52b16c8adae8080687def487a211c7ac86bd116ae9b10a169536cf557089fc821e4ef1432a820a"
SEVENTEEN_CORRECTIONS_OUTPUT="$(run_fixture \
  --correction-codes=2b,36,25,05,01,02,03,04,05,06,07,08,09,0a,0b,0c,0d)"
ACTUAL_SEVENTEEN_CORRECTIONS="$(printf '%s\n' "$SEVENTEEN_CORRECTIONS_OUTPUT" | awk -F= '/^SIGNATURE_HEX=/{print $2}')"
if [[ "$ACTUAL_SEVENTEEN_CORRECTIONS" != "$EXPECTED_SEVENTEEN_CORRECTIONS" ]]; then
  echo "17-correction 24-halfword SO-oracle vector mismatch" >&2
  exit 1
fi
echo "17 corrections -> 24 halfwords -> 145-byte payload -> 208-byte result original-SO exact match: PASS"
