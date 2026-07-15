#!/usr/bin/env python3
"""Generate the function-by-function arm64 recovery inventory from .eh_frame."""

from __future__ import annotations

import csv
import bisect
import pathlib
import re


HERE = pathlib.Path(__file__).resolve().parent
EH_FRAME = HERE / "arm64-eh-frame.txt"
DISASSEMBLY = HERE.parent / "libsigner-arm64-objdump.txt"
CSV_OUTPUT = HERE / "arm64-function-inventory.csv"
MD_OUTPUT = HERE.parent.parent / "native-reimplementation" / "SO_FUNCTION_COVERAGE.md"

KNOWN = {
    0x008070: ("module DSO finalizer wrapper", "recovered", "BTI entry computes the image DSO handle and tail-calls __cxa_finalize; represented by callback-driven C++ runtime operations"),
    0x008080: ("module no-op callback", "recovered", "BTI plus RET has no observable source-level effect"),
    0x008088: ("module no-op callback tail alias", "recovered", "BTI plus unconditional branch to 0x8080 represented by the shared no-op C++ callback"),
    0x008090: ("nullable module exit-callback dispatcher", "recovered", "null callback returns; non-null callback is tail-invoked with no argument mutation, recovered in direct C++"),
    0x0080A4: ("module __cxa_atexit registration wrapper", "recovered", "registers 0x8090 with the incoming callback as argument and the image DSO handle; registration return is preserved in callback-driven C++"),
    0x0080C0: ("correction 0x2b and flag-bit-0 helper", "recovered", "writes correction 0x2b then ORs context+0xe0 with 1 in C++"),
    0x0080F4: ("correction 0x39 and flag-bit-0 helper", "recovered", "writes correction 0x39 then ORs context+0xe0 with 1 in C++"),
    0x008128: ("client_sdk current-thread stack gate", "recovered", "caller/runtime-supplied Map client_sdk and current-thread stack strings; fixed Android marker, 4.38.2/5.0.0 boundary records, three original marker payload strings and max 20; exact status short-circuit, correction 0x2b/0x39, final 0x0200080000000000 mask and stack-array/client-sdk cleanup recovered cross-ABI in callback-driven C++"),
    0x008AF4: ("reserved Map value JNI materializer", "recovered", "exact case-sensitive secret_id/headers_id/native_version mapping to 1400000/9/3.67.0, miss no-op, NewStringUTF publication-before-exception, status 34 and null-result success recovered with static ARM64 interpretation"),
    0x00A334: ("native result metadata cleanup", "recovered", "clears context+0x18; unconditionally removes four metadata keys with exact status overwrite/preservation modeled in C++"),
    0x00AF3C: ("JNI result byte-array and metadata builder", "recovered", "byte-array creation/copy, flattened four-put order, per-stage status branch, rollback and success return recovered in C++"),
    0x00CDE4: ("context+0x108 string-consistency stage", "recovered", "15000ms timing pair, producer status 0x34, byte mismatch 0x09, final mask and unconditional free recovered in C++"),
    0x0CBA8C: ("nOnResume export jump", "recovered", "single unconditional tail branch to 0xd4908 represented by runRecoveredNOnResumeExport"),
    0x0CBA90: ("native context init stage 1", "recovered", "four-call orchestration, false-only fallback and status reset recovered in C++"),
    0x0CBBD4: ("native context init stage 2", "recovered", "fail-open HMAC branch, two owned-pointer stages, three cleanup paths and finalizer order recovered in C++"),
    0x0CBE94: ("environment dispatcher tail alias", "recovered", "four-byte tail branch to 0x143e8 represented by a source-level C++ entry"),
    0x0CC604: ("nSign JNI orchestrator", "recovered", "full ARM64 interpreter and callback-driven C++ recover exact environment=sandbox auxiliary flag, conditional begin/end logging, independent clock-status merges, descriptor values and saved-result return"),
    0x09279C: ("context +0xe0 bit setter", "recovered", "not an algorithm dispatcher"),
    0x0927C4: ("JNI GetStringUTFLength helper", "recovered", "null status 3, non-null JNI call despite preexisting status, signed jint widening, exception status 28 and final nonzero-status output clearing recovered by static ARM64 interpretation"),
    0x092A20: ("JNI exception describe-and-clear consumer", "recovered", "ExceptionOccurred vtable +0x78, conditional ExceptionDescribe +0x80 and ExceptionClear +0x88, exact boolean return recovered in direct C++"),
    0x0143E8: ("environment dispatcher", "recovered", "fixed d78b8/db410/13063c/1309cc/1311f0 order, per-probe status resets, result/status corrections 22/35/23/36/25/2d/3a/2e, duplicate-3a suppression and unconditional final mask recovered by full ARM64 state-machine interpretation and callback-driven C++"),
    0x013DC4: ("correction 0x32 tail alias", "recovered", "single unconditional tail branch to 0x14380 represented by a source-level C++ entry"),
    0x013DC8: ("packed-transition filtered record stage", "recovered", "kind-10 record filtering, 0x34bf4 uint16 match gate to correction 0x04, success-only 15000ms timing, allocation-failure correction 0x32, unconditional 0x0004000000000010 mask, temporary-array free and status-zero return recovered cross-ABI in C++"),
    0x014078: ("fixed-loopback filtered record stage", "recovered", "kind-10 record filtering, 0x34954 uint16 match gate to correction 0x0a, success-only 15000ms timing, allocation-failure correction 0x32, unconditional 0x0004000000000400 mask, temporary-array free and status-zero return recovered cross-ABI in C++"),
    0x014338: ("context flag-mask 0x0004000000000410", "recovered", "single load/OR/store leaf represented in C++"),
    0x014350: ("context flag-mask 0x0004000000000010", "recovered", "single load/OR/store leaf represented in C++"),
    0x014368: ("context flag-mask 0x0004000000000400", "recovered", "single load/OR/store leaf represented in C++"),
    0x014380: ("correction 0x32 and flag-bit-0 helper A", "recovered", "fixed correction write followed by context+0xe0 bit zero represented in C++"),
    0x0143B4: ("correction 0x32 and flag-bit-0 helper B", "recovered", "second distinct FDE with the same fixed correction and flag mutation represented in C++"),
    0x014E10: ("correction 0x35 and flag-bit-0 helper", "recovered", "fixed correction write followed by context+0xe0 bit zero represented in C++"),
    0x014E44: ("correction 0x36 and flag-bit-0 helper", "recovered", "fixed correction write followed by context+0xe0 bit zero represented in C++"),
    0x014E78: ("correction 0x3a and flag-bit-0 helper A", "recovered", "fixed correction write followed by context+0xe0 bit zero represented in C++"),
    0x014EAC: ("correction 0x3a and flag-bit-0 helper B", "recovered", "second distinct FDE with the same fixed correction and flag mutation represented in C++"),
    0x014EE0: ("context flag-mask 0x0460603c00000000", "recovered", "single load/OR/store leaf represented in C++"),
    0x00D184: ("realtime threshold comparison", "recovered", "CLOCK_REALTIME/-ENOSYS fallback, millisecond normalization, baseline and strict-threshold byte mutation recovered in C++"),
    0x00D428: ("cmdline missing/empty wrapper", "recovered", "correction 0x34"),
    0x00D45C: ("context flag-mask 0x0010000000000200", "recovered", "single load/OR/store leaf recovered in C++"),
    0x00D466C: ("process-global Android API setter", "recovered", "single 32-bit global store represented by runRecoveredAndroidApiSetterD466c and regression-tested"),
    0x00D3FF0: ("system-property metadata initializer", "recovered", "source creation, preexisting-status gate, calloc(1,0x30), source+0x08 plus uint32 +0x2c cursor, population failure free and unconditional source destruction implemented and regression-tested in C++"),
    0x00D3D90: ("mapped-file owner destructor", "recovered", "null owner no-op, nullptr/MAP_FAILED unmap suppression, valid mapping munmap, nonnegative fd syscall-close, ignored cleanup results and final owner free order implemented and regression-tested in C++"),
    0x0C8C44: ("owned pointer-array destructor", "recovered", "null-array no-op, ascending count-bounded non-null element free and slot clear, then unconditional array-allocation free implemented and regression-tested in C++"),
    0x00D6A2C: ("readable-file syscall reader", "recovered", "null/access/open gates, openat/read/close syscall arguments, exact -1 failure tests, output[readResult-1] termination including zero-read underflow risk, close ordering and ignored close result implemented and regression-tested in C++"),
    0x0D1A38: ("slice-to-owned-NUL-string materializer", "recovered", "consumes one {uint32 offset,length} descriptor, requests uint64(length)+1, copies source+8 data, appends NUL, publishes output, and preserves cursor advancement with output null/status 2 on allocation failure; recovered cross-ABI in direct C++"),
    0x0D1BF4: ("indexed string-table owned clone", "recovered", "consumes a uint32 index, maps UINT32_MAX to static empty string or resolves source+8 data through the uint32 offset table at source+0x24, performs native unbounded NUL scan, clones to output+8, and preserves cursor advancement with output null/status 2 on allocation failure; recovered cross-ABI in C++"),
    0x0D2018: ("two-stage owned string-pair materializer", "recovered", "always runs 0xd1a38, runs 0xd1bf4 only while status is zero, retains both strings on success, and on any nonzero status frees/clears first then second; preexisting status still permits stage-one allocation before ordered rollback; recovered cross-ABI in direct C++"),
    0x0D22D4: ("recursive 0x30-byte metadata-node content destructor", "recovered", "null no-op; ascending depth-first destruction of +0x18/count+0x10 then +0x28/count+0x20 contiguous 0x30-byte child arrays, array release/pointer/count clearing, then +0x00/+0x08 owned-string release recovered cross-ABI in recursive C++"),
    0x0D28D0: ("recursive metadata-node parser", "recovered", "consumes a 0x1c descriptor, redirects through source-relative own/child offsets, builds recursive +0x18 and pair-only +0x28 calloc(count,0x30) arrays, publishes counts only after child success, and uses d22d4 rollback with status 2 on allocation failure; recovered cross-ABI in recursive C++"),
    0x0D313C: ("dot-separated metadata area-name resolver", "recovered", "descends +0x18 recursive children by first strncmp(segmentLength) match, resolves the final segment by exact strcmp over +0x28 pair-only leaves, and returns the leaf second string or null; recovered cross-ABI in direct C++"),
    0x0D352C: ("property-info mapped source creator", "recovered", "calloc(1,0x30), decoded /dev/__properties__/property_info access/openat/fstat, >=24-byte gate, read-only private mmap and first-24-byte header copy recovered cross-ABI with statuses 2/8/10/12; native dereferences mmap result without MAP_FAILED check"),
    0x095110: ("JNI GetByteArrayElements acquisition wrapper", "recovered", "GetArrayLength-first ordering, JNI vtable +0x5c0 with null isCopy, exception/null status 28, preexisting-status behavior and paired elements/length cleanup implemented and regression-tested in C++"),
    0x034820: ("packed low-24 transition predicate", "recovered", "low 24 bits must match, second high byte must equal 1 and first high byte must differ from 1; recovered cross-ABI from ARM64 0x34820 and x86_64 0x32955 with direct C++ and truth-table regression"),
    0x034954: ("detector record cross-match counter", "recovered", "nested pointer-array scan counts matching +0x10 keys only when first-array record +0x28 equals 1 and +0x08 equals 0x0100007f; duplicate multiplicity and uint16 wrap recovered cross-ABI in direct C++"),
    0x034BF4: ("detector packed-transition cross-match counter", "recovered", "nested +0x10 key match, first-record +0x28==1 gate and low-32 +0x08/+0x18 forwarding to recovered 0x34820; duplicate multiplicity and uint16 wrap recovered cross-ABI in direct C++"),
    0x0B1E40: ("JNI java/lang/Exception ThrowNew helper", "recovered", "ARM64/x86_64 XOR-once class-name initialization, FindClass plus one exception-consumer call, status 18 on null/exception, success-only ThrowNew(message), ignored ThrowNew return and non-null DeleteLocalRef cleanup recovered in direct C++"),
    0x034F9C: ("detector record pointer filter", "recovered", "calloc(count,8), ordered +0x08/+0x18/+0x20 non-null and +0x28==10 selection, allocation status 2, success publication and input-order preservation implemented and regression-tested in C++"),
    0x023274: ("readable-file descriptor batch", "recovered", "0x100 record layout, reused 0x801 buffer, per-record first-0x800 clear, readable-file gate, ordered 0x23730 matching, first-match uint16 increment/wrap and read-failure skip implemented and regression-tested in C++"),
    0x00D4244: ("guarded system-property reader", "recovered", "metadata area-name resolution, /dev/__properties__/%s path, R_OK gate, direct fallback and denied-output clearing implemented and regression-tested in C++"),
    0x00D4220: ("recursive metadata-node owner destructor", "recovered", "preserves the outer 0x30-byte node pointer, invokes 0xd22d4 content destruction and tail-calls free on the same pointer; null still reaches free(nullptr), recovered cross-ABI in C++"),
    0x00D43E8: ("property-area path snprintf adapter", "recovered", "fixed /dev/__properties__/%s format and native 199-byte vsnprintf bound implemented in C++"),
    0x00D4678: ("Android API system-property compatibility dispatcher", "recovered", "API >27 lazy metadata cache, success-only guarded first use, direct fallback, non-null failed-object publication and steady-state routing implemented and regression-tested in C++"),
    0x00D474: ("public-source linked-list check", "recovered", "15000ms timing, list producer, corrections 0x37/0x29, node traversal, final mask and head cleanup recovered in C++"),
    0x00D7890: ("path existence helper", "recovered", "access(path, F_OK) success converted to exact boolean in C++"),
    0x01F058: ("QEMU/Genymotion socket-path probe", "recovered", "cross-ABI XOR-once /dev/socket/qemud, /dev/qemu_pipe, /dev/socket/genyd and /dev/socket/baseband_genyd constants, two ordered two-path calls to recovered 0x1f95c, shared incoming uint16 accumulation with modulo wrap and environment-stage nonzero correction-0x01 gate recovered in direct C++"),
    0x01F95C: ("path-existence array counter", "recovered", "exact count-bounded pointer walk, 0xd7890 predicate call, match-only uint16 increment and modulo-2^16 wrap implemented and regression-tested in C++"),
    0x024444: ("system-property descriptor-record batch matcher", "recovered", "0x100 record layout, ignored 0xd4678 return, 0x5c zeroed property buffer, ordered descriptor/kind traversal through 0x23730, first-match per-record short circuit and uint16 wrap implemented and regression-tested in C++"),
    0x024860: ("VirtualBox DMI file-content probe", "recovered", "cross-ABI XOR-once product_name/VirtualBox and sys_vendor/innotek pairs, two exact 0x100 records with kind-3 substring and descriptorCount one, recordCount two forwarding to recovered 0x23274, shared incoming uint16 accumulation and flattened caller count flow recovered in direct C++"),
    0x02C618: ("Raspberry manufacturer system-property probe", "recovered", "cross-ABI XOR-once ro.product.manufacturer, ro.product.vendor.manufacturer and raspberry strings; two kind-3 descriptor records forwarded to 0x24444 with fixed count 2, zeroed uint16 match count and count!=0 boolean return; caller correction 0x28 recovered in direct C++"),
    0x02CC9C: ("minical/vcloud/Scorpio system-property probe", "recovered", "cross-ABI XOR-once manufacturer/vendor/model/display property strings and minical/vcloud/Scorpio_rt OS markers; five kind-3 descriptor records forwarded to 0x24444 with fixed count 5, zeroed uint16 match count and count!=0 boolean return; caller correction 0x2c recovered in direct C++"),
    0x00D980: ("correction 0x37 and flag-bit-0 helper", "recovered", "writes correction 0x37 then ORs context+0xe0 with 1 in C++"),
    0x00D9B4: ("context flag-mask 0x0080020000000000", "recovered", "single load/OR/store leaf recovered in C++"),
    0x00D9CC: ("SHA-1 candidate digest comparator", "recovered", "candidate+0x10 length/data descriptor, null-data false path, SHA-1 and exact 20-byte context+0xf0 comparison recovered in C++"),
    0x00DDC4: ("public-source digest validation stage", "recovered", "parser status 0x38, candidate order +0x38/+0x28/+0x18, any-match acceptance, 0x2a mismatch, final mask and destructor recovered in C++"),
    0x00E674: ("correction 0x38 and flag-bit-0 helper", "recovered", "writes correction 0x38 then ORs context+0xe0 with 1 in C++"),
    0x00E6A8: ("context flag-mask 0x0100040000000000", "recovered", "single load/OR/store leaf recovered in C++"),
    0x00F1C8: ("correction 0x33 and flag-bit-0 helper", "recovered", "writes correction 0x33 then ORs context+0xe0 with 1"),
    0x00F1FC: ("context flag-mask helper", "recovered", "ORs context+0xe0 with 0x0008000000000080"),
    0x00F214: ("context stage-complete flag helper", "recovered", "ORs context+0xe0 with 0x20"),
    0x00F224: ("timing correction gate", "recovered", "low byte at context+0x08 controls correction 0x05 and flag bit 0; always sets flag 0x20"),
    0x00E6C0: ("supplied/expected Java-HMAC comparator", "recovered", "direct C++ preserves three 15000ms probes, API-key/toString/getBytes/Mac/supplied-copy ordering, exact compare, correction 0x07, fail-open result and reverse JNI cleanup; direct branch regression and 14-job parity pass"),
    0x01DDE0: ("JNI API-dependent PackageInfo certificate-array selector", "recovered", "signed Android API <28 path uses getPackageInfo flag 0x40, explicitly publishes hasMultipleSigners false and reads PackageInfo.signatures; API >=28 uses flag 0x08000000, PackageInfo.signingInfo, hasMultipleSigners and selects getApkContentsSigners or getSigningCertificateHistory; exact child status short-circuit, caller-owned Signature[] transfer, unchanged early-failure outputs and SigningInfo -> PackageInfo -> PackageManager -> packageName local-ref cleanup recovered cross-ABI in C++"),
    0x01E578: (
        "JNI certificate Signature[0] SHA1 materializer",
        "recovered",
        "certificate selector -> GetObjectArrayElement index zero -> "
        "Signature.toByteArray -> MessageDigest.getInstance(SHA1) -> update -> "
        "no-arg digest -> GetByteArrayElements flow, status 28 for element failure "
        "and 20 for non-20-byte digest, exact 16+4 byte publication, "
        "release-before-cleanup, MessageDigest/certificate byte[]/digest byte[]/"
        "Signature[] cleanup and original omitted Signature-element delete "
        "recovered cross-ABI in C++ with fresh dynamic ownership evidence",
    ),
    0x00F328: ("environment stage dispatcher", "recovered", "sole-entry flattened CFG reduced to seven ordered probes plus 0xfce0; scratch ownership, thresholds, corrections 01/02/03/08/28/2c/1f, seven timing probes, success/failure return, unconditional fallback and cleanup implemented and regression-tested in C++"),
    0x00FCE0: ("environment stage-1 emulator/automation initializer", "recovered", "24 one-time marker decoders represented as immutable plaintext, direct 14-stage fanout, fixed-field correction 0x19, dynamic-slot correction 0x0c, 0.8 score contributions, score>=0.8 ordered correction commit and flag-bit mutation, nested 0x13044 mask stage and status==0 return recovered in direct C++"),
    0x012A30: ("13-predicate post-detector aggregator", "recovered", "same scratch pointer forwarded through fixed 4d9bc/59658/5a8e0/5c6d8/5f900/615d8/6a4e0/6c590/6dbbc/6f758/76f2c/77f7c/78f68 order, first-true short circuit, correction 0x21 plus flag bit zero on hit and unconditional flag bit 33 recovered with static state-machine interpretation and C++ regression"),
    0x04D9BC: ("GreatFruit/Google sensor-pair predicate", "recovered", "eight exact ordered sensor/vendor pairs forwarded to recovered 0x58498 with count 8; raw marker decoding, table order and unchanged helper boolean return proven by static wrapper interpretation"),
    0x058498: ("ordered detector string-pair array equality", "recovered", "non-null scratch/table, exact pair-count equality, ordered scratch+0x70/+0x78 pairs, non-null elements and full-string ASCII-CI equality recovered with static instruction interpretation and direct C++"),
    0x059658: ("microvirt dynamic-pair substring predicate", "recovered", "iterates 16-byte scratch+0x70/+0x78 pairs up to count at +0x870; both strings in one slot must contain XOR-0x1d microvirt under overlapping ASCII-CI matching; null/nonmatching slots skip and first complete pair succeeds"),
    0x05A8E0: ("Tiantian sensor-pair predicate", "recovered", "TiantianVM Accelerometer/TianTian exact pair forwarded to recovered 0x58498 with count 1 and unchanged boolean return"),
    0x05C6D8: ("seven physical sensor-pair predicate", "recovered", "seven exact Invensense/AOSP/STMicroelectronics/AKM/Qualcomm sensor pairs forwarded to recovered 0x58498; table order/count 7 and unchanged boolean return proven statically"),
    0x05F900: ("Goldfish three-sensor predicate", "recovered", "three Goldfish accelerometer/gyroscope/orientation pairs with Android Open Source Project vendor forwarded to recovered 0x58498 count 3"),
    0x0615D8: ("MPU/Orientaion two-sensor predicate", "recovered", "MPU6515 Accelerometer/InvenSense and native-typo Orientaion/Qualcomm pairs forwarded to recovered 0x58498 count 2"),
    0x06A4E0: ("Goldfish two-sensor subset predicate", "recovered", "Goldfish accelerometer and orientation pairs with Android Open Source Project vendor forwarded to recovered 0x58498 count 2"),
    0x06C590: ("Genymotion sensor-pair predicate", "recovered", "one expected pair Genymotion Accelerometer/Genymobile, raw XOR marker decoding and exact ordered pair-array match through recovered 0x58498 implemented in direct C++"),
    0x06DBBC: ("leapdroid substring predicate", "recovered", "scratch+0x58 pointer, XOR-0xb7 leapdroid marker, overlapping ASCII case-insensitive substring behavior, null/empty rejection and prefix/suffix containment recovered with static instruction interpretation and direct C++"),
    0x06F758: ("open-source two-sensor predicate", "recovered", "Acceleration sensor/Acceleration Sensor Open Source Project and Compass Magnetic field sensor/Compass Sensor Open Source Project pairs forwarded to recovered 0x58498 count 2"),
    0x076F2C: ("haima substring predicate", "recovered", "scratch+0x20, XOR-0x80 haima marker, overlapping ASCII case-insensitive substring behavior, null/empty rejection and prefix/suffix containment recovered with static instruction interpretation and direct C++"),
    0x077F7C: ("vmos substring predicate", "recovered", "scratch+0x08, XOR-0x5b vmos marker, overlapping ASCII case-insensitive substring behavior, null/empty rejection and prefix/suffix containment recovered with static instruction interpretation and direct C++"),
    0x078F68: ("paired device/build substring predicate", "recovered", "scratch+0x20 must contain HWEVA, eva-al00 or zerofltezc and scratch+0x30 must contain :6.0.1/RB3N5C; all markers are XOR-decoded overlapping ASCII-CI substrings and both field conditions are required"),
    0x0D6CB8: ("package suffix after last-dot helper", "recovered", "NUL scan, last-dot tracking, leading/absent-dot empty result and pointer-after-dot return recovered in C++"),
    0x0D6ED8: ("128-byte newline-stripping getline-compatible helper", "recovered", "null-buffer calloc(128,1), full incoming-capacity clear, repeated fgets/strlen chunks, newline removal, append/NUL behavior, exact 128-byte growth including exact-multiple extra block, initial/partial EOF returns and direct realloc-failure pointer loss recovered cross-ABI in callback-driven C++"),
    0x018540: ("proc-maps public-source list producer", "recovered", "direct C++ producer preserves access/fopen status 8, fgets/sscanf loop, apk/package predicate, calloc status 2, append-before-strdup ownership, strdup status 2 and unconditional fclose"),
    0x013000: ("context fallback mask stage", "recovered", "ordered masks 0x00001181c000010e, nested 0x13044, then bit 33 recovered in C++"),
    0x013044: ("nested context mask stage", "recovered", "calls 0x7bb98 then ORs 0x02001000 in C++"),
    0x013078: ("context flag bit-33 leaf", "recovered", "ORs context+0xe0 with 0x0000000200000000 in C++"),
    0x014EF8: ("ART/linker stat post-stage", "recovered", "correction 0x2f on true result, correction 0x3b on nonzero status, then fixed context mask recovered in C++"),
    0x0150B8: ("correction 0x3b and flag-bit-0 helper", "recovered", "writes correction 0x3b then ORs context+0xe0 with 1 in C++"),
    0x0150EC: ("context flag-mask 0x0800800000000000", "recovered", "single load/OR/store leaf recovered in C++"),
    0x00D78B8: ("proc maps Frida scanner", "recovered", "access R_OK and fopen status 8, getline loop, exact case-sensitive frida-agent substring, early match return and free-before-close ownership recovered by full ARM64 interpretation and C++ callbacks"),
    0x00D6994: ("vsnprintf varargs adapter A", "recovered", "ARM64 GP/FP varargs save and va_list forwarding have the same source-level semantics as recoveredBoundedSnprintf"),
    0x00DD144: ("vsnprintf varargs adapter B", "recovered", "second ARM64 GP/FP varargs adapter forwarding directly to vsnprintf, represented by recoveredBoundedSnprintf"),
    0x0F18F4: ("ART/linker stat helper", "recovered", "correction 0x2f"),
    0x07BB98: ("context flag-mask 0x3dffe800", "recovered", "zero-extended 32-bit mask load/OR/store recovered in C++"),
    0x07BBB0: ("eight fixed-string detector marker matcher", "recovered", "scratch offsets 00/08/10/18/20/30/38/50, eight marker loops, full-string ASCII A-Z folding, null skipping and any-match return recovered in direct C++"),
    0x09954C: ("JNI Map.put(String,String) helper", "recovered", "put name/signature and JNI vtable calls recovered"),
    0x09AA5C: ("JNI Map.remove(String) helper", "recovered", "status 3/18/34/28, call progression, class/key cleanup, returned-object leak and opaque-anchor DeleteLocalRef attempt modeled"),
    0x09B684: ("JNI Object.toString helper", "recovered", "toString name/signature and JNI calls recovered"),
    0x09C030: ("JNI String.getBytes helper", "recovered", "no-argument getBytes and byte-array result recovered"),
    0x094BC0: ("JNI byte-array native copy helper", "recovered", "length, calloc, GetByteArrayRegion and allocation-failure cleanup recovered"),
    0x0927AC: ("detector context flag-mask 0x0001000000000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x092B24: ("JNI GetStringUTFChars acquisition helper", "recovered", "0x927c4 length stage, vtable +0x548 acquisition, status 28 exception/null result and dual-output clearing implemented and regression-tested in C++"),
    0x092DDC: ("JNI GetArrayLength helper", "recovered", "null-array status 3, vtable +0x558 call despite preexisting status, status 28 exception and 32-bit output clearing implemented and regression-tested in C++"),
    0x095020: ("JNI ReleaseStringUTFChars guard wrapper", "recovered", "requires non-null Java string and UTF pointer, then calls JNI vtable +0x550; JNIEnv itself unguarded"),
    0x09548C: ("JNI NewByteArray output helper", "recovered", "NewByteArray, status 31, null/preexisting-status output clearing recovered"),
    0x095680: ("JNI SetByteArrayRegion helper", "recovered", "null-array status 3 and pending-exception status 32 recovered"),
    0x095834: ("JNI ReleaseByteArrayElements guard wrapper", "recovered", "non-null array/elements gate and vtable +0x600 call with mode zero implemented and regression-tested in C++"),
    0x0A4450: ("JNI KeyStore.getInstance helper", "recovered", "java/security/KeyStore static getInstance(String) recovered"),
    0x0A8978: ("JNI size-method reader", "recovered", "null object status 3; GetObjectClass/GetMethodID(size,()I)/CallIntMethod with three exception-consumer stages; class/method status 18, call exception status 28, class local-ref cleanup, incoming-status preservation and final output clearing recovered cross-ABI in C++"),
    0x0A948C: ("JNI indexed object-method reader", "recovered", "null object status 3; GetObjectClass/GetMethodID(get,(I)Ljava/lang/Object;)/CallObjectMethod(index) with three exception-consumer stages; class/method status 18, call exception or null result status 28, class local-ref cleanup, returned local-ref transfer, incoming-status preservation and final output clearing recovered cross-ABI in C++"),
    0x0A5308: ("JNI KeyStore.load helper", "recovered", "load(KeyStore.LoadStoreParameter) with null argument recovered"),
    0x0A6C9C: ("JNI KeyStore.getKey helper", "recovered", "getKey(String,char[]) and output-reference transfer recovered"),
    0x0A9D44: ("JNI Mac.getInstance helper", "recovered", "javax/crypto/Mac getInstance(String) recovered"),
    0x0AB130: ("JNI Mac.init helper", "recovered", "init(java.security.Key) recovered"),
    0x0AB870: ("JNI Mac.update helper", "recovered", "update(byte[]) recovered"),
    0x0AC1D8: ("JNI Mac.doFinal helper", "recovered", "doFinal() byte-array result recovered"),
    0x0ACD90: ("JNI Map.containsKey helper", "recovered", "containsKey name/signature and CallBooleanMethod recovered"),
    0x0ADBF4: ("JNI Map.get helper", "recovered", "get name/signature and CallObjectMethod recovered"),
    0x0B21B4: ("JNI int-field reader", "recovered", "null object/name status 3; GetObjectClass/GetFieldID(name,\"I\")/GetIntField with three exception-consumer stages; class/field status 18, int-field exception status 28, conditional class local-ref cleanup, incoming-status preservation and final output clearing recovered cross-ABI in C++"),
    0x0B2978: ("JNI caller-selected String-field reader", "recovered", "null object/name status 3; GetObjectClass/GetFieldID(name,\"Ljava/lang/String;\")/GetObjectField with three exception-consumer stages; class/field status 18, object-field exception or null result status 28, class local-ref cleanup, returned String transfer, incoming-status preservation and final output clearing recovered cross-ABI in C++"),
    0x0B3230: ("JNI Context.getPackageName String reader", "recovered", "caller-supplied Context null gate, fixed getPackageName()Ljava/lang/String; contract, GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18/28, three exception consumes, class local-ref cleanup, returned String transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0B3BF4: ("JNI Context.getPackageManager object reader", "recovered", "caller-supplied Context null gate, fixed getPackageManager()Landroid/content/pm/PackageManager; contract, GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18, three exception consumes, null-result failure, class local-ref cleanup, returned PackageManager transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0B5828: ("JNI Context.getSystemService getter", "recovered", "null context/field-name status 3; FindClass(android/content/Context), GetMethodID(getSystemService), caller-selected static String GetStaticFieldID/GetStaticObjectField and CallObjectMethod recovered in exact five-exception-stage order; acquisition status 18, object/call status 28, service String before class local-ref cleanup and incoming-status output clearing modeled in C++"),
    0x0BB5A0: ("JNI Resources.getSystem getter", "recovered", "FindClass(android/content/res/Resources), GetStaticMethodID(getSystem,()Landroid/content/res/Resources;) and CallStaticObjectMethod recovered with three exception stages, class/method status 18, call exception or null result status 28, class local-ref cleanup and incoming-status output clearing"),
    0x0BCE98: ("JNI DisplayMetrics getter", "recovered", "null Resources object status 3; GetObjectClass/GetMethodID(getDisplayMetrics,()Landroid/util/DisplayMetrics;)/CallObjectMethod with three exception-consumer stages; class/method status 18, call exception or null result status 28, class local-ref cleanup, returned DisplayMetrics transfer, incoming-status preservation and final output clearing recovered cross-ABI in C++"),
    0x0BEA74: ("JNI Sensor.getName getter", "recovered", "null Sensor status 3; GetObjectClass/GetMethodID(getName,()Ljava/lang/String;)/CallObjectMethod, statuses 18/28, class local-ref cleanup, returned String transfer and incoming-status output clearing recovered cross-ABI in shared C++ regression"),
    0x0BF5FC: ("JNI Sensor.getVendor getter", "recovered", "null Sensor status 3; GetObjectClass/GetMethodID(getVendor,()Ljava/lang/String;)/CallObjectMethod, statuses 18/28, class local-ref cleanup, returned String transfer and incoming-status output clearing recovered cross-ABI in shared C++ regression"),
    0x0C0180: ("JNI SensorManager.getSensorList getter", "recovered", "null manager status 3; GetObjectClass/GetMethodID(getSensorList,(I)Ljava/util/List;)/CallObjectMethod(type) with three exception stages; class/method/call/null-result status 18, class local-ref cleanup, returned List transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0C2248: ("JNI Signature.toByteArray byte-array reader", "recovered", "fixed toByteArray()[B contract shared with the separately emitted 0x93fd0 helper; null Signature status 3, class/method status 18, call exception or null result status 28, three exception consumes, class local-ref cleanup, returned byte[] transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0C2B78: ("JNI SigningInfo.getApkContentsSigners reader", "recovered", "caller-supplied SigningInfo null gate, fixed getApkContentsSigners()[Landroid/content/pm/Signature; contract, GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18/28, three exception consumes, null-result failure, class local-ref cleanup, returned Signature[] transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0C375C: ("JNI SigningInfo.getSigningCertificateHistory reader", "recovered", "caller-supplied SigningInfo null gate, fixed getSigningCertificateHistory()[Landroid/content/pm/Signature; contract, GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18/28, three exception consumes, class local-ref cleanup, returned Signature[] transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0C4064: ("JNI SigningInfo.hasMultipleSigners boolean reader", "recovered", "caller-supplied SigningInfo null gate, fixed hasMultipleSigners()Z contract, GetObjectClass -> GetMethodID -> CallBooleanMethod flow, false as a valid result, status 3/18/28, three exception consumes, raw jboolean byte publication, class local-ref cleanup and incoming-status output clearing recovered cross-ABI in C++"),
    0x0C8EC0: ("Java HMAC key-route dispatcher", "recovered", "API <18, 18..22 and >=23 routes recovered"),
    0x0C9250: ("AndroidKeyStore key2 resolver", "recovered", "getInstance/load/getKey call failures, null-key success and KeyStore local-ref cleanup recovered"),
    0x0C9988: ("legacy wrapped HMAC-key resolver", "recovered", "five-helper order, preexisting-status first call, null forwarding, Base64 status 26 normalization, RSA boolean gate, success-only output publication and raw/decoded/preferences/string cleanup order recovered by full ARM64 interpretation"),
    0x0CA648: ("Java Mac HmacSHA256 producer", "recovered", "getInstance/init/update/doFinal sequence recovered"),
    0x016B7C: ("context+0x108 owned-string producer", "recovered", "Java string/UTF acquisition, wrapping malloc, NUL/copy, status 2, release and local-ref cleanup recovered in C++"),
    0x01709C: ("/proc/self/cmdline owned-string producer", "recovered", "cross-ABI XOR-once fixed OS path, caller-supplied access/openat/read/close/allocation/memory operations, 4095-byte read, statuses 8/12/2, close-before-result gate, wrapping signed-read conversion, terminator-before-copy, late output publication and original negative-read memory-corruption boundary recovered in callback-driven C++"),
    0x0179F8: ("context+0x110 publicSourceDir string producer", "recovered", "NewStringUTF/object chain, atomic XOR-once field decode, statuses 34/15/2, UTF copy and four-ref cleanup recovered in C++"),
    0x01DBD8: ("owned string-list destructor", "recovered", "16-byte {head,tailSlot} owner, value-before-node free order and empty invariant restoration recovered in C++"),
    0x12C12C: ("case-insensitive marker/triplet parser", "recovered", "naive marker search, repeated-dot token scanner, three strtol calls and partial mutation recovered in C++"),
    0x127A78: ("case-sensitive substring predicate", "recovered", "null rejection, empty-needle acceptance, naive overlapping byte scan, length boundary and first complete-match return recovered in direct C++"),
    0x128038: ("case-sensitive suffix predicate", "recovered", "null rejection, measured length comparison, value plus length-difference suffix alignment, byte-exact comparison, empty-suffix acceptance and longer-suffix rejection recovered in direct C++"),
    0x128364: ("optimized case-sensitive substring predicate", "recovered", "call-free byte-indexed table and four-byte packing implementation statically interpreted through the kind-seven caller state; null rejection, empty-marker acceptance, overlapping and case-sensitive substring behavior recovered in direct C++"),
    0x12AD00: ("ASCII case-insensitive prefix predicate", "recovered", "null rejection, empty-marker acceptance, lockstep comparison from value start and ASCII A-Z folding recovered in direct C++"),
    0x12B474: ("ASCII case-insensitive suffix predicate", "recovered", "null rejection, empty-suffix acceptance, measured length alignment and ASCII A-Z folding recovered in direct C++"),
    0x12BA10: ("ASCII case-insensitive substring predicate", "recovered", "null rejection, nonempty-value outer candidate loop, overlapping restart, ASCII A-Z folding, empty-value/empty-marker false and nonempty-value/empty-marker true recovered in direct C++"),
    0x036BFC: ("two-marker ASCII case-insensitive range equality helper", "recovered", "zero-length/null-table rejection, exact caller-supplied byte-range comparison against two marker strings, ASCII A-Z folding, first-match return and range-length boundary recovered with static instruction interpretation"),
    0x0352D4: ("three-field build-identity predicate", "recovered", "ordered scratch+0x10/+0x18/+0x20 checks against android, Android-SDK-build and generic-x86 marker pairs through 0x36bfc, null skipping and first-match short circuit recovered in direct C++"),
    0x12E95C: ("unsigned 96-bit comparator", "recovered", "three-limb comparison order and -1/0/1 result recovered in C++"),
    0x12EB48: ("final range-boundary predicate", "recovered", "equal low limb plus upper-pair ordering recovered in C++"),
    0x12EC1C: ("epoch-millisecond timestamp log front end", "recovered", "cross-ABI /1000 truncation, fmod millisecond component, localtime, date/zone strftime, exact line format and nSign begin/end labels modeled in C++"),
    0x12F298: ("Park-Miller next tail alias", "recovered", "single tail branch to 0x12f29c represented by the recovered C++ alias"),
    0x12F29C: ("Park-Miller minimal-standard next", "recovered", "zero-state substitute, 127773 quotient/remainder reduction, 16807/2836 terms, signed correction, unmasked state store and low-31-bit return recovered by static ARM64 proof and C++ regression"),
    0x12F2F8: ("Park-Miller state seed helper", "recovered", "null no-op and zero-extended 32-bit seed publication as a 64-bit state recovered by static ARM64 proof and C++ regression"),
    0x12F3AC: ("urandom/time fallback seed producer", "recovered", "null no-op, output clear, /dev/urandom R_OK plus ARM64 openat syscall 56, exact eight-byte read, close ordering and gettimeofday/getpid XOR fallback recovered by cross-ABI static proof and callback C++ regression"),
    0x12FA24: ("Android log varargs adapter", "recovered", "ARM64 GP/FP register save and va_list forwarding represented by the recovered source-level variadic log entry"),
    0x12FAB4: ("Android log formatter/router", "recovered", "two zeroed 0x400-byte buffers, message formatting, optional source@line prefix and sink routing recovered cross-ABI in C++"),
    0x130098: ("bounded snprintf varargs adapter", "recovered", "va_list construction and direct vsnprintf return-value forwarding recovered in C++"),
    0x13012C: ("Android log priority sink", "recovered", "priority table 2/3/5/6, signer tag, one-argument and prefix-plus-message formats recovered cross-ABI in C++"),
    0x13063C: ("signer-code trampoline detector", "recovered", "null-terminated table walk, per-table upper bounds, up-to-eight-byte copy and ARM64 LDR-literal plus BR-register mask recovered by static instruction interpretation and direct C++"),
    0x1309CC: ("loopback Frida-server probe", "recovered", "atomic XOR-once 127.0.0.1/AUTH strings, TCP port 27042, 100ms receive timeout, socket/connect/send/recv/close ordering, status 6 and exact recv-zero verdict recovered in callback-driven C++ without network execution"),
    0x134A74: ("correction codeword transform", "recovered", "encodeCorrection implemented"),
    0x134A1C: ("entropy-seeded correction-state initializer wrapper", "recovered", "0x12f3ac entropy producer, low-32-bit seed forwarding and 0x134a74 initialization order implemented and regression-tested in C++"),
    0x134DD8: ("correction replacement-slot finder", "recovered", "64 slots, 8 repeating sentinels and exhaustion index 64 recovered in C++"),
    0x134F40: ("16-byte Park-Miller permutation builder", "recovered", "zero initialization and incremental Fisher-Yates output[j]-to-output[i], i-to-output[j] construction for 16 iterations recovered by static ARM64 proof and C++ regression"),
    0x135050: ("16x16 correction-basis bit-matrix transpose", "recovered", "zeroed local matrix, MSB-first source/destination loops, conditional bit OR and sixteen-halfword copy-back recovered by cross-ABI static proof and involution regression"),
    0x13531C: ("state-local correction codeword writer", "recovered", "destination clear, reverse-bit basis XOR and index-64 sentinel alias recovered in C++"),
    0x13548C: ("correction find-and-write wrapper", "recovered", "preserves context/code across slot lookup then tail-calls writer"),
    0x135640: ("android marker triplet-range gate", "recovered", "nine-argument ABI, source copy, unconditional join, status 2/5, two lookups and cleanup order recovered in C++"),
    0x136A00: ("string-array trailing-delimiter join", "recovered", "two-pass allocation and byte-copy state machine recovered in C++"),
    0x0F1EC8: ("protected crypto/work engine", "recovered", "all 42,732 ARM64 instructions and 17 direct helper targets represented by the text-only VM; corrected 16-byte context-flags descriptor naturally resolves the 0x3e branch and reproduces the 176-byte Pixel result without PC skips, lane patches or output hardcoding"),
    0x0CBE98: ("native signing context orchestrator", "recovered", "loaded-value gate, realtime failure, certificate fail-open reset, fixed stage order, owned cleanup and result return implemented in C++"),
    0x0CC47C: ("CLOCK_REALTIME signing-context sampler", "recovered", "ARM64/x86_64 millisecond conversion, null-status behavior and failure status 14 implemented in C++"),
    0x0D4908: ("one-shot periodic timer installer", "recovered", "synchronous callback, CLOCK_MONOTONIC SIGEV_THREAD 1-second timer, global installed byte and silent create/arm failures modeled in C++"),
    0x0D4E0C: ("periodic TracerPid anti-debug callback", "recovered", "cross-ABI /proc/<pid>/status path, TracerPid marker, access/openat/read/close failures, case-insensitive search, native atoi and sticky verdict modeled in C++"),
    0x0D6888: ("TracerPid correction/context consumer", "recovered", "sticky verdict emits correction 0x26 and flag bit zero; both paths set context flag bit 38 in C++"),
    0x0AEBF8: ("JNI Map string owned-copy helper", "recovered", "Map.get, modified-UTF acquisition, length+1 malloc copy, statuses 2/3, UTF release and local-ref cleanup modeled in C++"),
    0x11BA78: ("JNI Map selected-value walker", "recovered", "one 1363-byte table allocation, exact 100-key order, 97 normal containsKey routes, reserved-value bypass, Map.get null-value callback, callback/DeleteLocalRef timing, preexisting/allocation/helper/callback failure states and retained-reference edges recovered by static ARM64 interpretation"),
    0x11D40C: ("Map value counting sink", "recovered", "first pass length accumulation"),
    0x11D528: ("Map value bounded-copy sink", "recovered", "capacity/offset/data layout recovered"),
    0x11D798: ("Map plaintext materializer", "recovered", "counting walker 0x11d40c, calloc(length+1,1), allocation status 2, copying walker 0x11d528, deferred pointer/length publication, explicit NUL and retained allocation on second-walker failure recovered"),
    0x11EA78: ("SHA-1 80-round compression", "recovered", "big-endian 16-word load, 80-word schedule, four SHA-1 round families/constants and five-state accumulation represented by the recovered SHA-1 implementation"),
    0x11F238: ("SHA-1 context initializer", "recovered", "standard SHA-1 initial words and zero counters represented by the recovered SHA-1 implementation used by the exact candidate digest comparator"),
    0x11F264: ("SHA-1 streaming update", "recovered", "block buffering, length accounting and SHA-1 compression behavior represented by the recovered SHA-1 implementation"),
    0x11F414: ("SHA-1 finalizer", "recovered", "SHA-1 padding, big-endian digest export and final compression represented by the recovered SHA-1 implementation"),
    0x11F89C: ("checked fread wrapper", "recovered", "fread argument order, short-item status 2 and unsigned itemsRead>=requestedCount return implemented and regression-tested in C++"),
    0x11F990: ("checked fseek wrapper", "recovered", "nonzero fseek status 2 and exact zero-success boolean implemented and regression-tested in C++"),
    0x11FA74: ("checked ftell wrapper", "recovered", "nonnegative output publication, negative status 2 and sign-bit boolean implemented and regression-tested in C++"),
    0x11FB60: ("24-byte owned file-list destructor", "recovered", "next-field traversal, payload-before-node free order and owner {null,&head} reset implemented and regression-tested in C++"),
    0x11FCCC: ("24-byte file-list node append", "recovered", "zeroed node allocation, status 1 failure, tail-slot publication and node+0x10 tail advance implemented and regression-tested in C++"),
    0x11FE4C: ("length-prefixed file-list record reader", "recovered", "append-before-read ownership, two uint32 headers, zero-extended payloadLength+8 validation, status 8 mismatch, calloc payload publication and checked one-item payload read implemented and regression-tested in C++"),
    0x12014C: ("bounded file-list sequence reader", "recovered", "four-byte record-size prefix, nested 0x11fe4c parsing, uint32 cumulative recordSize+4 progression, exact-total termination, overshoot status 8 and short-read propagation implemented and regression-tested in C++"),
    0x1203E4: ("24-byte owned file-list destructor alias", "recovered", "next at +0x10, payload-before-node free order and owner {null,&head} reset are identical to 0x11fb60 and represented by a tested C++ alias"),
    0x120550: ("24-byte file-list node append alias", "recovered", "calloc(1,0x18), status 1 failure, tail-slot publication and node+0x10 advance are identical to 0x11fccc and represented by a tested C++ alias"),
    0x1206D0: ("file-list fixed-size payload reader", "recovered", "append-before-publication, uint32 length at node+0, calloc payload at +8, status 1 allocation failure and exact checked one-item read implemented and regression-tested in C++"),
    0x120858: ("bounded fixed-size payload sequence reader", "recovered", "four-byte payload-length prefixes, nested 0x1206d0 reads, uint32 length+4 offset progression, exact-total status 8 and short-read propagation implemented and regression-tested in C++"),
    0x120AFC: ("24-byte owned file-list destructor alias B", "recovered", "node+0x10 traversal, payload-before-node free order and {null,&head} reset represented by a tested C++ alias"),
    0x120C68: ("24-byte file-list node append alias B", "recovered", "calloc(1,0x18), status 1, tail-slot publication and node+0x10 advance represented by a tested C++ alias"),
    0x120DE8: ("tagged payload record reader", "recovered", "append-before-read, uint32 recordSize-4 payload derivation, tag at +0, length at +4, calloc payload at +8 and exact checked read implemented and regression-tested in C++"),
    0x120FFC: ("bounded tagged-payload sequence reader", "recovered", "four-byte record-size prefixes, nested 0x120de8 reads, uint32 size+4 progression, exact-total status 8 and short-read propagation implemented and regression-tested in C++"),
    0x121260: ("24-byte owned file-list destructor alias C", "recovered", "node+0x10 traversal, payload-before-node free order and {null,&head} reset represented by a tested C++ alias"),
    0x1213CC: ("24-byte file-list node append alias C", "recovered", "calloc(1,0x18), status 1, tail-slot publication and node+0x10 advance represented by a tested C++ alias"),
    0x12154C: ("length-prefixed file-list record reader alias", "recovered", "two uint32 headers, zero-extended payloadLength+8 validation, status 8, calloc payload and exact checked read are identical to 0x11fe4c and represented by a tested C++ alias"),
    0x12183C: ("bounded file-list record sequence reader C", "recovered", "four-byte record-size prefixes, nested 0x12154c reads, uint32 size+4 progression and exact-total status 8 implemented and regression-tested in C++"),
    0x121AAC: ("three-list aggregate destructor", "recovered", "ordered +0x20 via 0x120afc, +0x10 via 0x1203e4 and +0x00 tail-call to 0x11fb60 implemented and regression-tested in C++"),
    0x121ADC: ("three-section file-list parser", "recovered", "three ordered uint32 section lengths, uint32 cumulative prefix accounting with per-stage upper bounds, 0x12014c/0x120858/0x120ffc routing, nested status short circuit and trailing SEEK_CUR skip implemented and regression-tested in C++"),
    0x122090: ("owned file-buffer reader", "recovered", "length-first publication, calloc(1,length), status 1 allocation failure and checked one-item fread implemented and regression-tested in C++"),
    0x1221B8: ("owned file-buffer destructor", "recovered", "conditional data free followed by pointer clear and length clear implemented and regression-tested in C++"),
    0x1222A8: ("four-list container-node append", "recovered", "calloc(1,0x58), four embedded {null,&head} owners, allocation status 1, outer tail-slot publication and node+0x50 advance implemented and regression-tested in C++"),
    0x122410: ("four-list container-node content destructor", "recovered", "ordered first-three aggregate, fourth list and owned-buffer cleanup without freeing the outer node implemented and regression-tested in C++"),
    0x12243C: ("three-section 0x58 container-node parser", "recovered", "append-before-read ownership, three uint32 sections routed to 0x121adc/+0x00, 0x12183c/+0x30 and 0x122090/+0x40, uint32 overshoot gates and exact-total status 8 implemented and regression-tested in C++"),
    0x122BB8: ("0x58 container-node list destructor", "recovered", "node+0x50 traversal, content-before-node cleanup and outer owner {null,&head} reset implemented and regression-tested in C++"),
    0x122D24: ("bounded 0x58 container-node sequence", "recovered", "zero-total no-op, length-prefixed 0x12243c records, parse-before-offset advancement, uint32 progression and exact-total status 8 implemented and regression-tested in C++"),
    0x122FE4: ("container-node list destructor alias", "recovered", "single tail branch to 0x122bb8 represented by a tested C++ alias"),
    0x122FE8: ("single-section container-sequence wrapper", "recovered", "one uint32 section length, pre-parse unsigned size+4 overshoot gate, 0x122d24 routing and exact-total status 8 implemented and regression-tested in C++"),
    0x123254: ("three-list two-field aggregate destructor", "recovered", "ordered +0x28 and +0x10 list cleanup, uint32 +0x20/+0x24 clear and +0x00 tail cleanup implemented and regression-tested in C++"),
    0x123288: ("three-list two-field aggregate parser", "recovered", "wire order list-size/body, list-size/body, two fixed uint32 values, list-size/body; uint32 overshoot gates, exact-total status 8 and nested status short-circuit implemented and regression-tested in C++"),
    0x1238EC: ("0x68 large-container node append", "recovered", "calloc(1,0x68), embedded owner tail slots at +0x08/+0x18/+0x30/+0x48, allocation status 1 and outer node+0x60 publication implemented and regression-tested in C++"),
    0x123A54: ("0x68 large-container content destructor", "recovered", "ordered +0x00 aggregate, +0x40 fourth list and +0x50 owned-buffer cleanup without outer-node free implemented and regression-tested in C++"),
    0x123A80: ("validated multi-section 0x68 node parser", "recovered", "append-before-read ownership, +0x00 aggregate, mirrored +0x38/+0x3c uint32 validation with status 9, +0x40 list and +0x50 buffer sections, uint32 overshoot/exact-total status 8 implemented and regression-tested in C++"),
    0x124608: ("0x68 large-container list destructor", "recovered", "node+0x60 traversal, content-before-node cleanup and owner {null,&head} reset implemented and regression-tested in C++"),
    0x124774: ("bounded 0x68 large-container sequence", "recovered", "zero-total no-op, length-prefixed 0x123a80 records, parse-before-offset uint32 progression and exact-total status 8 implemented and regression-tested in C++"),
    0x124A20: ("large-container list destructor alias", "recovered", "single tail branch to 0x124608 represented by a tested C++ alias"),
    0x124A24: ("single-section large-container sequence wrapper", "recovered", "uint32 section prefix, pre-parse overshoot, 0x124774 routing and post-parse exact-total status 8 implemented and regression-tested in C++"),
    0x124C90: ("public-source parser-owner constructor", "recovered", "access(path,R_OK), cross-ABI once-decoded rb fopen mode, calloc(1,0x48), access/open status 2, allocation status 1, FILE* +0x00 and ordered +0x18/+0x28/+0x38 owner initialization recovered in callback-driven C++; native allocation-failure stream leak preserved"),
    0x125074: ("composite parser-owner destructor", "recovered", "null outer owner no-op; optional FILE* at +0x00 fclose-and-clear followed by ordered embedded-owner destruction at +0x18/+0x28/+0x38 and final outer free recovered cross-ABI in callback-driven C++"),
    0x125210: ("ZIP EOCD signature matcher", "recovered", "zeroed four-byte buffer, checked one-item fread, cross-ABI once-decoded 50 4b 05 06 marker and exact ordered byte equality recovered in callback-driven C++"),
    0x125770: ("ZIP EOCD backward offset scanner", "recovered", "starts at -22, scans through -65556 with checked SEEK_END positioning and 0x125210 predicate, stops on seek failure/match and returns -65557 on exhaustion; unsigned boundary recovered cross-ABI in callback-driven C++"),
    0x1259B8: ("APK Signing Block locator and footer/header validator", "recovered", "EOCD+12 central-directory offset read, absolute PK 01 02 validation, -20 APK Sig Block 42 footer-magic validation, -24 footer offset publication, uint64 footer size, modulo-64-bit 8-size seek, duplicate header-size equality and statuses 3/5/6 recovered cross-ABI in callback-driven C++"),
    0x127194: ("APK Signing Block v2/v3/v3.1 entry dispatcher", "recovered", "raw uint64 size plus uint32 ID loop, exact 7109871a/f05368c0/1b93ad61 routing to owner +0x18/+0x28/+0x38, recognized low32(size)-4 parsing, unknown checked-ftell modulo bound and full64(size)-4 raw seek, zero-read normal exit and seek status 7 recovered cross-ABI in callback-driven C++"),
    0x11DA64: ("final consumer", "recovered", "time/srand, nine descriptor inputs, Map materialization, protected engine/export/result flow, status 4/2 normalization, metadata rollback, exact descriptor/work/buffer cleanup order and final status boolean recovered by full ARM64 interpretation and callback-driven C++"),
    0x122FDC: ("empty linked-list head initializer A", "recovered", "stores head=0 and tailSlot=&head; represented by direct C++ alias"),
    0x124A18: ("empty linked-list head initializer B", "recovered", "second distinct FDE with head=0 and tailSlot=&head; represented by direct C++ alias"),
    0x130128: ("no-op return leaf", "recovered", "standalone ret-only FDE represented in C++"),
    0x13716C: ("protected 96-bit range lookup", "recovered", "32-byte boundaries, half-open intervals and final predicate recovered in C++"),
    0x137894: ("word-stack allocator tail alias", "recovered", "tail-branches to 0x138988"),
    0x137898: ("word-stack push tail alias", "recovered", "tail-branches to 0x138a70"),
    0x13789C: ("word-stack empty tail alias", "recovered", "tail-branches to 0x138a60"),
    0x1378A0: ("word-stack pop tail alias", "recovered", "tail-branches to 0x138b74"),
    0x1378A4: ("word-stack destructor tail alias", "recovered", "tail-branches to 0x1390a8"),
    0x1378A8: ("counter-chain allocator", "recovered", "8-byte zeroed owner and status 2 recovered in C++"),
    0x137980: ("counter-node push", "recovered", "16-byte node insertion and status 2 recovered in C++"),
    0x137A78: ("counter-head decrement", "recovered", "decrement, zero unlink/free and return value recovered in C++"),
    0x137B64: ("counter node-chain destructor", "recovered", "recursive next-first cleanup recovered in C++"),
    0x137C38: ("counter-chain owner destructor", "recovered", "head chain then 8-byte owner cleanup recovered in C++"),
    0x137D0C: ("framed word-arena allocator", "recovered", "128-word rounding, three allocations and status 2 cleanup recovered in C++"),
    0x137FA8: ("word-arena big-endian exporter", "recovered", "4-byte alignment status 6 and native over-allocation rule recovered in C++"),
    0x138318: ("framed word-arena writer", "recovered", "128-word realloc growth and status 2 recovered in C++"),
    0x138560: ("word-arena frame push", "recovered", "frame-base realloc and status 2 recovered in C++"),
    0x138660: ("word-arena frame pop", "recovered", "length rollback and underflow status 7 recovered in C++"),
    0x138728: ("current word-frame length", "recovered", "length minus current frame base recovered in C++"),
    0x138744: ("framed word-arena reader", "recovered", "capacity bound and zero fallback recovered in C++"),
    0x138818: ("framed word-arena destructor", "recovered", "word/frame buffers and owner object cleanup recovered in C++"),
    0x138988: ("protected word-stack allocator", "recovered", "16-byte zeroed stack and allocation status 2 recovered in C++"),
    0x138A60: ("protected word-stack empty test", "recovered", "returns count equals zero"),
    0x138A70: ("protected word-stack push", "recovered", "16-byte node layout and allocation status 2 recovered in C++"),
    0x138B74: ("protected word-stack pop", "recovered", "head removal and empty status 3 recovered in C++"),
    0x138C8C: ("word-stack indexed duplicate", "recovered", "copies exactly one zero-based indexed word to the head; strict bound/status 4 and allocation failure recovered in C++"),
    0x138E58: ("word-stack nonempty check wrapper", "recovered", "tail-call duplicate-prefix helper with length zero"),
    0x138E60: ("word-stack top/index swap", "recovered", "zero-based traversal and status 4 recovered in C++"),
    0x138FD4: ("protected node-chain destructor", "recovered", "recursive next-first free recovered in C++"),
    0x1390A8: ("protected word-stack destructor", "recovered", "node-chain then owner cleanup recovered in C++"),
    0x13917C: ("byte descriptor allocator", "recovered", "16-byte length/data descriptor"),
    0x13926C: ("descriptor free wrapper", "recovered", "tail-calls free"),
    0x139270: ("protected export byte-length reader", "recovered", "reads frame word zero through object offset 0x28"),
    0x13927C: ("protected big-endian export wrapper", "recovered", "offset 0x20 data arena and offset 0x28 length arena recovered in C++"),
    0x1392C4: ("0xa0-byte protected work-object destructor", "recovered", "four fixed members, sixteen arena lanes and cleanup order recovered in C++"),
    0x1393CC: ("0xa0-byte protected work-object allocator", "recovered", "child allocation order, 0x100 arena capacity and partial cleanup recovered in C++"),
    0x1354BC: ("ordered correction-array writer", "recovered", "null/count no-op and ascending uint16 correction writes recovered cross-ABI in C++; caller-owned flag-bit mutation remains outside this helper"),
    0x07BA5C: ("14-stage detector fanout", "recovered", "four arguments forwarded unchanged to fixed ARM64 stage order, all callee returns ignored and wrapper always returns zero; x86_64 pattern confirms ABI-specific 17-stage variant"),
    0x008AD4: ("detector context flag-mask 0x0200080000000000", "recovered", "context+0xe0 load, MOV/MOVK mask materialization, OR, store and return recovered in the shared address-to-mask C++ leaf table"),
    0x016B64: ("detector context flag-mask 0x1000000000000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x040C70: ("generic substring detector and correction 0x0b", "recovered", "scratch+0x30, once-decoded generic marker, case-sensitive substring predicate, 0.3 score update and append-at-count correction 0x0b recovered in direct C++"),
    0x040FEC: ("detector context flag-mask 0x0000000000000800", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x040FFC: ("google_sdk substring detector and correction 0x0d", "recovered", "scratch+0x18, once-decoded google_sdk marker, overlapping ASCII case-insensitive substring scan, restart-at-next-start behavior, score-to-1 and append-at-count correction 0x0d recovered in direct C++"),
    0x0418D8: ("detector context flag-mask 0x0000000000002000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0418E8: ("emulator substring detector and correction 0x0e", "recovered", "scratch+0x18, once-decoded emulator marker, overlapping ASCII case-insensitive substring scan, restart-at-next-start behavior, score-to-1 and append-at-count correction 0x0e recovered in direct C++"),
    0x0421CC: ("detector context flag-mask 0x0000000000004000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0421DC: ("four-build-marker descriptor detector and correction 0x0f", "recovered", "scratch+0x18, four decoded android-sdk-built-for markers, zero-kind descriptor array, 0x42eb0 any-match, fixed kind-zero 0x23730 full-string ASCII-CI equality route, score-to-1 and correction 0x0f recovered in direct C++"),
    0x0430F4: ("detector context flag-mask 0x0000000000008000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x043104: ("goldfish substring detector and correction 0x10", "recovered", "scratch+0x40, once-decoded goldfish marker, overlapping ASCII case-insensitive substring scan, score-to-1 and append-at-count correction 0x10 recovered in direct C++"),
    0x043998: ("detector context flag-mask 0x0000000000010000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0439A8: ("vbox86 field-40 substring detector and correction 0x11", "recovered", "scratch+0x40, once-decoded vbox86 marker, overlapping ASCII case-insensitive substring scan, score-to-1 and append-at-count correction 0x11 recovered in direct C++"),
    0x0442DC: ("detector context flag-mask 0x0000000000020000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0442EC: ("vbox86 field-20 substring detector and correction 0x12", "recovered", "scratch+0x20, shared once-decoded vbox86 marker, overlapping ASCII case-insensitive substring scan, score-to-1 and append-at-count correction 0x12 recovered in direct C++"),
    0x044C28: ("detector context flag-mask 0x0000000000040000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x044DA0: ("detector context flag-mask 0x0000000000080000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x044DB0: ("android_x86 substring detector and correction 0x14", "recovered", "scratch+0x40, once-decoded android_x86 marker, overlapping ASCII case-insensitive substring scan, score-to-1 and append-at-count correction 0x14 recovered in direct C++"),
    0x0456A8: ("detector context flag-mask 0x0000000000100000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0456B8: ("fingerprint descriptor detector and correction 0x15", "recovered", "scratch+0x00, eleven XOR-decoded markers with exact kind tags 0/1/3, 0x42eb0 any-match, recovered 0x23730 routes, native score-count-correction store order and correction 0x15 recovered in direct C++"),
    0x047778: ("detector context flag-mask 0x0000000000200000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x047788: ("generic either-field detector and correction 0x16", "recovered", "ordered scratch+0x10 then +0x20 case-sensitive generic substring checks, first-match short circuit, shared once-decoded marker, score-to-1 and correction 0x16 recovered in direct C++"),
    0x047F84: ("detector context flag-mask 0x0000000000400000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x047F94: ("google-phone marker detector and correction 0x17", "recovered", "scratch+0x30, inlined overlapping ASCII-CI sdk_google_phone_arm search followed by two ordered kind-one ASCII-CI prefix checks, native count-correction-score store order and correction 0x17 recovered in direct C++"),
    0x0490E0: ("detector context flag-mask 0x0000000000800000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x0490F0: ("three-field iTools equality detector and correction 0x18", "recovered", "scratch+0x08/+0x18/+0x20 ordered full-string ASCII-CI equality against XOR-decoded itools marker, prefix/suffix rejection, native count-correction-score store order and correction 0x18 recovered in direct C++"),
    0x04AFD4: ("detector context flag-mask 0x0000000001000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x04AFE4: ("detector no-op return leaf A", "recovered", "standalone four-byte FDE contains only RET and is represented by the shared C++ no-op leaf"),
    0x04AFE8: ("detector no-op return leaf B", "recovered", "standalone four-byte FDE contains only RET and is represented by the shared C++ no-op leaf"),
    0x04AFEC: ("detector no-op return leaf C", "recovered", "standalone four-byte FDE contains only RET and is represented by the shared C++ no-op leaf"),
    0x04AFF0: ("detector context flag-mask 0x0000000020000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x04B000: ("detector context flag-mask 0x0000000004000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x04B010: ("detector context flag-mask 0x0000000008000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x04B020: ("two-field Apple/iPhone substring detector and correction 0x1c", "recovered", "scratch+0x10 then +0x20, ordered overlapping ASCII-CI substring scans for XOR-decoded apple/iphone markers, null skipping and first-match short circuit, native count-score-correction store order and correction 0x1c recovered in direct C++"),
    0x04D9AC: ("detector context flag-mask 0x0000000010000000", "recovered", "single context+0xe0 load/OR/store leaf recovered in the shared address-to-mask C++ table"),
    0x044C38: ("detector predicate wrapper and correction 0x13", "recovered", "null input gate, one 0x352d4 predicate call, false no-op and true score-to-1 plus append-at-count correction 0x13 recovered with direct callback regression"),
    0x042EB0: ("paired descriptor any-match wrapper", "recovered", "pointer-array null gate, paired pointer/uint32 indexed forwarding to 0x23730, first-true short circuit and exhausted false return recovered with callback regression"),
    0x023730: ("descriptor predicate dispatcher", "recovered", "all kinds constant-propagated and implemented: 0 ASCII-CI equality; 1 ASCII-CI prefix; 2 ASCII-CI suffix; 3 ASCII-CI substring; 4 case-sensitive equality; 5 naive case-sensitive substring; 6 case-sensitive suffix; 7 optimized case-sensitive substring; 8 non-null non-empty argument-zero predicate independent of descriptor"),
    0x0868B4: ("ASCII case-insensitive detector marker matcher", "recovered", "scratch+0x70 16-byte string slots and +0x870 count, null skipping, full-string ASCII A-Z folding, prefix rejection and first-match return recovered cross-ABI in C++"),
    0x08F56C: ("detector scratch owned string-pair appender", "recovered", "count >=127 returns 0x26; otherwise performs two independent malloc(length+1) and forward byte copies with NUL termination, publishes first/second pointers at +0x70+count*0x10 and increments +0x870 only after both succeed, or unconditionally frees first then second and returns 2; recovered cross-ABI in C++"),
    0x08FB44: ("detector scratch content destructor", "recovered", "null no-op; releases and clears fixed owned pointers in +08,+18,+20,+00,+30,+38,+10,+50 order, then scans +0x70 16-byte pairs until the first all-null sentinel and releases first then second pointer without reading +0x870 count or imposing a 128-slot bound; recovered cross-ABI in C++"),
    0x087158: ("display-dimension unordered-pair predicate", "recovered", "scratch displayWidth +0x60 and displayHeight +0x64 matched in either orientation against eight cross-ABI identical fixed pairs; field roles dynamically corroborated with 1440x3120 profile, first-match true and exhausted false recovered in direct C++"),
    0x08746C: ("detector property/sensor/display scratch producer", "recovered", "thirteen property reads and mallocs with delayed publication/status 2; service failure normalized to 0x24, width/height failure to 0x1d and other helper statuses preserved; signed sensor loop, last-only JNI cleanup, post-appender increment, display flow and sole-caller 0x8fb44 partial-ownership envelope recovered cross-ABI in C++ with isolated traces"),
    0x091428: ("AndroidKeyStore key-pair generation orchestrator", "recovered", "cross-ABI XOR-once AndroidKeyStore provider lock, KeyStore.getInstance -> load(null) -> KeyPairGenerator.generateKeyPair order, per-helper status short-circuit, success output transfer and failure clearing of both caller outputs recovered in callback-driven C++"),
    0x0917A8: ("BigInteger unsigned big-endian byte materializer", "recovered", "BigInteger.toByteArray -> GetByteArrayElements flow, zero-length status 28, one-byte zero sign-prefix removal, signed 32-bit length widening, calloc(length,1), status 2 allocation failure, memcpy(elements+skip), release-before-local-ref cleanup and dual-output failure clearing recovered cross-ABI in C++"),
    0x093FD0: ("JNI BigInteger.toByteArray helper", "recovered", "cross-ABI toByteArray()[B GetObjectClass/GetMethodID/CallObjectMethod flow, status 3/18/28, three exception consumes, class local-ref cleanup, returned byte-array transfer and incoming-status output clearing recovered in C++"),
    0x096EA8: ("JNI Cipher.init(int,Key) helper", "recovered", "caller-supplied cipher/key null gate, GetObjectClass -> GetMethodID(init,(ILjava/security/Key;)V) -> CallVoidMethod flow, fixed DECRYPT_MODE 2 at the sole caller, status 3/18/41, three exception consumes, signed jint forwarding, incoming-status preservation and cipher-class local-ref cleanup recovered cross-ABI in C++"),
    0x09816C: ("JNI object-class assignability helper", "recovered", "caller-supplied object/class-name null gate, GetObjectClass -> FindClass -> IsAssignableFrom JNI flow, status 3/18/28, three exception consumes, normalized jboolean output, object-class then target-class local-ref cleanup and incoming-status output clearing recovered cross-ABI in C++"),
    0x0AF438: ("JNI MessageDigest.getInstance(String) helper", "recovered", "caller-supplied algorithm string, fixed java/security/MessageDigest getInstance(Ljava/lang/String;)Ljava/security/MessageDigest; contract, FindClass -> GetStaticMethodID -> NewStringUTF -> CallStaticObjectMethod flow, status 3/18/27/28, four exception consumes, class-then-algorithm-String local-ref cleanup, returned MessageDigest transfer and incoming-status output clearing recovered cross-ABI in C++ with original-SO dynamic ordering"),
    0x0B081C: ("JNI update(byte[]) void-method helper", "recovered", "caller-supplied object/byte-array null gate, GetObjectClass -> GetMethodID(update,([B)V) -> CallVoidMethod flow, status 3/18/28, three exception consumes, exact byte-array forwarding, incoming-status preservation and object-class local-ref cleanup recovered cross-ABI in C++"),
    0x0B0F38: ("JNI MessageDigest.digest overload helper", "recovered", "caller-supplied MessageDigest and optional byte-array select digest()()[B or digest([B)[B, with GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18/28, three exception consumes, exact optional byte-array forwarding, class local-ref cleanup, returned digest byte-array transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0B8830: ("JNI PackageInfo.signatures object-field reader", "recovered", "legacy caller-supplied PackageInfo object, fixed signatures [Landroid/content/pm/Signature; field contract, GetObjectClass -> GetFieldID -> GetObjectField flow, status 3/18/28, three exception consumes, null-result failure, class local-ref cleanup, returned Signature[] transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0B9424: ("JNI PackageInfo.signingInfo object-field reader", "recovered", "caller-supplied PackageInfo object, fixed signingInfo Landroid/content/pm/SigningInfo; field contract, GetObjectClass -> GetFieldID -> GetObjectField flow, status 3/18/28, three exception consumes, class local-ref cleanup, returned SigningInfo transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0BA914: ("JNI PackageManager.getPackageInfo object reader", "recovered", "caller-supplied PackageManager/package-name/flags, fixed getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo; contract, legacy 0x40 and API-28 0x08000000 caller flags, GetObjectClass -> GetMethodID -> CallObjectMethod flow, status 3/18/35, three exception consumes, null-result failure, class local-ref cleanup, returned PackageInfo transfer and incoming-status output clearing recovered cross-ABI in C++"),
    0x0A0640: ("JNI KeyPairGenerator.generateKeyPair helper", "recovered", "cross-ABI generateKeyPair()Ljava/security/KeyPair; GetObjectClass/GetMethodID/CallObjectMethod flow, status 3/18/28, three exception consumes, class local-ref cleanup, returned-reference transfer and incoming-status output clearing recovered in C++"),
    0x139800: ("acquire byte compare-exchange", "recovered", "LSE/fallback equivalent atomic semantics recovered in C++"),
    0x139834: ("LSE atomics capability initializer", "recovered", "HWCAP bit 8 and exynos9810 blacklist recovered in C++"),
    0x1398CC: ("AArch64 CPU-feature word decoder", "recovered", "bit-62 descriptor tag, HWCAP/HWCAP2 mapping, HWCAP-bit-11 ID_AA64PFR0/PFR1/ZFR0/ISAR0/ISAR1 path, ordered intermediate global publications and final bit-58 publication recovered in pure C++; every runtime field has an explicit caller-provided presence gate"),
    0x139D04: ("AArch64 CPU-feature constructor wrapper", "recovered", "nonzero-global no-op, ro.arch exynos9810 prefix skip, ordered AT_HWCAP/AT_HWCAP2 reads, {24,hwcap,hwcap2} descriptor and bit-62 tagged call to 0x1398cc recovered in callback-driven C++"),
}


def ranges() -> list[tuple[int, int]]:
    text = EH_FRAME.read_text(errors="replace")
    return [
        (int(start, 16), int(end, 16))
        for start, end in re.findall(r"pc=([0-9a-f]+)\.\.\.([0-9a-f]+)", text)
    ]


def call_graph(functions: list[tuple[int, int]]) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    starts = [start for start, _ in functions]
    end_by_start = dict(functions)

    def owner(address: int) -> int | None:
        index = bisect.bisect_right(starts, address) - 1
        if index < 0:
            return None
        start = starts[index]
        return start if address < end_by_start[start] else None

    outgoing = {start: set() for start in starts}
    incoming = {start: set() for start in starts}
    pattern = re.compile(r"^\s*([0-9a-f]+):.*\s(?:bl|b)\s+0x([0-9a-f]+)")
    for line in DISASSEMBLY.read_text(errors="replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        source = owner(int(match.group(1), 16))
        target = owner(int(match.group(2), 16))
        if source is None or target is None or source == target:
            continue
        outgoing[source].add(target)
        incoming[target].add(source)
    return outgoing, incoming


def main() -> None:
    functions = ranges()
    outgoing, incoming = call_graph(functions)
    reachable = set()
    pending = [0x0CBA8C, 0x0CC604]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(outgoing.get(current, ()))
    rows = []
    for index, (start, end) in enumerate(functions):
        name, status, evidence = KNOWN.get(
            start, (f"sub_{start:x}", "unknown", "not yet assigned semantic role")
        )
        rows.append(
            {
                "index": index,
                "start": f"0x{start:x}",
                "end": f"0x{end:x}",
                "size": f"0x{end - start:x}",
                "name": name,
                "status": status,
                "reachable": "yes" if start in reachable else "no",
                "callers": len(incoming[start]),
                "callees": len(outgoing[start]),
                "evidence": evidence,
            }
        )

    with CSV_OUTPUT.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("recovered", "partial", "unknown")}
    lines = [
        "# arm64 `libsigner.so` function-by-function coverage",
        "",
        "Authoritative target:",
        "",
        "```text",
        "/Users/sanbo/Desktop/api/qbdi/adjust-android-signature-3.67.0/jni/arm64-v8a/libsigner.so",
        "```",
        "",
        "Implementation target:",
        "",
        "```text",
        "/Users/sanbo/Desktop/api/qbdi/native-reimplementation",
        "```",
        "",
        "Function ranges come from the target ELF `.eh_frame` FDEs, not guessed prologues.",
        f"Total FDE function ranges: **{len(rows)}**.",
        "",
        "## Status",
        "",
        f"- recovered: **{counts['recovered']}**",
        f"- partial: **{counts['partial']}**",
        f"- unknown: **{counts['unknown']}**",
        f"- statically reachable from JNI exports: **{len(reachable)}**",
        "",
        "`recovered` means the currently relevant behavior has source-level C++ parity evidence; it does not",
        "mean the whole SO is complete. `partial` means some states/data flow are known. `unknown` is queued",
        "for function-level triage. The full machine-readable table is also written to",
        "`.omx/static-audit-20260713/arm64-function-inventory.csv`.",
        "",
        "## All FDE functions",
        "",
        "| # | range | size | semantic name | status | JNI reachable | callers/callees | evidence / remaining work |",
        "|---:|---:|---:|---|---|---|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['index']} | `{row['start']}..{row['end']}` | `{row['size']}` | "
            f"{row['name']} | **{row['status']}** | {row['reachable']} | "
            f"{row['callers']}/{row['callees']} | {row['evidence']} |"
        )
    MD_OUTPUT.write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
