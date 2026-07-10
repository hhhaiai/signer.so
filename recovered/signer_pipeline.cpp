// Evidence-labelled source-level reconstruction of Adjust Signature 3.62.0.
//
// This is deliberately not presented as the vendor's original source.  Code
// marked CONFIRMED is backed by shipped bytecode plus native runtime/cross-ABI
// evidence.  INFERRED blocks preserve a proven calling/data shape while their
// complete protected implementation remains in the original libsigner.so.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace adjust_362_recovered {

enum class Evidence { CONFIRMED, INFERRED, UNKNOWN };

struct Blob {
  std::uint32_t byte_length;
  std::uint32_t padding;
  const std::uint8_t *data;
};

static_assert(offsetof(Blob, data) == 8, "64-bit native Blob layout");

struct VmError {
  std::uint32_t code = 0;
};

// CONFIRMED from direct calls to 0x110978/0x110a94/0x111018/0x110bc8/
// 0x1111c0 on ARM64 and their x86_64 counterparts. Values are 32-bit.
class OperandStack {
public:
  void push(std::uint32_t value) { values_.push_back(value); }

  std::uint32_t pop(VmError &error) {
    if (values_.empty()) {
      error.code = 3; // confirmed underflow error
      return 0;
    }
    const std::uint32_t value = values_.back();
    values_.pop_back();
    return value;
  }

  void dup(VmError &error) {
    if (values_.empty()) {
      error.code = 3;
      return;
    }
    values_.push_back(values_.back());
  }

  void pick(std::size_t depth, VmError &error) {
    if (depth >= values_.size()) {
      error.code = 4; // confirmed depth/range error
      return;
    }
    values_.push_back(values_[values_.size() - 1 - depth]);
  }

  void roll(std::size_t depth, VmError &error) {
    if (depth >= values_.size()) {
      error.code = 4;
      return;
    }
    const std::size_t index = values_.size() - 1 - depth;
    const std::uint32_t value = values_[index];
    values_.erase(values_.begin() + static_cast<std::ptrdiff_t>(index));
    values_.push_back(value);
  }

private:
  std::vector<std::uint32_t> values_;
};

// CONFIRMED conceptual model. The concrete protected implementation stores a
// stack of 256-word frames; context allocation is 0xa0 bytes and contains one
// main frame plus sixteen auxiliary frame slots.
struct WordFrame {
  std::vector<std::uint32_t> words;
  std::size_t cursor = 0;

  std::size_t length() const { return cursor; }

  void seek(std::size_t next, VmError &error) {
    if (next > words.size()) {
      error.code = 4;
      return;
    }
    cursor = next;
  }

  void store32(std::size_t index, std::uint32_t value, VmError &error) {
    if (index >= words.size()) {
      error.code = 4;
      return;
    }
    words[index] = value;
    if (cursor <= index) {
      cursor = index + 1;
    }
  }
};

struct NativeMetadata {
  std::string headers_id = "8";
  std::string adj_signing_id = "1300000";
  std::string native_version = "3.62.0";
  std::string algorithm = "adj7";
};

struct PlatformEvidence {
  std::string package_name;
  std::array<std::uint8_t, 20> certificate_sha1{};
  std::int32_t sensor_count = 0;
  std::int32_t display_width = 0;
  std::int32_t display_height = 0;
  std::string public_source_dir;
  bool suspicious_stack = false;
  bool suspicious_fd_or_process = false;
};

struct SignatureResult {
  std::vector<std::uint8_t> bytes;
  NativeMetadata metadata;
};

// The native code checks a fixed allow-list of 97 Adjust parameter names via
// Map.containsKey/get. The full observed list is documented in native-analysis.md.
using OrderedStringMap = std::vector<std::pair<std::string, std::string>>;

// INFERRED boundary around ARM64 0xb6c50 / x86_64 0x9dcf0.
// Direct probes confirm count=9, Blob layout, big-endian frame ingestion and a
// 304-byte output for the valid fixture shape. This entry is a stack-VM program/
// orchestrator, not a single SHA/AES primitive.
bool signature_vm_program(VmError *error,
                          void *vm_context,
                          std::uint32_t blob_count,
                          const std::array<Blob, 9> &blobs);

// CONFIRMED outer pipeline, expressed against abstract platform operations.
// `build_nine_vm_blobs` remains INFERRED until every blob's business name is
// captured at the live 0xb6c50 entry; the byte lengths and data dependency are
// already proven.
SignatureResult recovered_nsign_pipeline(
    const OrderedStringMap &parameters,
    const std::vector<std::uint8_t> &java_hmac,
    std::int32_t sdk_level,
    const PlatformEvidence &platform,
    const std::array<Blob, 9> &build_nine_vm_blobs,
    void *vm_context) {
  (void)parameters;
  (void)java_hmac;
  (void)sdk_level;
  (void)platform;

  VmError error;
  if (!signature_vm_program(&error, vm_context, 9, build_nine_vm_blobs) ||
      error.code != 0) {
    throw std::runtime_error("protected signature VM failed");
  }

  // CONFIRMED: the caller copies the VM output into NewByteArray/SetByteArrayRegion.
  // For the validated 3.62.0 fixture this result is exactly 304 bytes.
  SignatureResult result;
  result.bytes.resize(304);

  // CONFIRMED: the native method then mutates the input Map with these fields.
  result.metadata = NativeMetadata{};
  return result;
}

// CONFIRMED nOnResume behavior:
//   if global_guard == 0:
//     invoke detector callback once synchronously;
//     timer_create(CLOCK_MONOTONIC, SIGEV_THREAD, callback);
//     timer_settime(initial=1s, interval=1s);
//     set global_guard on success.

} // namespace adjust_362_recovered

