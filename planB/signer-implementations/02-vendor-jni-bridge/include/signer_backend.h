#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace libsigner_compat {

using JniEnvironmentHandle = void*;
using JavaObjectHandle = void*;
using JavaByteArrayHandle = void*;

enum class SignerError : std::int32_t {
    Ok = 0,
    InvalidArgument = 1,
    InvalidParameterFormat = 2,
    InvalidState = 3,
    BackendClosed = 4,
    BackendNotConfigured = 5,
    LibraryOpenFailed = 10,
    SymbolMissing = 11,
    VendorExceptionPending = 12,
    // Reserved for numeric ABI stability; never emitted. A null vendor result
    // without a pending Java exception is a successful JNI return.
    VendorReturnedNull = 13,
    VendorSelfReference = 14,
    InternalError = 100,
};

struct SignerStatus {
    SignerError code = SignerError::Ok;
    std::string message;

    bool ok() const noexcept { return code == SignerError::Ok; }

    static SignerStatus success();
    static SignerStatus failure(SignerError code, std::string message);
};

enum class BackendKind : std::uint8_t {
    None,
    Vendor,
    FakeForTesting,
};

enum class SignerLifecycleState : std::uint8_t {
    Created,
    Resumed,
    Closed,
};

enum class SignerLifecyclePolicy : std::uint8_t {
    // Exact native compatibility: nSign itself performs the process-global
    // initialization/timer path, so an explicit nOnResume call is optional.
    VendorCompatible,

    // Optional owned-wrapper policy used by callers that intentionally pin
    // the higher-level onResume -> sign order.
    RequireOnResumeBeforeSign,
};

enum class SignerOutputKind : std::uint8_t {
    None,
    VendorJavaByteArray,
    TestOnlyBytes,
};

struct JniExceptionOperations {
    void* context = nullptr;
    bool (*exceptionPending)(
            void* context, JniEnvironmentHandle environment) = nullptr;
};

struct JniCallContext {
    JniEnvironmentHandle environment = nullptr;
    JavaObjectHandle nativeLibHelper = nullptr;
    JniExceptionOperations exceptions;
};

// The Java descriptor remains:
// (Landroid/content/Context;Ljava/lang/Object;[BI)[B
// parameterObjectIsJavaMap is used only by FakeSignerBackend after an
// IsInstanceOf check. VendorSignerBackend forwards the descriptor's Object
// handle untouched and lets the official library preserve its own null/type
// behavior. The compatibility layer never enumerates Map contents or extracts
// device, key, certificate, credential or authentication state.
struct SignerRequest {
    JniCallContext jni;
    JavaObjectHandle androidContext = nullptr;
    JavaObjectHandle parameterObject = nullptr;
    bool parameterObjectIsJavaMap = false;
    JavaByteArrayHandle inputByteArray = nullptr;
    std::int32_t androidApi = 0;
};

struct SignerResult {
    SignerStatus status;
    SignerOutputKind outputKind = SignerOutputKind::None;
    JavaByteArrayHandle vendorByteArray = nullptr;
    std::vector<std::uint8_t> testOnlyBytes;

    // True only when the bytes came directly from the caller-supplied official
    // vendor library. The Adjust service remains the final authority and may
    // still reject vendor output for ordinary protocol or account reasons.
    bool productionEligible = false;
};

class ISignerBackend {
public:
    virtual ~ISignerBackend() = default;

    virtual BackendKind kind() const noexcept = 0;
    virtual const char* name() const noexcept = 0;
    virtual SignerStatus onResume(const JniCallContext& context) = 0;
    virtual SignerResult sign(const SignerRequest& request) = 0;
    virtual SignerStatus close() noexcept = 0;
};

using VendorOnResumeEntry = void (*)(
        JniEnvironmentHandle environment,
        JavaObjectHandle nativeLibHelper);

using VendorSignEntry = JavaByteArrayHandle (*)(
        JniEnvironmentHandle environment,
        JavaObjectHandle nativeLibHelper,
        JavaObjectHandle androidContext,
        JavaObjectHandle parameterObject,
        JavaByteArrayHandle inputByteArray,
        std::int32_t androidApi);

struct DynamicLibraryOperations {
    void* context = nullptr;
    void* (*open)(void* context, const char* path) = nullptr;
    void* (*resolve)(
            void* context, void* library, const char* symbol) = nullptr;
    int (*close)(void* context, void* library) = nullptr;
    const char* (*lastError)(void* context) = nullptr;
};

struct ForbiddenVendorEntryPoints {
    VendorOnResumeEntry onResume = nullptr;
    VendorSignEntry sign = nullptr;
};

DynamicLibraryOperations systemDynamicLibraryOperations();

class VendorSignerBackend final : public ISignerBackend {
public:
    explicit VendorSignerBackend(
            std::string officialLibraryPath,
            DynamicLibraryOperations operations =
                    systemDynamicLibraryOperations(),
            ForbiddenVendorEntryPoints forbiddenEntryPoints = {});
    ~VendorSignerBackend() override;

    VendorSignerBackend(const VendorSignerBackend&) = delete;
    VendorSignerBackend& operator=(const VendorSignerBackend&) = delete;

    BackendKind kind() const noexcept override;
    const char* name() const noexcept override;
    SignerStatus load();
    SignerStatus onResume(const JniCallContext& context) override;
    SignerResult sign(const SignerRequest& request) override;
    SignerStatus close() noexcept override;

    const std::string& officialLibraryPath() const noexcept;

private:
    SignerStatus loadLocked();
    SignerStatus dynamicErrorLocked(
            SignerError code, const char* operation) const;

    std::string officialLibraryPath_;
    DynamicLibraryOperations operations_;
    ForbiddenVendorEntryPoints forbiddenEntryPoints_;
    void* library_ = nullptr;
    VendorOnResumeEntry onResumeEntry_ = nullptr;
    VendorSignEntry signEntry_ = nullptr;
    bool vendorEntered_ = false;
    bool closed_ = false;
    mutable std::mutex mutex_;
};

class SignerCompatibilityLayer final {
public:
    explicit SignerCompatibilityLayer(
            std::unique_ptr<ISignerBackend> backend,
            SignerLifecyclePolicy policy =
                    SignerLifecyclePolicy::VendorCompatible);
    ~SignerCompatibilityLayer();

    SignerCompatibilityLayer(const SignerCompatibilityLayer&) = delete;
    SignerCompatibilityLayer& operator=(const SignerCompatibilityLayer&) =
            delete;

    SignerStatus onResume(const JniCallContext& context);
    SignerResult sign(const SignerRequest& request);
    SignerStatus close() noexcept;

    BackendKind backendKind() const noexcept;
    SignerLifecycleState state() const noexcept;

private:
    SignerStatus validateJniContextLocked(
            const JniCallContext& context) const;

    std::unique_ptr<ISignerBackend> backend_;
    SignerLifecyclePolicy policy_;
    SignerLifecycleState state_ = SignerLifecycleState::Created;
    mutable std::mutex mutex_;
};

}  // namespace libsigner_compat
