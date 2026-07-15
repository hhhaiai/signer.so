#include "signer_backend.h"

#include <cstring>
#include <dlfcn.h>
#include <exception>
#include <new>
#include <utility>

namespace libsigner_compat {
namespace {

constexpr char kVendorOnResumeSymbol[] =
        "Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume";
constexpr char kVendorSignSymbol[] =
        "Java_com_adjust_sdk_sig_NativeLibHelper_nSign";

void* systemOpen(void*, const char* path) {
    static_cast<void>(::dlerror());
    return ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

void* systemResolve(void*, void* library, const char* symbol) {
    static_cast<void>(::dlerror());
    return ::dlsym(library, symbol);
}

int systemClose(void*, void* library) {
    return ::dlclose(library);
}

const char* systemLastError(void*) {
    const char* error = ::dlerror();
    return error == nullptr ? "dynamic loader did not provide an error" : error;
}

template <typename Function>
Function functionFromSymbol(void* symbol) {
    static_assert(sizeof(Function) == sizeof(symbol),
            "POSIX function and data pointers must have equal size");
    Function function = nullptr;
    std::memcpy(&function, &symbol, sizeof(function));
    return function;
}

bool exceptionPending(const JniCallContext& context) {
    return context.exceptions.exceptionPending != nullptr
            && context.exceptions.exceptionPending(
                    context.exceptions.context, context.environment);
}

SignerResult failureResult(SignerError code, std::string message) {
    SignerResult result;
    result.status = SignerStatus::failure(code, std::move(message));
    return result;
}

}  // namespace

SignerStatus SignerStatus::success() {
    return {};
}

SignerStatus SignerStatus::failure(
        SignerError code, std::string message) {
    SignerStatus status;
    status.code = code;
    status.message = std::move(message);
    return status;
}

DynamicLibraryOperations systemDynamicLibraryOperations() {
    return {
        nullptr,
        systemOpen,
        systemResolve,
        systemClose,
        systemLastError,
    };
}

VendorSignerBackend::VendorSignerBackend(
        std::string officialLibraryPath,
        DynamicLibraryOperations operations,
        ForbiddenVendorEntryPoints forbiddenEntryPoints)
    : officialLibraryPath_(std::move(officialLibraryPath)),
      operations_(operations),
      forbiddenEntryPoints_(forbiddenEntryPoints) {}

VendorSignerBackend::~VendorSignerBackend() {
    static_cast<void>(close());
}

BackendKind VendorSignerBackend::kind() const noexcept {
    return BackendKind::Vendor;
}

const char* VendorSignerBackend::name() const noexcept {
    return "VendorSignerBackend";
}

const std::string& VendorSignerBackend::officialLibraryPath() const noexcept {
    return officialLibraryPath_;
}

SignerStatus VendorSignerBackend::dynamicErrorLocked(
        SignerError code, const char* operation) const {
    const char* detail = operations_.lastError == nullptr
            ? "dynamic loader error unavailable"
            : operations_.lastError(operations_.context);
    std::string message(operation);
    message += ": ";
    message += detail == nullptr ? "unknown error" : detail;
    return SignerStatus::failure(code, std::move(message));
}

SignerStatus VendorSignerBackend::loadLocked() {
    if (closed_) {
        return SignerStatus::failure(
                SignerError::BackendClosed,
                "official vendor backend is closed");
    }
    if (library_ != nullptr) return SignerStatus::success();
    if (officialLibraryPath_.empty()) {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "official libsigner.so path must be supplied by the caller");
    }
    if (officialLibraryPath_.front() != '/') {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "official libsigner.so path must be absolute");
    }
    if (operations_.open == nullptr || operations_.resolve == nullptr
            || operations_.close == nullptr) {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "dynamic-library operations are incomplete");
    }

    library_ = operations_.open(
            operations_.context, officialLibraryPath_.c_str());
    if (library_ == nullptr) {
        return dynamicErrorLocked(
                SignerError::LibraryOpenFailed,
                "cannot open caller-supplied official libsigner.so");
    }

    void* onResumeSymbol = operations_.resolve(
            operations_.context, library_, kVendorOnResumeSymbol);
    if (onResumeSymbol == nullptr) {
        const SignerStatus status = dynamicErrorLocked(
                SignerError::SymbolMissing,
                "official libsigner.so is missing nOnResume JNI export");
        static_cast<void>(operations_.close(operations_.context, library_));
        library_ = nullptr;
        return status;
    }

    void* signSymbol = operations_.resolve(
            operations_.context, library_, kVendorSignSymbol);
    if (signSymbol == nullptr) {
        const SignerStatus status = dynamicErrorLocked(
                SignerError::SymbolMissing,
                "official libsigner.so is missing nSign JNI export");
        static_cast<void>(operations_.close(operations_.context, library_));
        library_ = nullptr;
        return status;
    }

    const VendorOnResumeEntry resolvedOnResume =
            functionFromSymbol<VendorOnResumeEntry>(onResumeSymbol);
    const VendorSignEntry resolvedSign =
            functionFromSymbol<VendorSignEntry>(signSymbol);
    if ((forbiddenEntryPoints_.onResume != nullptr
                && resolvedOnResume == forbiddenEntryPoints_.onResume)
            || (forbiddenEntryPoints_.sign != nullptr
                && resolvedSign == forbiddenEntryPoints_.sign)) {
        static_cast<void>(operations_.close(operations_.context, library_));
        library_ = nullptr;
        return SignerStatus::failure(
                SignerError::VendorSelfReference,
                "vendor path resolved to compatibility JNI wrappers");
    }

    onResumeEntry_ = resolvedOnResume;
    signEntry_ = resolvedSign;
    return SignerStatus::success();
}

SignerStatus VendorSignerBackend::load() {
    std::lock_guard<std::mutex> lock(mutex_);
    return loadLocked();
}

SignerStatus VendorSignerBackend::onResume(
        const JniCallContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    SignerStatus status = loadLocked();
    if (!status.ok()) return status;
    if (context.environment == nullptr) {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "JNIEnv is required");
    }

    try {
        vendorEntered_ = true;
        onResumeEntry_(context.environment, context.nativeLibHelper);
        if (exceptionPending(context)) {
            return SignerStatus::failure(
                    SignerError::VendorExceptionPending,
                    "official nOnResume left a pending Java exception");
        }
        return SignerStatus::success();
    } catch (const std::exception& error) {
        return SignerStatus::failure(
                SignerError::InternalError,
                std::string("official nOnResume crossed C++ boundary: ")
                        + error.what());
    } catch (...) {
        return SignerStatus::failure(
                SignerError::InternalError,
                "official nOnResume crossed C++ boundary with unknown error");
    }
}

SignerResult VendorSignerBackend::sign(const SignerRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    SignerStatus status = loadLocked();
    if (!status.ok()) {
        SignerResult result;
        result.status = std::move(status);
        return result;
    }
    if (request.jni.environment == nullptr) {
        return failureResult(
                SignerError::InvalidArgument,
                "JNIEnv is required");
    }
    try {
        vendorEntered_ = true;
        JavaByteArrayHandle output = signEntry_(
                request.jni.environment,
                request.jni.nativeLibHelper,
                request.androidContext,
                request.parameterObject,
                request.inputByteArray,
                request.androidApi);
        if (exceptionPending(request.jni)) {
            return failureResult(
                    SignerError::VendorExceptionPending,
                    "official nSign left a pending Java exception");
        }
        SignerResult result;
        result.status = SignerStatus::success();
        result.outputKind = SignerOutputKind::VendorJavaByteArray;
        result.vendorByteArray = output;
        result.productionEligible = output != nullptr;
        return result;
    } catch (const std::exception& error) {
        return failureResult(
                SignerError::InternalError,
                std::string("official nSign crossed C++ boundary: ")
                        + error.what());
    } catch (...) {
        return failureResult(
                SignerError::InternalError,
                "official nSign crossed C++ boundary with unknown error");
    }
}

SignerStatus VendorSignerBackend::close() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_) return SignerStatus::success();

    SignerStatus status = SignerStatus::success();
    // Once either vendor JNI entry has been invoked, unloading the official
    // DSO could leave process-lifetime callbacks or timers dangling. The
    // handle is therefore intentionally retained until process exit.
    if (library_ != nullptr && !vendorEntered_ && operations_.close != nullptr
            && operations_.close(operations_.context, library_) != 0) {
        status = SignerStatus::failure(
                SignerError::InternalError,
                "closing official libsigner.so failed");
    }
    library_ = nullptr;
    onResumeEntry_ = nullptr;
    signEntry_ = nullptr;
    closed_ = true;
    return status;
}

SignerCompatibilityLayer::SignerCompatibilityLayer(
        std::unique_ptr<ISignerBackend> backend,
        SignerLifecyclePolicy policy)
    : backend_(std::move(backend)),
      policy_(policy) {}

SignerCompatibilityLayer::~SignerCompatibilityLayer() {
    static_cast<void>(close());
}

SignerStatus SignerCompatibilityLayer::validateJniContextLocked(
        const JniCallContext& context) const {
    if (context.environment == nullptr) {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "JNIEnv is required");
    }
    return SignerStatus::success();
}

SignerStatus SignerCompatibilityLayer::onResume(
        const JniCallContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (backend_ == nullptr) {
        return SignerStatus::failure(
                SignerError::BackendNotConfigured,
                "no signer backend is configured");
    }
    if (state_ == SignerLifecycleState::Closed) {
        return SignerStatus::failure(
                SignerError::BackendClosed,
                "signer compatibility layer is closed");
    }
    SignerStatus status = validateJniContextLocked(context);
    if (!status.ok()) return status;

    try {
        status = backend_->onResume(context);
        if (status.ok()) state_ = SignerLifecycleState::Resumed;
        return status;
    } catch (const std::bad_alloc&) {
        return SignerStatus::failure(
                SignerError::InternalError,
                "allocation failed during onResume delegation");
    } catch (const std::exception& error) {
        return SignerStatus::failure(
                SignerError::InternalError,
                std::string("backend onResume failed: ") + error.what());
    } catch (...) {
        return SignerStatus::failure(
                SignerError::InternalError,
                "backend onResume failed with unknown error");
    }
}

SignerResult SignerCompatibilityLayer::sign(
        const SignerRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (backend_ == nullptr) {
        return failureResult(
                SignerError::BackendNotConfigured,
                "no signer backend is configured");
    }
    if (state_ == SignerLifecycleState::Closed) {
        return failureResult(
                SignerError::BackendClosed,
                "signer compatibility layer is closed");
    }
    if (state_ != SignerLifecycleState::Resumed
            && policy_
                == SignerLifecyclePolicy::RequireOnResumeBeforeSign) {
        return failureResult(
                SignerError::InvalidState,
                "onResume must succeed before sign");
    }
    SignerStatus status = validateJniContextLocked(request.jni);
    if (!status.ok()) {
        SignerResult result;
        result.status = std::move(status);
        return result;
    }
    try {
        SignerResult result = backend_->sign(request);
        if (result.status.ok()) state_ = SignerLifecycleState::Resumed;
        return result;
    } catch (const std::bad_alloc&) {
        return failureResult(
                SignerError::InternalError,
                "allocation failed during sign delegation");
    } catch (const std::exception& error) {
        return failureResult(
                SignerError::InternalError,
                std::string("backend sign failed: ") + error.what());
    } catch (...) {
        return failureResult(
                SignerError::InternalError,
                "backend sign failed with unknown error");
    }
}

SignerStatus SignerCompatibilityLayer::close() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == SignerLifecycleState::Closed) {
        return SignerStatus::success();
    }
    SignerStatus status = backend_ == nullptr
            ? SignerStatus::success() : backend_->close();
    state_ = SignerLifecycleState::Closed;
    return status;
}

BackendKind SignerCompatibilityLayer::backendKind() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return backend_ == nullptr ? BackendKind::None : backend_->kind();
}

SignerLifecycleState SignerCompatibilityLayer::state() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

}  // namespace libsigner_compat
