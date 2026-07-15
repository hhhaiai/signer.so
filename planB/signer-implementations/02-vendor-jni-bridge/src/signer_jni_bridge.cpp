#include "signer_jni_bridge.h"

#include "signer_backend.h"

#if defined(LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND)
#include "fake_signer_backend.h"
#endif

#include <jni.h>

#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

extern "C" JNIEXPORT void JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume(
        JNIEnv* environment, jobject receiver);

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nSign(
        JNIEnv* environment,
        jobject receiver,
        jobject androidContext,
        jobject parameterObject,
        jbyteArray inputByteArray,
        jint androidApi);

namespace libsigner_compat {
namespace {

std::mutex gLayerMutex;
std::mutex gConfigurationMutex;
std::shared_ptr<SignerCompatibilityLayer> gLayer;
thread_local std::string gLastError;

ForbiddenVendorEntryPoints compatibilityEntryPoints() {
    ForbiddenVendorEntryPoints result;
    const auto onResume =
            &Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume;
    const auto sign = &Java_com_adjust_sdk_sig_NativeLibHelper_nSign;
    static_assert(sizeof(result.onResume) == sizeof(onResume));
    static_assert(sizeof(result.sign) == sizeof(sign));
    std::memcpy(&result.onResume, &onResume, sizeof(result.onResume));
    std::memcpy(&result.sign, &sign, sizeof(result.sign));
    return result;
}

std::int32_t setLastError(const SignerStatus& status) {
    gLastError = status.message;
    return static_cast<std::int32_t>(status.code);
}

std::int32_t setSuccess() {
    gLastError.clear();
    return static_cast<std::int32_t>(SignerError::Ok);
}

std::shared_ptr<SignerCompatibilityLayer> currentLayer() {
    std::lock_guard<std::mutex> lock(gLayerMutex);
    return gLayer;
}

SignerStatus replaceLayer(
        std::shared_ptr<SignerCompatibilityLayer> replacement) {
    std::lock_guard<std::mutex> configurationLock(gConfigurationMutex);
    std::shared_ptr<SignerCompatibilityLayer> previous;
    {
        std::lock_guard<std::mutex> lock(gLayerMutex);
        previous = std::move(gLayer);
    }
    if (previous != nullptr) {
        const SignerStatus status = previous->close();
        if (!status.ok()) return status;
    }
    {
        std::lock_guard<std::mutex> lock(gLayerMutex);
        gLayer = std::move(replacement);
    }
    return SignerStatus::success();
}

bool jniExceptionPending(
        void*, JniEnvironmentHandle environmentHandle) {
    auto* environment = static_cast<JNIEnv*>(environmentHandle);
    return environment != nullptr
            && environment->ExceptionCheck() == JNI_TRUE;
}

JniCallContext callContext(JNIEnv* environment, jobject receiver) {
    JniCallContext context;
    context.environment = environment;
    context.nativeLibHelper = receiver;
    context.exceptions.exceptionPending = jniExceptionPending;
    return context;
}

const char* exceptionClassFor(SignerError error) {
    switch (error) {
        case SignerError::InvalidArgument:
        case SignerError::InvalidParameterFormat:
            return "java/lang/IllegalArgumentException";
        case SignerError::LibraryOpenFailed:
        case SignerError::SymbolMissing:
        case SignerError::VendorSelfReference:
            return "java/lang/UnsatisfiedLinkError";
        case SignerError::InternalError:
            return "java/lang/RuntimeException";
        case SignerError::Ok:
            return nullptr;
        default:
            return "java/lang/IllegalStateException";
    }
}

void throwStatus(JNIEnv* environment, const SignerStatus& status) {
    if (status.ok() || environment == nullptr
            || environment->ExceptionCheck() == JNI_TRUE) {
        return;
    }
    const char* className = exceptionClassFor(status.code);
    if (className == nullptr) return;
    jclass exceptionClass = environment->FindClass(className);
    if (exceptionClass == nullptr) return;
    static_cast<void>(environment->ThrowNew(
            exceptionClass, status.message.c_str()));
    environment->DeleteLocalRef(exceptionClass);
}

#if defined(LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND)
bool isJavaMap(JNIEnv* environment, jobject parameterObject) {
    if (environment == nullptr || parameterObject == nullptr) return false;
    jclass mapClass = environment->FindClass("java/util/Map");
    if (mapClass == nullptr) return false;
    const bool result = environment->IsInstanceOf(
            parameterObject, mapClass) == JNI_TRUE;
    environment->DeleteLocalRef(mapClass);
    return result;
}

jbyteArray materializeTestOnlyBytes(
        JNIEnv* environment, const SignerResult& result) {
    if (result.testOnlyBytes.size()
            > static_cast<std::size_t>(
                    std::numeric_limits<jsize>::max())) {
        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                "test-only output is too large for a Java byte array"));
        return nullptr;
    }
    const jsize length = static_cast<jsize>(result.testOnlyBytes.size());
    jbyteArray output = environment->NewByteArray(length);
    if (output == nullptr) return nullptr;
    if (length != 0) {
        environment->SetByteArrayRegion(
                output, 0, length,
                reinterpret_cast<const jbyte*>(
                        result.testOnlyBytes.data()));
    }
    if (environment->ExceptionCheck() == JNI_TRUE) return nullptr;
    return output;
}
#endif

}  // namespace
}  // namespace libsigner_compat

extern "C" std::int32_t libsigner_compat_install_vendor(
        const char* officialLibraryPath) {
    using namespace libsigner_compat;
    try {
        SignerStatus status = replaceLayer(nullptr);
        if (!status.ok()) return setLastError(status);
        if (officialLibraryPath == nullptr || *officialLibraryPath == '\0') {
            return setLastError(SignerStatus::failure(
                    SignerError::InvalidArgument,
                    "official libsigner.so absolute path is required"));
        }
        auto vendor = std::make_unique<VendorSignerBackend>(
                officialLibraryPath,
                systemDynamicLibraryOperations(),
                compatibilityEntryPoints());
        status = vendor->load();
        if (!status.ok()) return setLastError(status);
        auto layer = std::make_shared<SignerCompatibilityLayer>(
                std::move(vendor));
        status = replaceLayer(std::move(layer));
        return status.ok() ? setSuccess() : setLastError(status);
    } catch (const std::exception& error) {
        return setLastError(SignerStatus::failure(
                SignerError::InternalError,
                std::string("installing vendor backend failed: ")
                        + error.what()));
    } catch (...) {
        return setLastError(SignerStatus::failure(
                SignerError::InternalError,
                "installing vendor backend failed with unknown error"));
    }
}

extern "C" std::int32_t
libsigner_compat_install_fake_for_testing_only() {
    using namespace libsigner_compat;
#if defined(LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND)
    try {
        auto layer = std::make_shared<SignerCompatibilityLayer>(
                std::make_unique<FakeSignerBackend>());
        const SignerStatus status = replaceLayer(std::move(layer));
        return status.ok() ? setSuccess() : setLastError(status);
    } catch (const std::exception& error) {
        return setLastError(SignerStatus::failure(
                SignerError::InternalError,
                std::string("installing fake backend failed: ")
                        + error.what()));
    } catch (...) {
        return setLastError(SignerStatus::failure(
                SignerError::InternalError,
                "installing fake backend failed with unknown error"));
    }
#else
    return setLastError(SignerStatus::failure(
            SignerError::InvalidState,
            "FakeSignerBackend is not linked into this production build"));
#endif
}

extern "C" std::int32_t libsigner_compat_close() {
    using namespace libsigner_compat;
    const SignerStatus status = replaceLayer(nullptr);
    return status.ok() ? setSuccess() : setLastError(status);
}

extern "C" std::int32_t libsigner_compat_backend_kind() {
    using namespace libsigner_compat;
    const auto layer = currentLayer();
    return static_cast<std::int32_t>(layer == nullptr
            ? BackendKind::None : layer->backendKind());
}

extern "C" const char* libsigner_compat_last_error() {
    return libsigner_compat::gLastError.c_str();
}

extern "C" JNIEXPORT void JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume(
        JNIEnv* environment, jobject receiver) {
    using namespace libsigner_compat;
    try {
        const auto layer = currentLayer();
        if (layer == nullptr) {
            throwStatus(environment, SignerStatus::failure(
                    SignerError::BackendNotConfigured,
                    "install VendorSignerBackend before nOnResume"));
            return;
        }
        const SignerStatus status = layer->onResume(
                callContext(environment, receiver));
        throwStatus(environment, status);
    } catch (const std::exception& error) {
        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                std::string("C++ nOnResume bridge failure: ")
                        + error.what()));
    } catch (...) {
        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                "C++ nOnResume bridge failure with unknown error"));
    }
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nSign(
        JNIEnv* environment,
        jobject receiver,
        jobject androidContext,
        jobject parameterObject,
        jbyteArray inputByteArray,
        jint androidApi) {
    using namespace libsigner_compat;
    try {
        const auto layer = currentLayer();
        if (layer == nullptr) {
            throwStatus(environment, SignerStatus::failure(
                    SignerError::BackendNotConfigured,
                    "install VendorSignerBackend before nSign"));
            return nullptr;
        }

        bool parameterObjectIsMap = false;
#if defined(LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND)
        if (layer->backendKind() == BackendKind::FakeForTesting) {
            parameterObjectIsMap = isJavaMap(
                    environment, parameterObject);
            if (environment->ExceptionCheck() == JNI_TRUE) return nullptr;
        }
#endif

        SignerRequest request;
        request.jni = callContext(environment, receiver);
        request.androidContext = androidContext;
        request.parameterObject = parameterObject;
        request.parameterObjectIsJavaMap = parameterObjectIsMap;
        request.inputByteArray = inputByteArray;
        request.androidApi = static_cast<std::int32_t>(androidApi);

        const SignerResult result = layer->sign(request);
        if (!result.status.ok()) {
            throwStatus(environment, result.status);
            return nullptr;
        }
        if (result.outputKind == SignerOutputKind::VendorJavaByteArray) {
            return static_cast<jbyteArray>(result.vendorByteArray);
        }
#if defined(LIBSIGNER_COMPAT_ENABLE_TEST_BACKEND)
        if (result.outputKind == SignerOutputKind::TestOnlyBytes
                && !result.productionEligible) {
            return materializeTestOnlyBytes(environment, result);
        }
#endif

        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                "backend returned an invalid output contract"));
        return nullptr;
    } catch (const std::exception& error) {
        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                std::string("C++ nSign bridge failure: ") + error.what()));
        return nullptr;
    } catch (...) {
        throwStatus(environment, SignerStatus::failure(
                SignerError::InternalError,
                "C++ nSign bridge failure with unknown error"));
        return nullptr;
    }
}
