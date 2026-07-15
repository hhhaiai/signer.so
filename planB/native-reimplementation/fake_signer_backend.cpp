#include "fake_signer_backend.h"

namespace libsigner_compat {
namespace {

constexpr char kFakeMarker[] =
        "FAKE-ADJUST-SIGNATURE-NOT-FOR-PRODUCTION-v1";
static_assert(sizeof(kFakeMarker) - 1 < 64,
        "fake output must remain visibly outside production envelopes");

SignerResult failureResult(SignerError code, const char* message) {
    SignerResult result;
    result.status = SignerStatus::failure(code, message);
    return result;
}

}  // namespace

BackendKind FakeSignerBackend::kind() const noexcept {
    return BackendKind::FakeForTesting;
}

const char* FakeSignerBackend::name() const noexcept {
    return "FakeSignerBackend(TEST_ONLY)";
}

const char* FakeSignerBackend::marker() noexcept {
    return kFakeMarker;
}

SignerStatus FakeSignerBackend::onResume(const JniCallContext& context) {
    if (closed_) {
        return SignerStatus::failure(
                SignerError::BackendClosed,
                "test-only fake backend is closed");
    }
    if (context.environment == nullptr || context.nativeLibHelper == nullptr) {
        return SignerStatus::failure(
                SignerError::InvalidArgument,
                "JNIEnv and NativeLibHelper receiver are required");
    }
    return SignerStatus::success();
}

SignerResult FakeSignerBackend::sign(const SignerRequest& request) {
    if (closed_) {
        return failureResult(
                SignerError::BackendClosed,
                "test-only fake backend is closed");
    }
    if (request.parameterObject == nullptr
            || !request.parameterObjectIsJavaMap) {
        return failureResult(
                SignerError::InvalidParameterFormat,
                "nSign Object argument must be a java.util.Map");
    }

    SignerResult result;
    result.status = SignerStatus::success();
    result.outputKind = SignerOutputKind::TestOnlyBytes;
    result.testOnlyBytes.assign(
            kFakeMarker, kFakeMarker + sizeof(kFakeMarker) - 1);
    result.productionEligible = false;
    return result;
}

SignerStatus FakeSignerBackend::close() noexcept {
    closed_ = true;
    return SignerStatus::success();
}

}  // namespace libsigner_compat
