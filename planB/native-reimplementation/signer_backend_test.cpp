#include "signer_backend.h"
#include "fake_signer_backend.h"

#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

using namespace libsigner_compat;

struct TestState {
    int failures = 0;
};

#define CHECK(state, condition)                                                \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::cerr << __FILE__ << ':' << __LINE__                           \
                      << ": CHECK failed: " #condition << '\n';              \
            ++(state).failures;                                                \
        }                                                                      \
    } while (false)

JniCallContext validJniContext() {
    JniCallContext context;
    context.environment = reinterpret_cast<void*>(0x1111);
    context.nativeLibHelper = reinterpret_cast<void*>(0x2222);
    return context;
}

SignerRequest validRequest() {
    SignerRequest request;
    request.jni = validJniContext();
    request.androidContext = reinterpret_cast<void*>(0x3333);
    request.parameterObject = reinterpret_cast<void*>(0x4444);
    request.parameterObjectIsJavaMap = true;
    request.inputByteArray = reinterpret_cast<void*>(0x5555);
    request.androidApi = 36;
    return request;
}

void testFakeBackend(TestState& test) {
    SignerCompatibilityLayer layer(
            std::make_unique<FakeSignerBackend>(),
            SignerLifecyclePolicy::RequireOnResumeBeforeSign);
    CHECK(test, layer.backendKind() == BackendKind::FakeForTesting);
    CHECK(test, layer.state() == SignerLifecycleState::Created);

    SignerResult beforeResume = layer.sign(validRequest());
    CHECK(test, beforeResume.status.code == SignerError::InvalidState);
    CHECK(test, beforeResume.outputKind == SignerOutputKind::None);
    CHECK(test, !beforeResume.productionEligible);

    SignerStatus status = layer.onResume(validJniContext());
    CHECK(test, status.ok());
    CHECK(test, layer.state() == SignerLifecycleState::Resumed);
    CHECK(test, layer.onResume(validJniContext()).ok());

    SignerRequest wrongFormat = validRequest();
    wrongFormat.parameterObjectIsJavaMap = false;
    SignerResult wrongFormatResult = layer.sign(wrongFormat);
    CHECK(test, wrongFormatResult.status.code
            == SignerError::InvalidParameterFormat);

    SignerResult result = layer.sign(validRequest());
    CHECK(test, result.status.ok());
    CHECK(test, result.outputKind == SignerOutputKind::TestOnlyBytes);
    CHECK(test, result.vendorByteArray == nullptr);
    CHECK(test, !result.productionEligible);
    const std::string output(
            result.testOnlyBytes.begin(), result.testOnlyBytes.end());
    CHECK(test, output == FakeSignerBackend::marker());
    CHECK(test, output.rfind("FAKE-ADJUST-", 0) == 0);
    CHECK(test, output.find("NOT-FOR-PRODUCTION") != std::string::npos);
    CHECK(test, result.testOnlyBytes.size() != 176);
    CHECK(test, result.testOnlyBytes.size() != 192);
    CHECK(test, result.testOnlyBytes.size() != 208);

    CHECK(test, layer.close().ok());
    CHECK(test, layer.close().ok());
    CHECK(test, layer.state() == SignerLifecycleState::Closed);
    CHECK(test, layer.sign(validRequest()).status.code
            == SignerError::BackendClosed);
    CHECK(test, layer.onResume(validJniContext()).code
            == SignerError::BackendClosed);
}

struct MockVendorState {
    bool openFails = false;
    bool omitOnResume = false;
    bool omitSign = false;
    bool pendingException = false;
    int openCalls = 0;
    int resolveCalls = 0;
    int closeCalls = 0;
    int onResumeCalls = 0;
    int signCalls = 0;
    std::string openedPath;
    std::vector<std::string> resolvedSymbols;
    std::vector<void*> resolvedLibraries;
    JniEnvironmentHandle environment = nullptr;
    JavaObjectHandle receiver = nullptr;
    JavaObjectHandle androidContext = nullptr;
    JavaObjectHandle parameterObject = nullptr;
    JavaByteArrayHandle inputByteArray = nullptr;
    std::int32_t androidApi = 0;
    JavaByteArrayHandle returnValue = reinterpret_cast<void*>(0x7777);
    std::string lastError = "mock dynamic-loader failure";
};

MockVendorState* gMockVendorState = nullptr;

void mockVendorOnResume(
        JniEnvironmentHandle environment,
        JavaObjectHandle receiver) {
    ++gMockVendorState->onResumeCalls;
    gMockVendorState->environment = environment;
    gMockVendorState->receiver = receiver;
}

JavaByteArrayHandle mockVendorSign(
        JniEnvironmentHandle environment,
        JavaObjectHandle receiver,
        JavaObjectHandle androidContext,
        JavaObjectHandle parameterObject,
        JavaByteArrayHandle inputByteArray,
        std::int32_t androidApi) {
    ++gMockVendorState->signCalls;
    gMockVendorState->environment = environment;
    gMockVendorState->receiver = receiver;
    gMockVendorState->androidContext = androidContext;
    gMockVendorState->parameterObject = parameterObject;
    gMockVendorState->inputByteArray = inputByteArray;
    gMockVendorState->androidApi = androidApi;
    return gMockVendorState->returnValue;
}

template <typename Function>
void* symbolFromFunction(Function function) {
    static_assert(sizeof(function) == sizeof(void*));
    void* symbol = nullptr;
    std::memcpy(&symbol, &function, sizeof(symbol));
    return symbol;
}

void* mockOpen(void* context, const char* path) {
    auto* state = static_cast<MockVendorState*>(context);
    ++state->openCalls;
    state->openedPath = path;
    return state->openFails ? nullptr : reinterpret_cast<void*>(0x6000);
}

void* mockResolve(void* context, void* library, const char* symbol) {
    auto* state = static_cast<MockVendorState*>(context);
    ++state->resolveCalls;
    state->resolvedLibraries.push_back(library);
    state->resolvedSymbols.emplace_back(symbol);
    if (std::strcmp(symbol,
                "Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume") == 0) {
        return state->omitOnResume
                ? nullptr : symbolFromFunction(mockVendorOnResume);
    }
    if (std::strcmp(symbol,
                "Java_com_adjust_sdk_sig_NativeLibHelper_nSign") == 0) {
        return state->omitSign ? nullptr : symbolFromFunction(mockVendorSign);
    }
    return nullptr;
}

int mockClose(void* context, void*) {
    ++static_cast<MockVendorState*>(context)->closeCalls;
    return 0;
}

const char* mockLastError(void* context) {
    return static_cast<MockVendorState*>(context)->lastError.c_str();
}

bool mockExceptionPending(
        void* context, JniEnvironmentHandle) {
    return static_cast<MockVendorState*>(context)->pendingException;
}

DynamicLibraryOperations mockOperations(MockVendorState* state) {
    return {
        state,
        mockOpen,
        mockResolve,
        mockClose,
        mockLastError,
    };
}

void testVendorBackend(TestState& test) {
    MockVendorState state;
    gMockVendorState = &state;
    auto vendor = std::make_unique<VendorSignerBackend>(
            "/authorized/official/libsigner.so", mockOperations(&state));
    CHECK(test, vendor->officialLibraryPath()
            == "/authorized/official/libsigner.so");
    CHECK(test, vendor->load().ok());
    CHECK(test, vendor->load().ok());
    CHECK(test, state.openCalls == 1);
    CHECK(test, state.resolveCalls == 2);
    CHECK(test, state.openedPath == "/authorized/official/libsigner.so");
    CHECK(test, state.resolvedSymbols == std::vector<std::string>({
        "Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume",
        "Java_com_adjust_sdk_sig_NativeLibHelper_nSign",
    }));
    CHECK(test, state.resolvedLibraries == std::vector<void*>({
        reinterpret_cast<void*>(0x6000),
        reinterpret_cast<void*>(0x6000),
    }));

    SignerCompatibilityLayer layer(std::move(vendor));
    JniCallContext context = validJniContext();
    context.exceptions.context = &state;
    context.exceptions.exceptionPending = mockExceptionPending;
    SignerRequest request = validRequest();
    request.jni = context;
    SignerResult result = layer.sign(request);
    CHECK(test, result.status.ok());
    CHECK(test, layer.state() == SignerLifecycleState::Resumed);
    CHECK(test, state.signCalls == 1);

    CHECK(test, layer.onResume(context).ok());
    CHECK(test, state.onResumeCalls == 1);
    CHECK(test, state.environment == context.environment);
    CHECK(test, state.receiver == context.nativeLibHelper);

    result = layer.sign(request);
    CHECK(test, result.status.ok());
    CHECK(test, result.outputKind == SignerOutputKind::VendorJavaByteArray);
    CHECK(test, result.vendorByteArray == state.returnValue);
    CHECK(test, result.testOnlyBytes.empty());
    CHECK(test, result.productionEligible);
    CHECK(test, state.signCalls == 2);
    CHECK(test, state.androidContext == request.androidContext);
    CHECK(test, state.parameterObject == request.parameterObject);
    CHECK(test, state.inputByteArray == request.inputByteArray);
    CHECK(test, state.androidApi == 36);

    state.pendingException = true;
    result = layer.sign(request);
    CHECK(test, result.status.code == SignerError::VendorExceptionPending);
    CHECK(test, !result.productionEligible);
    state.pendingException = false;
    state.returnValue = nullptr;
    result = layer.sign(request);
    CHECK(test, result.status.ok());
    CHECK(test, result.outputKind == SignerOutputKind::VendorJavaByteArray);
    CHECK(test, result.vendorByteArray == nullptr);
    CHECK(test, !result.productionEligible);

    CHECK(test, layer.close().ok());
    CHECK(test, layer.close().ok());
    CHECK(test, state.closeCalls == 0);
    gMockVendorState = nullptr;
}

void testVendorForwardsOpaqueNullsAndIntegerExtremes(TestState& test) {
    MockVendorState state;
    gMockVendorState = &state;
    auto vendor = std::make_unique<VendorSignerBackend>(
            "/authorized/official/libsigner.so", mockOperations(&state));
    SignerCompatibilityLayer layer(std::move(vendor));

    JniCallContext context = validJniContext();
    context.nativeLibHelper = nullptr;
    context.exceptions.context = &state;
    context.exceptions.exceptionPending = mockExceptionPending;
    CHECK(test, layer.onResume(context).ok());
    CHECK(test, state.onResumeCalls == 1);
    CHECK(test, state.receiver == nullptr);

    SignerRequest request;
    request.jni = context;
    request.androidContext = nullptr;
    request.parameterObject = nullptr;
    request.parameterObjectIsJavaMap = false;
    request.inputByteArray = nullptr;
    const std::int32_t apiValues[] = {
        0,
        -1,
        std::numeric_limits<std::int32_t>::min(),
        std::numeric_limits<std::int32_t>::max(),
    };
    for (const std::int32_t api : apiValues) {
        request.androidApi = api;
        const SignerResult result = layer.sign(request);
        CHECK(test, result.status.ok());
        CHECK(test, result.vendorByteArray == state.returnValue);
        CHECK(test, state.receiver == nullptr);
        CHECK(test, state.androidContext == nullptr);
        CHECK(test, state.parameterObject == nullptr);
        CHECK(test, state.inputByteArray == nullptr);
        CHECK(test, state.androidApi == api);
    }
    CHECK(test, state.signCalls == 4);
    CHECK(test, layer.close().ok());
    CHECK(test, state.closeCalls == 0);
    gMockVendorState = nullptr;
}

void testVendorEntryRetainsDsoWhenJavaExceptionIsPending(TestState& test) {
    MockVendorState state;
    state.pendingException = true;
    gMockVendorState = &state;
    auto vendor = std::make_unique<VendorSignerBackend>(
            "/authorized/official/libsigner.so", mockOperations(&state));
    SignerCompatibilityLayer layer(std::move(vendor));

    JniCallContext context = validJniContext();
    context.exceptions.context = &state;
    context.exceptions.exceptionPending = mockExceptionPending;
    const SignerStatus status = layer.onResume(context);
    CHECK(test, status.code == SignerError::VendorExceptionPending);
    CHECK(test, state.onResumeCalls == 1);
    CHECK(test, layer.close().ok());
    CHECK(test, state.closeCalls == 0);
    gMockVendorState = nullptr;
}

void testVendorLoadFailures(TestState& test) {
    {
        MockVendorState state;
        state.openFails = true;
        VendorSignerBackend vendor(
                "/missing/libsigner.so", mockOperations(&state));
        const SignerStatus status = vendor.load();
        CHECK(test, status.code == SignerError::LibraryOpenFailed);
        CHECK(test, status.message.find("mock dynamic-loader failure")
                != std::string::npos);
        CHECK(test, state.closeCalls == 0);
    }
    {
        MockVendorState state;
        state.omitSign = true;
        VendorSignerBackend vendor(
                "/wrong/libsigner.so", mockOperations(&state));
        const SignerStatus status = vendor.load();
        CHECK(test, status.code == SignerError::SymbolMissing);
        CHECK(test, state.resolveCalls == 2);
        CHECK(test, state.closeCalls == 1);
    }
    {
        MockVendorState state;
        VendorSignerBackend vendor("", mockOperations(&state));
        CHECK(test, vendor.load().code == SignerError::InvalidArgument);
        CHECK(test, state.openCalls == 0);
    }
    {
        MockVendorState state;
        VendorSignerBackend vendor(
                "relative/libsigner.so", mockOperations(&state));
        CHECK(test, vendor.load().code == SignerError::InvalidArgument);
        CHECK(test, state.openCalls == 0);
    }
    {
        MockVendorState state;
        VendorSignerBackend vendor(
                "/authorized/official/libsigner.so",
                mockOperations(&state));
        CHECK(test, vendor.load().ok());
        CHECK(test, vendor.close().ok());
        CHECK(test, state.closeCalls == 1);
    }
    {
        MockVendorState state;
        const ForbiddenVendorEntryPoints forbidden = {
            mockVendorOnResume,
            mockVendorSign,
        };
        VendorSignerBackend vendor(
                "/self/libsigner_compat.so",
                mockOperations(&state), forbidden);
        CHECK(test, vendor.load().code == SignerError::VendorSelfReference);
        CHECK(test, state.closeCalls == 1);
    }
}

}  // namespace

int main() {
    TestState test;
    testFakeBackend(test);
    testVendorBackend(test);
    testVendorForwardsOpaqueNullsAndIntegerExtremes(test);
    testVendorEntryRetainsDsoWhenJavaExceptionIsPending(test);
    testVendorLoadFailures(test);
    if (test.failures != 0) {
        std::cerr << "signer compatibility tests: FAIL count="
                  << test.failures << '\n';
        return 1;
    }
    std::cout << "signer compatibility tests: PASS\n";
    std::cout << "fake marker: " << FakeSignerBackend::marker() << '\n';
    std::cout << "vendor JNI delegation: exact handles/symbols PASS\n";
    return 0;
}
