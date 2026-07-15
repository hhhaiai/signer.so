#include "signer_backend.h"
#include "signer_jni_bridge.h"

#include <iostream>
#include <string>

int main() {
    using namespace libsigner_compat;
    int failures = 0;
    const auto check = [&failures](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "CHECK failed: " << message << '\n';
            ++failures;
        }
    };

    check(libsigner_compat_close()
                    == static_cast<std::int32_t>(SignerError::Ok),
            "initial close");
    check(libsigner_compat_backend_kind()
                    == static_cast<std::int32_t>(BackendKind::None),
            "initial backend kind");

    check(libsigner_compat_install_fake_for_testing_only()
                    == static_cast<std::int32_t>(SignerError::Ok),
            "test-only fake installation");
    check(libsigner_compat_backend_kind()
                    == static_cast<std::int32_t>(BackendKind::FakeForTesting),
            "fake backend kind");
    check(std::string(libsigner_compat_last_error()).empty(),
            "fake install last error");
    check(libsigner_compat_install_vendor(nullptr)
                    == static_cast<std::int32_t>(SignerError::InvalidArgument),
            "null vendor path after fake");
    check(libsigner_compat_backend_kind()
                    == static_cast<std::int32_t>(BackendKind::None),
            "failed vendor install does not retain fake backend");
    check(std::string(libsigner_compat_last_error()).find("path")
                    != std::string::npos,
            "null vendor path message");
    check(libsigner_compat_install_vendor("relative/libsigner.so")
                    == static_cast<std::int32_t>(SignerError::InvalidArgument),
            "relative vendor path");
    check(libsigner_compat_backend_kind()
                    == static_cast<std::int32_t>(BackendKind::None),
            "failed vendor install leaves no backend");

    if (failures != 0) {
        std::cerr << "signer bridge configuration tests: FAIL count="
                  << failures << '\n';
        return 1;
    }
    std::cout << "signer bridge configuration tests: PASS\n";
    return 0;
}
