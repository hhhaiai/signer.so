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
    check(libsigner_compat_install_fake_for_testing_only()
                    == static_cast<std::int32_t>(SignerError::InvalidState),
            "production build rejects fake installation");
    check(libsigner_compat_backend_kind()
                    == static_cast<std::int32_t>(BackendKind::None),
            "rejected fake leaves no backend");
    check(std::string(libsigner_compat_last_error()).find(
                    "not linked into this production build")
                    != std::string::npos,
            "production rejection message");

    if (failures != 0) {
        std::cerr << "signer production bridge configuration tests: FAIL "
                  << "count=" << failures << '\n';
        return 1;
    }
    std::cout << "signer production bridge configuration tests: PASS\n";
    return 0;
}
