#include "signer_jni_bridge.h"

#include <cstdio>

// Call this from an owned native initialization point after both libraries are
// available and before Java calls NativeLibHelper.nOnResume/nSign.
bool installOfficialSigner(const char* absoluteOfficialSoPath) {
    const std::int32_t status =
            libsigner_compat_install_vendor(absoluteOfficialSoPath);
    if (status != 0) {
        std::fprintf(stderr, "install vendor failed (%d): %s\n",
                static_cast<int>(status), libsigner_compat_last_error());
        return false;
    }
    return true;
}

void closeSignerCompatibilityLayer() {
    const std::int32_t status = libsigner_compat_close();
    if (status != 0) {
        std::fprintf(stderr, "close failed (%d): %s\n",
                static_cast<int>(status), libsigner_compat_last_error());
    }
}
