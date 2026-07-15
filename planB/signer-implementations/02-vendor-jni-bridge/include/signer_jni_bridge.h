#pragma once

#include <cstdint>

#if defined(_WIN32)
#define LIBSIGNER_COMPAT_EXPORT __declspec(dllexport)
#else
#define LIBSIGNER_COMPAT_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

// The official library path is always caller supplied. The compatibility
// library must have a distinct filename/SONAME (for example
// libsigner_compat.so) so loading the official libsigner.so cannot recurse
// back into this bridge.
LIBSIGNER_COMPAT_EXPORT std::int32_t libsigner_compat_install_vendor(
        const char* officialLibraryPath);

// Test-only. The installed backend returns a short ASCII marker rather than a
// cryptographic signature and sets productionEligible=false internally.
LIBSIGNER_COMPAT_EXPORT std::int32_t
libsigner_compat_install_fake_for_testing_only();

LIBSIGNER_COMPAT_EXPORT std::int32_t libsigner_compat_close();
LIBSIGNER_COMPAT_EXPORT std::int32_t libsigner_compat_backend_kind();
LIBSIGNER_COMPAT_EXPORT const char* libsigner_compat_last_error();

}  // extern "C"
