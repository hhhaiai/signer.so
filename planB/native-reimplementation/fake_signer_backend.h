#pragma once

#include "signer_backend.h"

namespace libsigner_compat {

// Test-support implementation. Do not link this translation unit into the
// production compatibility shared library.
class FakeSignerBackend final : public ISignerBackend {
public:
    BackendKind kind() const noexcept override;
    const char* name() const noexcept override;
    SignerStatus onResume(const JniCallContext& context) override;
    SignerResult sign(const SignerRequest& request) override;
    SignerStatus close() noexcept override;

    static const char* marker() noexcept;

private:
    bool closed_ = false;
};

}  // namespace libsigner_compat
