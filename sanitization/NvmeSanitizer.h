#pragma once
#include "SanitizationEngine.h"

namespace core::sanitization {
    class NvmeSanitizer : public ISanitizer {
    public:
        bool wipe(const core::drive::DriveInfo& drive) override;
        std::string getProtocolName() const override { return "NVMe Format NVM / Sanitize"; }
    };
}