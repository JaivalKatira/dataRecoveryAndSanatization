#pragma once
#include "SanitizationEngine.h"

namespace core::sanitization {
    class HddSanitizer : public ISanitizer {
    public:
        bool wipe(const core::drive::DriveInfo& drive) override;
        std::string getProtocolName() const override { return "Block Device Overwrite (O_DIRECT)"; }
    };
}
