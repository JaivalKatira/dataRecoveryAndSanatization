#pragma once

#include "SanitizationEngine.h"

namespace core::sanitization {

class SataSanitizer : public ISanitizer {
public:
    bool wipe(
        const core::drive::DriveInfo& drive
    ) override;

    std::string getProtocolName() const override {
        return "ATA Sanitize / Secure Erase";
    }
};

}