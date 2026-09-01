#pragma once
#include "../device/DriveInfo.h"

namespace core::sanitization {

    class Verification {
    public:
        Verification() = default;
        ~Verification() = default;

        // Performs a NIST-compliant pseudorandom sample verification
        bool verifyZeroes(const core::drive::DriveInfo& drive);
    };

} // namespace core::sanitization