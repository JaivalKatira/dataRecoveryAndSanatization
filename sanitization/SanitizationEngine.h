#pragma once
#include "../drive/DriveInfo.h"
#include <memory>
#include <string>

namespace core::sanitization {

    // Base interface for all hardware wiping protocols
    class ISanitizer {
    public:
        virtual ~ISanitizer() = default;
        
        // Executes the wipe command on the target drive
        virtual bool wipe(const core::drive::DriveInfo& drive) = 0;
        
        // Returns the name of the protocol being used (e.g., "NVMe Format NVM")
        virtual std::string getProtocolName() const = 0;
    };

    // The router and orchestrator
    class SanitizationEngine {
    public:
        SanitizationEngine() = default;
        ~SanitizationEngine() = default;

        // Factory method to determine the correct wipe protocol based on the bus
        std::unique_ptr<ISanitizer> getSanitizerForDrive(const core::drive::DriveInfo& drive);

        // Executes the wipe and triggers verification
        bool executeSanitization(const core::drive::DriveInfo& drive);
    };

} // namespace core::sanitization