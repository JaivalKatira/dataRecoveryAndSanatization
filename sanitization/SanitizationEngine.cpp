#include "SanitizationEngine.h"
#include <iostream>

// We will define these classes in their respective files next
#include "NvmeSanitizer.h"
#include "SataSanitizer.h"
#include "HddSanitizer.h"
#include "Verification.h"

namespace core::sanitization {

    std::unique_ptr<ISanitizer> SanitizationEngine::getSanitizerForDrive(const core::drive::DriveInfo& drive) {
        using namespace core::drive;

        switch (drive.bus) {
            case BusType::NVME:
                return std::make_unique<NvmeSanitizer>();
            
            case BusType::SATA:
                return std::make_unique<SataSanitizer>();
            
            case BusType::SCSI:
            case BusType::USB:
            case BusType::UNKNOWN:
            default:
                // Fallback to standard POSIX block overwriting for unknown/USB/SCSI
                // unless specific SCSI Format Unit commands are implemented later.
                return std::make_unique<HddSanitizer>(); 
        }
    }

    bool SanitizationEngine::executeSanitization(const core::drive::DriveInfo& drive) {
        auto sanitizer = getSanitizerForDrive(drive);
        
        std::cout << "Initiating sanitization on " << drive.devicePath 
                  << " using protocol: " << sanitizer->getProtocolName() << "\n";

        // 1. Execute the Wipe
        if (!sanitizer->wipe(drive)) {
            std::cerr << "Wipe failed on " << drive.devicePath << "\n";
            return false;
        }

        // 2. Execute Verification
        Verification verifier;
        if (!verifier.verifyZeroes(drive)) {
            std::cerr << "Verification failed on " << drive.devicePath << "\n";
            return false;
        }

        std::cout << "Sanitization and verification successful for " << drive.devicePath << "\n";
        return true;
    }

} // namespace core::sanitization