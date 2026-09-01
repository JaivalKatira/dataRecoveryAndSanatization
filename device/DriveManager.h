#pragma once
#include "DriveInfo.h"
#include <vector>
#include <string>

namespace core::drive {

    class DriveManager {
    public:
        DriveManager() = default;
        ~DriveManager() = default;

        // Scans the system and returns a list of physical target drives
        std::vector<DriveInfo> getAvailableDrives();

    private:
        // Helper to read a single line from a sysfs file
        std::string readSysfsValue(const std::string& path) const;
        
        // Helper to determine the bus type based on sysfs data and device name
        BusType determineBusType(const std::string& devName, const std::string& sysfsPath) const;
    };

} // namespace core::drive