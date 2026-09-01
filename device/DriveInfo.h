#pragma once
#include <string>
#include <cstdint>

namespace core::drive {

    enum class BusType {
        NVME,
        SATA,
        SCSI,
        USB,
        UNKNOWN
    };

    struct DriveInfo {
        std::string devicePath;      // e.g., "/dev/sda" or "/dev/nvme0n1"
        std::string model;
        std::string serialNumber;
        uint64_t capacityBytes;
        uint32_t logicalSectorSize;
        uint32_t physicalSectorSize;
        bool isRotational;           // true for HDD, false for SSD/NVMe
        BusType bus;

        // Helper to get a human-readable bus type
        std::string getBusTypeString() const {
            switch (bus) {
                case BusType::NVME: return "NVMe";
                case BusType::SATA: return "SATA";
                case BusType::SCSI: return "SCSI";
                case BusType::USB:  return "USB";
                default:            return "Unknown";
            }
        }
    };

} // namespace core::drive