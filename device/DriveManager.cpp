#include "DriveManager.h"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iostream>

namespace fs = std::filesystem;

namespace core::drive {

    std::string DriveManager::readSysfsValue(const std::string& path) const {
        std::ifstream file(path);
        std::string value;
        if (file.is_open()) {
            std::getline(file, value);
            // Trim trailing whitespace
            value.erase(value.find_last_not_of(" \n\r\t") + 1);
        }
        return value;
    }

    BusType DriveManager::determineBusType(const std::string& devName, const std::string& sysfsPath) const {
        if (devName.find("nvme") != std::string::npos) {
            return BusType::NVME;
        } 
        
        // Check for USB by looking at the device symlink path in sysfs
        std::error_code ec;
        fs::path devPath(sysfsPath);
        fs::path realPath = fs::read_symlink(devPath, ec);
        if (!ec && realPath.string().find("usb") != std::string::npos) {
            return BusType::USB;
        }

        // Default Linux sdX block devices are typically SATA/SCSI
        if (devName.find("sd") != std::string::npos) {
            // For a highly accurate distinction between SATA and SCSI, you would query 
            // the ATA pass-through ioctl or SCSI INQUIRY here. 
            // We will default to SATA for standard sdX targets as a baseline.
            return BusType::SATA; 
        }

        return BusType::UNKNOWN;
    }

    std::vector<DriveInfo> DriveManager::getAvailableDrives() {
        std::vector<DriveInfo> drives;
        const std::string sysBlockPath = "/sys/block";

        if (!fs::exists(sysBlockPath)) {
            std::cerr << "Error: /sys/block does not exist. Are you running on Linux?" << std::endl;
            return drives;
        }

        for (const auto& entry : fs::directory_iterator(sysBlockPath)) {
            std::string devName = entry.path().filename().string();

            // Filter out loopback devices, ramdisks, and optical drives
            if (devName.find("loop") == 0 || 
                devName.find("ram") == 0 || 
                devName.find("sr") == 0) {
                continue;
            }

            DriveInfo info;
            info.devicePath = "/dev/" + devName;
            
            std::string basePath = entry.path().string();

            // Read model and serial number
            info.model = readSysfsValue(basePath + "/device/model");
            info.serialNumber = readSysfsValue(basePath + "/device/serial");

            // Handle NVMe specific paths where model/serial are often at the device root
            if (devName.find("nvme") == 0 && info.model.empty()) {
                info.model = readSysfsValue(basePath + "/device/device/model");
            }

            // Read logical sector size
            std::string logicalSizeStr = readSysfsValue(basePath + "/queue/logical_block_size");
            info.logicalSectorSize = logicalSizeStr.empty() ? 512 : std::stoul(logicalSizeStr);

            // Read physical sector size
            std::string physicalSizeStr = readSysfsValue(basePath + "/queue/physical_block_size");
            info.physicalSectorSize = physicalSizeStr.empty() ? info.logicalSectorSize : std::stoul(physicalSizeStr);

            // Read capacity (sysfs size is reported in 512-byte blocks, regardless of logical sector size)
            std::string sizeBlocksStr = readSysfsValue(basePath + "/size");
            uint64_t sizeBlocks = sizeBlocksStr.empty() ? 0 : std::stoull(sizeBlocksStr);
            info.capacityBytes = sizeBlocks * 512;

            // Check if drive is rotational (HDD) or solid state (SSD/NVMe)
            std::string rotationalStr = readSysfsValue(basePath + "/queue/rotational");
            info.isRotational = (rotationalStr == "1");

            // Determine interface
            info.bus = determineBusType(devName, basePath);

            drives.push_back(info);
        }

        return drives;
    }

} // namespace core::drive