#include <iostream>
#include "C:\Users\My Pc\Desktop\Code\SIH proj\device\DriveManager.h"
using namespace core::drive;

int main() {
    DriveManager manager;

    auto drives = manager.getAvailableDrives();
    std::cout << "\n";
    std::cout << "=====================================\n";
    std::cout << "       SIH DEVICE MANAGER TEST\n";
    std::cout << "=====================================\n\n";

    if (drives.empty()) {
        std::cout << "No drives detected.\n";
        return 0;
    }

    for (size_t i = 0; i < drives.size(); ++i) {
        const auto& d = drives[i];

        std::cout << "[" << i << "]\n";
        std::cout << "  Device        : " << d.devicePath << "\n";
        std::cout << "  Model         : "
                  << (d.model.empty() ? "Unknown" : d.model)
                  << "\n";
        std::cout << "  Serial        : "
                  << (d.serialNumber.empty() ? "Unknown" : d.serialNumber)
                  << "\n";
        std::cout << "  Bus           : " << d.getBusTypeString() << "\n";
        std::cout << "  Capacity      : " << d.capacityBytes << " bytes\n";
        std::cout << "  Logical Sector: " << d.logicalSectorSize << " bytes\n";
        std::cout << "  Physical Sector: " << d.physicalSectorSize << " bytes\n";
        std::cout << "  Rotational    : "
                  << (d.isRotational ? "Yes (HDD)" : "No (SSD)")
                  << "\n";

        std::cout << "-------------------------------------\n";
    }

    return 0;
}