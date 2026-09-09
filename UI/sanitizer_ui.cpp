#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "sanitization/SanitizationEngine.h"
#include "device/DriveInfo.h"
// Ensure this header exists in your C++ core for DriveManager
#include "device/DriveManager.h" 

#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace py = pybind11;

// Existing helper method
static core::drive::DriveInfo makeDriveInfo(const std::string& path)
{
    core::drive::DriveInfo drive;
    drive.devicePath = path;

    struct stat st{};

    if (stat(path.c_str(), &st) != 0)
        throw std::runtime_error("Cannot stat target: " + path);

    drive.physicalSectorSize = 512;
    drive.logicalSectorSize = 512;

    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        throw std::runtime_error("Cannot open target: " + path);

    if (S_ISBLK(st.st_mode))
    {
        unsigned long long bytes = 0;

        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
        {
            close(fd);
            throw std::runtime_error(
                "Cannot determine block-device capacity: " + path
            );
        }

        drive.capacityBytes = static_cast<uint64_t>(bytes);

        unsigned int sector = 512;

        if (ioctl(fd, BLKSSZGET, &sector) == 0 && sector > 0)
        {
            drive.logicalSectorSize = sector;
            drive.physicalSectorSize = sector;
        }
    }
    else if (S_ISREG(st.st_mode))
    {
        // Allows safe file/loopback testing.
        drive.capacityBytes = static_cast<uint64_t>(st.st_size);
    }
    else
    {
        close(fd);
        throw std::runtime_error(
            "Target is not a regular file or block device: " + path
        );
    }

    close(fd);

    /*
     * NVMe can be identified reliably from its Linux device path.
     * /dev/sd* is intentionally left UNKNOWN for now because
     * /dev/sd* can represent SATA, SCSI or USB devices.
     */
    if (path.rfind("/dev/nvme", 0) == 0)
    {
        drive.bus = core::drive::BusType::NVME;
        drive.mediaType = core::drive::MediaType::SSD;
    }
    else
    {
        drive.bus = core::drive::BusType::UNKNOWN;
    }

    return drive;
}

// --- NEW C++ BACKEND API FUNCTIONS ---

py::list get_drives()
{
    core::drive::DriveManager manager;
    auto drives = manager.getAvailableDrives();

    py::list result;

    for (const auto& drive : drives) {
        py::dict d;

        d["device"] = drive.devicePath;
        d["model"] = drive.model;
        d["serial"] = drive.serialNumber;
        d["capacity"] = drive.capacityBytes;
        d["logical_sector_size"] = drive.logicalSectorSize;
        d["physical_sector_size"] = drive.physicalSectorSize;
        d["rotational"] = drive.isRotational;
        d["bus"] = drive.getBusTypeString();
        d["media_type"] = drive.getMediaTypeString();

        result.append(d);
    }

    return result;
}

// Stub: To be connected to actual C++ backend info logic later
py::dict get_drive_info(const std::string& device)
{
    py::dict d;
    d["device"] = device;
    d["status"] = "Pending Implementation";
    return d;
}

// Stub: To be connected to SanitizationEngine logic later
py::dict get_sanitization_info(const std::string& device)
{
    py::dict d;
    d["device"] = device;
    d["recommended_protocol"] = "Pending Implementation";
    return d;
}

// Stub: To be connected to FileCarver::scan() later
py::list scan_image(const std::string& image_path)
{
    py::list result;
    // Returns an empty list for now until FileCarver is wired up
    return result;
}

// Existing class
class DataSanitizer
{
public:
    bool sanitizeSector(const std::string& targetPath, int /*passes*/ = 3)
    {
        auto drive = makeDriveInfo(targetPath);
        core::sanitization::SanitizationEngine engine;
        return engine.executeSanitization(drive);
    }

    bool zeroFill(const std::string& targetPath)
    {
        auto drive = makeDriveInfo(targetPath);
        core::sanitization::SanitizationEngine engine;
        return engine.executeSanitization(drive);
    }
};

PYBIND11_MODULE(cpp_sanitizer, m)
{
    m.doc() = "Python bindings for the SIH C++ sanitization engine";

    // Expose the new module-level API endpoints
    m.def("get_drives", &get_drives, "Get a list of all available drives");
    m.def("get_drive_info", &get_drive_info, "Get detailed info for a specific drive");
    m.def("get_sanitization_info", &get_sanitization_info, "Get recommended sanitization protocol");
    m.def("scan_image", &scan_image, "Scan an acquired forensic image for file signatures");

    py::class_<DataSanitizer>(m, "DataSanitizer")
        .def(py::init<>())
        .def(
            "sanitizeSector",
            &DataSanitizer::sanitizeSector,
            py::arg("targetPath"),
            py::arg("passes") = 3
        )
        .def(
            "zeroFill",
            &DataSanitizer::zeroFill,
            py::arg("targetPath")
        );
}