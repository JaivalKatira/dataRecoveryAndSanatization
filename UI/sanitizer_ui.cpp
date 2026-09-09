#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "sanitization/SanitizationEngine.h"
#include "device/DriveInfo.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstdint>
#include <stdexcept>
#include <string>

namespace py = pybind11;

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
        drive.capacityBytes =
            static_cast<uint64_t>(st.st_size);
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
     *
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


class DataSanitizer
{
public:

    bool sanitizeSector(
        const std::string& targetPath,
        int /*passes*/ = 3)
    {
        auto drive = makeDriveInfo(targetPath);

        core::sanitization::SanitizationEngine engine;

        return engine.executeSanitization(drive);
    }


    bool zeroFill(
        const std::string& targetPath)
    {
        auto drive = makeDriveInfo(targetPath);

        core::sanitization::SanitizationEngine engine;

        return engine.executeSanitization(drive);
    }
};


PYBIND11_MODULE(cpp_sanitizer, m)
{
    m.doc() =
        "Python bindings for the SIH C++ sanitization engine";

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