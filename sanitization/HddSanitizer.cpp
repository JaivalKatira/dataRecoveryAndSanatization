#include "HddSanitizer.h"
#include <fcntl.h>
#include <unistd.h>
#include <vector>
#include <iostream>

namespace core::sanitization {

    bool HddSanitizer::wipe(const core::drive::DriveInfo& drive) {
        std::cout << "  -> Starting single-pass unbuffered overwrite (O_DIRECT)...\n";
        
        // O_DIRECT requires memory buffers to be aligned to the physical sector size
        int fd = open(drive.devicePath.c_str(), O_WRONLY | O_DIRECT | O_EXCL);
        if (fd < 0) return false;

        const size_t bufferSize = 4 * 1024 * 1024; // 4 MiB chunks
        void* alignedBuffer = nullptr;
        if (posix_memalign(&alignedBuffer, drive.physicalSectorSize, bufferSize) != 0) {
            close(fd);
            return false;
        }

        // Zero out the buffer
        std::memset(alignedBuffer, 0, bufferSize);
        char* writeBuf = static_cast<char*>(alignedBuffer);

        uint64_t bytesWritten = 0;
        while (bytesWritten < drive.capacityBytes) {
            size_t toWrite = std::min(static_cast<uint64_t>(bufferSize), drive.capacityBytes - bytesWritten);
            
            // Align final chunk to physical sector size
            if (toWrite % drive.physicalSectorSize != 0) {
                toWrite = ((toWrite / drive.physicalSectorSize) + 1) * drive.physicalSectorSize;
            }

            ssize_t result = write(fd, writeBuf, toWrite);
            if (result <= 0) {
                free(alignedBuffer);
                close(fd);
                return false;
            }
            bytesWritten += result;
        }

        fsync(fd);
        free(alignedBuffer);
        close(fd);
        return true;
    }

} // namespace core::sanitization