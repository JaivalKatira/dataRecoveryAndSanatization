#include "Verification.h"
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <random>
#include <cstring>

namespace core::sanitization {

    bool Verification::verifyZeroes(const core::drive::DriveInfo& drive) {
        std::cout << "  -> Starting NIST-compliant verification sampling...\n";

        // Open with O_DIRECT to bypass page cache and read directly from the physical platters/NAND
        int fd = open(drive.devicePath.c_str(), O_RDONLY | O_DIRECT);
        if (fd < 0) {
            std::cerr << "  -> Error: Could not open drive " << drive.devicePath << " for verification.\n";
            return false;
        }

        const size_t sampleBlockSize = 1024 * 1024; // 1 MiB per sample
        void* alignedBuffer = nullptr;
        
        // O_DIRECT requires the memory buffer to be aligned to the physical sector size
        if (posix_memalign(&alignedBuffer, drive.physicalSectorSize, sampleBlockSize) != 0) {
            close(fd);
            return false;
        }

        char* readBuf = static_cast<char*>(alignedBuffer);

        std::random_device rd;
        std::mt19937_64 gen(rd());

        // Configure sampling: Take 1000 1MiB samples evenly distributed across the entire drive
        const uint64_t numSamples = 1000; 
        
        if (drive.capacityBytes < sampleBlockSize * 2) {
            std::cerr << "  -> Drive too small for sampling logic.\n";
            free(alignedBuffer);
            close(fd);
            return false;
        }

        const uint64_t regionSize = drive.capacityBytes / numSamples;
        bool verificationPassed = true;

        for (uint64_t i = 0; i < numSamples; ++i) {
            uint64_t regionStart = i * regionSize;
            uint64_t maxOffset = regionStart + regionSize - sampleBlockSize;
            
            // Clamp to drive boundary to prevent reading out-of-bounds
            if (maxOffset > drive.capacityBytes - sampleBlockSize) {
                maxOffset = drive.capacityBytes - sampleBlockSize;
            }

            // Distribute randomly within the current region
            std::uniform_int_distribution<uint64_t> dist(regionStart, maxOffset);
            uint64_t randomOffset = dist(gen);

            // Align the random offset to the physical sector size boundary
            randomOffset = (randomOffset / drive.physicalSectorSize) * drive.physicalSectorSize;

            if (lseek(fd, randomOffset, SEEK_SET) == (off_t)-1) {
                std::cerr << "  -> Error: Seek failed at offset " << randomOffset << "\n";
                verificationPassed = false;
                break;
            }

            ssize_t bytesRead = read(fd, readBuf, sampleBlockSize);
            if (bytesRead <= 0) {
                std::cerr << "  -> Error: Read failed at offset " << randomOffset << "\n";
                verificationPassed = false;
                break;
            }

            // Verify the buffer contains exclusively zeros
            for (ssize_t j = 0; j < bytesRead; ++j) {
                if (readBuf[j] != 0x00) {
                    std::cerr << "  -> Verification FAILED: Non-zero data (0x" 
                              << std::hex << (int)(unsigned char)readBuf[j] << std::dec 
                              << ") found at absolute offset " << (randomOffset + j) << "\n";
                    verificationPassed = false;
                    break;
                }
            }

            if (!verificationPassed) break;
        }

        free(alignedBuffer);
        close(fd);

        if (verificationPassed) {
            std::cout << "  -> Verification passed. " << numSamples << " MB sampled across full drive with no residual data.\n";
        }

        return verificationPassed;
    }

} // namespace core::sanitization