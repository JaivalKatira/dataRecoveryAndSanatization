#include "NvmeSanitizer.h"
#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <cerrno>
#include <cstring>
#include <thread>
#include <chrono>

namespace core::sanitization {

    struct NvmeCapabilities {
        uint32_t sanicap;
        uint16_t oacs;
        uint8_t fna;
        bool sanitizeSupported;
        bool cryptoEraseSupported;
        bool blockEraseSupported;
        bool overwriteSupported;
        bool formatSupported;
        bool formatCryptoSupported;
    };

    struct SanitizeMethod {
        enum Type { NONE, SANITIZE_CRYPTO, SANITIZE_BLOCK, FORMAT_CRYPTO } type = NONE;
        uint32_t cdw10 = 0;
        std::string name;
    };

    // Step 1: Capability Detection
    bool getControllerInfo(int fd, NvmeCapabilities& caps) {
        uint8_t id_ctrl[4096] = {0};
        struct nvme_admin_cmd cmd = {};
        cmd.opcode = 0x06; // Identify Command
        cmd.nsid = 0;
        cmd.addr = reinterpret_cast<__u64>(id_ctrl);
        cmd.data_len = 4096;
        cmd.cdw10 = 1; // CNS = 1 (Identify Controller)

        if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
            return false;
        }

        // Parse OACS (Optional Admin Command Support) for Format NVM support
        std::memcpy(&caps.oacs, &id_ctrl[256], 2);
        // Parse SANICAP (Sanitize Capabilities)
        std::memcpy(&caps.sanicap, &id_ctrl[328], 4);
        // Parse FNA (Format NVM Attributes)
        caps.fna = id_ctrl[527];

        caps.cryptoEraseSupported = (caps.sanicap & (1 << 0)) != 0;
        caps.blockEraseSupported  = (caps.sanicap & (1 << 1)) != 0;
        caps.overwriteSupported   = (caps.sanicap & (1 << 2)) != 0;
        caps.sanitizeSupported    = (caps.sanicap != 0);

        caps.formatSupported       = (caps.oacs & (1 << 1)) != 0;
        caps.formatCryptoSupported = (caps.fna & (1 << 1)) != 0; 

        return true;
    }

    // Step 2: Method Selection
    SanitizeMethod determineSanitizeMethod(const NvmeCapabilities& caps) {
        SanitizeMethod method;
        
        if (caps.cryptoEraseSupported) {
            method.type = SanitizeMethod::SANITIZE_CRYPTO;
            method.cdw10 = 0x04;
            method.name = "NVMe Sanitize (Crypto Erase)";
        } else if (caps.blockEraseSupported) {
            method.type = SanitizeMethod::SANITIZE_BLOCK;
            method.cdw10 = 0x02;
            method.name = "NVMe Sanitize (Block Erase)";
        } else if (caps.formatSupported && caps.formatCryptoSupported) {
            method.type = SanitizeMethod::FORMAT_CRYPTO;
            method.cdw10 = (0x02 << 9); 
            method.name = "NVMe Format NVM (Crypto Erase)";
        }
        
        return method;
    }

    // Step 4: Completion/status checking
    bool pollSanitizeCompletion(int fd) {
        std::cout << "  -> Polling sanitize status log page 0x81...\n";
        uint8_t log_buf[512] = {0};
        
        while (true) {
            struct nvme_admin_cmd cmd = {};
            cmd.opcode = 0x02; // Get Log Page
            cmd.nsid = 0xFFFFFFFF; 
            cmd.addr = reinterpret_cast<__u64>(log_buf);
            cmd.data_len = 512;
            cmd.cdw10 = 0x81 | (0x7F << 16); // Log Identifier (0x81) + Num Dwords (127)

            if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
                std::cerr << "  -> Failed to read Sanitize Log Page.\n";
                return false;
            }

            uint16_t sprog = log_buf[0] | (log_buf[1] << 8); 
            uint16_t sstat = log_buf[2] | (log_buf[3] << 8); 
            uint8_t status = sstat & 0x07; 

            switch (status) {
                case 0x01: // Most recent sanitize completed successfully
                    std::cout << "\n  -> Sanitize completed successfully.\n";
                    return true;
                
                case 0x02: // Sanitize in progress
                {
                    unsigned int pct = static_cast<unsigned int>((sprog * 100ULL) / 65535ULL);
                    std::cout << "  -> Sanitize in progress: " << pct << "%\r" << std::flush;
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    break; // Continue polling
                }
                
                case 0x03: // Most recent sanitize failed
                    std::cerr << "\n  -> Sanitize failed on device.\n";
                    return false;
                
                case 0x04: // Completed successfully with deallocation
                    std::cout << "\n  -> Sanitize completed successfully (with deallocation).\n";
                    return true;
                
                default:
                    std::cerr << "\n  -> Unknown sanitize status (" << (int)status << "). Manual verification recommended.\n";
                    return false;
            }
        }
    }

    bool NvmeSanitizer::wipe(const core::drive::DriveInfo& drive) {
        // Note: O_RDWR | O_EXCL is a preliminary safeguard. 
        // A robust DriveManager must verify mounts, root partitions, and user auth before this is called.
        int fd = open(drive.devicePath.c_str(), O_RDWR | O_EXCL);
        if(fd<0){
        std::cerr<<"  -> Failed to open device: "<<drive.devicePath
                <<" ("<<errno<<": "<<std::strerror(errno)<<")\n";

        if(errno==EBUSY){
        std::cerr<<"  -> Device is busy. A namespace or filesystem may be in use.\n";
        }

        return false;
        }

        // --- STEP 1: CAPABILITY DETECTION ---
        NvmeCapabilities caps = {};
        if (!getControllerInfo(fd, caps)) {
            std::cerr << "  -> Failed to Identify NVMe Controller. Aborting.\n";
            close(fd);
            return false;
        }

        // --- STEP 2: METHOD SELECTION ---
        SanitizeMethod method = determineSanitizeMethod(caps);
        if (method.type == SanitizeMethod::NONE) {
            std::cerr << "  -> No acceptable cryptographic or block sanitization method found for this drive.\n";
            close(fd);
            return false;
        }
        
        std::cout << "  -> Capability detected.\n";
        std::cout << "     - Sanitize Supported: " << (caps.sanitizeSupported ? "Yes" : "No") << "\n";
        std::cout << "     - Block Erase Supported: " << (caps.blockEraseSupported ? "Yes" : "No") << "\n";
        std::cout << "     - Format NVM Supported: " << (caps.formatSupported ? "Yes" : "No") << "\n";
        std::cout << "  -> Selected Method: " << method.name << "\n";

        // --- STEP 3: CORRECT COMMAND CONSTRUCTION ---
        struct nvme_admin_cmd cmd = {};
        bool isSanitize = (method.type == SanitizeMethod::SANITIZE_CRYPTO || method.type == SanitizeMethod::SANITIZE_BLOCK);
        
        if (isSanitize) {
            cmd.opcode = 0x84; // NVMe Sanitize
            cmd.cdw10 = method.cdw10;
        } else {
            cmd.opcode = 0x80; // NVMe Format NVM
            cmd.cdw10 = method.cdw10; 
            cmd.nsid = 0xFFFFFFFF; // Apply to all namespaces
        }

        // --- STEP 5: ONLY THEN ACTUAL SANITIZATION ---
        // (Execution disabled as requested. Ready for Dry Run verification)
        std::cout << "  -> [DRY RUN] Command constructed. Opcode: 0x" << std::hex << (int)cmd.opcode << std::dec << "\n";
        
        /*
        std::cout << "  -> Dispatching wipe command to drive...\n";
        if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) != 0) {
            std::cerr << "  -> Command submission failed via ioctl.\n";
            close(fd);
            return false;
        }

        // --- STEP 4: COMPLETION / STATUS CHECKING ---
        bool success = true;
        if (isSanitize) {
            success = pollSanitizeCompletion(fd); 
        } else {
            std::cout << "  -> Format NVM completed successfully.\n";
        }
        
        close(fd);
        return success;
        */

        close(fd);
        return true; 
    }

} // namespace core::sanitization