#include "SataSanitizer.h"

#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

namespace core::sanitization {

// ============================================================
// ATA CAPABILITIES
// ============================================================

struct AtaCapabilities {
    bool sanitizeSupported = false;

    bool cryptoScrambleSupported = false;
    bool blockEraseSupported = false;
    bool overwriteSupported = false;

    bool securitySupported = false;
    bool securityEnabled = false;
    bool securityFrozen = false;
    bool enhancedSecurityEraseSupported = false;
};

// ============================================================
// SATA SANITIZATION METHOD
// ============================================================

struct SataMethod {
    enum class Type {
        NONE,
        SANITIZE_CRYPTO,
        SANITIZE_BLOCK,
        SANITIZE_OVERWRITE
    };

    Type type = Type::NONE;

    uint8_t featureCode = 0x00;
    std::string name;
};

// ============================================================
// ATA COMMAND RESULT
// ============================================================

struct AtaCommandResult {
    bool success = false;

    uint8_t scsiStatus = 0;
    uint16_t hostStatus = 0;
    uint16_t driverStatus = 0;

    std::array<uint8_t, 32> senseData{};

    uint8_t ataStatus = 0;
    uint8_t ataError = 0;
};

// ============================================================
// LOW-LEVEL ATA PASS-THROUGH
// ============================================================

AtaCommandResult executeAtaPassthrough(
    int fd,
    uint8_t* cdb,
    uint8_t cdbLength,
    uint8_t* data,
    uint32_t dataLength,
    int direction,
    uint32_t timeoutMs
) {
    AtaCommandResult result;

    sg_io_hdr_t io_hdr{};

    io_hdr.interface_id = 'S';

    io_hdr.cmd_len = cdbLength;
    io_hdr.mx_sb_len = result.senseData.size();

    io_hdr.dxfer_direction = direction;
    io_hdr.dxfer_len = dataLength;
    io_hdr.dxferp = data;

    io_hdr.cmdp = cdb;

    io_hdr.sbp = result.senseData.data();

    io_hdr.timeout = timeoutMs;

    if (ioctl(fd, SG_IO, &io_hdr) < 0) {
        std::cerr << "  -> SG_IO ioctl failed.\n";
        return result;
    }

    result.scsiStatus = io_hdr.status;
    result.hostStatus = io_hdr.host_status;
    result.driverStatus = io_hdr.driver_status;

    if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        std::cerr << "  -> ATA command failed.\n";
        std::cerr << "     SCSI status : 0x"
                  << std::hex
                  << static_cast<int>(result.scsiStatus)
                  << "\n";

        std::cerr << "     Host status : 0x"
                  << std::hex
                  << result.hostStatus
                  << "\n";

        std::cerr << "     Driver status : 0x"
                  << std::hex
                  << result.driverStatus
                  << std::dec
                  << "\n";

        return result;
    }

    result.success = true;

    return result;
}

// ============================================================
// ATA IDENTIFY DEVICE
// ============================================================

bool identifyAtaDevice(
    int fd,
    std::array<uint8_t, 512>& data
) {
    uint8_t cdb[16] = {};

    /*
     * ATA PASS-THROUGH(16)
     *
     * Opcode:
     *     0x85
     *
     * Protocol:
     *     PIO Data-In
     *
     * Command:
     *     IDENTIFY DEVICE = 0xEC
     */

    cdb[0] = 0x85;

    // Protocol = 4 (PIO Data-In)
    cdb[1] = (4 << 1);

    /*
     * T_LENGTH = 2
     * BYTE_BLOCK = 1
     * T_DIR = 1
     */
    cdb[2] = 0x0E;

    // ATA command register
    cdb[14] = 0xEC;

    AtaCommandResult result = executeAtaPassthrough(
        fd,
        cdb,
        sizeof(cdb),
        data.data(),
        data.size(),
        SG_DXFER_FROM_DEV,
        20000
    );

    return result.success;
}

// ============================================================
// ATA IDENTIFY CAPABILITY DETECTION
// ============================================================

bool getAtaCapabilities(
    int fd,
    AtaCapabilities& caps
) {
    std::array<uint8_t, 512> data{};

    if (!identifyAtaDevice(fd, data)) {
        return false;
    }

    /*
     * ATA IDENTIFY DEVICE words are 16-bit values.
     *
     * Convert two bytes into a word.
     */
    auto getWord = [&](std::size_t word) -> uint16_t {
        const std::size_t offset = word * 2;

        return static_cast<uint16_t>(
            data[offset] |
            (static_cast<uint16_t>(data[offset + 1]) << 8)
        );
    };

    // --------------------------------------------------------
    // Sanitize capabilities
    // --------------------------------------------------------

    const uint16_t word59 = getWord(59);

    /*
     * The exact interpretation of ATA capability words should
     * remain tied to the ATA standard revision supported by the
     * device.
     *
     * Keep the capability parsing isolated here so it can be
     * updated without touching the passthrough layer.
     */

    if ((word59 & 0xC000) == 0x4000) {

        caps.sanitizeSupported = true;

        caps.cryptoScrambleSupported =
            (word59 & (1 << 1)) != 0;

        caps.blockEraseSupported =
            (word59 & (1 << 2)) != 0;

        caps.overwriteSupported =
            (word59 & (1 << 3)) != 0;
    }

    // --------------------------------------------------------
    // Security capabilities
    // --------------------------------------------------------

    const uint16_t word128 = getWord(128);

    caps.securitySupported =
        (word128 & (1 << 0)) != 0;

    caps.securityEnabled =
        (word128 & (1 << 1)) != 0;

    caps.securityFrozen =
        (word128 & (1 << 3)) != 0;

    caps.enhancedSecurityEraseSupported =
        (word128 & (1 << 5)) != 0;

    return true;
}

// ============================================================
// METHOD SELECTION
// ============================================================

SataMethod determineSataMethod(
    const AtaCapabilities& caps
) {
    SataMethod method;

    if (!caps.sanitizeSupported) {
        return method;
    }

    /*
     * Preferred order:
     *
     * 1. Crypto Scramble
     * 2. Block Erase
     * 3. Overwrite
     */

    if (caps.cryptoScrambleSupported) {

        method.type =
            SataMethod::Type::SANITIZE_CRYPTO;

        method.featureCode = 0x11;

        method.name =
            "ATA Sanitize (Crypto Scramble)";

    } else if (caps.blockEraseSupported) {

        method.type =
            SataMethod::Type::SANITIZE_BLOCK;

        method.featureCode = 0x12;

        method.name =
            "ATA Sanitize (Block Erase)";

    } else if (caps.overwriteSupported) {

        method.type =
            SataMethod::Type::SANITIZE_OVERWRITE;

        method.featureCode = 0x14;

        method.name =
            "ATA Sanitize (Overwrite)";
    }

    return method;
}

// ============================================================
// BUILD ATA SANITIZE COMMAND
// ============================================================

std::array<uint8_t, 16> buildSanitizeCommand(
    const SataMethod& method
) {
    std::array<uint8_t, 16> cdb{};

    /*
     * ATA PASS-THROUGH(16)
     */
    cdb[0] = 0x85;

    /*
     * Non-data ATA protocol.
     */
    cdb[1] = (3 << 1);

    /*
     * No data transfer.
     */
    cdb[2] = 0x20;

    /*
     * Feature register.
     */
    cdb[3] = method.featureCode;

    /*
     * ATA SANITIZE DEVICE.
     */
    cdb[14] = 0xB4;

    return cdb;
}

// ============================================================
// PRINT CAPABILITIES
// ============================================================

void printCapabilities(
    const AtaCapabilities& caps
) {
    std::cout << "\n  -> ATA capabilities:\n";

    std::cout
        << "     Sanitize Supported: "
        << (caps.sanitizeSupported ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Crypto Scramble: "
        << (caps.cryptoScrambleSupported ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Block Erase: "
        << (caps.blockEraseSupported ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Overwrite: "
        << (caps.overwriteSupported ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Security Supported: "
        << (caps.securitySupported ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Security Enabled: "
        << (caps.securityEnabled ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Security Frozen: "
        << (caps.securityFrozen ? "Yes" : "No")
        << "\n";

    std::cout
        << "     Enhanced Security Erase: "
        << (caps.enhancedSecurityEraseSupported ? "Yes" : "No")
        << "\n";
}

// ============================================================
// SATA SANITIZER
// ============================================================

bool SataSanitizer::wipe(
    const core::drive::DriveInfo& drive
) {
    std::cout
        << "\n=== SATA Sanitizer ===\n";

    std::cout
        << "Device: "
        << drive.devicePath
        << "\n";

    /*
     * IMPORTANT:
     *
     * This is currently still a DRY-RUN.
     *
     * Do not enable destructive execution until the ATA
     * command encoding and capability parsing have been
     * validated against a disposable test drive.
     */

    int fd = open(
        drive.devicePath.c_str(),
        O_RDWR | O_EXCL
    );

    if (fd < 0) {

        std::cerr
            << "  -> Failed to open device: "
            << drive.devicePath
            << "\n";

        return false;
    }

    // --------------------------------------------------------
    // Capability detection
    // --------------------------------------------------------

    AtaCapabilities caps{};

    if (!getAtaCapabilities(fd, caps)) {

        std::cerr
            << "  -> IDENTIFY DEVICE failed.\n";

        close(fd);

        return false;
    }

    printCapabilities(caps);

    // --------------------------------------------------------
    // Security state warning
    // --------------------------------------------------------

    if (caps.securityFrozen) {

        std::cout
            << "\n  -> WARNING: ATA Security is frozen.\n";

        std::cout
            << "     This does not automatically mean ATA "
               "Sanitize is unavailable.\n";
    }

    // --------------------------------------------------------
    // Select sanitize method
    // --------------------------------------------------------

    SataMethod method =
        determineSataMethod(caps);

    if (method.type == SataMethod::Type::NONE) {

        std::cerr
            << "\n  -> No supported ATA Sanitize method "
               "was detected.\n";

        close(fd);

        return false;
    }

    std::cout
        << "\n  -> Selected method: "
        << method.name
        << "\n";

    // --------------------------------------------------------
    // Build command
    // --------------------------------------------------------

    auto cdb =
        buildSanitizeCommand(method);

    std::cout
        << "\n  -> SANITIZE DEVICE command:\n";

    std::cout
        << "     ATA opcode: 0x"
        << std::hex
        << static_cast<int>(cdb[14])
        << "\n";

    std::cout
        << "     Feature: 0x"
        << static_cast<int>(cdb[3])
        << std::dec
        << "\n";

    // --------------------------------------------------------
    // DRY RUN
    // --------------------------------------------------------

    std::cout#pragma once
#include "SanitizationEngine.h"

namespace core::sanitization {
    class SataSanitizer : public ISanitizer {
    public:
        bool wipe(const core::drive::DriveInfo& drive) override;
        std::string getProtocolName() const override { return "ATA Secure Erase"; }
    };
}
        << "\n  -> [DRY RUN]\n";

    std::cout
        << "     Command was constructed successfully.\n";

    std::cout
        << "     No destructive ATA command was sent.\n";

    /*
     * ========================================================
     * DO NOT ENABLE YET
     * ========================================================
     *
     * AtaCommandResult result = executeAtaPassthrough(
     *     fd,
     *     cdb.data(),
     *     cdb.size(),
     *     nullptr,
     *     0,
     *     SG_DXFER_NONE,
     *     ...
     * );
     *
     * This is intentionally disabled.
     */

    close(fd);

    /*
     * IMPORTANT:
     *
     * We return false here rather than true because a dry-run
     * is NOT a successful sanitization.
     *
     * Later we should replace bool with SanitizationResult.
     */

    return false;
}

} // namespace core::sanitization