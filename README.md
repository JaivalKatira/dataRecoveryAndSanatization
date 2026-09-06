# SIH SanitizerOS — Data Recovery & Sanitization

> **A modular C++ storage forensics and secure data sanitization framework for identifying, acquiring, recovering, and securely sanitizing storage devices.**

[![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/)
[![CMake](https://img.shields.io/badge/CMake-3.15%2B-064F8C.svg)](https://cmake.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-SHA--256-721412.svg)](https://www.openssl.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](#)
[![Status](https://img.shields.io/badge/Status-Development-orange.svg)](#)

---

## 📌 Overview

**SIH SanitizerOS** is a modular storage security and digital-forensics framework designed to provide a controlled workflow for handling storage media.

The project combines:

* 🔍 **Storage device discovery**
* 🛡️ **Write protection**
* 💾 **Forensic disk imaging**
* 🔐 **Cryptographic hashing**
* 🔎 **Deleted-file recovery**
* 🧹 **Storage sanitization**
* ✅ **Post-sanitization verification**
* 🖥️ **CLI and optional GUI interfaces**

The system is designed around a modular architecture so that different storage technologies and forensic operations can be implemented independently.

---

## 🎯 Objectives

The primary objectives of the project are:

1. **Identify connected storage devices**
2. **Collect device metadata safely**
3. **Protect source media from accidental modification**
4. **Create forensic images of storage media**
5. **Generate cryptographic hashes for integrity verification**
6. **Recover potentially deleted or fragmented files**
7. **Select an appropriate sanitization method based on device type**
8. **Verify that sanitization was successfully performed**
9. **Provide an auditable workflow for storage handling**

---

## 🏗️ Architecture

The project is divided into several core modules:

```text
                    ┌─────────────────────────┐
                    │       Applications      │
                    │                         │
                    │  Device Test            │
                    │  Acquisition Test       │
                    │  Recovery Test          │
                    │  Sanitizer CLI          │
                    │  Sanitizer GUI          │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │       SIH Core          │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          ▼                      ▼                      ▼
 ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 │ Device Manager  │    │   Acquisition   │    │    Recovery     │
 │                 │    │                 │    │                 │
 │ Drive Detection │    │ Disk Imaging    │    │ File Carving    │
 │ Drive Metadata  │    │ Hashing         │    │ Validation      │
 │ Bus Detection   │    │ Write Protect   │    │ Classification  │
 └─────────────────┘    └─────────────────┘    └─────────────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │    Sanitization    │
                       │                    │
                       │ HDD                │
                       │ SATA               │
                       │ NVMe               │
                       │ Verification       │
                       └────────────────────┘
```

---

## 📂 Project Structure

```text
dataRecoveryAndSanatization/
│
├── apps/
│   ├── acquisition-test/
│   │   └── main.cpp
│   │
│   ├── device-test/
│   │   └── main.cpp
│   │
│   ├── recovery-test/
│   │   └── main.cpp
│   │
│   ├── sanitizer/
│   │   └── main.cpp
│   │
│   └── sanitizer-ui/
│       └── main.cpp
│
├── acquisition/
│   ├── AcquisitionManager.cpp
│   ├── AcquisitionManager.h
│   ├── DiskImager.cpp
│   ├── DiskImager.h
│   ├── HashEngine.cpp
│   ├── HashEngine.h
│   ├── WriteProtection.cpp
│   └── WriteProtection.h
│
├── device/
│   ├── DriveInfo.h
│   ├── DriveManager.cpp
│   └── DriveManager.h
│
├── recovery/
│   ├── FileCarver.cpp
│   ├── FileCarver.h
│   ├── FileValidator.cpp
│   ├── FileValidator.h
│   ├── ConfidenceScorer.cpp
│   ├── ConfidenceScorer.h
│   ├── FileClassifier.cpp
│   └── FileClassifier.h
│
├── sanitization/
│   ├── SanitizationEngine.cpp
│   ├── SanitizationEngine.h
│   ├── HddSanitizer.cpp
│   ├── HddSanitizer.h
│   ├── SataSanitizer.cpp
│   ├── SataSanitizer.h
│   ├── NvmeSanitizer.cpp
│   ├── NvmeSanitizer.h
│   ├── Verification.cpp
│   └── Verification.h
│
├── CMakeLists.txt
└── README.md
```

The current repository contains dedicated `apps`, `device`, and `sanitization` components, while the CMake build integrates acquisition and recovery modules as part of the core library.

---

# 🔧 Core Modules

## 1. Device Management

The device-management layer detects available storage devices and collects information such as:

* Device path
* Model
* Serial number
* Capacity
* Bus type
* Media type

Example:

```text
Device: /dev/sda
Model: Samsung SSD
Serial: XXXXXXXX
Bus: SATA
Capacity: 512000000000 bytes
Media: SSD
```

The `DriveManager` provides the abstraction used by the rest of the system to interact with storage devices.

---

## 2. Acquisition

The acquisition subsystem is designed for forensic collection of storage media.

### Components

* `AcquisitionManager`
* `DiskImager`
* `HashEngine`
* `WriteProtection`

The acquisition workflow is intended to follow:

```text
Storage Device
      │
      ▼
Write Protection
      │
      ▼
Forensic Imaging
      │
      ▼
SHA-256 Hash
      │
      ▼
Evidence Image
```

The build system links the acquisition components into the `sih_core` static library and uses OpenSSL's cryptographic API for hashing.

---

# 🔎 3. Data Recovery

The recovery subsystem provides a pipeline for analyzing acquired storage data.

```text
Disk/Image
    │
    ▼
File Carving
    │
    ▼
File Validation
    │
    ▼
Confidence Scoring
    │
    ▼
File Classification
    │
    ▼
Recovered Files
```

### Components

| Component          | Purpose                                               |
| ------------------ | ----------------------------------------------------- |
| `FileCarver`       | Searches storage data for recoverable file structures |
| `FileValidator`    | Validates recovered file candidates                   |
| `ConfidenceScorer` | Assigns confidence to recovery results                |
| `FileClassifier`   | Determines recovered file types                       |

This allows the recovery process to go beyond simply locating byte patterns and instead provide additional validation and confidence information.

---

# 🧹 4. Data Sanitization

The sanitization subsystem is responsible for securely processing storage devices before disposal, reuse, or reassignment.

The system selects a sanitizer according to the detected drive bus:

```text
                 Drive
                   │
                   ▼
           SanitizationEngine
                   │
          ┌────────┼────────┐
          │        │        │
         NVMe     SATA     Other
          │        │        │
          ▼        ▼        ▼
       NVMe     SATA      HDD
     Sanitizer Sanitizer Sanitizer
```

The current implementation selects:

* **NVMe** → `NvmeSanitizer`
* **SATA** → `SataSanitizer`
* **SCSI / USB / Unknown** → `HddSanitizer` fallback

After the wipe operation, the engine performs a verification step.

---

## 5. Sanitization Verification

Sanitization is followed by verification to ensure the expected storage state has been achieved.

```text
             Sanitization
                   │
                   ▼
              Verification
                   │
            ┌──────┴──────┐
            ▼             ▼
         Success         Failure
            │             │
            ▼             ▼
       Completed       Abort / Report
```

The current engine performs the wipe first and then calls `Verification::verifyZeroes()` before reporting successful sanitization.

---

# 🖥️ Applications

The project provides multiple test and utility applications.

## Device Test

Used to enumerate connected storage devices and inspect their metadata.

```bash
./device-test
```

---

## Acquisition Test

Tests the acquisition pipeline:

```text
Write Protection
       ↓
Disk Imaging
       ↓
Hash Generation
```

```bash
./acquisition-test
```

---

## Recovery Test

Tests the recovery pipeline:

```text
Carve
  ↓
Validate
  ↓
Score
  ↓
Classify
```

```bash
./recovery-test
```

---

## Sanitizer CLI

The sanitizer CLI displays detected drives and allows the operator to select a target device.

Example workflow:

```text
=====================================
        SIH SANITIZER TEST
=====================================

[0]
Device: /dev/sda
Model: ...
Serial: ...
Bus: SATA
Capacity: ...
Media: ...

Select drive index:
```

The application then passes the selected drive to `SanitizationEngine`.

> ⚠️ **Warning:** Storage sanitization can permanently destroy data. Never run sanitization against a drive containing data that needs to be preserved.

---

# 🛠️ Tech Stack

| Technology           | Purpose                              |
| -------------------- | ------------------------------------ |
| **C++17**            | Core implementation                  |
| **CMake**            | Build system                         |
| **OpenSSL**          | Cryptographic hashing                |
| **POSIX/Linux APIs** | Device and block-storage interaction |
| **pthread**          | Threading/system integration         |
| **FLTK**             | Optional lightweight GUI             |

The project currently requires C++17 and CMake 3.15+, with OpenSSL required by the core build. FLTK is optional and enables the `sanitizer-ui` target when installed.

---

# 🚀 Getting Started

## Prerequisites

A Linux environment is recommended.

Install the required packages on Debian/Ubuntu:

```bash
sudo apt update

sudo apt install \
    build-essential \
    cmake \
    libssl-dev
```

For the optional GUI:

```bash
sudo apt install libfltk1.3-dev
```

---

## Clone the Repository

```bash
git clone https://github.com/sanyampat/dataRecoveryAndSanatization.git

cd dataRecoveryAndSanatization
```

---

## Build

Create a build directory:

```bash
mkdir build
cd build
```

Configure the project:

```bash
cmake ..
```

Build:

```bash
make -j$(nproc)
```

The CMake configuration creates a static `sih_core` library and builds the available test/utility applications against it.

---

# ▶️ Running

From the `build` directory:

```bash
./device-test
```

```bash
./acquisition-test
```

```bash
./recovery-test
```

```bash
./sanitizer
```

If FLTK is installed:

```bash
./sanitizer-ui
```

Depending on the operation, **root privileges may be required** to access raw block devices.

For example:

```bash
sudo ./device-test
```

---

# 🔐 Security Considerations

This project interacts directly with storage devices. Therefore:

* Always verify the selected device before destructive operations.
* Do not run sanitization on production drives.
* Test recovery functionality on copies or disposable media.
* Use write protection during forensic acquisition whenever possible.
* Preserve hashes and acquisition metadata as part of the evidence record.
* Run destructive operations only after explicit operator confirmation.

> **Never assume `/dev/sda`, `/dev/sdb`, etc. refers to a particular physical device. Always verify the device identity and capacity.**

---

# 🧪 Development Status

This project is currently under active development.

### Implemented / In Progress

* [x] Storage device discovery
* [x] Drive metadata abstraction
* [x] Modular sanitization engine
* [x] HDD sanitization abstraction
* [x] SATA sanitization abstraction
* [x] NVMe sanitization abstraction
* [x] Sanitization verification layer
* [x] Acquisition architecture
* [x] SHA-256 hashing integration
* [x] Recovery pipeline architecture
* [x] CLI test applications
* [x] Optional FLTK sanitizer UI
* [ ] Full production-grade recovery engine
* [ ] Complete forensic audit logging
* [ ] Comprehensive automated testing
* [ ] Hardware compatibility testing
* [ ] Bootable live forensic/sanitization environment

---

# 🗺️ Roadmap

### Phase 1 — Core Infrastructure

* [x] Device detection
* [x] Drive metadata
* [x] Modular C++ architecture
* [x] CMake build system

### Phase 2 — Forensic Acquisition

* [x] Disk imaging architecture
* [x] Hashing
* [x] Write protection abstraction
* [ ] Evidence manifest
* [ ] Acquisition logs

### Phase 3 — Recovery

* [x] File carving architecture
* [x] File validation
* [x] Confidence scoring
* [x] File classification
* [ ] More file signatures
* [ ] Fragmented-file recovery
* [ ] Recovery reporting

### Phase 4 — Sanitization

* [x] Sanitization engine
* [x] Device-specific sanitizer abstraction
* [x] Verification
* [ ] Expanded NVMe command support
* [ ] Improved SATA secure-erase support
* [ ] Device capability detection
* [ ] Detailed sanitization certificates

### Phase 5 — SIH SanitizerOS

* [ ] Live Linux environment
* [ ] Bootable ISO
* [ ] Full graphical interface
* [ ] Automated device classification
* [ ] Evidence/audit logs
* [ ] Sanitization reports
* [ ] Hardware compatibility database

---

# 📊 Design Philosophy

The system follows a **modular architecture** rather than implementing all storage operations inside a single application.

This makes it possible to independently extend:

```text
Device Layer
     ↓
Acquisition Layer
     ↓
Recovery Layer
     ↓
Sanitization Layer
     ↓
Verification Layer
     ↓
User Interface
```

This separation makes the project easier to test, maintain, and extend to additional storage technologies.

---

# ⚠️ Disclaimer

This project is intended for **authorized forensic analysis, data recovery, research, and secure storage sanitization**.

The sanitization functionality is potentially destructive and can permanently erase data.

Only operate on storage devices that you own or have explicit authorization to process.

The authors are not responsible for data loss, hardware damage, or misuse of the software.

---

# 🤝 Contributing

Contributions are welcome.

A typical workflow:

```bash
git checkout -b feature/your-feature

# Make your changes

git add .

git commit -m "Add: your feature"

git push origin feature/your-feature
```

Then open a Pull Request.

When contributing, please:

* Keep modules separated by responsibility.
* Follow modern C++ practices.
* Avoid destructive operations in tests.
* Add tests for new functionality.
* Document hardware-specific behavior.
* Clearly identify experimental functionality.

---

# 📜 License

Add your chosen license here.

For example:

```text
MIT License
```

See `LICENSE` for the complete license terms.

---

# 👥 Team

**SIH — Data Recovery & Sanitization**

Built as a Smart India Hackathon project focused on secure storage handling, digital forensics, data recovery, and data sanitization.

---

## ⭐ Project

If you find this project useful, consider giving the repository a ⭐.

**Repository:**
https://github.com/sanyampat/dataRecoveryAndSanatization
