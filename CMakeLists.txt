cmake_minimum_required(VERSION 3.15)
project(SIH_SanitizerOS VERSION 1.0 LANGUAGES CXX)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories for core modules
include_directories(${CMAKE_SOURCE_DIR})

# Collect all core source files
set(CORE_SOURCES
    device/DriveManager.cpp
    sanitization/SanitizationEngine.cpp
    sanitization/HddSanitizer.cpp
    sanitization/NvmeSanitizer.cpp
    sanitization/SataSanitizer.cpp
    sanitization/Verification.cpp
)

# Create the core static library
add_library(sih_core STATIC ${CORE_SOURCES})

# Build the device test application
add_executable(device-test apps/device-test/main.cpp)

# Link the test app against the core library and pthread (often required for system calls)
target_link_libraries(device-test PRIVATE sih_core pthread)