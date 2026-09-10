cmake_minimum_required(VERSION 3.15)
project(SIH_SanitizerOS VERSION 1.0 LANGUAGES CXX)

# Set C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include directories for core modules
# (device/ added directly because apps/device-test/main.cpp does
#  #include "DriveManager.h" with no path prefix)
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/device)

# HashEngine (acquisition module) uses OpenSSL's EVP API for SHA-256
find_package(OpenSSL REQUIRED)

# Sleuth Kit (libtsk) — used throughout recovery/ for image I/O
find_library(TSK_LIBRARY NAMES tsk)
if(NOT TSK_LIBRARY)
    message(FATAL_ERROR
        "libtsk not found. Confirm libtsk-dev is installed "
        "(expected e.g. /usr/lib/x86_64-linux-gnu/libtsk.so).")
endif()

find_path(TSK_INCLUDE_DIR NAMES tsk/libtsk.h)

add_library(tsk::tsk UNKNOWN IMPORTED)
set_target_properties(tsk::tsk PROPERTIES
    IMPORTED_LOCATION "${TSK_LIBRARY}"
)
if(TSK_INCLUDE_DIR)
    set_target_properties(tsk::tsk PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${TSK_INCLUDE_DIR}"
    )
endif()

# Collect all core source files
set(CORE_SOURCES
    device/DriveManager.cpp
    sanitization/SanitizationEngine.cpp
    sanitization/HddSanitizer.cpp
    sanitization/NvmeSanitizer.cpp
    sanitization/SataSanitizer.cpp
    sanitization/Verification.cpp
    acquisition/HashEngine.cpp
    acquisition/WriteProtection.cpp
    acquisition/DiskImager.cpp
    acquisition/AcquisitionManager.cpp
    recovery/FileCarver.cpp
    recovery/FileValidator.cpp
    recovery/ConfidenceScorer.cpp
    recovery/FileClassifier.cpp
)

# Create the core static library
add_library(sih_core STATIC ${CORE_SOURCES})

# sih_core needs OpenSSL for HashEngine and TSK for recovery modules
target_link_libraries(sih_core PRIVATE OpenSSL::Crypto)
target_link_libraries(sih_core PUBLIC tsk::tsk)

# Build the device test application
add_executable(device-test apps/device-test/main.cpp)
target_link_libraries(device-test PRIVATE sih_core pthread)

# Build the hash engine test application
add_executable(hashengine-test apps/hashengine-test/main.cpp)
target_link_libraries(hashengine-test PRIVATE sih_core pthread)

# Build the acquisition test application (write-protect -> image -> hash)
add_executable(acquisition-test apps/acquisition-test/main.cpp)
target_link_libraries(acquisition-test PRIVATE sih_core pthread)

# Build the sanitizer CLI application (drive picker -> dry-run sanitize)
add_executable(sanitizer apps/sanitizer/main.cpp)
target_link_libraries(sanitizer PRIVATE sih_core pthread)

# Build the recovery test application (carve -> validate -> score -> classify)
add_executable(recovery-test apps/recovery-test/main.cpp)
target_link_libraries(recovery-test PRIVATE sih_core pthread)

# Sanitizer UI (drive picker -> sanitize selected/all -> confirm -> log)
find_package(FLTK)
if(FLTK_FOUND)
    add_executable(sanitizer-ui apps/sanitizer-ui/main.cpp)
    target_include_directories(sanitizer-ui PRIVATE ${FLTK_INCLUDE_DIR})
    target_link_libraries(sanitizer-ui PRIVATE sih_core ${FLTK_LIBRARIES} pthread)
else()
    message(STATUS "FLTK not found - skipping sanitizer-ui target (install libfltk1.3-dev / fltk to build it)")
endif()

# ------------------------------------------------------------
# Python C++ Sanitizer Module
# ------------------------------------------------------------

find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(cpp_sanitizer
    UI/sanitizer_ui.cpp
)

target_link_libraries(cpp_sanitizer
    PRIVATE
    sih_core
)

target_include_directories(cpp_sanitizer
    PRIVATE
    ${CMAKE_SOURCE_DIR}
)

set_target_properties(cpp_sanitizer PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY
    ${CMAKE_SOURCE_DIR}/UI
)
