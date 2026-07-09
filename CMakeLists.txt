cmake_minimum_required(VERSION 3.28)
project(acmecli VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -Wall -Wextra -O0)
else()
    add_compile_options(-O2 -DNDEBUG)
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(KERBEROS5 REQUIRED IMPORTED_TARGET krb5)
pkg_check_modules(GSSAPI REQUIRED IMPORTED_TARGET krb5-gssapi)
pkg_check_modules(OPENSSL REQUIRED IMPORTED_TARGET openssl)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/server
    ${CMAKE_SOURCE_DIR}/src/client
    ${CMAKE_SOURCE_DIR}/3rdparty/libconsole
    ${KERBEROS5_INCLUDE_DIRS}
    ${GSSAPI_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

# JSON library
add_library(jsoncpp STATIC
    ${CMAKE_SOURCE_DIR}/3rdparty/jsoncpp/jsoncpp.cpp
)
target_include_directories(jsoncpp PUBLIC
    ${CMAKE_SOURCE_DIR}/3rdparty/jsoncpp
)
target_link_libraries(jsoncpp PUBLIC)

# Console library
add_subdirectory(3rdparty/libconsole)

# HTTP Client Library
add_subdirectory(3rdparty/libhttp)

# ACME Server
add_executable(acme_server
    src/server/main.cpp
    src/server/acme_server.cpp
    src/server/certificate_manager.cpp
    src/server/policy_manager.cpp
)
target_link_libraries(acme_server
    jsoncpp
    libhttp
    PkgConfig::KERBEROS5
    PkgConfig::GSSAPI
    PkgConfig::OPENSSL
)

# ACME Client
add_executable(acme_client
    src/client/main.cpp
    src/client/acme_client.cpp
)
target_link_libraries(acme_client
    jsoncpp
    libhttp
    PkgConfig::KERBEROS5
    PkgConfig::OPENSSL
    PkgConfig::GSSAPI
)

# Install targets
install(TARGETS acme_server acme_client
    RUNTIME DESTINATION bin
)

install(DIRECTORY etc/
    DESTINATION etc/acmecli
    FILES_MATCHING PATTERN "*.conf"
)

# Create directories for certificates
install(DIRECTORY /etc/ssl
    DESTINATION /etc/ssl
    USE_SOURCE_PERMISSIONS
)