# HTTP Client Library
# Provides HTTP client and server functionality with GSSAPI/Kerberos authentication support

add_library(libhttp STATIC
    HTTPClient.cpp
    HTTPServer.cpp
    KerberosAuth.cpp
)

target_include_directories(libhttp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(libhttp PUBLIC
    libconsole
)

# Check for libfetch
find_library(FETCH_LIBRARY NAMES fetch PATHS /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64)
if(FETCH_LIBRARY)
    target_compile_definitions(libhttp PRIVATE HAVE_LIBFETCH)
    target_link_libraries(libhttp PUBLIC ${FETCH_LIBRARY})
    message(STATUS "Found libfetch: ${FETCH_LIBRARY}")
else()
    message(STATUS "libfetch not found, will use libcurl as fallback")
    find_package(CURL REQUIRED)
    target_link_libraries(libhttp PUBLIC CURL::libcurl)
endif()

# GSSAPI support
if(GSSAPI_FOUND)
    target_include_directories(libhttp PUBLIC ${GSSAPI_INCLUDE_DIRS})
    target_link_libraries(libhttp PUBLIC ${GSSAPI_LIBRARIES})
endif()

# Set C++ standard
target_compile_features(libhttp PUBLIC cxx_std_26)