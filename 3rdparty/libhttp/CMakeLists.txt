# HTTP Client Library
# Provides HTTP client functionality with GSSAPI/Kerberos authentication support

add_library(libhttp STATIC
    HTTPClient.cpp
    Request.cpp
    Response.cpp
)

target_include_directories(libhttp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Check for libfetch
if(PKG_CONFIG_FOUND)
    pkg_check_modules(LIBFETCH libfetch)
    if(LIBFETCH_FOUND)
        target_compile_definitions(libhttp PRIVATE HAVE_LIBFETCH)
        target_link_libraries(libhttp PUBLIC ${LIBFETCH_LIBRARIES})
    endif()
endif()

# Check for libcurl as fallback
if(NOT LIBFETCH_FOUND)
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