# Console Library
# Provides console output functionality with ANSI color support

add_library(libconsole STATIC
    Console.cpp
)

target_include_directories(libconsole PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(libconsole PUBLIC cxx_std_26)