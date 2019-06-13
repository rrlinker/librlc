cmake_minimum_required(VERSION 3.14)

project(
    librlcrypto
    VERSION 0.1
    DESCRIPTION "librlcom crypto wrapper for Remote Run-time Linker."
    LANGUAGES CXX
)

include("${CMAKE_SOURCE_DIR}/../cmake/find_libs_dir.cmake")
include("${CMAKE_SOURCE_DIR}/../cmake/find_arch.cmake")

file(GLOB SOURCE_FILES
    "*.cpp"
)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})

set_target_properties(
    ${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

target_link_directories(
    ${PROJECT_NAME}
    PRIVATE "${C_LIBS_DIR}/openssl"
    PRIVATE "${CXX_LIBS_DIR}/openssl"
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE libcrypto
)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE "${PROJECT_SOURCE_DIR}/.."
    PRIVATE "${C_LIBS_DIR}/openssl/include"
    PRIVATE "${CXX_LIBS_DIR}/openssl/include"
)
