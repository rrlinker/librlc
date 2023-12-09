cmake_minimum_required(VERSION 3.14)

project(
    librrlcrypto
    VERSION 0.1
    DESCRIPTION "librrlcom crypto wrapper for Remote Run-time Linker."
    LANGUAGES CXX
)

set(SOURCE_FILES
    "lib/aes.cpp"
    "lib/bytes.cpp"
    "lib/crypto_connection.cpp"
    "lib/crypto_courier.cpp"
    "lib/evp_context.cpp"
    "lib/exception.cpp"
    "lib/random.cpp"
    "lib/rsa.cpp"
)

set(HEADER_FILES
    "include/rrlinker/crypto/aes.hpp"
    "include/rrlinker/crypto/bytes.hpp"
    "include/rrlinker/crypto/crypto_connection.hpp"
    "include/rrlinker/crypto/crypto_courier.hpp"
    "include/rrlinker/crypto/evp_context.hpp"
    "include/rrlinker/crypto/exception.hpp"
    "include/rrlinker/crypto/mode.hpp"
    "include/rrlinker/crypto/operation.hpp"
    "include/rrlinker/crypto/random.hpp"
    "include/rrlinker/crypto/rsa.hpp"
)

add_library(${PROJECT_NAME} STATIC
    ${HEADER_FILES}
    ${SOURCE_FILES}
)

set_target_properties(
    ${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    PUBLIC_HEADER "${HEADER_FILES}"
)

target_include_directories(${PROJECT_NAME} PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC librrlcom
)

if(UNIX)
    target_link_libraries(${PROJECT_NAME} PUBLIC crypto)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC libcrypto)
endif()

include(GNUInstallDirs)
install(
    TARGETS ${PROJECT_NAME}
    EXPORT crypto
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/rrlinker/crypto"
)
install(EXPORT crypto DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake")
