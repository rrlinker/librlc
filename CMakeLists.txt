cmake_minimum_required(VERSION 3.14)

project(
    librrlcrypto
    VERSION 0.1
    DESCRIPTION "librrlcom crypto wrapper for Remote Run-time Linker."
    LANGUAGES CXX
)

set(SOURCE_FILES
    "lib/crypto_connection.cpp"
    "lib/exception.cpp"
    "lib/aes.cpp"
    "lib/crypto_courier.cpp"
    "lib/random.cpp"
    "lib/bytes.cpp"
    "lib/evp_context.cpp"
    "lib/rsa.cpp"
)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})

set_target_properties(
    ${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC include
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC libcrypto librrlcom
)
