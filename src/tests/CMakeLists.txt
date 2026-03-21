cmake_minimum_required(VERSION 3.20)
project(tests CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(GTest REQUIRED)

add_library(dice_crypto INTERFACE)
target_include_directories(dice_crypto INTERFACE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(dice_crypto INTERFACE ${SODIUM_LIBRARIES})

set(TESTS sha256_test uds_gen_test hmac_sha256_test hkdf_test ed25519_test)

foreach(test ${TESTS})
    add_executable(${test} ${test}.cpp)
    target_link_libraries(${test} PRIVATE dice_crypto GTest::gtest_main)
endforeach()

include(GoogleTest)
foreach(test ${TESTS})
    gtest_discover_tests(${test})
endforeach()
