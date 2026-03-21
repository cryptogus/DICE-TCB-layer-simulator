cmake_minimum_required(VERSION 3.10)
project(tests CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(GTest REQUIRED)

add_executable(sha256_test sha256_test.cpp)
target_include_directories(sha256_test PRIVATE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(sha256_test PRIVATE ${SODIUM_LIBRARIES} GTest::gtest_main)

add_executable(uds_gen_test uds_gen_test.cpp)
target_include_directories(uds_gen_test PRIVATE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(uds_gen_test PRIVATE ${SODIUM_LIBRARIES} GTest::gtest_main)


add_executable(hmac_sha256_test hmac_sha256_test.cpp)
target_include_directories(hmac_sha256_test PRIVATE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(hmac_sha256_test PRIVATE ${SODIUM_LIBRARIES} GTest::gtest_main)

add_executable(hkdf_test hkdf_test.cpp)
target_include_directories(hkdf_test PRIVATE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(hkdf_test PRIVATE ${SODIUM_LIBRARIES} GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(sha256_test)
gtest_discover_tests(uds_gen_test)
gtest_discover_tests(hmac_sha256_test)
gtest_discover_tests(hkdf_test)