cmake_minimum_required(VERSION 3.10)
project(tests CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(GTest REQUIRED)

add_executable(sha256_test sha256_test.cpp)
target_include_directories(sha256_test PRIVATE ${SODIUM_INCLUDE_DIRS} ..)
target_link_libraries(sha256_test PRIVATE ${SODIUM_LIBRARIES} GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(sha256_test)