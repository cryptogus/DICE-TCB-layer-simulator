cmake_minimum_required(VERSION 3.20)
project(dice_simulator CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Header-only INTERFACE library
add_library(dice_crypto INTERFACE)
target_include_directories(dice_crypto INTERFACE ${SODIUM_INCLUDE_DIRS} src/)
target_link_libraries(dice_crypto INTERFACE ${SODIUM_LIBRARIES})

add_executable(dice_demo src/main.cpp)
target_link_libraries(dice_demo PRIVATE dice_crypto)
