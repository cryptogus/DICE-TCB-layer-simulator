cmake_minimum_required(VERSION 3.20)
project(dice_simulator CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)