#!/bin/bash

cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug
cd build && make -j$(nproc)
./sha256_test
cd .. && rm -rf build