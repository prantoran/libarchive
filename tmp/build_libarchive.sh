#!/bin/bash

export PWD=$(pwd)

mkdir -p ${HOME}/libarchive/build_p

cd ${HOME}/libarchive/build_p

cmake -DENABLE_EXTRACT_RAR_CMT=ON -DCMAKE_BUILD_TYPE=Debug -S ../ -B ./
# cmake -DENABLE_EXTRACT_RAR_CMT=OFF -DCMAKE_BUILD_TYPE=Debug -S ../ -B ./
# cmake -DCMAKE_BUILD_TYPE=Debug -S ../ -B ./
cmake --build  ./ -j$(nproc)


cd ${PWD}