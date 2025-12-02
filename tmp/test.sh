#!/bin/bash

export PWD=$(pwd)

mkdir -p ${HOME}/libarchive/build_p

cd ${HOME}/libarchive/build_p

# make test
make libarchive_test

# /usr/local/bin/ctest --force_new_ctest_process --debug -R test_read_format_rar_subblock
/usr/local/bin/ctest --force_new_ctest_process -R test_read_format_rar_subblock


/home/pinku/libarchive/build_p/bin/libarchive_test -vvv -r /home/pinku/libarchive/libarchive/test -s test_read_format_rar_subblock

cd ${PWD}