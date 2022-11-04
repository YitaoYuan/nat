#!/bin/bash

set -e

cd $(dirname $0)
P4_NAME=nat_test
P4_PATH=`pwd`/src/switch.p4

set -x

mkdir -p build_test
cd build_test

cmake $SDE/p4studio/ \
  -DCMAKE_INSTALL_PREFIX=$SDE_INSTALL \
  -DCMAKE_MODULE_PATH=$SDE/cmake \
  -DP4_NAME=$P4_NAME \
  -DP4_PATH=$P4_PATH \
