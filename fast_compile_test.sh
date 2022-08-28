#!/bin/bash
DIR=$(dirname $0)

p4c -a v1model -b tofino ${DIR}/src/switch.p4 -o ${DIR}/build
