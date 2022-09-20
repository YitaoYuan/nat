#!/bin/bash
DIR=$(dirname $0)

p4c -a tna -b tofino ${DIR}/src/switch.p4 -o ${DIR}/build --Wdisable unused

non_stages=`cat ${DIR}/build/pipe/switch.bfa | grep -c stage`
echo "Take up $non_stages stages"
