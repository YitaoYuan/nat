#!/bin/bash

~/tools/p4_build.sh $(dirname $0)/src/switch.p4 P4_NAME=nat

non_stages=`cat $SDE/build/p4-build/nat/tofino/nat/pipe/switch.bfa | grep -c stage`
echo "Take up $non_stages stages"
