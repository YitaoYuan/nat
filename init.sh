#!/bin/bash

set -e 

DIR=`cd $(dirname $0); pwd`

echo "Find and kill previous process"

$DIR/kill_nat_switch.sh

echo "Boot switch in the background"

$SDE/run_switchd.sh -p nat >/dev/null 2>&1 &

echo -n "Configuring ports... "

~/tools/run_pd_rpc.py ${DIR}/rpc_port_init.py >/dev/null 2>&1

echo "Done"

echo -n "Initializing tables... "

$SDE/run_bfshell.sh -b ${DIR}/bfshell_table_init.py >/dev/null 2>&1

echo "Done"
