#!/bin/bash

set -e 

DIR=`cd $(dirname $0); pwd`

echo "Find and kill previous process"

$DIR/kill_nat_switch.sh

echo "Boot switch in the background"

$SDE/run_switchd.sh -p nat_test2 > /dev/null 2>&1 &

if [ "$1" == "--skip-table" ]
then
	:
else
	echo -n "Initializing tables... "

	$SDE/run_bfshell.sh -b ${DIR}/bfrt_test2.py > /dev/null 2>&1

	echo "Done"
fi

echo -n "Configuring ports... "

#~/tools/run_pd_rpc.py ${DIR}/rpc_port_init.py >/dev/null 2>&1
$SDE/run_bfshell.sh -f ${DIR}/ucli_port_init.py > /dev/null 2>&1

echo "Done"
