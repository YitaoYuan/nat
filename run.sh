#!/bin/bash

set -e 

DIR=`cd $(dirname $0); pwd`
PROGRAM=nat

echo "Find and kill previous process."

$DIR/kill.sh $PROGRAM

sleep 0.1

if [ -n "`pgrep bf_switchd`" ];
then 
    echo "Switch is being used by another program."
    exit 1
fi

echo "Boot switch in the background."

$SDE/run_switchd.sh -p $PROGRAM > /dev/null 2>&1 &

if [ "$1" == "--skip-table" ]
then
	:
else
	echo -n "Initializing tables... "

	$SDE/run_bfshell.sh -b ${DIR}/bfrt_table_init.py > /dev/null 2>&1

	echo "Done."
fi

echo -n "Configuring ports... "

#~/tools/run_pd_rpc.py ${DIR}/rpc_port_init.py >/dev/null 2>&1
$SDE/run_bfshell.sh -f ${DIR}/ucli_port_init.py > /dev/null 2>&1

echo "Done."
