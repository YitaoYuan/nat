#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

set -e 

if [ $# -ne 2 ];
then 
	echo_e "Usage: run.sh <P4_PROGRAM_NAME> <BFRT_PRELOAD_FILE>"
	exit 1
fi

DIR=`cd $(dirname $0); pwd`
PROGRAM=$1
BFRT_PRELOAD_FILE=`cd $(dirname $2); pwd`/$(basename $2)

echo_i "Find and kill previous process."

$DIR/kill.sh $PROGRAM

sleep 0.1

if [ -n "`pgrep bf_switchd`" ];
then 
    echo_e "Switch is being used by another program."
    exit 1
fi

echo_i "Boot switch in the background."

echo_r "$SDE/run_switchd.sh -p $PROGRAM > /dev/null 2>&1 &"


echo_i "Initializing tables... "

echo_r "$SDE/run_bfshell.sh -b $BFRT_PRELOAD_FILE > /dev/null 2>&1"

echo_i "Done."


echo_i "Configuring ports... "

#~/tools/run_pd_rpc.py ${DIR}/rpc_port_init.py >/dev/null 2>&1
echo_r "$SDE/run_bfshell.sh -f ${DIR}/ucli_port_init.py > /dev/null 2>&1"

echo_i "Done."
