#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

if [ $# -ne 1 ];
then 
	echo_e "Usage: kill.sh <P4_PROGRAM_NAME>"
	exit 1
fi

PROGRAM="$1"
PIDS=`pgrep bf_switchd`
MATCH=`ps aux | grep -E "$PIDS.{6,}bf_switchd.+$PROGRAM.conf"`

if [ -n "$PIDS" ] && [ -n "$MATCH" ] # not empty
then
	echo_i "These running switch processes will be killed: "$PIDS"."
	echo_r "kill -9 $PIDS > /dev/null 2>&1" #This will cause an error because it also kill the process of "grep", however it has terminated.
else
	echo_i "No running switch process should be killed."
fi
