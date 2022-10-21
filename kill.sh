#!/bin/bash

if [ $# -ne 1 ];
then 
	echo "Usage: kill.sh <P4_PROGRAM_NAME>"
	exit 1
fi

PROGRAM="$1"
PIDS=`pgrep bf_switchd`
MATCH=`ps aux | grep -E "$PIDS.{6,}bf_switchd.+$PROGRAM.conf"`

if [ -n "$PIDS" ] && [ -n "$MATCH" ] # not empty
then
	echo "These running switch processes will be killed: "$PIDS"."
	kill -9 $PIDS > /dev/null 2>&1 #This will cause an error because it also kill the process of "grep", however it has terminated.
else
	echo "No running switch process should be killed."
fi
