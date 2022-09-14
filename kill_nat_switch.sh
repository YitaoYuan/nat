PIDS=`ps aux | grep -E "bf_switchd.*nat" | sed "s/[^0-9]*\([0-9]*\).*/\1/g"`
echo $PIDS
kill -9 $PIDS > /dev/null 2>&1 #This will cause an error because it also kill the process of "grep", however it has terminated.
