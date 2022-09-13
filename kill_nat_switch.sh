PIDS=`ps aux | grep -E "bf_switchd.*nat" | sed "s/[^0-9]*\([0-9]*\).*/\1/g"`
echo $PIDS
kill -9 $PIDS
