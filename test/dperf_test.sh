#!/bin/bash

# eg. dperf_test.sh "-B 192.168.1.1 -s -p 12345 -P 4"

DIR=$(dirname $0)
. $DIR/../utils.sh

if [ $# -gt 1 ]; 
then
    echo "Usage: ./dperf_test.sh \"CMD\""
    exit 1
fi

echo_r "sudo dperf $1 -l 1300"