#!/bin/bash

DIR=$(dirname $0)
. $DIR/utils.sh

for i in {1..4}
do 
	echo_r 'rsync -rv -e ssh --exclude "build*" --exclude "tmp*" --exclude ".*" -r $DIR switch3worker${i}:~/nat'
done
