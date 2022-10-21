#!/bin/bash

DIR=$(dirname $0)

for i in {1..4}
do 
	rsync -rv -e ssh --exclude "build*" --exclude "tmp*" --exclude ".*" -r $DIR switch3worker${i}:~/nat
done
