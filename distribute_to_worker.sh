#!/bin/bash

DIR=$(dirname $0)

for i in {6..8}
do 
	rsync -rv -e ssh --exclude "build*" --exclude "tmp*" --exclude ".*" -r $DIR worker${i}:~/nat
done
